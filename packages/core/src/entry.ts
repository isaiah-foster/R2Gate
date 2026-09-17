// Log entry schema v1 (PLAN §5.2): canonical JSON objects with `"v":1` and a `"type"`.
//
// Validation is strict in both directions. The writer refuses to log anything outside the schema,
// and a reader rejects a known type that violates it, because a malformed entry in a signed log is
// evidence of a writer bug or of tampering. Unknown types (or versions) are reported as unknown
// rather than rejected, so the schema can grow without breaking old readers.
//
// The audit.* types are provisional until the auditor lands (M6); nothing has been published yet.

import { MAX_ENTRY_SIZE } from './bundle.ts';
import {
  CanonicalJsonError,
  decodeCanonical,
  encodeCanonical,
  type JsonValue,
} from './canonical.ts';
import { utf8Encode } from './bytes.ts';

export const ENTRY_SCHEMA_VERSION = 1;

/** R2 object keys are at most 1,024 bytes of UTF-8. */
export const MAX_OBJECT_KEY_BYTES = 1024;

export const OBJECT_ACTIONS = [
  'PutObject',
  'CopyObject',
  'CompleteMultipartUpload',
  'DeleteObject',
  'LifecycleDeletion',
] as const;
export type ObjectAction = (typeof OBJECT_ACTIONS)[number];
const DELETE_ACTIONS: readonly ObjectAction[] = ['DeleteObject', 'LifecycleDeletion'];

export const FINDING_KINDS = [
  'UNLOGGED_OBJECT',
  'MISSING_OBJECT',
  'ETAG_MISMATCH',
  'SIZE_MISMATCH',
  'PHANTOM_DELETE',
] as const;
export type FindingKind = (typeof FINDING_KINDS)[number];

/** An R2 event notification, as ingested. `account` is deliberately not logged. */
export interface ObjectEvent {
  readonly v: 1;
  readonly type: 'object.event';
  readonly bucket: string;
  readonly key: string;
  readonly action: ObjectAction;
  /** Absent on delete events (R2 does not send it). */
  readonly size?: number;
  /** Absent on delete events. MD5 for single-part uploads; not a content hash for multipart. */
  readonly etag?: string;
  /** RFC 3339, verbatim from the notification. */
  readonly eventTime: string;
  /** RFC 3339, from the Worker clock when the event was ingested. */
  readonly ingestedAt: string;
  /** CopyObject only. R2 sends this as `{bucket, object}`; it is logged as `{bucket, key}`. */
  readonly copySource?: { readonly bucket: string; readonly key: string };
}

/** Baseline state of a pre-existing object, recorded by backfill. */
export interface ObjectSnapshot {
  readonly v: 1;
  readonly type: 'object.snapshot';
  readonly bucket: string;
  readonly key: string;
  readonly size: number;
  readonly etag: string;
  readonly uploaded: string;
  readonly snapshotId: string;
}

export interface ObservedState {
  readonly etag: string;
  readonly size: number;
  readonly uploaded: string;
}

export interface ExpectedState {
  readonly etag?: string;
  readonly size?: number;
  readonly eventTime: string;
  /** Log index of the entry that established the expected state. */
  readonly seq: number;
}

export interface AuditFinding {
  readonly v: 1;
  readonly type: 'audit.finding';
  readonly kind: FindingKind;
  readonly bucket: string;
  readonly key: string;
  readonly observed?: ObservedState;
  readonly expected?: ExpectedState;
  readonly scanId: string;
  readonly observedAt: string;
  /** The grace window in force when the finding was made (PLAN §5.6). */
  readonly graceSeconds: number;
}

export interface AuditScan {
  readonly v: 1;
  readonly type: 'audit.scan';
  readonly scanId: string;
  readonly phase: 'start' | 'end';
  readonly objectsScanned?: number;
  readonly findings?: number;
  readonly logSizeAtStart?: number;
}

export interface AuditObservation {
  readonly v: 1;
  readonly type: 'audit.observation';
  readonly bucket: string;
  readonly key: string;
  readonly etag: string;
  readonly size: number;
  /** Lowercase hex SHA-256 of the object body. */
  readonly sha256: string;
  readonly scanId: string;
  readonly observedAt: string;
}

export type Entry = ObjectEvent | ObjectSnapshot | AuditFinding | AuditScan | AuditObservation;
export type EntryType = Entry['type'];

export type DecodedEntry =
  | { readonly known: true; readonly entry: Entry }
  | { readonly known: false; readonly type: string; readonly v: number };

export class EntryError extends Error {
  override name = 'EntryError';
}

// ---- field validators -------------------------------------------------------------------------

type Check = (value: unknown, path: string) => void;

function fail(path: string, what: string): never {
  throw new EntryError(`${path}: ${what}`);
}

function pattern(re: RegExp, what: string): Check {
  return (v, path) => {
    if (typeof v !== 'string' || !re.test(v)) fail(path, `must be ${what}`);
  };
}

function oneOf(values: readonly string[]): Check {
  return (v, path) => {
    if (typeof v !== 'string' || !values.includes(v))
      fail(path, `must be one of ${values.join(', ')}`);
  };
}

const literal =
  (want: string | number): Check =>
  (v, path) => {
    if (v !== want) fail(path, `must be ${JSON.stringify(want)}`);
  };

/** R2 bucket names: 3-63 of [a-z0-9-], not starting or ending with a hyphen. */
const bucketName = pattern(/^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/, 'a valid R2 bucket name');

const objectKey: Check = (v, path) => {
  if (typeof v !== 'string' || v.length === 0) fail(path, 'must be a non-empty string');
  if (!v.isWellFormed()) fail(path, 'key contains a lone surrogate');
  if (utf8Encode(v).length > MAX_OBJECT_KEY_BYTES) {
    fail(path, `key exceeds ${String(MAX_OBJECT_KEY_BYTES)} UTF-8 bytes`);
  }
};

/** Unquoted entity tag: 1-256 printable ASCII characters, no space or double quote. */
const etag = pattern(/^[\x21\x23-\x7e]{1,256}$/, 'an unquoted ETag');

const uint: Check = (v, path) => {
  if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 0) {
    fail(path, 'must be a non-negative safe integer');
  }
};

/** Identifier safe to embed in an R2 key or URL path segment. */
const id = pattern(/^[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}$/, 'an identifier of [A-Za-z0-9._-]');

const sha256Hex = pattern(/^[0-9a-f]{64}$/, '64 lowercase hex digits');

const RFC3339 =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|[+-](\d{2}):(\d{2}))$/;

/** RFC 3339 date-time with an explicit offset (`Z` or ±hh:mm) and a real calendar date. */
const timestamp: Check = (v, path) => {
  const m = typeof v === 'string' ? RFC3339.exec(v) : null;
  if (!m) fail(path, 'must be an RFC 3339 timestamp with an offset');
  const n = (i: number): number => Number(m[i] ?? 0); // absent offset groups (`Z`) read as 0
  const [year, month, day] = [n(1), n(2), n(3)];
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const daysInMonth = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1] ?? 0;
  const ok =
    day >= 1 &&
    day <= daysInMonth &&
    n(4) <= 23 &&
    n(5) <= 59 &&
    n(6) <= 59 &&
    n(7) <= 23 &&
    n(8) <= 59;
  if (!ok) fail(path, 'is not a valid date and time');
};

interface Field {
  readonly check: Check;
  readonly optional?: boolean;
}

const req = (check: Check): Field => ({ check });
const opt = (check: Check): Field => ({ check, optional: true });

function record(v: unknown, path: string): Record<string, unknown> {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) fail(path, 'must be an object');
  return v as Record<string, unknown>;
}

/** Checks that `v` is an object with exactly the given fields (optional ones may be absent). */
function shape(
  v: unknown,
  path: string,
  fields: Readonly<Record<string, Field>>,
): Record<string, unknown> {
  const o = record(v, path);
  for (const k of Object.keys(o)) {
    if (!(k in fields)) fail(`${path}.${k}`, 'unknown field');
    if (o[k] === undefined) fail(`${path}.${k}`, 'must not be undefined');
  }
  for (const [k, f] of Object.entries(fields)) {
    if (!(k in o)) {
      if (f.optional) continue;
      fail(`${path}.${k}`, 'is required');
    }
    f.check(o[k], `${path}.${k}`);
  }
  return o;
}

const nested =
  (fields: Readonly<Record<string, Field>>): Check =>
  (v, path) => {
    shape(v, path, fields);
  };

const header = (type: EntryType): Record<string, Field> => ({
  v: req(literal(ENTRY_SCHEMA_VERSION)),
  type: req(literal(type)),
});

const observedState = nested({ etag: req(etag), size: req(uint), uploaded: req(timestamp) });
const expectedState = nested({
  etag: opt(etag),
  size: opt(uint),
  eventTime: req(timestamp),
  seq: req(uint),
});

const validators: Readonly<Record<EntryType, (v: unknown) => void>> = {
  'object.event': (v) => {
    const o = shape(v, 'entry', {
      ...header('object.event'),
      bucket: req(bucketName),
      key: req(objectKey),
      action: req(oneOf(OBJECT_ACTIONS)),
      size: opt(uint),
      etag: opt(etag),
      eventTime: req(timestamp),
      ingestedAt: req(timestamp),
      copySource: opt(nested({ bucket: req(bucketName), key: req(objectKey) })),
    });
    const action = o.action as ObjectAction;
    if (DELETE_ACTIONS.includes(action) && ('size' in o || 'etag' in o)) {
      fail('entry', `${action} events carry no size or etag`);
    }
    if ('copySource' in o && action !== 'CopyObject') {
      fail('entry.copySource', 'only allowed on CopyObject');
    }
  },
  'object.snapshot': (v) => {
    shape(v, 'entry', {
      ...header('object.snapshot'),
      bucket: req(bucketName),
      key: req(objectKey),
      size: req(uint),
      etag: req(etag),
      uploaded: req(timestamp),
      snapshotId: req(id),
    });
  },
  'audit.finding': (v) => {
    const o = shape(v, 'entry', {
      ...header('audit.finding'),
      kind: req(oneOf(FINDING_KINDS)),
      bucket: req(bucketName),
      key: req(objectKey),
      observed: opt(observedState),
      expected: opt(expectedState),
      scanId: req(id),
      observedAt: req(timestamp),
      graceSeconds: req(uint),
    });
    const kind = o.kind as FindingKind;
    const wantObserved = kind !== 'MISSING_OBJECT';
    const wantExpected = kind !== 'UNLOGGED_OBJECT';
    if ('observed' in o !== wantObserved) {
      fail('entry.observed', `must be ${wantObserved ? 'present' : 'absent'} for ${kind}`);
    }
    if ('expected' in o !== wantExpected) {
      fail('entry.expected', `must be ${wantExpected ? 'present' : 'absent'} for ${kind}`);
    }
  },
  'audit.scan': (v) => {
    const o = shape(v, 'entry', {
      ...header('audit.scan'),
      scanId: req(id),
      phase: req(oneOf(['start', 'end'])),
      objectsScanned: opt(uint),
      findings: opt(uint),
      logSizeAtStart: opt(uint),
    });
    const forbidden = o.phase === 'start' ? ['objectsScanned', 'findings'] : ['logSizeAtStart'];
    for (const k of forbidden) {
      if (k in o) fail(`entry.${k}`, `not allowed when phase is ${String(o.phase)}`);
    }
  },
  'audit.observation': (v) => {
    shape(v, 'entry', {
      ...header('audit.observation'),
      bucket: req(bucketName),
      key: req(objectKey),
      etag: req(etag),
      size: req(uint),
      sha256: req(sha256Hex),
      scanId: req(id),
      observedAt: req(timestamp),
    });
  },
};

function isEntryType(t: string): t is EntryType {
  return Object.hasOwn(validators, t);
}

/** Throws EntryError unless `v` is a valid v1 entry. */
export function validateEntry(v: unknown): asserts v is Entry {
  const o = record(v, 'entry');
  if (typeof o.type !== 'string' || !isEntryType(o.type)) fail('entry.type', 'unknown entry type');
  validators[o.type](o);
}

function checkSize(n: number): void {
  if (n > MAX_ENTRY_SIZE) {
    throw new EntryError(`entry is ${String(n)} bytes; the maximum is ${String(MAX_ENTRY_SIZE)}`);
  }
}

/** Validates and encodes an entry as canonical JSON bytes (at most 65,535). */
export function encodeEntry(entry: Entry): Uint8Array {
  validateEntry(entry);
  let bytes: Uint8Array;
  try {
    bytes = encodeCanonical(entry as unknown as JsonValue);
  } catch (e) {
    if (e instanceof CanonicalJsonError) throw new EntryError(e.message);
    throw e;
  }
  checkSize(bytes.length);
  return bytes;
}

/**
 * Decodes entry bytes. Throws EntryError if they are not canonical JSON, lack a string `type` and
 * integer `v`, or are a known type that violates the schema. Unknown (type, v) pairs are returned
 * as `{ known: false }` so callers can print and skip them.
 */
export function decodeEntry(bytes: Uint8Array): DecodedEntry {
  checkSize(bytes.length);
  let value: JsonValue;
  try {
    value = decodeCanonical(bytes);
  } catch (e) {
    if (e instanceof CanonicalJsonError) throw new EntryError(e.message);
    throw e;
  }
  const o = record(value, 'entry');
  const { type, v } = o;
  if (typeof type !== 'string') fail('entry.type', 'must be a string');
  if (typeof v !== 'number') fail('entry.v', 'must be an integer');
  if (v !== ENTRY_SCHEMA_VERSION || !isEntryType(type)) return { known: false, type, v };
  validateEntry(o);
  return { known: true, entry: o };
}

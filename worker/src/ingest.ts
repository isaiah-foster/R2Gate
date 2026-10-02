// Queue consumer (PLAN §5.4). R2 event notifications arrive at least once and unordered; each is
// validated, turned into an `object.event` entry, and appended to the Sequencer, which dedupes by
// eventId (I5). Log order is ingestion order; each entry keeps R2's `eventTime` for real time.
//
// Message shape (R2 event-notification docs): {account, action, bucket, object{key, size?, eTag?},
// eventTime, copySource?{bucket, object}}. `size` and `eTag` are absent on deletes.

import {
  EntryError,
  MAX_OBJECT_KEY_BYTES,
  OBJECT_ACTIONS,
  encodeCanonical,
  encodeEntry,
  sha256,
  toHex,
  utf8Encode,
  type KeyBlinder,
  type ObjectAction,
  type ObjectEvent,
} from '@r2notary/core';
import type { Config } from './config.ts';
import type { AppendItem, AppendResult, IngestReport } from './store.ts';

/** The Sequencer RPC the consumer needs (an interface so tests can make it fail). */
export interface IngestSink {
  ingest(items: AppendItem[], report: IngestReport): Promise<AppendResult>;
}

export type Classified =
  | { readonly kind: 'event'; readonly item: AppendItem }
  | { readonly kind: 'loop' }
  | { readonly kind: 'foreign' }
  | { readonly kind: 'invalid'; readonly reason: string };

export interface EventIdFields {
  readonly bucket: string;
  readonly key: string;
  readonly action: string;
  readonly etag: string | undefined;
  readonly eventTime: string;
}

/**
 * hex(SHA-256(canonical JSON of [bucket, key, action, etag or null, eventTime])). PLAN §5.4 joins
 * the fields with '|', but keys and ETags may contain '|', so two different events could share an
 * ID and the second would be dropped as a duplicate. A JSON array has one encoding per tuple.
 */
export async function eventId(f: EventIdFields): Promise<string> {
  const tuple = [f.bucket, f.key, f.action, f.etag ?? null, f.eventTime];
  return toHex(await sha256(encodeCanonical(tuple)));
}

/** Seconds before a failed batch is redelivered: 10 s doubling per attempt, at most 5 minutes. */
export function retryDelaySeconds(attempts: number): number {
  return Math.min(300, 10 * 2 ** Math.min(Math.max(attempts, 1) - 1, 5));
}

class Invalid extends Error {}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

// Reasons name the field, never its value: they reach /status, and keys can be sensitive.
function str(o: Record<string, unknown>, field: string, path = field): string {
  const v = o[field];
  if (typeof v !== 'string') throw new Invalid(`${path} must be a string`);
  return v;
}

function optionalNumber(
  o: Record<string, unknown>,
  field: string,
  path: string,
): number | undefined {
  const v = o[field];
  if (!(field in o)) return undefined;
  if (typeof v !== 'number') throw new Invalid(`${path} must be a number when present`);
  return v;
}

function optionalString(
  o: Record<string, unknown>,
  field: string,
  path: string,
): string | undefined {
  const v = o[field];
  if (!(field in o)) return undefined;
  if (typeof v !== 'string') throw new Invalid(`${path} must be a string when present`);
  return v;
}

/** The HMAC of a key; a key that cannot be one (empty, a lone surrogate) is an invalid message. */
async function blindKey(blinder: KeyBlinder, key: string, field: string): Promise<string> {
  try {
    return await blinder.blind(key);
  } catch {
    throw new Invalid(`${field} is not a valid object key`);
  }
}

/**
 * The key rules encodeEntry applies to `key`, for a blinded entry that carries only its HMAC: the
 * Sequencer refuses an item whose private key is not a valid object key.
 */
function checkObjectKey(key: string): void {
  if (utf8Encode(key).length > MAX_OBJECT_KEY_BYTES) {
    throw new Invalid(`object.key exceeds ${String(MAX_OBJECT_KEY_BYTES)} UTF-8 bytes`);
  }
}

function isAction(v: string): v is ObjectAction {
  return (OBJECT_ACTIONS as readonly string[]).includes(v);
}

/**
 * Classifies one queue message. Events from the log bucket are recognised before anything else is
 * checked, so a malformed one is still counted as a loop (I8). The documented fields are checked
 * strictly (types here, formats by the entry schema); fields R2 might add later are ignored rather
 * than rejected, so a new field does not turn every event into a dropped message.
 */
export async function classifyMessage(
  body: unknown,
  config: Pick<Config, 'monitoredBucket' | 'logBucket'>,
  ingestedAt: string,
  blinder: KeyBlinder | null = null,
): Promise<Classified> {
  try {
    if (!isRecord(body)) throw new Invalid('message body must be a JSON object');
    const bucket = str(body, 'bucket');
    if (bucket === config.logBucket) return { kind: 'loop' };
    if (bucket !== config.monitoredBucket) return { kind: 'foreign' };

    const action = str(body, 'action');
    if (!isAction(action)) throw new Invalid('action is not a known R2 event action');
    const object = body.object;
    if (!isRecord(object)) throw new Invalid('object must be a JSON object');
    const key = str(object, 'key', 'object.key');
    const size = optionalNumber(object, 'size', 'object.size');
    const etag = optionalString(object, 'eTag', 'object.eTag');
    const eventTime = str(body, 'eventTime');
    let copySource: ObjectEvent['copySource'];
    if ('copySource' in body) {
      const src = body.copySource;
      if (!isRecord(src)) throw new Invalid('copySource must be a JSON object');
      const srcBucket = str(src, 'bucket', 'copySource.bucket');
      const srcKey = str(src, 'object', 'copySource.object');
      copySource =
        blinder === null
          ? { bucket: srcBucket, key: srcKey }
          : { bucket: srcBucket, keyHmac: await blindKey(blinder, srcKey, 'copySource.object') };
    }

    // On a blinded log (M8) the entry names the object by keyHmac; the key travels next to it to
    // the Sequencer, which keeps it privately for the objects view (store.ts).
    const name =
      blinder === null ? { key } : { keyHmac: await blindKey(blinder, key, 'object.key') };
    // encodeEntry enforces the rest: bucket and key rules, ETag format, integer sizes, RFC 3339
    // times, no size/etag on deletes, copySource only on CopyObject, the entry size limit.
    const entry = encodeEntry({
      v: 1,
      type: 'object.event',
      bucket,
      ...name,
      action,
      ...(size === undefined ? {} : { size }),
      ...(etag === undefined ? {} : { etag }),
      eventTime,
      ingestedAt,
      ...(copySource === undefined ? {} : { copySource }),
    });
    if (blinder !== null) checkObjectKey(key);
    return {
      kind: 'event',
      item: {
        eventId: await eventId({ bucket, key, action, etag, eventTime }),
        entry,
        ...(blinder === null ? {} : { key }),
      },
    };
  } catch (e) {
    if (e instanceof Invalid || e instanceof EntryError) {
      return { kind: 'invalid', reason: e.message.slice(0, 200) };
    }
    throw e;
  }
}

export interface ConsumeDeps {
  readonly config: Config;
  readonly sink: IngestSink;
  /** The log's key blinder (M8), or null if the log is not blinded. */
  readonly blinder: KeyBlinder | null;
  /** Worker clock (ms); stamps `ingestedAt`. */
  readonly now: () => number;
}

/**
 * Handles one queue batch with a single Sequencer call that carries both the events and the
 * counts of everything dropped. On success the batch is acked: invalid messages are not retried,
 * since they will never become valid. If the call fails, the whole batch is retried with backoff
 * (after `max_retries` it goes to the dead-letter queue), so counts are recorded once the call
 * commits. A call that commits but whose response is lost is retried too: its events are then
 * deduplicated, but its drop counts are added twice. The counters are operational, not evidence.
 */
export async function consumeBatch(batch: MessageBatch, deps: ConsumeDeps): Promise<void> {
  const ingestedAt = new Date(deps.now()).toISOString();
  const items: AppendItem[] = [];
  let invalid = 0;
  let loopDropped = 0;
  let foreignDropped = 0;
  let lastInvalid: string | undefined;
  for (const msg of batch.messages) {
    const c = await classifyMessage(msg.body, deps.config, ingestedAt, deps.blinder);
    if (c.kind === 'event') items.push(c.item);
    else if (c.kind === 'loop') loopDropped++;
    else if (c.kind === 'foreign') foreignDropped++;
    else {
      invalid++;
      lastInvalid = c.reason;
    }
  }
  if (loopDropped > 0) {
    console.warn(`r2notary ingest: dropped ${String(loopDropped)} events from the log bucket`);
  }
  const report: IngestReport = {
    invalid,
    loopDropped,
    foreignDropped,
    deadLettered: batch.queue === deps.config.eventsDlqName ? batch.messages.length : 0,
    ...(lastInvalid === undefined ? {} : { lastInvalid }),
  };
  try {
    await deps.sink.ingest(items, report);
  } catch (e) {
    const attempts = Math.max(...batch.messages.map((m) => m.attempts));
    const delaySeconds = retryDelaySeconds(attempts);
    console.error(
      `r2notary ingest: sequencer call failed (attempt ${String(attempts)}), retrying ` +
        `${String(batch.messages.length)} messages in ${String(delaySeconds)} s: ` +
        (e instanceof Error ? `${e.name}: ${e.message}` : String(e)),
    );
    batch.retryAll({ delaySeconds });
    return;
  }
  batch.ackAll();
}

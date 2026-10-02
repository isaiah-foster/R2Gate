// C2SP tlog-checkpoint: the note text `<origin>\n<size>\n<base64 root hash>\n[extension lines]`,
// signed as a signed-note. R2Notary writes no extension lines but parses them.

import { fromBase64, toBase64, utf8Encode } from './bytes.ts';
import { HASH_SIZE } from './merkle.ts';
import {
  SignatureError,
  cosignatureTimestamp,
  isValidKeyName,
  openNote,
  signNote,
  type NoteSigner,
  type NoteVerifier,
} from './note.ts';

export const MAX_ORIGIN_BYTES = 255;

export interface Checkpoint {
  readonly origin: string;
  readonly size: number;
  readonly rootHash: Uint8Array;
  readonly extensions: readonly string[];
}

export class CheckpointError extends Error {
  override name = 'CheckpointError';
}

function checkOriginLength(origin: string): void {
  if (origin.length === 0) throw new CheckpointError('origin is empty');
  if (utf8Encode(origin).length > MAX_ORIGIN_BYTES) {
    throw new CheckpointError(`origin exceeds ${String(MAX_ORIGIN_BYTES)} bytes`);
  }
}

/**
 * Validates this log's own origin (LOG_ORIGIN). Stricter than what parsing accepts: a scheme-less
 * URL prefix with no trailing slash (tlog-tiles), usable as a signed-note key name (no spaces or
 * `+`), because the signing key is named after the origin.
 */
export function validateOrigin(origin: string): void {
  if (!origin.isWellFormed()) throw new CheckpointError('origin is not valid UTF-8');
  checkOriginLength(origin);
  if (!isValidKeyName(origin)) {
    throw new CheckpointError('origin must not contain spaces, "+" or control characters');
  }
  if (origin.includes('://')) throw new CheckpointError('origin must not include a URL scheme');
  if (origin.endsWith('/')) throw new CheckpointError('origin must not end with "/"');
}

const SIZE_RE = /^(?:0|[1-9]\d*)$/;

function checkExtension(line: string): void {
  if (line.length === 0 || line.includes('\n')) {
    throw new CheckpointError('extension lines must be non-empty single lines');
  }
}

export function formatCheckpoint(cp: Checkpoint): string {
  validateOrigin(cp.origin);
  if (!Number.isSafeInteger(cp.size) || cp.size < 0) {
    throw new CheckpointError(`invalid tree size ${String(cp.size)}`);
  }
  if (cp.rootHash.length !== HASH_SIZE) throw new CheckpointError('root hash must be 32 bytes');
  cp.extensions.forEach(checkExtension);
  const lines = [cp.origin, String(cp.size), toBase64(cp.rootHash), ...cp.extensions];
  return lines.map((l) => `${l}\n`).join('');
}

/** Parses checkpoint note text (not the signatures; see openCheckpoint). */
export function parseCheckpoint(text: string): Checkpoint {
  if (!text.endsWith('\n')) throw new CheckpointError('checkpoint must end with a newline');
  const lines = text.slice(0, -1).split('\n');
  const [origin, sizeLine, rootLine, ...extensions] = lines;
  if (origin === undefined || sizeLine === undefined || rootLine === undefined) {
    throw new CheckpointError('checkpoint needs at least three lines');
  }
  checkOriginLength(origin);
  if (!SIZE_RE.test(sizeLine)) throw new CheckpointError('tree size must be a decimal integer');
  const size = Number(sizeLine);
  if (!Number.isSafeInteger(size)) throw new CheckpointError('tree size is too large');
  let rootHash: Uint8Array;
  try {
    rootHash = fromBase64(rootLine);
  } catch {
    throw new CheckpointError('root hash is not canonical base64');
  }
  if (rootHash.length !== HASH_SIZE) throw new CheckpointError('root hash must be 32 bytes');
  extensions.forEach(checkExtension);
  return { origin, size, rootHash, extensions };
}

/** Signs a checkpoint. The signer's key name must equal the origin (tlog-checkpoint SHOULD). */
export async function signCheckpoint(cp: Checkpoint, signer: NoteSigner): Promise<string> {
  const text = formatCheckpoint(cp);
  if (signer.name !== cp.origin) {
    throw new CheckpointError(`signer ${signer.name} does not match origin ${cp.origin}`);
  }
  return signNote(text, [signer]);
}

/**
 * Verifies a signed checkpoint with `verifier` and checks its origin. Throws NoteError for a bad
 * signature and CheckpointError for a malformed body or unexpected origin.
 */
export async function openCheckpoint(
  note: string | Uint8Array,
  verifier: NoteVerifier,
  expectedOrigin: string,
): Promise<Checkpoint> {
  const { text } = await openNote(note, [verifier]);
  const cp = parseCheckpoint(text);
  if (cp.origin !== expectedOrigin) {
    throw new CheckpointError(`checkpoint origin ${cp.origin} is not ${expectedOrigin}`);
  }
  return cp;
}

/** A witness cosignature that verified, with the time the witness signed it (POSIX seconds). */
export interface VerifiedCosignature {
  readonly name: string;
  readonly keyId: number;
  readonly timestamp: number;
}

/**
 * Like openCheckpoint, and also reports which of `witnesses` cosigned the checkpoint (C2SP
 * tlog-cosignature), with their timestamps. A cosignature from a supplied witness that does not
 * verify rejects the note (signed-note rules); one from any other key is ignored. The log's own
 * signature is still required. How many cosignatures are enough is the caller's policy.
 */
export async function openCosignedCheckpoint(
  note: string | Uint8Array,
  log: NoteVerifier,
  expectedOrigin: string,
  witnesses: readonly NoteVerifier[],
): Promise<{ checkpoint: Checkpoint; cosignatures: VerifiedCosignature[] }> {
  const opened = await openNote(note, [log, ...witnesses]);
  const is = (k: { name: string; keyId: number }, v: NoteVerifier): boolean =>
    k.name === v.name && k.keyId === v.keyId;
  if (!opened.verified.some((k) => is(k, log))) {
    throw new SignatureError(`no valid log signature from ${log.name}`);
  }
  const checkpoint = parseCheckpoint(opened.text);
  if (checkpoint.origin !== expectedOrigin) {
    throw new CheckpointError(`checkpoint origin ${checkpoint.origin} is not ${expectedOrigin}`);
  }
  const cosignatures: VerifiedCosignature[] = [];
  for (const s of opened.signatures) {
    if (!witnesses.some((w) => is(s, w))) continue;
    cosignatures.push({
      name: s.name,
      keyId: s.keyId,
      timestamp: cosignatureTimestamp(s.signature),
    });
  }
  return { checkpoint, cosignatures };
}

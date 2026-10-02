// C2SP tlog-witness `add-checkpoint` (M8): the request and response formats, and the checks a
// witness makes before cosigning. Pure: storage, the clock and the cosigner belong to the caller.
// The witness Worker (witness/) wraps evaluateAddCheckpoint in a Durable Object that does the
// final "old size still matches" check and the update in one synchronous transaction, as the spec
// requires; the log (worker/src/witness.ts) uses the formatters to submit its checkpoints.
//
//   POST <prefix>/add-checkpoint
//   old <size>\n  <base64 hash>\n ... (at most 63)  \n  <signed checkpoint note>
//   200: cosignature lines · 400 malformed · 403 signature · 404 unknown origin
//   409: the witness's latest size (`text/x.tlog.size`) · 422 proof or root does not check out

import { bytesEqual, fromBase64, toBase64 } from './bytes.ts';
import { CheckpointError, parseCheckpoint, type Checkpoint } from './checkpoint.ts';
import { EMPTY_ROOT, HASH_SIZE } from './merkle.ts';
import {
  NoteError,
  SignatureError,
  openNote,
  type NoteSignature,
  type NoteVerifier,
} from './note.ts';
import { ProofError, verifyConsistency } from './proof.ts';

/** The spec's limit on consistency proof lines (a proof between two uint64 sizes needs fewer). */
export const MAX_PROOF_LINES = 63;
/** Content type of a 409 response body. */
export const SIZE_CONTENT_TYPE = 'text/x.tlog.size';

export class WitnessProtocolError extends Error {
  override name = 'WitnessProtocolError';
}

export interface AddCheckpointRequest {
  readonly oldSize: number;
  readonly proof: readonly Uint8Array[];
  /** The signed checkpoint note, as sent. */
  readonly checkpoint: string;
}

const DECIMAL = /^(?:0|[1-9]\d*)$/;

function decimal(s: string, what: string): number {
  const n = DECIMAL.test(s) ? Number(s) : Number.NaN;
  if (!Number.isSafeInteger(n)) throw new WitnessProtocolError(`${what} is not a decimal size`);
  return n;
}

export function formatAddCheckpoint(r: AddCheckpointRequest): string {
  if (!Number.isSafeInteger(r.oldSize) || r.oldSize < 0) {
    throw new WitnessProtocolError('old size must be a non-negative integer');
  }
  if (r.proof.length > MAX_PROOF_LINES) throw new WitnessProtocolError('proof is too long');
  if (r.proof.some((h) => h.length !== HASH_SIZE)) {
    throw new WitnessProtocolError('proof hashes must be 32 bytes');
  }
  return `old ${String(r.oldSize)}\n${r.proof.map((h) => `${toBase64(h)}\n`).join('')}\n${r.checkpoint}`;
}

/** Parses a request body. Throws WitnessProtocolError (the witness answers 400). */
export function parseAddCheckpoint(body: string): AddCheckpointRequest {
  const split = body.indexOf('\n\n');
  if (split < 0) throw new WitnessProtocolError('no empty line before the checkpoint');
  const [oldLine = '', ...proofLines] = body.slice(0, split).split('\n');
  const checkpoint = body.slice(split + 2);
  if (checkpoint === '') throw new WitnessProtocolError('no checkpoint');
  if (!oldLine.startsWith('old '))
    throw new WitnessProtocolError('first line must be "old <size>"');
  const oldSize = decimal(oldLine.slice(4), 'old size');
  if (proofLines.length > MAX_PROOF_LINES) {
    throw new WitnessProtocolError(`more than ${String(MAX_PROOF_LINES)} proof lines`);
  }
  const proof = proofLines.map((l) => {
    let h: Uint8Array;
    try {
      h = fromBase64(l);
    } catch {
      throw new WitnessProtocolError('proof line is not canonical base64');
    }
    if (h.length !== HASH_SIZE) throw new WitnessProtocolError('proof line is not a 32-byte hash');
    return h;
  });
  return { oldSize, proof, checkpoint };
}

/** A 409 body: the witness's latest size and a newline. */
export function formatSizeBody(size: number): string {
  return `${String(size)}\n`;
}

export function parseSizeBody(body: string): number {
  if (!body.endsWith('\n')) throw new WitnessProtocolError('size body must end in a newline');
  return decimal(body.slice(0, -1), 'size');
}

const SIG_LINE = /^— [^\s+]+ [A-Za-z0-9+/]+=*$/u;

/**
 * Splits a 200 body into signature lines, each with its newline, so they can be appended to the
 * checkpoint note. Only the syntax is checked here; the caller verifies the cosignatures it trusts
 * by opening the note with them appended (unknown keys are ignored, as the spec says).
 */
export function parseCosignatureLines(body: string): string[] {
  if (body === '' || !body.endsWith('\n')) {
    throw new WitnessProtocolError('response must be newline-terminated signature lines');
  }
  return body
    .slice(0, -1)
    .split('\n')
    .map((l) => {
      if (!SIG_LINE.test(l)) throw new WitnessProtocolError('malformed signature line');
      return `${l}\n`;
    });
}

/** The latest checkpoint a witness has cosigned for one log. */
export interface WitnessedLogRecord {
  readonly size: number;
  readonly rootHash: Uint8Array;
}

export type AddCheckpointEvaluation =
  | {
      readonly ok: true;
      readonly oldSize: number;
      readonly checkpoint: Checkpoint;
      /** The note text the witness cosigns (the checkpoint body). */
      readonly text: string;
      /** Signature lines from the log's trusted keys, kept with the witness's own record. */
      readonly logSignatures: readonly string[];
    }
  | {
      readonly ok: false;
      readonly status: 400 | 403 | 404 | 409 | 422;
      readonly error: string;
      /** For 409: the witness's latest size. */
      readonly size?: number;
    };

const fail = (status: 400 | 403 | 404 | 422, error: string): AddCheckpointEvaluation => ({
  ok: false,
  status,
  error,
});

function signatureLine(s: NoteSignature): string {
  const raw = new Uint8Array(4 + s.signature.length);
  new DataView(raw.buffer).setUint32(0, s.keyId);
  raw.set(s.signature, 4);
  return `— ${s.name} ${toBase64(raw)}\n`;
}

/**
 * Everything a witness checks before cosigning, in the spec's order. `trusted` returns the log
 * keys the witness trusts for an origin (undefined: unknown origin); `latest` the record of the
 * last checkpoint it cosigned for that origin (null: never). The caller must still compare the
 * old size with its record atomically with storing the new one (see the module comment).
 */
export async function evaluateAddCheckpoint(
  body: string,
  trusted: (origin: string) => readonly NoteVerifier[] | undefined,
  latest: (origin: string) => WitnessedLogRecord | null,
): Promise<AddCheckpointEvaluation> {
  let req: AddCheckpointRequest;
  try {
    req = parseAddCheckpoint(body);
  } catch (e) {
    if (e instanceof WitnessProtocolError) return fail(400, e.message);
    throw e;
  }
  const origin = req.checkpoint.slice(0, Math.max(0, req.checkpoint.indexOf('\n')));
  const keys = trusted(origin);
  if (keys === undefined || keys.length === 0) return fail(404, 'unknown log origin');

  let text: string;
  let logSignatures: string[];
  try {
    const opened = await openNote(req.checkpoint, keys);
    text = opened.text;
    const known = (s: NoteSignature): boolean =>
      opened.verified.some((v) => v.name === s.name && v.keyId === s.keyId);
    logSignatures = opened.signatures.filter(known).map(signatureLine);
  } catch (e) {
    if (e instanceof SignatureError) return fail(403, e.message);
    if (e instanceof NoteError) return fail(400, e.message);
    throw e;
  }
  let checkpoint: Checkpoint;
  try {
    checkpoint = parseCheckpoint(text);
  } catch (e) {
    if (e instanceof CheckpointError) return fail(400, e.message);
    throw e;
  }
  if (checkpoint.origin !== origin) return fail(400, 'checkpoint origin line is malformed');
  if (req.oldSize > checkpoint.size) return fail(400, 'old size exceeds the checkpoint size');

  const record = latest(origin);
  const recorded = record?.size ?? 0;
  if (req.oldSize !== recorded) {
    return { ok: false, status: 409, error: 'old size does not match', size: recorded };
  }
  if (checkpoint.size === 0 && !bytesEqual(checkpoint.rootHash, EMPTY_ROOT)) {
    return fail(422, 'an empty tree must have the empty root');
  }
  if (req.oldSize === 0) {
    if (req.proof.length !== 0) return fail(422, 'a proof from size 0 must be empty');
  } else {
    if (record === null) throw new Error('unreachable: a non-zero recorded size has a record');
    try {
      await verifyConsistency(
        req.oldSize,
        checkpoint.size,
        record.rootHash,
        checkpoint.rootHash,
        req.proof,
      );
    } catch (e) {
      if (e instanceof ProofError) return fail(422, e.message);
      throw e;
    }
  }
  return { ok: true, oldSize: req.oldSize, checkpoint, text, logSignatures };
}

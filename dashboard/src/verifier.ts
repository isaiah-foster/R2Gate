// The browser verifier's logic (PLAN §5.8, M8): everything the dashboard shows as "verified" goes
// through here. It reads a tlog-tiles log through a LogSource (fetch in the browser, a map in the
// tests), checks the checkpoint signature, and proves every entry it returns against the signed
// root with inclusion proofs computed locally from tiles. The server is trusted only to serve
// bytes; anything it lies about surfaces as a VerifyError.
//
// Two kinds of failure, as in the Go CLI (DECISIONS D5.2): VerifyError means the log served
// something that does not verify (evidence), UnavailableError means something could not be read
// (a 404, a network error) or a policy was not met, which proves nothing.
//
// This uses packages/core, the same code as the writer, so it is a demonstration that a browser
// need not trust the server, not an independent implementation; the Go CLI is that (PLAN G3).

import {
  CHECKPOINT_PATH,
  CheckpointError,
  NoteError,
  ProofError,
  TILE_WIDTH,
  consistencyProof,
  decodeBundle,
  entryBundlePath,
  hashLeaf,
  inclusionProof,
  newCosignatureVerifier,
  newVerifier,
  openCosignedCheckpoint,
  tileNodeReader,
  tilePath,
  utf8Decode,
  verifyConsistency,
  verifyInclusion,
  type Checkpoint,
  type NodeReader,
  type VerifiedCosignature,
} from '@r2notary/core';

/** The log tells a falsehood: a signature, tile, bundle or checkpoint that does not verify. */
export class VerifyError extends Error {
  override name = 'VerifyError';
}

/** Something could not be read, or a policy (witness quorum) was not met. Not evidence. */
export class UnavailableError extends Error {
  override name = 'UnavailableError';
}

/** Reads a resource by its path relative to the log prefix; null if it does not exist. */
export interface LogSource {
  get(path: string): Promise<Uint8Array | null>;
}

export interface TrustPolicy {
  /** The log's verifier key, obtained out of band (never from the log). */
  readonly vkey: string;
  /** Expected origin; by default the vkey's name (R2Notary names its key after the origin). */
  readonly origin?: string;
  /** Witness cosigner keys, and how many must have cosigned (default 1 if any are given). */
  readonly witnesses?: readonly string[];
  readonly quorum?: number;
}

export interface VerifiedCheckpoint {
  readonly checkpoint: Checkpoint;
  readonly cosignatures: readonly VerifiedCosignature[];
  /** The signed note as served. */
  readonly note: string;
  /** Reads subtree hashes from this checkpoint's tiles; tiles are fetched once per checkpoint. */
  readonly nodes: (source: LogSource) => NodeReader;
}

export interface ProvenEntry {
  readonly index: number;
  /** The exact bytes committed to by the log. */
  readonly entry: Uint8Array;
}

function asVerifyError(e: unknown): never {
  if (e instanceof VerifyError || e instanceof UnavailableError || e instanceof RangeError) {
    throw e;
  }
  if (e instanceof NoteError || e instanceof CheckpointError || e instanceof ProofError) {
    throw new VerifyError(e.message);
  }
  throw e;
}

async function must(source: LogSource, path: string): Promise<Uint8Array> {
  const b = await source.get(path);
  if (b === null) throw new UnavailableError(`${path} is not available`);
  return b;
}

/** Fetches and verifies the live checkpoint under `policy`. */
export async function openLog(source: LogSource, policy: TrustPolicy): Promise<VerifiedCheckpoint> {
  const bytes = await must(source, CHECKPOINT_PATH);
  return openNoteBytes(bytes, policy);
}

/** Verifies a checkpoint already in hand (e.g. one saved by an earlier visit). */
export async function openNoteBytes(
  bytes: Uint8Array,
  policy: TrustPolicy,
): Promise<VerifiedCheckpoint> {
  const log = await newVerifier(policy.vkey);
  const witnesses = await Promise.all((policy.witnesses ?? []).map(newCosignatureVerifier));
  const quorum = policy.quorum ?? (witnesses.length > 0 ? 1 : 0);
  let note: string;
  let opened: Awaited<ReturnType<typeof openCosignedCheckpoint>>;
  try {
    note = utf8Decode(bytes);
    opened = await openCosignedCheckpoint(note, log, policy.origin ?? log.name, witnesses);
  } catch (e) {
    if (e instanceof TypeError) throw new VerifyError('checkpoint is not valid UTF-8');
    asVerifyError(e);
  }
  // tlog-witness: a cosignature must carry a time; one without does not count.
  const cosignatures = opened.cosignatures.filter((c) => c.timestamp > 0);
  if (cosignatures.length < quorum) {
    throw new UnavailableError(
      `checkpoint has ${String(cosignatures.length)} of the ${String(quorum)} witness cosignatures required`,
    );
  }
  const size = opened.checkpoint.size;
  const readers = new WeakMap<LogSource, NodeReader>();
  return {
    checkpoint: opened.checkpoint,
    cosignatures,
    note,
    nodes: (source) => {
      let r = readers.get(source);
      if (r === undefined) {
        r = tileNodeReader(size, (t) => must(source, tilePath(t.level, t.index, t.width)));
        readers.set(source, r);
      }
      return r;
    },
  };
}

/** Entry bundle `n` at the checkpoint's size, parsed strictly. */
async function bundle(source: LogSource, cp: VerifiedCheckpoint, n: number): Promise<Uint8Array[]> {
  const width = Math.min(TILE_WIDTH, cp.checkpoint.size - n * TILE_WIDTH);
  const path = entryBundlePath(n, width);
  const data = await must(source, path);
  let entries: Uint8Array[];
  try {
    entries = decodeBundle(data);
  } catch (e) {
    throw new VerifyError(`${path}: ${e instanceof Error ? e.message : String(e)}`);
  }
  if (entries.length !== width) {
    throw new VerifyError(`${path} has ${String(entries.length)} entries, want ${String(width)}`);
  }
  return entries;
}

async function prove(cp: VerifiedCheckpoint, source: LogSource, index: number, e: Uint8Array) {
  const { size, rootHash } = cp.checkpoint;
  try {
    const proof = await inclusionProof(index, size, cp.nodes(source));
    await verifyInclusion(index, size, await hashLeaf(e), proof, rootHash);
  } catch (err) {
    if (err instanceof ProofError) {
      throw new VerifyError(`entry ${String(index)} is not in the signed tree: ${err.message}`);
    }
    asVerifyError(err);
  }
}

/** Fetches entry `index` and proves it is in the checkpoint's tree. */
export async function proveEntry(
  source: LogSource,
  cp: VerifiedCheckpoint,
  index: number,
): Promise<ProvenEntry> {
  if (!Number.isSafeInteger(index) || index < 0 || index >= cp.checkpoint.size) {
    throw new RangeError(`no entry ${String(index)} in a tree of ${String(cp.checkpoint.size)}`);
  }
  const n = Math.floor(index / TILE_WIDTH);
  const entries = await bundle(source, cp, n);
  const e = entries[index - n * TILE_WIDTH];
  if (e === undefined) throw new Error('unreachable');
  await prove(cp, source, index, e);
  return { index, entry: e };
}

/** The newest `count` entries, each proven; one bundle read per 256 entries. */
export async function recentEntries(
  source: LogSource,
  cp: VerifiedCheckpoint,
  count: number,
): Promise<ProvenEntry[]> {
  const size = cp.checkpoint.size;
  const from = Math.max(0, size - count);
  const out: ProvenEntry[] = [];
  for (let n = Math.floor(from / TILE_WIDTH); n * TILE_WIDTH < size; n++) {
    const entries = await bundle(source, cp, n);
    for (const [k, e] of entries.entries()) {
      const index = n * TILE_WIDTH + k;
      if (index < from) continue;
      await prove(cp, source, index, e);
      out.push({ index, entry: e });
    }
  }
  return out;
}

/**
 * Proves that `newer` extends `older` (both already verified). A smaller newer tree, or the same
 * size with another root, is a rollback or a fork: two signed checkpoints that cannot both be
 * honest.
 */
export async function proveConsistency(
  source: LogSource,
  older: VerifiedCheckpoint,
  newer: VerifiedCheckpoint,
): Promise<void> {
  const o = older.checkpoint;
  const n = newer.checkpoint;
  if (n.size < o.size) {
    throw new VerifyError(`tree size went backwards: ${String(n.size)} after ${String(o.size)}`);
  }
  try {
    const proof = await consistencyProof(o.size, n.size, newer.nodes(source));
    await verifyConsistency(o.size, n.size, o.rootHash, n.rootHash, proof);
  } catch (e) {
    if (e instanceof ProofError) {
      throw new VerifyError(
        `checkpoint ${String(n.size)} does not extend checkpoint ${String(o.size)}: ${e.message}`,
      );
    }
    asVerifyError(e);
  }
}

/** A source over HTTP: `<base>/<path>`, with an optional bearer token (private logs). */
export function httpSource(base: string, token: string | null, fetcher = fetch): LogSource {
  const prefix = base.replace(/\/+$/, '');
  return {
    async get(path) {
      let res: Response;
      try {
        res = await fetcher(`${prefix}/${path}`, {
          headers: token === null ? {} : { authorization: `Bearer ${token}` },
          // Every resource but the checkpoint is immutable; the checkpoint changes every few
          // seconds, so it must not come from the browser's cache.
          cache: path === CHECKPOINT_PATH ? 'no-store' : 'default',
        });
      } catch (e) {
        throw new UnavailableError(`${path}: ${e instanceof Error ? e.message : String(e)}`);
      }
      if (res.status === 404) return null;
      if (!res.ok) throw new UnavailableError(`${path}: HTTP ${String(res.status)}`);
      return new Uint8Array(await res.arrayBuffer());
    },
  };
}

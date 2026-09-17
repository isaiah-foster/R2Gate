// RFC 6962 §2.1 Merkle tree hashing (SHA-256), as used by C2SP tlog-tiles.
//
// WebCrypto's digest() is async, and awaiting one hash at a time serializes on the event loop.
// Every function here that needs many independent hashes issues them together with Promise.all,
// level by level. Which batching strategy is fastest is a benchmark question (PLAN §14.5).

import { concatBytes, fromHex } from './bytes.ts';

export const HASH_SIZE = 32;

/** MTH({}) = SHA-256 of the empty string. */
export const EMPTY_ROOT: Uint8Array = fromHex(
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
);

const LEAF_PREFIX = Uint8Array.of(0x00);
const NODE_PREFIX = Uint8Array.of(0x01);

/** WebCrypto takes only ArrayBuffer-backed views; copy anything else (e.g. shared memory). */
function bufferSource(b: Uint8Array): Uint8Array<ArrayBuffer> {
  return b.buffer instanceof ArrayBuffer ? (b as Uint8Array<ArrayBuffer>) : new Uint8Array(b);
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bufferSource(data)));
}

/** Leaf hash: SHA-256(0x00 || entry). */
export async function hashLeaf(entry: Uint8Array): Promise<Uint8Array> {
  return sha256(concatBytes(LEAF_PREFIX, entry));
}

/** Interior node hash: SHA-256(0x01 || left || right). */
export async function hashChildren(left: Uint8Array, right: Uint8Array): Promise<Uint8Array> {
  if (left.length !== HASH_SIZE || right.length !== HASH_SIZE) {
    throw new RangeError('child hashes must be 32 bytes');
  }
  return sha256(concatBytes(NODE_PREFIX, left, right));
}

export async function hashLeaves(entries: readonly Uint8Array[]): Promise<Uint8Array[]> {
  return Promise.all(entries.map(hashLeaf));
}

function isPowerOfTwo(n: number): boolean {
  return Number.isSafeInteger(n) && n > 0 && (n & (n - 1)) === 0;
}

function at<T>(xs: readonly T[], i: number): T {
  const x = xs[i];
  if (x === undefined) throw new RangeError(`index ${String(i)} out of range`);
  return x;
}

/**
 * Root of a perfect subtree whose bottom row is `hashes` (width a power of two). The hashes may be
 * leaf hashes or roots of equal-size subtrees, e.g. the 256 hashes of a full tile.
 */
export async function perfectSubtreeRoot(hashes: readonly Uint8Array[]): Promise<Uint8Array> {
  if (!isPowerOfTwo(hashes.length)) {
    throw new RangeError(`subtree width ${String(hashes.length)} is not a power of two`);
  }
  let row = hashes;
  while (row.length > 1) {
    const next: Promise<Uint8Array>[] = [];
    for (let i = 0; i < row.length; i += 2) next.push(hashChildren(at(row, i), at(row, i + 1)));
    row = await Promise.all(next);
  }
  return at(row, 0);
}

/**
 * Root hash from the frontier: the roots of the maximal perfect subtrees of the tree, left to
 * right (strictly decreasing sizes, i.e. the binary decomposition of the tree size). RFC 6962
 * splits at the largest power of two, so the root is a right fold: H(f0, H(f1, ... H(fk-1, fk))).
 */
export async function rootFromFrontier(frontier: readonly Uint8Array[]): Promise<Uint8Array> {
  if (frontier.length === 0) return EMPTY_ROOT;
  let acc = at(frontier, frontier.length - 1);
  for (let i = frontier.length - 2; i >= 0; i--) acc = await hashChildren(at(frontier, i), acc);
  return acc;
}

/** Binary decomposition of n, largest power of two first (e.g. 7 → [4, 2, 1]). */
export function decompose(n: number): number[] {
  if (!Number.isSafeInteger(n) || n < 0) throw new RangeError(`invalid size ${String(n)}`);
  let top = 1;
  while (top * 2 <= n) top *= 2;
  const out: number[] = [];
  for (let bit = top; bit >= 1; bit /= 2) {
    if (Math.floor(n / bit) % 2 === 1) out.push(bit);
  }
  return out;
}

/** MTH over a list of leaf hashes (whole tree in memory; fine for tests and small trees). */
export async function merkleRoot(leafHashes: readonly Uint8Array[]): Promise<Uint8Array> {
  const groups: Promise<Uint8Array>[] = [];
  let off = 0;
  for (const width of decompose(leafHashes.length)) {
    groups.push(perfectSubtreeRoot(leafHashes.slice(off, off + width)));
    off += width;
  }
  return rootFromFrontier(await Promise.all(groups));
}

// RFC 6962 / RFC 9162 inclusion and consistency proofs, generated from any source of subtree
// hashes (in particular from tlog-tiles) and verified with the RFC 9162 §2.1.3.2 and §2.1.4.2
// algorithms.
//
// The writer uses these to check its own output (I3: any two archived checkpoints are consistent),
// to send witnesses consistency proofs, and the browser verifier (dashboard/) uses them to check a
// log it does not trust. The Go verifier (M5) has its own implementation and shares nothing here.

import { bytesEqual } from './bytes.ts';
import {
  HASH_SIZE,
  decompose,
  hashChildren,
  perfectSubtreeRoot,
  rootFromFrontier,
} from './merkle.ts';
import {
  MAX_TILE_LEVEL,
  TILE_HEIGHT,
  TILE_WIDTH,
  levelHashCount,
  type TileCoord,
} from './tiles.ts';

export class ProofError extends Error {
  override name = 'ProofError';
}

/** A perfect subtree: the node at `height` covering leaves [index·2^height, (index+1)·2^height). */
export interface NodeCoord {
  readonly height: number;
  readonly index: number;
}

/** Returns the hashes of the given nodes, in order. Batched so tile reads can be shared. */
export type NodeReader = (nodes: readonly NodeCoord[]) => Promise<Uint8Array[]>;

function checkSize(size: number, what: string): void {
  if (!Number.isSafeInteger(size) || size < 0) {
    throw new RangeError(`invalid ${what} ${String(size)}`);
  }
}

/** Largest power of two strictly less than n (n >= 2). */
function splitPoint(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/** A leaf range [lo, hi) whose MTH is one element of a proof. */
interface Range {
  readonly lo: number;
  readonly hi: number;
}

/**
 * RFC 6962 §2.1.2 SUBPROOF, as the list of leaf ranges whose MTH forms the proof. Iterative form
 * of the recursion: each step narrows [lo, hi) and records the sibling range, which is appended
 * after everything the deeper steps produce, so the list is reversed at the end.
 */
function consistencyRanges(m: number, n: number): Range[] {
  const out: Range[] = [];
  let lo = 0;
  let hi = n;
  let complete = true; // the RFC's `b`: is the old tree's subtree still a complete subtree here?
  let rest = m;
  for (;;) {
    if (rest === hi - lo) {
      if (!complete) out.push({ lo, hi });
      break;
    }
    const k = splitPoint(hi - lo);
    if (rest <= k) {
      out.push({ lo: lo + k, hi });
      hi = lo + k;
    } else {
      out.push({ lo, hi: lo + k });
      lo += k;
      rest -= k;
      complete = false;
    }
  }
  return out.reverse();
}

/**
 * The perfect subtrees making up a range. Ranges produced by the RFC 6962 recursion always start
 * at a multiple of a power of two at least as large as their length, so the binary decomposition
 * of the length, laid out from `lo`, is a list of aligned perfect subtrees.
 */
function rangeNodes({ lo, hi }: Range): NodeCoord[] {
  const out: NodeCoord[] = [];
  let off = lo;
  for (const w of decompose(hi - lo)) {
    if (off % w !== 0) throw new Error('unreachable: unaligned proof range');
    out.push({ height: Math.log2(w), index: off / w });
    off += w;
  }
  return out;
}

/** Consistency proof from tree size `size1` to `size2` (RFC 6962 PROOF(m, D[n])). */
export async function consistencyProof(
  size1: number,
  size2: number,
  read: NodeReader,
): Promise<Uint8Array[]> {
  checkSize(size1, 'size1');
  checkSize(size2, 'size2');
  if (size1 > size2) throw new RangeError(`size1 ${String(size1)} exceeds size2 ${String(size2)}`);
  if (size1 === 0 || size1 === size2) return [];
  const ranges = consistencyRanges(size1, size2).map(rangeNodes);
  const hashes = await read(ranges.flat());
  let off = 0;
  return Promise.all(
    ranges.map((nodes) => {
      const part = hashes.slice(off, off + nodes.length);
      off += nodes.length;
      return rootFromFrontier(part);
    }),
  );
}

/**
 * RFC 6962 §2.1.1 PATH(m, D[n]), as the list of leaf ranges whose MTH forms the audit path: at
 * each split the sibling range is recorded, and deeper siblings come first in the proof.
 */
function inclusionRanges(m: number, n: number): Range[] {
  const out: Range[] = [];
  let lo = 0;
  let hi = n;
  while (hi - lo > 1) {
    const k = splitPoint(hi - lo);
    if (m < lo + k) {
      out.push({ lo: lo + k, hi });
      hi = lo + k;
    } else {
      out.push({ lo, hi: lo + k });
      lo += k;
    }
  }
  return out.reverse();
}

/** Inclusion proof (audit path) for leaf `index` in the tree of `size` leaves. */
export async function inclusionProof(
  index: number,
  size: number,
  read: NodeReader,
): Promise<Uint8Array[]> {
  checkSize(size, 'tree size');
  if (!Number.isSafeInteger(index) || index < 0 || index >= size) {
    throw new RangeError(`index ${String(index)} is outside a tree of ${String(size)}`);
  }
  const ranges = inclusionRanges(index, size).map(rangeNodes);
  const hashes = await read(ranges.flat());
  let off = 0;
  return Promise.all(
    ranges.map((nodes) => {
      const part = hashes.slice(off, off + nodes.length);
      off += nodes.length;
      return rootFromFrontier(part);
    }),
  );
}

const isOdd = (n: number): boolean => n % 2 === 1;
const half = (n: number): number => Math.floor(n / 2);

function isPowerOfTwo(n: number): boolean {
  let p = 1;
  while (p < n) p *= 2;
  return p === n;
}

/**
 * Verifies that the tree of `size1` leaves with root `root1` is a prefix of the tree of `size2`
 * leaves with root `root2` (RFC 9162 §2.1.4.2). Throws ProofError if not. Sizes use arithmetic, not
 * bitwise operators, because JavaScript bit operations truncate to 32 bits.
 */
export async function verifyConsistency(
  size1: number,
  size2: number,
  root1: Uint8Array,
  root2: Uint8Array,
  proof: readonly Uint8Array[],
): Promise<void> {
  if (!Number.isSafeInteger(size1) || !Number.isSafeInteger(size2) || size1 < 0) {
    throw new ProofError('invalid tree sizes');
  }
  if (size2 < size1) throw new ProofError('size2 is smaller than size1');
  if (root1.length !== HASH_SIZE || root2.length !== HASH_SIZE) {
    throw new ProofError('roots must be 32 bytes');
  }
  if (proof.some((h) => h.length !== HASH_SIZE))
    throw new ProofError('proof hashes must be 32 bytes');
  if (size1 === size2) {
    if (proof.length !== 0) throw new ProofError('proof between equal sizes must be empty');
    if (!bytesEqual(root1, root2)) throw new ProofError('roots differ for equal sizes');
    return;
  }
  if (size1 === 0) {
    // The empty tree is a prefix of every tree.
    if (proof.length !== 0) throw new ProofError('proof from the empty tree must be empty');
    return;
  }
  if (proof.length === 0) throw new ProofError('empty consistency proof');

  // When size1 is a power of two the old tree is a complete subtree of the new one, so the RFC
  // proof omits its root and the verifier starts from it.
  const path = isPowerOfTwo(size1) ? [root1, ...proof] : proof;
  let fn = size1 - 1;
  let sn = size2 - 1;
  while (isOdd(fn)) {
    fn = half(fn);
    sn = half(sn);
  }
  const [first, ...rest] = path;
  if (first === undefined) throw new ProofError('empty consistency proof');
  let fr = first;
  let sr = first;
  for (const c of rest) {
    if (sn === 0) throw new ProofError('consistency proof is too long');
    if (isOdd(fn) || fn === sn) {
      fr = await hashChildren(c, fr);
      sr = await hashChildren(c, sr);
      while (!isOdd(fn) && fn !== 0) {
        fn = half(fn);
        sn = half(sn);
      }
    } else {
      sr = await hashChildren(sr, c);
    }
    fn = half(fn);
    sn = half(sn);
  }
  if (sn !== 0) throw new ProofError('consistency proof is too short');
  if (!bytesEqual(fr, root1)) throw new ProofError('consistency proof does not match root1');
  if (!bytesEqual(sr, root2)) throw new ProofError('consistency proof does not match root2');
}

/**
 * Verifies that `leafHash` is the leaf at `index` in the tree of `size` leaves with root `root`
 * (RFC 9162 §2.1.3.2). Throws ProofError if not. Arithmetic instead of bit operations, as above.
 */
export async function verifyInclusion(
  index: number,
  size: number,
  leafHash: Uint8Array,
  proof: readonly Uint8Array[],
  root: Uint8Array,
): Promise<void> {
  if (!Number.isSafeInteger(index) || !Number.isSafeInteger(size) || index < 0) {
    throw new ProofError('invalid index or tree size');
  }
  if (index >= size) throw new ProofError('index is outside the tree');
  if (leafHash.length !== HASH_SIZE || root.length !== HASH_SIZE) {
    throw new ProofError('leaf and root hashes must be 32 bytes');
  }
  if (proof.some((h) => h.length !== HASH_SIZE))
    throw new ProofError('proof hashes must be 32 bytes');
  let fn = index;
  let sn = size - 1;
  let r = leafHash;
  for (const p of proof) {
    if (sn === 0) throw new ProofError('inclusion proof is too long');
    if (isOdd(fn) || fn === sn) {
      r = await hashChildren(p, r);
      while (!isOdd(fn) && fn !== 0) {
        fn = half(fn);
        sn = half(sn);
      }
    } else {
      r = await hashChildren(r, p);
    }
    fn = half(fn);
    sn = half(sn);
  }
  if (sn !== 0) throw new ProofError('inclusion proof is too short');
  if (!bytesEqual(r, root)) throw new ProofError('inclusion proof does not match the root');
}

/**
 * Node reader over tlog-tiles for a tree of `size` leaves. A node at height 8L + r is the root of
 * 2^r consecutive hashes in one tile at level L. Tiles are fetched with the width they have at
 * `size` (full, or the partial tile published with that checkpoint), once each per reader.
 */
export function tileNodeReader(
  size: number,
  readTile: (tile: TileCoord) => Promise<Uint8Array>,
): NodeReader {
  checkSize(size, 'tree size');
  const cache = new Map<string, Promise<Uint8Array>>();

  function tile(level: number, index: number): Promise<Uint8Array> {
    const width = Math.min(TILE_WIDTH, levelHashCount(level, size) - index * TILE_WIDTH);
    const key = `${String(level)}/${String(index)}`;
    let p = cache.get(key);
    if (p === undefined) {
      p = readTile({ level, index, width }).then((data) => {
        if (data.length !== width * HASH_SIZE) {
          throw new ProofError(
            `tile ${key} has ${String(data.length)} bytes, want ${String(width * HASH_SIZE)}`,
          );
        }
        return data;
      });
      cache.set(key, p);
    }
    return p;
  }

  async function node({ height, index }: NodeCoord): Promise<Uint8Array> {
    if (!Number.isInteger(height) || height < 0 || height > TILE_HEIGHT * (MAX_TILE_LEVEL + 1)) {
      throw new RangeError(`invalid node height ${String(height)}`);
    }
    if (!Number.isSafeInteger(index) || index < 0 || (index + 1) * 2 ** height > size) {
      throw new RangeError(
        `node ${String(height)}/${String(index)} is outside a tree of ${String(size)}`,
      );
    }
    const level = Math.floor(height / TILE_HEIGHT);
    const count = 2 ** (height % TILE_HEIGHT);
    const first = index * count;
    const data = await tile(level, Math.floor(first / TILE_WIDTH));
    const off = (first % TILE_WIDTH) * HASH_SIZE;
    const hashes: Uint8Array[] = [];
    for (let i = 0; i < count; i++) {
      hashes.push(data.slice(off + i * HASH_SIZE, off + (i + 1) * HASH_SIZE));
    }
    return perfectSubtreeRoot(hashes);
  }

  return (nodes) => Promise.all(nodes.map(node));
}

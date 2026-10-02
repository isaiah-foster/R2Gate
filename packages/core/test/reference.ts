// Naive reference implementations used only by tests. Deliberately independent of src/: they use
// Node's synchronous `node:crypto` instead of WebCrypto and the textbook recursive definitions
// instead of tiles or frontiers.
import { createHash } from 'node:crypto';

export function sha256(...parts: Uint8Array[]): Uint8Array {
  const h = createHash('sha256');
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
}

export function refLeafHash(entry: Uint8Array): Uint8Array {
  return sha256(Uint8Array.of(0x00), entry);
}

export function refNodeHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(Uint8Array.of(0x01), left, right);
}

/** Largest power of two strictly less than n (n >= 2). */
function splitPoint(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/**
 * RFC 6962 §2.1 MTH, over leaf hashes rather than entries so that large trees can be tested
 * without materializing entries. MTH({}) = SHA-256(), MTH({d}) = leaf hash,
 * MTH(D[n]) = H(0x01 || MTH(D[0:k]) || MTH(D[k:n])).
 */
export function refRootFromLeafHashes(leaves: readonly Uint8Array[]): Uint8Array {
  if (leaves.length === 0) return sha256();
  const go = (lo: number, hi: number): Uint8Array => {
    const n = hi - lo;
    if (n === 1) {
      const leaf = leaves[lo];
      if (leaf === undefined) throw new Error('unreachable');
      return leaf;
    }
    const k = splitPoint(n);
    return refNodeHash(go(lo, lo + k), go(lo + k, hi));
  };
  return go(0, leaves.length);
}

/**
 * RFC 6962 §2.1.2 consistency proof PROOF(m, D[n]), straight from the textbook recursion:
 * SUBPROOF(m, D[m], true) = {}; SUBPROOF(m, D[m], false) = {MTH(D[m])}; otherwise split at k and
 * recurse left (m <= k, appending MTH of the right part) or right (appending MTH of the left part).
 */
export function refConsistencyProof(m: number, leaves: readonly Uint8Array[]): Uint8Array[] {
  const sub = (m: number, d: readonly Uint8Array[], b: boolean): Uint8Array[] => {
    const n = d.length;
    if (m === n) return b ? [] : [refRootFromLeafHashes(d)];
    const k = splitPoint(n);
    if (m <= k) return [...sub(m, d.slice(0, k), b), refRootFromLeafHashes(d.slice(k))];
    return [...sub(m - k, d.slice(k), false), refRootFromLeafHashes(d.slice(0, k))];
  };
  if (m === 0 || m === leaves.length) return [];
  return sub(m, leaves, true);
}

/**
 * RFC 6962 §2.1.1 audit path PATH(m, D[n]), straight from the textbook recursion: PATH(0, {d}) =
 * {}; otherwise split at k and recurse into the half holding m, appending the MTH of the other.
 */
export function refInclusionProof(m: number, leaves: readonly Uint8Array[]): Uint8Array[] {
  const path = (m: number, d: readonly Uint8Array[]): Uint8Array[] => {
    const n = d.length;
    if (n <= 1) return [];
    const k = splitPoint(n);
    if (m < k) return [...path(m, d.slice(0, k)), refRootFromLeafHashes(d.slice(k))];
    return [...path(m - k, d.slice(k)), refRootFromLeafHashes(d.slice(0, k))];
  };
  if (m < 0 || m >= leaves.length) throw new RangeError('index outside the tree');
  return path(m, leaves);
}

export function refRoot(entries: readonly Uint8Array[]): Uint8Array {
  return refRootFromLeafHashes(entries.map(refLeafHash));
}

/** Deterministic synthetic leaf hash for index i (cheap stand-in for hashing a real entry). */
export function syntheticLeafHash(i: number): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(i));
  return sha256(Uint8Array.of(0xaa), b);
}

export function syntheticLeafHashes(n: number, start = 0): Uint8Array[] {
  return Array.from({ length: n }, (_, i) => syntheticLeafHash(start + i));
}

export function hex(b: Uint8Array): string {
  return Buffer.from(b).toString('hex');
}

export function unhex(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, 'hex'));
}

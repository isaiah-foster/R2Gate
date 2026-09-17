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

import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
  EMPTY_ROOT,
  hashChildren,
  hashLeaf,
  hashLeaves,
  merkleRoot,
  perfectSubtreeRoot,
  rootFromFrontier,
} from '../src/merkle.ts';
import {
  hex,
  refLeafHash,
  refRootFromLeafHashes,
  syntheticLeafHashes,
  unhex,
} from './reference.ts';

// RFC 6962 test vectors published by transparency-dev/merkle (testonly/constants.go), used as
// data only. Leaves, then the root hash for each tree size 0..8.
const LEAVES = [
  '',
  '00',
  '10',
  '2021',
  '3031',
  '40414243',
  '5051525354555657',
  '606162636465666768696a6b6c6d6e6f',
].map(unhex);
const ROOTS = [
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d',
  'fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125',
  'aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77',
  'd37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7',
  '4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4',
  '76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef',
  'ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c',
  '5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328',
];

describe('RFC 6962 hashing', () => {
  it('empty root is SHA-256 of the empty string', () => {
    expect(hex(EMPTY_ROOT)).toBe(ROOTS[0]);
  });

  it('leaf hash prefixes 0x00', async () => {
    expect(hex(await hashLeaf(new Uint8Array()))).toBe(ROOTS[1]);
  });

  it('matches the published root for every size 0..8', async () => {
    const leafHashes = await hashLeaves(LEAVES);
    for (let n = 0; n <= LEAVES.length; n++) {
      expect(hex(await merkleRoot(leafHashes.slice(0, n))), `size ${String(n)}`).toBe(ROOTS[n]);
    }
  });

  it('interior node hash prefixes 0x01', async () => {
    const [a, b] = await hashLeaves(LEAVES.slice(0, 2));
    if (a === undefined || b === undefined) throw new Error('unreachable');
    expect(hex(await hashChildren(a, b))).toBe(ROOTS[2]);
  });

  it('batched leaf hashing agrees with the reference', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(fc.uint8Array({ maxLength: 40 }), { maxLength: 40 }),
        async (es) => {
          const got = await hashLeaves(es);
          expect(got.map(hex)).toEqual(es.map(refLeafHash).map(hex));
        },
      ),
    );
  });

  it('merkleRoot agrees with the naive recursive MTH for sizes 0..300', async () => {
    const leaves = syntheticLeafHashes(300);
    for (let n = 0; n <= 300; n++) {
      const want = refRootFromLeafHashes(leaves.slice(0, n));
      expect(hex(await merkleRoot(leaves.slice(0, n))), `size ${String(n)}`).toBe(hex(want));
    }
  });

  it('perfectSubtreeRoot requires a power-of-two width', async () => {
    const leaves = syntheticLeafHashes(8);
    expect(hex(await perfectSubtreeRoot(leaves))).toBe(hex(refRootFromLeafHashes(leaves)));
    await expect(perfectSubtreeRoot(leaves.slice(0, 6))).rejects.toThrow();
    await expect(perfectSubtreeRoot([])).rejects.toThrow();
  });

  it('rootFromFrontier folds from the right', async () => {
    // Size 7 = 4 + 2 + 1: root = H(f4, H(f2, f1)).
    const leaves = syntheticLeafHashes(7);
    const f4 = refRootFromLeafHashes(leaves.slice(0, 4));
    const f2 = refRootFromLeafHashes(leaves.slice(4, 6));
    const f1 = refRootFromLeafHashes(leaves.slice(6, 7));
    expect(hex(await rootFromFrontier([f4, f2, f1]))).toBe(hex(refRootFromLeafHashes(leaves)));
    expect(hex(await rootFromFrontier([]))).toBe(ROOTS[0]);
  });

  it('rejects hashes of the wrong length', async () => {
    await expect(hashChildren(new Uint8Array(31), new Uint8Array(32))).rejects.toThrow();
  });
});

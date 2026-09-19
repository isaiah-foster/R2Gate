import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
  ProofError,
  consistencyProof,
  tileNodeReader,
  verifyConsistency,
  type NodeCoord,
  type NodeReader,
} from '../src/proof.ts';
import { EMPTY_TREE, extendTree, partialTiles, type TileCoord } from '../src/tiles.ts';
import {
  hex,
  refConsistencyProof,
  refLeafHash,
  refRootFromLeafHashes,
  syntheticLeafHashes,
  unhex,
} from './reference.ts';

/** Node reader over an in-memory leaf list, using the reference MTH (independent of src/). */
function memoryReader(leaves: readonly Uint8Array[]): NodeReader {
  return (nodes: readonly NodeCoord[]) =>
    Promise.resolve(
      nodes.map(({ height, index }) => {
        const w = 2 ** height;
        if ((index + 1) * w > leaves.length) throw new RangeError('node outside tree');
        return refRootFromLeafHashes(leaves.slice(index * w, (index + 1) * w));
      }),
    );
}

function flipBit(b: Uint8Array, bit: number): Uint8Array {
  const out = b.slice();
  const i = Math.floor(bit / 8) % out.length;
  out[i] = (out[i] ?? 0) ^ (1 << (bit % 8));
  return out;
}

// transparency-dev/merkle testonly NodeHashes() / RootHashes() for its 8 leaf inputs (data only).
// Expected proofs below were derived by hand from RFC 6962 §2.1.2 and match nodes in that table.
const NH = {
  l0_1: '96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7',
  l0_4: 'bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b',
  l1_1: '5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e',
  l1_2: '0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a',
  l1_3: 'ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0',
  l2_0: 'd37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7',
  l2_1: '6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4',
};
const ROOTS: Record<number, string> = {
  1: '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d',
  2: 'fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125',
  5: '4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4',
  6: '76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef',
  8: '5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328',
};
const LEAF_INPUTS = [
  '',
  '00',
  '10',
  '2021',
  '3031',
  '40414243',
  '5051525354555657',
  '606162636465666768696a6b6c6d6e6f',
];

describe('consistency proofs: RFC 6962 vectors', () => {
  const vectors: [number, number, string[]][] = [
    [1, 8, [NH.l0_1, NH.l1_1, NH.l2_1]],
    [6, 8, [NH.l1_2, NH.l1_3, NH.l2_0]],
    [2, 5, [NH.l1_1, NH.l0_4]],
  ];

  it.each(vectors)('PROOF(%i, D[%i]) is generated and verifies', async (m, n, want) => {
    const leaves = LEAF_INPUTS.slice(0, n).map((h) => refLeafHash(unhex(h)));
    const proof = await consistencyProof(m, n, memoryReader(leaves));
    expect(proof.map(hex)).toEqual(want);
    const r1 = unhex(ROOTS[m] ?? '');
    const r2 = unhex(ROOTS[n] ?? '');
    await expect(verifyConsistency(m, n, r1, r2, proof)).resolves.toBeUndefined();
    await expect(verifyConsistency(m, n, r2, r1, proof)).rejects.toThrow(ProofError);
  });
});

describe('consistency proofs: properties against the reference', () => {
  it('matches RFC 6962 PROOF and verifies, for all 0 <= m <= n', async () => {
    const leaves = syntheticLeafHashes(600);
    await fc.assert(
      fc.asyncProperty(
        fc
          .integer({ min: 1, max: 600 })
          .chain((n) => fc.tuple(fc.integer({ min: 0, max: n }), fc.constant(n))),
        async ([m, n]) => {
          const d = leaves.slice(0, n);
          const proof = await consistencyProof(m, n, memoryReader(d));
          expect(proof.map(hex)).toEqual(refConsistencyProof(m, d).map(hex));
          await verifyConsistency(
            m,
            n,
            refRootFromLeafHashes(d.slice(0, m)),
            refRootFromLeafHashes(d),
            proof,
          );
        },
      ),
      { numRuns: 300 },
    );
  });

  // Sizes are not mutated here: a proof is a list of opaque hashes, and another size can have the
  // same proof shape (e.g. PROOF(1, D[5]) also "verifies" 1 -> 6 against the size-5 root). That is
  // not a forgery, because each size is bound to its root by the checkpoint signature.
  it('rejects any tampering with the proof or the roots', async () => {
    const leaves = syntheticLeafHashes(300);
    await fc.assert(
      fc.asyncProperty(
        fc
          .integer({ min: 2, max: 300 })
          .chain((n) => fc.tuple(fc.integer({ min: 1, max: n - 1 }), fc.constant(n))),
        fc.nat(),
        async ([m, n], bit) => {
          const d = leaves.slice(0, n);
          const r1 = refRootFromLeafHashes(d.slice(0, m));
          const r2 = refRootFromLeafHashes(d);
          const proof = refConsistencyProof(m, d);
          const reject = (p: Promise<void>) => expect(p).rejects.toThrow(ProofError);

          const which = bit % proof.length;
          const flipped = proof.map((h, i) => (i === which ? flipBit(h, bit) : h));
          await reject(verifyConsistency(m, n, r1, r2, flipped));
          await reject(verifyConsistency(m, n, flipBit(r1, bit), r2, proof));
          await reject(verifyConsistency(m, n, r1, flipBit(r2, bit), proof));
          await reject(verifyConsistency(m, n, r1, r2, proof.slice(0, -1)));
          await reject(verifyConsistency(m, n, r1, r2, [...proof, r1]));
        },
      ),
      { numRuns: 300 },
    );
  });

  it('handles the degenerate sizes exactly', async () => {
    const leaves = syntheticLeafHashes(5);
    const r = refRootFromLeafHashes(leaves);
    const empty = refRootFromLeafHashes([]);
    // The empty tree is a prefix of every tree; equal sizes need equal roots and no proof.
    await verifyConsistency(0, 5, empty, r, []);
    await verifyConsistency(0, 0, empty, empty, []);
    await verifyConsistency(5, 5, r, r, []);
    const reject = (p: Promise<void>) => expect(p).rejects.toThrow(ProofError);
    await reject(verifyConsistency(0, 5, empty, r, [r]));
    await reject(verifyConsistency(5, 5, r, r, [r]));
    await reject(verifyConsistency(5, 5, r, empty, []));
    await reject(verifyConsistency(5, 4, r, r, []));
    await reject(verifyConsistency(2, 5, r, r, []));
    await reject(verifyConsistency(2, 5, r, r, [r.slice(1), r]));
    await reject(verifyConsistency(-1, 5, r, r, []));
    await reject(verifyConsistency(1, 2 ** 53, r, r, [r]));
    await expect(consistencyProof(3, 2, memoryReader(leaves))).rejects.toThrow(RangeError);
    expect(await consistencyProof(0, 5, memoryReader(leaves))).toEqual([]);
    expect(await consistencyProof(5, 5, memoryReader(leaves))).toEqual([]);
  });
});

describe('tileNodeReader', () => {
  const SIZES = [1, 255, 256, 257, 1000, 65_535, 65_536, 65_537, 70_000];
  const leaves = syntheticLeafHashes(70_000);
  const tiles = new Map<string, Uint8Array>();
  const tileKey = (t: TileCoord) => `${String(t.level)}/${String(t.index)}/${String(t.width)}`;

  // Publish the tree at each recorded size, keeping every full tile and that size's partial tiles,
  // exactly the set of resources a log that published those checkpoints would hold.
  const built = (async () => {
    let state = EMPTY_TREE;
    for (const size of SIZES) {
      const r = await extendTree(state, leaves.slice(state.size, size));
      state = r.state;
      for (const t of [...r.fullTiles, ...partialTiles(state)]) tiles.set(tileKey(t), t.data);
    }
  })();

  function reader(size: number, reads: string[] = []): NodeReader {
    return tileNodeReader(size, (t) => {
      reads.push(tileKey(t));
      const data = tiles.get(tileKey(t));
      return data === undefined
        ? Promise.reject(new Error(`no tile ${tileKey(t)}`))
        : Promise.resolve(data);
    });
  }

  it('produces verifying proofs between every pair of published sizes', async () => {
    await built;
    const roots = new Map(SIZES.map((s) => [s, refRootFromLeafHashes(leaves.slice(0, s))]));
    for (const n of SIZES) {
      for (const m of SIZES.filter((s) => s <= n)) {
        const proof = await consistencyProof(m, n, reader(n));
        await verifyConsistency(
          m,
          n,
          roots.get(m) ?? new Uint8Array(),
          roots.get(n) ?? new Uint8Array(),
          proof,
        );
      }
    }
  });

  it('matches the reference proof exactly across tile levels', async () => {
    await built;
    for (const [m, n] of [
      [1000, 70_000],
      [65_535, 65_537],
      [257, 65_536],
    ] as const) {
      const proof = await consistencyProof(m, n, reader(n));
      expect(proof.map(hex)).toEqual(refConsistencyProof(m, leaves.slice(0, n)).map(hex));
    }
  });

  it('reads each tile at most once per reader', async () => {
    await built;
    const reads: string[] = [];
    await consistencyProof(1000, 70_000, reader(70_000, reads));
    expect(new Set(reads).size).toBe(reads.length);
  });

  it('rejects nodes outside the tree and tiles of the wrong length', async () => {
    await built;
    await expect(reader(256)([{ height: 0, index: 256 }])).rejects.toThrow(RangeError);
    await expect(reader(256)([{ height: 9, index: 0 }])).rejects.toThrow(RangeError);
    const short = tileNodeReader(256, () => Promise.resolve(new Uint8Array(32)));
    await expect(short([{ height: 0, index: 0 }])).rejects.toThrow(ProofError);
  });
});

import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
  EMPTY_TREE,
  FULL_TILE_BYTES,
  TILE_WIDTH,
  extendTree,
  fullTileCount,
  levelHashCount,
  partialTileWidth,
  partialTiles,
  splitTileHashes,
  tilesForTreeSize,
  treeRoot,
  type Tile,
  type TreeState,
} from '../src/tiles.ts';
import { hex, refRootFromLeafHashes, syntheticLeafHashes } from './reference.ts';

/** Build a tree from leaf hashes in the given chunk sizes, collecting every full tile emitted. */
async function buildChunked(
  leaves: readonly Uint8Array[],
  chunks: readonly number[],
): Promise<{ state: TreeState; fullTiles: Tile[] }> {
  let state = EMPTY_TREE;
  const fullTiles: Tile[] = [];
  let pos = 0;
  for (const c of chunks) {
    const r = await extendTree(state, leaves.slice(pos, pos + c));
    pos += c;
    state = r.state;
    fullTiles.push(...r.fullTiles);
  }
  expect(pos).toBe(leaves.length);
  return { state, fullTiles };
}

function key(t: { level: number; index: number; width: number }): string {
  return `${String(t.level)}/${String(t.index)}/${String(t.width)}`;
}

/**
 * Checks a tile against the tlog-tiles definition: hash i of tile n at level l is
 * MTH(D[(n*256 + i) * 256**l : (n*256 + i + 1) * 256**l]).
 */
function expectTileMatchesSpec(t: Tile, leaves: readonly Uint8Array[]): void {
  const span = TILE_WIDTH ** t.level;
  const hashes = splitTileHashes(t.data);
  expect(hashes.length).toBe(t.width);
  hashes.forEach((h, i) => {
    const lo = (t.index * TILE_WIDTH + i) * span;
    expect(hex(h), `tile ${key(t)} hash ${String(i)}`).toBe(
      hex(refRootFromLeafHashes(leaves.slice(lo, lo + span))),
    );
  });
}

describe('tile math', () => {
  it('tlog-tiles worked example: size 70,000', () => {
    const s = 70_000;
    expect([0, 1, 2, 3].map((l) => fullTileCount(l, s))).toEqual([273, 1, 0, 0]);
    expect([0, 1, 2, 3].map((l) => partialTileWidth(l, s))).toEqual([112, 17, 1, 0]);

    const coords = tilesForTreeSize(s);
    const full0 = coords.filter((c) => c.level === 0 && c.width === TILE_WIDTH);
    expect(full0).toHaveLength(273);
    expect(full0.map((c) => c.index)).toEqual([...Array(273).keys()]);
    expect(coords.filter((c) => c.width !== TILE_WIDTH)).toEqual([
      { level: 0, index: 273, width: 112 },
      { level: 1, index: 1, width: 17 },
      { level: 2, index: 0, width: 1 },
    ]);
    expect(coords.filter((c) => c.level === 1 && c.width === TILE_WIDTH)).toEqual([
      { level: 1, index: 0, width: 256 },
    ]);
    expect(coords).toHaveLength(273 + 1 + 1 + 1 + 1);
  });

  it('tlog-tiles example: size 256 is one full L0 tile and a partial L1 tile of width 1', () => {
    expect(tilesForTreeSize(256)).toEqual([
      { level: 0, index: 0, width: 256 },
      { level: 1, index: 0, width: 1 },
    ]);
  });

  it('an empty tree has no tiles', () => {
    expect(tilesForTreeSize(0)).toEqual([]);
  });

  it('levelHashCount is floor(size / 256^level)', () => {
    fc.assert(
      fc.property(fc.integer({ min: 0, max: Number.MAX_SAFE_INTEGER }), fc.nat(7), (s, l) => {
        expect(levelHashCount(l, s)).toBe(Math.floor(s / 256 ** l));
        expect(partialTileWidth(l, s)).toBe(levelHashCount(l, s) % 256);
        expect(fullTileCount(l, s)).toBe(Math.floor(levelHashCount(l, s) / 256));
      }),
    );
  });

  it('rejects unsafe or negative sizes', () => {
    expect(() => tilesForTreeSize(-1)).toThrow();
    expect(() => tilesForTreeSize(1.5)).toThrow();
    expect(() => tilesForTreeSize(2 ** 53)).toThrow();
  });
});

describe('tile builder', () => {
  it('produces the worked-example tiles for 70,000 leaves, each matching the spec definition', async () => {
    const leaves = syntheticLeafHashes(70_000);
    const { state, fullTiles } = await extendTree(EMPTY_TREE, leaves);
    expect(state.size).toBe(70_000);

    const parts = partialTiles(state);
    expect(parts.map(key)).toEqual(['0/273/112', '1/1/17', '2/0/1']);
    expect(fullTiles.filter((t) => t.level === 0)).toHaveLength(273);
    expect(fullTiles.filter((t) => t.level === 1).map(key)).toEqual(['1/0/256']);
    expect(fullTiles.filter((t) => t.level > 1)).toEqual([]);

    // Emitted tiles are exactly the coordinates the tile math predicts.
    expect([...fullTiles, ...parts].map(key).sort()).toEqual(
      tilesForTreeSize(70_000).map(key).sort(),
    );
    for (const t of fullTiles) expect(t.data.length).toBe(FULL_TILE_BYTES);
    for (const t of [...fullTiles, ...parts]) expectTileMatchesSpec(t, leaves);

    expect(hex(await treeRoot(state))).toBe(hex(refRootFromLeafHashes(leaves)));
  });

  // I1: the published root equals the naive recursive MTH, including at tile boundaries.
  // Slow (several 65k-leaf trees and their naive roots): it sometimes exceeded vitest's default 5 s
  // timeout while the worker suite ran alongside (seen in M7). Not a performance test.
  it(
    'I1: root equals naive MTH at sizes around 255/256/257 and 65,535/65,536/65,537',
    {
      timeout: 60_000,
    },
    async () => {
      const leaves = syntheticLeafHashes(65_537);
      const checkpoints = [255, 256, 257, 65_535, 65_536, 65_537];
      let state = EMPTY_TREE;
      for (const size of checkpoints) {
        state = (await extendTree(state, leaves.slice(state.size, size))).state;
        expect(state.size).toBe(size);
        expect(hex(await treeRoot(state)), `size ${String(size)}`).toBe(
          hex(refRootFromLeafHashes(leaves.slice(0, size))),
        );
        for (const t of partialTiles(state)) expectTileMatchesSpec(t, leaves);
      }
    },
  );

  it('I1: root equals naive MTH for every size 0..600', async () => {
    const leaves = syntheticLeafHashes(600);
    let state = EMPTY_TREE;
    expect(hex(await treeRoot(state))).toBe(hex(refRootFromLeafHashes([])));
    for (let n = 1; n <= 600; n++) {
      state = (await extendTree(state, leaves.slice(n - 1, n))).state;
      expect(hex(await treeRoot(state)), `size ${String(n)}`).toBe(
        hex(refRootFromLeafHashes(leaves.slice(0, n))),
      );
    }
  });

  it('I1 property: any chunking of appends yields the naive root and the same tiles', async () => {
    const leaves = syntheticLeafHashes(1500);
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 0, max: 1500 }),
        fc.array(fc.integer({ min: 0, max: 300 }), { minLength: 1, maxLength: 20 }),
        async (n, rawChunks) => {
          const chunks: number[] = [];
          let left = n;
          for (const c of rawChunks) {
            const take = Math.min(c, left);
            chunks.push(take);
            left -= take;
          }
          chunks.push(left);
          const prefix = leaves.slice(0, n);
          const chunked = await buildChunked(prefix, chunks);
          const oneShot = await buildChunked(prefix, [n]);
          expect(hex(await treeRoot(chunked.state))).toBe(hex(refRootFromLeafHashes(prefix)));
          expect(chunked.fullTiles.map(key)).toEqual(oneShot.fullTiles.map(key));
          expect(chunked.fullTiles.map((t) => hex(t.data))).toEqual(
            oneShot.fullTiles.map((t) => hex(t.data)),
          );
          expect(partialTiles(chunked.state).map((t) => hex(t.data))).toEqual(
            partialTiles(oneShot.state).map((t) => hex(t.data)),
          );
        },
      ),
      { numRuns: 40 },
    );
  });

  it('chunked appends across the 65,536 boundary emit the same L1 tile as one shot', async () => {
    const leaves = syntheticLeafHashes(65_600);
    const a = await buildChunked(leaves, [65_000, 535, 1, 63, 1]);
    const b = await buildChunked(leaves, [65_600]);
    const l1 = (ts: Tile[]): string[] => ts.filter((t) => t.level === 1).map((t) => hex(t.data));
    expect(l1(a.fullTiles)).toHaveLength(1);
    expect(l1(a.fullTiles)).toEqual(l1(b.fullTiles));
    expect(hex(await treeRoot(a.state))).toBe(hex(await treeRoot(b.state)));
  });

  it('size 256 state holds an empty L0 partial and serves only the L1 partial', async () => {
    const { state, fullTiles } = await extendTree(EMPTY_TREE, syntheticLeafHashes(256));
    expect(state.partials.map((p) => p.length)).toEqual([0, 32]);
    expect(fullTiles.map(key)).toEqual(['0/0/256']);
    expect(partialTiles(state).map(key)).toEqual(['1/0/1']);
  });

  it('appending nothing is a no-op', async () => {
    const { state } = await extendTree(EMPTY_TREE, syntheticLeafHashes(5));
    const r = await extendTree(state, []);
    expect(r.state).toEqual(state);
    expect(r.fullTiles).toEqual([]);
  });

  it('rejects a state whose partial tiles do not match its size', async () => {
    const { state } = await extendTree(EMPTY_TREE, syntheticLeafHashes(5));
    const bad: TreeState = { size: 6, partials: state.partials };
    await expect(extendTree(bad, syntheticLeafHashes(1))).rejects.toThrow();
    await expect(treeRoot(bad)).rejects.toThrow();
    const extraLevel: TreeState = { size: 5, partials: [...state.partials, new Uint8Array()] };
    await expect(treeRoot(extraLevel)).rejects.toThrow();
  });

  it('rejects leaf hashes of the wrong length', async () => {
    await expect(extendTree(EMPTY_TREE, [new Uint8Array(31)])).rejects.toThrow();
  });

  it('splitTileHashes rejects data that is not a whole number of hashes', () => {
    expect(() => splitTileHashes(new Uint8Array(33))).toThrow();
    expect(() => splitTileHashes(new Uint8Array(32 * 257))).toThrow();
    expect(splitTileHashes(new Uint8Array(64))).toHaveLength(2);
  });
});

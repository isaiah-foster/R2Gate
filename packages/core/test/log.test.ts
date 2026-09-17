import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { decodeBundle } from '../src/bundle.ts';
import { EMPTY_LOG, appendEntries, type Bundle, type LogState } from '../src/log.ts';
import { TILE_WIDTH, splitTileHashes, type Tile } from '../src/tiles.ts';
import { hex, refLeafHash, refRoot } from './reference.ts';

function entry(i: number): Uint8Array {
  return new TextEncoder().encode(`{"i":${String(i)}}`);
}

async function build(
  entries: readonly Uint8Array[],
  chunks: readonly number[],
): Promise<{
  state: LogState;
  root: Uint8Array;
  fullTiles: Tile[];
  fullBundles: Bundle[];
  lastPartialTiles: readonly Tile[];
  lastPartialBundle: Bundle | null;
}> {
  let state = EMPTY_LOG;
  let root: Uint8Array = new Uint8Array();
  const fullTiles: Tile[] = [];
  const fullBundles: Bundle[] = [];
  let lastPartialTiles: readonly Tile[] = [];
  let lastPartialBundle: Bundle | null = null;
  let pos = 0;
  for (const c of chunks) {
    const u = await appendEntries(state, entries.slice(pos, pos + c));
    pos += c;
    state = u.state;
    root = u.root;
    fullTiles.push(...u.fullTiles);
    fullBundles.push(...u.fullBundles);
    lastPartialTiles = u.partialTiles;
    lastPartialBundle = u.partialBundle;
  }
  return { state, root, fullTiles, fullBundles, lastPartialTiles, lastPartialBundle };
}

describe('appendEntries', () => {
  it('empty append on an empty log yields the empty root and no resources', async () => {
    const u = await appendEntries(EMPTY_LOG, []);
    expect(hex(u.root)).toBe(hex(refRoot([])));
    expect(u.state.tree.size).toBe(0);
    expect(u.fullTiles).toEqual([]);
    expect(u.fullBundles).toEqual([]);
    expect(u.partialTiles).toEqual([]);
    expect(u.partialBundle).toBeNull();
  });

  it('bundles align with level-0 tiles: entry i hashes to tile hash i', async () => {
    const entries = Array.from({ length: 600 }, (_, i) => entry(i));
    const r = await build(entries, [600]);
    expect(r.fullBundles.map((b) => [b.index, b.width])).toEqual([
      [0, 256],
      [1, 256],
    ]);
    expect(r.lastPartialBundle).toMatchObject({ index: 2, width: 88 });
    const l0 = [...r.fullTiles, ...r.lastPartialTiles].filter((t) => t.level === 0);
    const bundles = [...r.fullBundles, ...(r.lastPartialBundle ? [r.lastPartialBundle] : [])];
    expect(l0.map((t) => [t.index, t.width])).toEqual(bundles.map((b) => [b.index, b.width]));
    for (const [k, b] of bundles.entries()) {
      const tile = l0[k];
      if (tile === undefined) throw new Error('unreachable');
      const decoded = decodeBundle(b.data);
      expect(decoded).toEqual(entries.slice(b.index * TILE_WIDTH, b.index * TILE_WIDTH + b.width));
      expect(splitTileHashes(tile.data).map(hex)).toEqual(decoded.map(refLeafHash).map(hex));
    }
  });

  it('no partial bundle is produced at a multiple of 256', async () => {
    const r = await build(
      Array.from({ length: 512 }, (_, i) => entry(i)),
      [512],
    );
    expect(r.lastPartialBundle).toBeNull();
    expect(r.state.bundle).toEqual([]);
  });

  it('I1 property: root equals naive MTH over entries, independent of chunking', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(fc.uint8Array({ maxLength: 24 }), { maxLength: 700, size: 'max' }),
        fc.array(fc.nat(260), { minLength: 1, maxLength: 8 }),
        async (entries, raw) => {
          const chunks: number[] = [];
          let left = entries.length;
          for (const c of raw) {
            chunks.push(Math.min(c, left));
            left -= Math.min(c, left);
          }
          chunks.push(left);
          const a = await build(entries, chunks);
          const b = await build(entries, [entries.length]);
          expect(hex(a.root)).toBe(hex(refRoot(entries)));
          expect(a.fullBundles.map((x) => hex(x.data))).toEqual(
            b.fullBundles.map((x) => hex(x.data)),
          );
          expect(a.fullTiles.map((x) => hex(x.data))).toEqual(b.fullTiles.map((x) => hex(x.data)));
          expect(a.state).toEqual(b.state);
        },
      ),
      { numRuns: 40 },
    );
  });

  it('rejects an oversize entry without changing anything', async () => {
    await expect(appendEntries(EMPTY_LOG, [entry(1), new Uint8Array(65_536)])).rejects.toThrow(
      /65535/,
    );
  });

  it('rejects a state whose partial bundle does not match the tree size', async () => {
    const { state } = await build([entry(0), entry(1)], [2]);
    const bad: LogState = { tree: state.tree, bundle: state.bundle.slice(0, 1) };
    await expect(appendEntries(bad, [entry(2)])).rejects.toThrow();
  });
});

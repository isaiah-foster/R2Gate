// C2SP tlog-tiles: tile math and an incremental tile builder.
//
// A tile at level L holds up to 256 consecutive hashes. At level 0 those are leaf hashes; at level
// L+1 each hash is the root of one *full* level-L tile (the subtree of 256^(L+1) leaves it spans).
// The whole tree state needed to keep appending is the current partial tile at every level: full
// tiles are immutable once emitted and never needed again by the writer.

import { concatBytes } from './bytes.ts';
import { HASH_SIZE, decompose, perfectSubtreeRoot, rootFromFrontier } from './merkle.ts';

export const TILE_HEIGHT = 8;
export const TILE_WIDTH = 2 ** TILE_HEIGHT; // 256
export const FULL_TILE_BYTES = TILE_WIDTH * HASH_SIZE; // 8,192
export const MAX_TILE_LEVEL = 63;

/** A tile coordinate. `width` is 256 for a full tile and 1..255 for a partial tile. */
export interface TileCoord {
  readonly level: number;
  readonly index: number;
  readonly width: number;
}

export interface Tile extends TileCoord {
  /** `width` concatenated 32-byte hashes. */
  readonly data: Uint8Array;
}

/**
 * Writer-side tree state: the tree size plus the hashes of the current partial tile at each level
 * (concatenated, possibly empty). `partials.length` equals `tileLevelCount(size)`, and
 * `partials[l]` holds exactly `partialTileWidth(l, size)` hashes.
 */
export interface TreeState {
  readonly size: number;
  readonly partials: readonly Uint8Array[];
}

export const EMPTY_TREE: TreeState = { size: 0, partials: [] };

function checkSize(size: number): void {
  if (!Number.isSafeInteger(size) || size < 0) {
    throw new RangeError(`invalid tree size ${String(size)}`);
  }
}

function checkLevel(level: number): void {
  if (!Number.isInteger(level) || level < 0 || level > MAX_TILE_LEVEL) {
    throw new RangeError(`invalid tile level ${String(level)}`);
  }
}

/** Number of hashes at tile level `level` in a tree of `size` leaves: floor(size / 256^level). */
export function levelHashCount(level: number, size: number): number {
  checkLevel(level);
  checkSize(size);
  // Division by a power of two is exact in binary floating point, so this is exact for safe sizes.
  return Math.floor(size / TILE_WIDTH ** level);
}

/** Width of the partial tile at `level`: floor(size / 256^level) mod 256 (0 = no partial tile). */
export function partialTileWidth(level: number, size: number): number {
  return levelHashCount(level, size) % TILE_WIDTH;
}

/** Number of full tiles at `level`. */
export function fullTileCount(level: number, size: number): number {
  return Math.floor(levelHashCount(level, size) / TILE_WIDTH);
}

/** Number of tile levels that contain at least one hash (0 for the empty tree). */
export function tileLevelCount(size: number): number {
  checkSize(size);
  let levels = 0;
  while (levels <= MAX_TILE_LEVEL && levelHashCount(levels, size) > 0) levels++;
  return levels;
}

/** Every tile (full, then partial, level by level) that exists for a tree of `size` leaves. */
export function tilesForTreeSize(size: number): TileCoord[] {
  const out: TileCoord[] = [];
  for (let level = 0; level < tileLevelCount(size); level++) {
    const full = fullTileCount(level, size);
    for (let index = 0; index < full; index++) out.push({ level, index, width: TILE_WIDTH });
    const width = partialTileWidth(level, size);
    if (width > 0) out.push({ level, index: full, width });
  }
  return out;
}

/** Splits tile data into its hashes (0..256 of them). */
export function splitTileHashes(data: Uint8Array): Uint8Array[] {
  if (data.length % HASH_SIZE !== 0 || data.length > FULL_TILE_BYTES) {
    throw new RangeError(`tile data length ${String(data.length)} is not 0..256 hashes`);
  }
  const out: Uint8Array[] = [];
  for (let off = 0; off < data.length; off += HASH_SIZE) out.push(data.slice(off, off + HASH_SIZE));
  return out;
}

/** Throws unless `state` is internally consistent (guards state loaded from storage). */
export function checkTreeState(state: TreeState): void {
  checkSize(state.size);
  const levels = tileLevelCount(state.size);
  if (state.partials.length !== levels) {
    throw new RangeError(
      `tree state for size ${String(state.size)} has ${String(state.partials.length)} levels, want ${String(levels)}`,
    );
  }
  state.partials.forEach((p, level) => {
    const want = partialTileWidth(level, state.size) * HASH_SIZE;
    if (p.length !== want) {
      throw new RangeError(
        `tree state level ${String(level)} has ${String(p.length)} bytes, want ${String(want)}`,
      );
    }
  });
}

/**
 * Appends leaf hashes. Returns the new state and every tile that became full, in level order and
 * then index order. Pure: the input state is not modified, and the same inputs always give
 * byte-identical outputs, which is what makes re-publication after a crash idempotent.
 */
export async function extendTree(
  state: TreeState,
  leafHashes: readonly Uint8Array[],
): Promise<{ state: TreeState; fullTiles: Tile[] }> {
  checkTreeState(state);
  for (const h of leafHashes) {
    if (h.length !== HASH_SIZE) throw new RangeError('leaf hashes must be 32 bytes');
  }
  if (leafHashes.length === 0) return { state, fullTiles: [] };
  const size = state.size + leafHashes.length;
  checkSize(size);

  const partials: Uint8Array[] = [];
  const fullTiles: Tile[] = [];
  let pending: readonly Uint8Array[] = leafHashes;
  for (let level = 0; level < tileLevelCount(size); level++) {
    const row = [...splitTileHashes(state.partials[level] ?? new Uint8Array()), ...pending];
    const firstIndex = fullTileCount(level, state.size);
    const completed: Uint8Array[][] = [];
    let off = 0;
    for (; off + TILE_WIDTH <= row.length; off += TILE_WIDTH) {
      const hashes = row.slice(off, off + TILE_WIDTH);
      completed.push(hashes);
      fullTiles.push({
        level,
        index: firstIndex + completed.length - 1,
        width: TILE_WIDTH,
        data: concatBytes(...hashes),
      });
    }
    partials.push(concatBytes(...row.slice(off)));
    // Each completed tile contributes its subtree root as one hash at the next level.
    pending = await Promise.all(completed.map(perfectSubtreeRoot));
  }
  // The top level holds < 256 hashes, so it never completes a tile.
  if (pending.length !== 0) throw new Error('unreachable: hashes left above the top level');

  const next: TreeState = { size, partials };
  checkTreeState(next);
  return { state: next, fullTiles };
}

/** The partial tiles that must be served for a checkpoint at `state.size` (empty ones omitted). */
export function partialTiles(state: TreeState): Tile[] {
  checkTreeState(state);
  const out: Tile[] = [];
  state.partials.forEach((data, level) => {
    const width = data.length / HASH_SIZE;
    if (width > 0) out.push({ level, index: fullTileCount(level, state.size), width, data });
  });
  return out;
}

/**
 * Root hash of the tree, from the partial tiles alone. The frontier (maximal perfect subtrees,
 * left to right) is: for each level from the top down, the binary decomposition of that level's
 * partial tile. E.g. 70,000 = 1×65,536 (L2) + 16×256 + 1×256 (L1) + 64 + 32 + 16 (L0).
 */
export async function treeRoot(state: TreeState): Promise<Uint8Array> {
  checkTreeState(state);
  const frontier: Promise<Uint8Array>[] = [];
  for (let level = state.partials.length - 1; level >= 0; level--) {
    const hashes = splitTileHashes(state.partials[level] ?? new Uint8Array());
    let off = 0;
    for (const width of decompose(hashes.length)) {
      frontier.push(perfectSubtreeRoot(hashes.slice(off, off + width)));
      off += width;
    }
  }
  return rootFromFrontier(await Promise.all(frontier));
}

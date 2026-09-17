// Combines the tile builder and entry bundles into the one operation the sequencer needs: given
// the persisted state and a batch of new entries, compute every resource to write to R2 and the
// new root. Pure and deterministic, so re-running it after a crash yields identical bytes.

import { checkEntrySize, encodeBundle } from './bundle.ts';
import { hashLeaves } from './merkle.ts';
import {
  EMPTY_TREE,
  TILE_WIDTH,
  checkTreeState,
  extendTree,
  partialTiles,
  partialTileWidth,
  treeRoot,
  type Tile,
  type TreeState,
} from './tiles.ts';

export interface Bundle {
  readonly index: number;
  /** 256 for a full bundle, 1..255 for a partial one. */
  readonly width: number;
  readonly data: Uint8Array;
}

export interface LogState {
  readonly tree: TreeState;
  /** Entries of the current partial bundle, i.e. the last `size mod 256` entries. */
  readonly bundle: readonly Uint8Array[];
}

export const EMPTY_LOG: LogState = { tree: EMPTY_TREE, bundle: [] };

export interface LogUpdate {
  readonly state: LogState;
  readonly root: Uint8Array;
  /** Immutable resources completed by this update (write create-if-absent). */
  readonly fullTiles: readonly Tile[];
  readonly fullBundles: readonly Bundle[];
  /** Partial resources for the new size (empty ones omitted). */
  readonly partialTiles: readonly Tile[];
  readonly partialBundle: Bundle | null;
}

function checkLogState(state: LogState): void {
  checkTreeState(state.tree);
  const want = partialTileWidth(0, state.tree.size);
  if (state.bundle.length !== want) {
    throw new RangeError(
      `partial bundle has ${String(state.bundle.length)} entries, want ${String(want)}`,
    );
  }
}

export async function appendEntries(
  state: LogState,
  entries: readonly Uint8Array[],
): Promise<LogUpdate> {
  checkLogState(state);
  for (const e of entries) checkEntrySize(e);

  const { state: tree, fullTiles } = await extendTree(state.tree, await hashLeaves(entries));

  const firstBundle = Math.floor(state.tree.size / TILE_WIDTH);
  const pending = [...state.bundle, ...entries];
  const fullBundles: Bundle[] = [];
  let off = 0;
  for (; off + TILE_WIDTH <= pending.length; off += TILE_WIDTH) {
    fullBundles.push({
      index: firstBundle + fullBundles.length,
      width: TILE_WIDTH,
      data: encodeBundle(pending.slice(off, off + TILE_WIDTH)),
    });
  }
  const bundle = pending.slice(off);
  const partialBundle: Bundle | null =
    bundle.length === 0
      ? null
      : {
          index: Math.floor(tree.size / TILE_WIDTH),
          width: bundle.length,
          data: encodeBundle(bundle),
        };

  const next: LogState = { tree, bundle };
  checkLogState(next);
  return {
    state: next,
    root: await treeRoot(tree),
    fullTiles,
    fullBundles,
    partialTiles: partialTiles(tree),
    partialBundle,
  };
}

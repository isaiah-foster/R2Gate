// Resource paths of a tiled log, relative to the log prefix (C2SP tlog-tiles, plus the `x-`
// extensions from PLAN §6). Parsing is strict: a path parses only if it is exactly what the
// encoder would produce, so every resource has one canonical name.

import { MAX_TILE_LEVEL, TILE_WIDTH } from './tiles.ts';

export const CHECKPOINT_PATH = 'checkpoint';
const ARCHIVED_CHECKPOINT_PREFIX = 'x-checkpoints/';

function checkIndex(n: number, what: string): void {
  if (!Number.isSafeInteger(n) || n < 0) throw new RangeError(`invalid ${what} ${String(n)}`);
}

/**
 * Tile index as zero-padded 3-digit path elements, all but the last prefixed with `x`:
 * 1234067 → `x001/x234/067`.
 */
export function encodeTileIndex(n: number): string {
  checkIndex(n, 'tile index');
  const groups: string[] = [];
  let rest = n;
  do {
    groups.unshift(String(rest % 1000).padStart(3, '0'));
    rest = Math.floor(rest / 1000);
  } while (rest > 0);
  return groups.map((g, i) => (i < groups.length - 1 ? `x${g}` : g)).join('/');
}

const INDEX_RE = /^(?:x\d{3}\/)*\d{3}$/;

/** Inverse of `encodeTileIndex`; throws on any non-canonical form. */
export function decodeTileIndex(s: string): number {
  if (!INDEX_RE.test(s)) throw new RangeError(`invalid tile index path ${JSON.stringify(s)}`);
  let n = 0;
  for (const g of s.split('/')) n = n * 1000 + Number(g.replace('x', ''));
  if (!Number.isSafeInteger(n) || encodeTileIndex(n) !== s) {
    throw new RangeError(`non-canonical tile index path ${JSON.stringify(s)}`);
  }
  return n;
}

function widthSuffix(width: number): string {
  if (!Number.isInteger(width) || width < 1 || width > TILE_WIDTH) {
    throw new RangeError(`invalid tile width ${String(width)}`);
  }
  return width === TILE_WIDTH ? '' : `.p/${String(width)}`;
}

/** `tile/<L>/<N>[.p/<W>]`; width 256 means a full tile. */
export function tilePath(level: number, index: number, width: number): string {
  if (!Number.isInteger(level) || level < 0 || level > MAX_TILE_LEVEL) {
    throw new RangeError(`invalid tile level ${String(level)}`);
  }
  return `tile/${String(level)}/${encodeTileIndex(index)}${widthSuffix(width)}`;
}

/** `tile/entries/<N>[.p/<W>]`; width 256 means a full bundle. */
export function entryBundlePath(index: number, width: number): string {
  return `tile/entries/${encodeTileIndex(index)}${widthSuffix(width)}`;
}

/** `x-checkpoints/<size>`: immutable archive of every checkpoint the log has published. */
export function archivedCheckpointPath(size: number): string {
  checkIndex(size, 'checkpoint size');
  return `${ARCHIVED_CHECKPOINT_PREFIX}${String(size)}`;
}

export type LogPath =
  | { readonly kind: 'checkpoint' }
  | {
      readonly kind: 'tile';
      readonly level: number;
      readonly index: number;
      readonly width: number;
    }
  | { readonly kind: 'bundle'; readonly index: number; readonly width: number }
  | { readonly kind: 'archived-checkpoint'; readonly size: number };

const TILE_RE = /^tile\/(entries|0|[1-9]\d?)\/((?:x\d{3}\/)*\d{3})(?:\.p\/([1-9]\d{0,2}))?$/;
const ARCHIVED_RE = /^x-checkpoints\/(0|[1-9]\d{0,15})$/;

/** Parses a path relative to the log prefix; returns null unless it is a canonical log path. */
export function parseLogPath(path: string): LogPath | null {
  if (path === CHECKPOINT_PATH) return { kind: 'checkpoint' };
  try {
    const archived = ARCHIVED_RE.exec(path);
    if (archived?.[1] !== undefined) {
      const size = Number(archived[1]);
      return archivedCheckpointPath(size) === path ? { kind: 'archived-checkpoint', size } : null;
    }
    const m = TILE_RE.exec(path);
    if (m?.[1] === undefined || m[2] === undefined) return null;
    const index = decodeTileIndex(m[2]);
    const width = m[3] === undefined ? TILE_WIDTH : Number(m[3]);
    const canonical =
      m[1] === 'entries' ? entryBundlePath(index, width) : tilePath(Number(m[1]), index, width);
    if (canonical !== path) return null;
    return m[1] === 'entries'
      ? { kind: 'bundle', index, width }
      : { kind: 'tile', level: Number(m[1]), index, width };
  } catch {
    return null;
  }
}

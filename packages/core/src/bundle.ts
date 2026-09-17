// C2SP tlog-tiles entry bundles: a sequence of big-endian uint16 length-prefixed entries. Bundle N
// holds entries [256N, 256N + width), aligned with level-0 tile N.

import { TILE_WIDTH } from './tiles.ts';

/** The uint16 length prefix caps an entry at 65,535 bytes. This is spec-fixed (PLAN §11.11). */
export const MAX_ENTRY_SIZE = 0xffff;

export function checkEntrySize(entry: Uint8Array): void {
  if (entry.length > MAX_ENTRY_SIZE) {
    throw new RangeError(
      `entry is ${String(entry.length)} bytes; the maximum is ${String(MAX_ENTRY_SIZE)}`,
    );
  }
}

export function encodeBundle(entries: readonly Uint8Array[]): Uint8Array {
  if (entries.length > TILE_WIDTH) {
    throw new RangeError(`a bundle holds at most ${String(TILE_WIDTH)} entries`);
  }
  let n = 0;
  for (const e of entries) {
    checkEntrySize(e);
    n += 2 + e.length;
  }
  const out = new Uint8Array(n);
  let off = 0;
  for (const e of entries) {
    out[off] = e.length >>> 8;
    out[off + 1] = e.length & 0xff;
    out.set(e, off + 2);
    off += 2 + e.length;
  }
  return out;
}

/** Strict decode: the data must be exactly a whole number (at most 256) of entries. */
export function decodeBundle(data: Uint8Array): Uint8Array[] {
  const out: Uint8Array[] = [];
  let off = 0;
  while (off < data.length) {
    if (out.length === TILE_WIDTH) throw new RangeError('bundle has more than 256 entries');
    const hi = data[off];
    const lo = data[off + 1];
    if (hi === undefined || lo === undefined) throw new RangeError('truncated entry length');
    const len = (hi << 8) | lo;
    if (off + 2 + len > data.length) throw new RangeError('truncated entry');
    out.push(data.slice(off + 2, off + 2 + len));
    off += 2 + len;
  }
  return out;
}

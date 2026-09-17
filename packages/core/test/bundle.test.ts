import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { MAX_ENTRY_SIZE, decodeBundle, encodeBundle } from '../src/bundle.ts';

describe('entry bundles', () => {
  it('uses big-endian uint16 length prefixes', () => {
    const b = encodeBundle([Uint8Array.of(0xaa), new Uint8Array(0x0102)]);
    expect([...b.slice(0, 3)]).toEqual([0x00, 0x01, 0xaa]);
    expect([...b.slice(3, 5)]).toEqual([0x01, 0x02]);
    expect(b.length).toBe(2 + 1 + 2 + 0x0102);
  });

  it('round-trips up to 256 entries', () => {
    fc.assert(
      fc.property(fc.array(fc.uint8Array({ maxLength: 300 }), { maxLength: 256 }), (es) => {
        expect(decodeBundle(encodeBundle(es))).toEqual(es);
      }),
      { numRuns: 50 },
    );
  });

  it('enforces the 65,535-byte entry limit', () => {
    expect(MAX_ENTRY_SIZE).toBe(65_535);
    const max = new Uint8Array(MAX_ENTRY_SIZE).fill(7);
    expect(decodeBundle(encodeBundle([max]))).toEqual([max]);
    expect(() => encodeBundle([new Uint8Array(MAX_ENTRY_SIZE + 1)])).toThrow(/65535/);
  });

  it('refuses more than 256 entries', () => {
    expect(() => encodeBundle(Array.from({ length: 257 }, () => Uint8Array.of(1)))).toThrow();
  });

  it.each([
    ['truncated length', Uint8Array.of(0x00)],
    ['truncated body', Uint8Array.of(0x00, 0x02, 0x01)],
    ['trailing byte', Uint8Array.of(0x00, 0x01, 0x01, 0x00)],
  ])('rejects %s', (_name, data) => {
    expect(() => decodeBundle(data)).toThrow();
  });

  it('rejects a bundle with more than 256 entries', () => {
    expect(() => decodeBundle(new Uint8Array(2 * 257))).toThrow();
  });
});

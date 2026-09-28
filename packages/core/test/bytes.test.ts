import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
  bytesEqual,
  compareUtf8,
  concatBytes,
  fromBase64,
  fromHex,
  toBase64,
  toHex,
  utf8Decode,
  utf8Encode,
} from '../src/bytes.ts';

describe('hex', () => {
  it('round-trips arbitrary bytes and matches Node', () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 64 }), (b) => {
        const h = toHex(b);
        expect(h).toBe(Buffer.from(b).toString('hex'));
        expect(fromHex(h)).toEqual(b);
      }),
    );
  });

  it.each(['0', 'abc', 'AB', 'zz', '0x00', ' 00'])('rejects malformed hex %j', (s) => {
    expect(() => fromHex(s)).toThrow();
  });
});

describe('base64', () => {
  it('round-trips arbitrary bytes and matches Node', () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 80 }), (b) => {
        const s = toBase64(b);
        expect(s).toBe(Buffer.from(b).toString('base64'));
        expect(fromBase64(s)).toEqual(b);
      }),
    );
  });

  // signed-note and tlog-checkpoint: decoders MUST reject non-canonical encodings (RFC 4648 §3.5).
  it.each([
    ['missing padding', 'AQ'],
    ['too much padding', 'AQ==='],
    ['non-zero trailing bits (1 byte)', 'AR=='],
    ['non-zero trailing bits (2 bytes)', 'AQF='],
    ['whitespace', 'AQ= ='],
    ['newline', 'AQ==\n'],
    ['url-safe alphabet', '-_8='],
    ['padding in the middle', 'AQ==AQ=='],
    ['bad length', 'AQIDB'],
  ])('rejects %s (%j)', (_name, s) => {
    expect(() => fromBase64(s)).toThrow();
  });

  it('accepts the empty string', () => {
    expect(fromBase64('')).toEqual(new Uint8Array());
  });
});

describe('utf8', () => {
  it('rejects invalid UTF-8 when decoding', () => {
    expect(() => utf8Decode(Uint8Array.of(0xc3, 0x28))).toThrow();
    expect(() => utf8Decode(Uint8Array.of(0xed, 0xa0, 0x80))).toThrow(); // encoded surrogate
  });

  it('refuses to encode lone surrogates instead of silently replacing them', () => {
    expect(() => utf8Encode('a\uD800b')).toThrow();
  });

  it('keeps a leading BOM rather than stripping it', () => {
    expect(utf8Decode(Uint8Array.of(0xef, 0xbb, 0xbf, 0x61))).toBe('﻿a');
  });

  it('round-trips well-formed strings', () => {
    fc.assert(
      fc.property(fc.string({ unit: 'grapheme' }), (s) => {
        expect(utf8Decode(utf8Encode(s))).toBe(s);
      }),
    );
  });
});

describe('concat / equal', () => {
  it('concatenates and compares', () => {
    const c = concatBytes(Uint8Array.of(1), new Uint8Array(), Uint8Array.of(2, 3));
    expect(c).toEqual(Uint8Array.of(1, 2, 3));
    expect(bytesEqual(c, Uint8Array.of(1, 2, 3))).toBe(true);
    expect(bytesEqual(c, Uint8Array.of(1, 2))).toBe(false);
    expect(bytesEqual(c, Uint8Array.of(1, 2, 4))).toBe(false);
  });
});

describe('compareUtf8', () => {
  // The auditor merge-joins R2 list() order with SQLite ORDER BY key; both are UTF-8 byte order
  // (DECISIONS D6.2). JavaScript's < compares UTF-16 code units, which disagrees for astral
  // characters against U+E000..U+FFFF, so this must not be a plain string comparison.
  const byBytes = (a: string, b: string): number => Buffer.compare(utf8Encode(a), utf8Encode(b));

  it('orders astral characters after U+E000..U+FFFF, unlike UTF-16 comparison', () => {
    const astral = '\u{1F600}';
    const privateUse = '\uE000';
    const utf16Less = (a: string, b: string): boolean => a < b;
    expect(utf16Less(astral, privateUse)).toBe(true); // UTF-16: D83D < E000
    expect(compareUtf8(astral, privateUse)).toBeGreaterThan(0); // UTF-8: F0 > EE
    expect(compareUtf8('\uFFFD', '\u{10000}')).toBeLessThan(0);
  });

  it('treats a prefix as smaller and equal strings as equal', () => {
    expect(compareUtf8('a', 'ab')).toBeLessThan(0);
    expect(compareUtf8('ab', 'a')).toBeGreaterThan(0);
    expect(compareUtf8('', '')).toBe(0);
    expect(compareUtf8('\u{1F600}x', '\u{1F600}x')).toBe(0);
  });

  it('agrees in sign with a byte comparison of the UTF-8 encodings', () => {
    const str = fc.string({ unit: 'grapheme' });
    fc.assert(
      fc.property(str, str, (a, b) => {
        expect(Math.sign(compareUtf8(a, b))).toBe(Math.sign(byBytes(a, b)));
      }),
      { numRuns: 2000 },
    );
    // Strings sharing a long prefix, differing inside or after a surrogate pair.
    const unit = fc.constantFrom('a', '\uE000', '\uFFFF', '\u{10000}', '\u{1F600}', '\u{10FFFF}');
    const s = fc.array(unit, { maxLength: 6 }).map((a) => a.join(''));
    fc.assert(
      fc.property(s, s, s, (p, a, b) => {
        expect(Math.sign(compareUtf8(p + a, p + b))).toBe(Math.sign(byBytes(p + a, p + b)));
      }),
      { numRuns: 2000 },
    );
  });
});

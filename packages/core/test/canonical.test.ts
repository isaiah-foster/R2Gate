import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
  canonicalJson,
  decodeCanonical,
  encodeCanonical,
  type JsonValue,
} from '../src/canonical.ts';

const enc = new TextEncoder();

/** JSON values within the canonical subset: safe integers only, well-formed strings. */
const canonicalValue: fc.Arbitrary<JsonValue> = fc.letrec((tie) => ({
  value: fc.oneof(
    { depthSize: 'small' },
    fc.constant(null),
    fc.boolean(),
    fc.maxSafeInteger().filter((n) => !Object.is(n, -0)),
    fc.string({ unit: 'grapheme' }),
    fc.array(tie('value')),
    fc.dictionary(fc.string({ unit: 'grapheme' }), tie('value')),
  ),
})).value as fc.Arbitrary<JsonValue>;

describe('canonical JSON', () => {
  it('sorts keys and omits whitespace', () => {
    expect(canonicalJson({ b: 1, a: [true, null, 'x'], c: { z: 0, y: -2 } })).toBe(
      '{"a":[true,null,"x"],"b":1,"c":{"y":-2,"z":0}}',
    );
  });

  it('sorts keys by UTF-16 code units (RFC 8785 order)', () => {
    expect(canonicalJson({ é: 1, z: 2, '😀': 3, '｡': 4 })).toBe('{"z":2,"é":1,"😀":3,"｡":4}');
  });

  it('writes non-ASCII as raw UTF-8 and escapes control characters', () => {
    expect(canonicalJson('é\n\u0001"\\')).toBe('"é\\n\\u0001\\"\\\\"');
  });

  it('round-trips arbitrary canonical values', () => {
    fc.assert(
      fc.property(canonicalValue, (v) => {
        const b = encodeCanonical(v);
        expect(decodeCanonical(b)).toEqual(v);
        expect(encodeCanonical(decodeCanonical(b))).toEqual(b);
      }),
    );
  });

  it.each([
    ['float', 1.5],
    ['NaN', NaN],
    ['Infinity', Infinity],
    ['unsafe integer', 2 ** 53],
    ['negative zero', -0],
    ['undefined', undefined],
    ['bigint', 1n],
    ['lone surrogate', '\ud800'],
    ['undefined property', { a: undefined }],
    ['nested float', { a: [1, 2.5] }],
    ['Date', new Date(0)],
    ['function', () => 1],
  ])('refuses to encode %s', (_name, v) => {
    expect(() => encodeCanonical(v as JsonValue)).toThrow();
  });

  it('refuses excessive nesting', () => {
    let v: JsonValue = 1;
    for (let i = 0; i < 100; i++) v = [v];
    expect(() => encodeCanonical(v)).toThrow();
  });

  it.each([
    ['whitespace', '{ "a":1}'],
    ['unsorted keys', '{"b":1,"a":2}'],
    ['duplicate keys', '{"a":1,"a":1}'],
    ['float', '{"a":1.0}'],
    ['exponent', '{"a":1e2}'],
    ['huge integer', '{"a":12345678901234567890}'],
    ['escaped ASCII', '{"a":"\\u0061"}'],
    ['escaped slash', '{"a":"\\/"}'],
    ['BOM', '﻿{"a":1}'],
    ['trailing newline', '{"a":1}\n'],
    ['negative zero', '-0'],
    ['not JSON', '{a:1}'],
  ])('rejects non-canonical input: %s', (_name, s) => {
    expect(() => decodeCanonical(enc.encode(s))).toThrow();
  });

  it('rejects invalid UTF-8', () => {
    expect(() => decodeCanonical(Uint8Array.of(0x22, 0xff, 0x22))).toThrow();
  });
});

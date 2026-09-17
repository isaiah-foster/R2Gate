// Canonical JSON for log entries: UTF-8, object keys sorted by UTF-16 code units (the RFC 8785
// order, which is JavaScript's default sort), no insignificant whitespace, strings escaped exactly
// as JSON.stringify does (RFC 8785 uses the same rules), and numbers restricted to safe integers so
// that every value has exactly one encoding. Decoding is strict: input is accepted only if
// re-encoding the parsed value reproduces it byte for byte.

import { utf8Decode, utf8Encode } from './bytes.ts';

export type JsonValue =
  null | boolean | number | string | readonly JsonValue[] | { readonly [key: string]: JsonValue };

export class CanonicalJsonError extends Error {
  override name = 'CanonicalJsonError';
}

/** Entries are shallow; a small cap keeps recursion bounded on hostile input. */
const MAX_DEPTH = 32;

function isPlainObject(v: object): v is Record<string, unknown> {
  const proto: unknown = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

function writeString(s: string): string {
  if (!s.isWellFormed()) throw new CanonicalJsonError('string contains a lone surrogate');
  return JSON.stringify(s);
}

function write(v: unknown, depth: number): string {
  if (depth > MAX_DEPTH) throw new CanonicalJsonError('nesting too deep');
  if (v === null) return 'null';
  switch (typeof v) {
    case 'boolean':
      return v ? 'true' : 'false';
    case 'number':
      if (!Number.isSafeInteger(v) || Object.is(v, -0)) {
        throw new CanonicalJsonError(`number ${String(v)} is not a safe integer`);
      }
      return String(v);
    case 'string':
      return writeString(v);
    case 'object': {
      if (Array.isArray(v)) {
        const items: string[] = [];
        for (let i = 0; i < v.length; i++) {
          if (!(i in v)) throw new CanonicalJsonError('sparse array');
          items.push(write(v[i], depth + 1));
        }
        return `[${items.join(',')}]`;
      }
      if (!isPlainObject(v)) throw new CanonicalJsonError('not a plain object');
      const members: string[] = [];
      for (const k of Object.keys(v).sort()) {
        const value = v[k];
        if (value === undefined) throw new CanonicalJsonError(`property ${k} is undefined`);
        members.push(`${writeString(k)}:${write(value, depth + 1)}`);
      }
      return `{${members.join(',')}}`;
    }
    default:
      throw new CanonicalJsonError(`cannot encode a ${typeof v}`);
  }
}

/** Canonical JSON text. Throws CanonicalJsonError for anything outside the canonical subset. */
export function canonicalJson(value: JsonValue): string {
  return write(value, 0);
}

export function encodeCanonical(value: JsonValue): Uint8Array {
  return utf8Encode(canonicalJson(value));
}

/** Parses canonical JSON bytes; throws CanonicalJsonError unless they are exactly canonical. */
export function decodeCanonical(bytes: Uint8Array): JsonValue {
  let text: string;
  let value: unknown;
  try {
    text = utf8Decode(bytes);
    value = JSON.parse(text);
  } catch (e) {
    throw new CanonicalJsonError(`not valid UTF-8 JSON: ${String(e)}`);
  }
  if (write(value, 0) !== text) throw new CanonicalJsonError('JSON is not in canonical form');
  return value as JsonValue;
}

// Byte helpers shared by the rest of the library. Strict by design: every decoder rejects input
// that a different encoder could have produced for the same bytes.

const encoder = new TextEncoder();
// fatal: reject invalid UTF-8 instead of substituting U+FFFD.
// ignoreBOM: keep a leading BOM as U+FEFF so that callers comparing bytes see it.
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/** UTF-8 encode. Throws on lone surrogates, which TextEncoder would silently replace. */
export function utf8Encode(s: string): Uint8Array {
  if (!s.isWellFormed()) throw new TypeError('string contains a lone surrogate');
  return encoder.encode(s);
}

/** Strict UTF-8 decode: throws on invalid sequences; a BOM is kept, not stripped. */
export function utf8Decode(b: Uint8Array): string {
  return decoder.decode(b);
}

export function toHex(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}

/** Decodes lowercase hex only. */
export function fromHex(s: string): Uint8Array {
  if (!/^(?:[0-9a-f]{2})*$/.test(s)) throw new TypeError('invalid lowercase hex');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return out;
}

/** Standard base64 (RFC 4648 §4) with padding. */
export function toBase64(b: Uint8Array): string {
  let bin = '';
  for (const x of b) bin += String.fromCharCode(x);
  return btoa(bin);
}

const BASE64_RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

/**
 * Decodes canonical standard base64 only (RFC 4648 §3.5), as signed-note and tlog-checkpoint
 * require: padding is mandatory, no whitespace, and unused trailing bits must be zero.
 */
export function fromBase64(s: string): Uint8Array {
  if (!BASE64_RE.test(s)) throw new TypeError('invalid base64');
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  // The regex fixes the alphabet and padding; re-encoding catches non-zero trailing bits.
  if (toBase64(out) !== s) throw new TypeError('non-canonical base64');
  return out;
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** Byte equality. Not constant-time; do not use for secrets. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

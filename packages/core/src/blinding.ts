// Key blinding (M8): instead of an object's key, a blinded log records
//
//   keyHmac = lowercase hex of HMAC-SHA256(secret, UTF-8 key)
//
// with a per-log secret (KEY_BLINDING_KEY, base64url, at least 32 bytes). A reader without the
// secret learns no key names. A reader with it can locate a key's entries by computing its HMAC,
// and can also test guesses, so the secret is shared like a read capability, never published.
//
// What blinding does not hide: the same key always has the same HMAC, so the number of writes per
// key, their sizes, ETags (an MD5 of the content for single-part uploads) and times stay visible.

import { sha256 } from './merkle.ts';
import { concatBytes, fromBase64, toHex, utf8Encode } from './bytes.ts';

export class BlindingError extends Error {
  override name = 'BlindingError';
}

export const MIN_BLINDING_KEY_BYTES = 32;

export interface KeyBlinder {
  /** keyHmac for an object key. */
  blind(key: string): Promise<string>;
  /**
   * 16 hex digits identifying the secret (not derived from any HMAC the log publishes), so a
   * writer can notice that its secret changed under an existing log.
   */
  readonly fingerprint: string;
}

/** Decodes KEY_BLINDING_KEY: unpadded base64url (RFC 4648 §5), at least 32 bytes. */
export function parseBlindingKey(s: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(s)) throw new BlindingError('blinding key must be base64url');
  let out: Uint8Array;
  try {
    out = fromBase64(
      s
        .replace(/-/g, '+')
        .replace(/_/g, '/')
        .padEnd(Math.ceil(s.length / 4) * 4, '='),
    );
  } catch {
    throw new BlindingError('blinding key is not canonical base64url');
  }
  if (out.length < MIN_BLINDING_KEY_BYTES) {
    throw new BlindingError(
      `blinding key must be at least ${String(MIN_BLINDING_KEY_BYTES)} bytes`,
    );
  }
  return out;
}

export async function newKeyBlinder(secret: string): Promise<KeyBlinder> {
  const raw = parseBlindingKey(secret);
  const key = await crypto.subtle.importKey(
    'raw',
    new Uint8Array(raw),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const fingerprint = toHex(
    (await sha256(concatBytes(utf8Encode('r2notary/key-blinding/v1\0'), raw))).slice(0, 8),
  );
  return {
    fingerprint,
    blind: async (k) => {
      if (k === '' || !k.isWellFormed()) throw new BlindingError('not a valid object key');
      return toHex(
        new Uint8Array(await crypto.subtle.sign('HMAC', key, new Uint8Array(utf8Encode(k)))),
      );
    },
  };
}

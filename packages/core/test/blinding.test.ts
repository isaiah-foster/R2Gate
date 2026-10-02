// Key blinding (M8, PLAN §9 item 3): a public log names objects by HMAC-SHA256 of their key under
// a per-log secret, so a reader without the secret learns no key names.
import { createHmac } from 'node:crypto';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { BlindingError, newKeyBlinder, parseBlindingKey } from '../src/blinding.ts';

const SECRET = Buffer.alloc(32, 7).toString('base64url');

describe('newKeyBlinder', () => {
  it('matches RFC 4231 test case 6 (a key longer than the block size)', async () => {
    // RFC 4231 §4.7: key = 131 bytes of 0xaa, data = the ASCII string below.
    const b = await newKeyBlinder(Buffer.alloc(131, 0xaa).toString('base64url'));
    expect(await b.blind('Test Using Larger Than Block-Size Key - Hash Key First')).toBe(
      '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54',
    );
  });

  it('is HMAC-SHA256 of the UTF-8 key, as lowercase hex (checked against node:crypto)', async () => {
    const b = await newKeyBlinder(SECRET);
    await fc.assert(
      fc.asyncProperty(
        fc.string({ unit: 'grapheme', minLength: 1, maxLength: 40 }),
        async (key) => {
          const want = createHmac('sha256', Buffer.alloc(32, 7)).update(key, 'utf8').digest('hex');
          expect(await b.blind(key)).toBe(want);
        },
      ),
      { numRuns: 200 },
    );
  });

  it('gives different names under different secrets, and a stable fingerprint', async () => {
    const a = await newKeyBlinder(SECRET);
    const b = await newKeyBlinder(Buffer.alloc(32, 8).toString('base64url'));
    expect(await a.blind('photos/cat.jpg')).not.toBe(await b.blind('photos/cat.jpg'));
    expect(a.fingerprint).toMatch(/^[0-9a-f]{16}$/);
    expect(a.fingerprint).toBe((await newKeyBlinder(SECRET)).fingerprint);
    expect(a.fingerprint).not.toBe(b.fingerprint);
  });

  it('rejects short, malformed or padded secrets, and non-keys', async () => {
    for (const s of [
      '',
      'short',
      Buffer.alloc(31).toString('base64url'),
      `${SECRET}=`,
      `${SECRET}!`,
    ]) {
      expect(() => parseBlindingKey(s), JSON.stringify(s)).toThrow(BlindingError);
    }
    const b = await newKeyBlinder(SECRET);
    await expect(b.blind('')).rejects.toThrow(BlindingError);
    await expect(b.blind('\ud800')).rejects.toThrow(BlindingError);
  });
});

// Bearer-token parsing, the constant-time comparison, and access configuration (PLAN §5.5).
import { env } from 'cloudflare:workers';
import { describe, expect, it } from 'vitest';
import { bearerToken, parseAccess, tokensEqual } from '../src/auth.ts';
import { ConfigError } from '../src/config.ts';

const withAuth = (value: string): Request =>
  new Request('https://r2notary.example.com/', { headers: { authorization: value } });

describe('bearerToken', () => {
  it('extracts the token from an RFC 6750 Authorization header', () => {
    expect(bearerToken(withAuth('Bearer abc.DEF-123_~+/=='))).toBe('abc.DEF-123_~+/==');
    // The auth scheme is case-insensitive (RFC 9110 §11.1).
    expect(bearerToken(withAuth('bearer abc'))).toBe('abc');
    expect(bearerToken(withAuth('BEARER abc'))).toBe('abc');
  });

  it('returns null for anything that is not one well-formed bearer token', () => {
    expect(bearerToken(new Request('https://r2notary.example.com/'))).toBeNull();
    for (const bad of [
      '',
      'Bearer',
      'Bearer ',
      'Basic dXNlcjpwYXNz',
      'Bearer a b',
      'Bearer a,b',
      'Bearer "abc"',
      'Bearer =abc',
      'Bearerabc',
      'Token abc',
    ]) {
      expect(bearerToken(withAuth(bad)), bad).toBeNull();
    }
  });
});

describe('tokensEqual', () => {
  const secret = 'Zm9vYmFyYmF6cXV4LXRoaXMtaXMtYS10ZXN0LXRva2Vu';

  it('accepts only the exact token', async () => {
    expect(await tokensEqual(secret, secret)).toBe(true);
    expect(await tokensEqual(secret.slice(0, -1), secret)).toBe(false); // prefix
    expect(await tokensEqual(`${secret}x`, secret)).toBe(false); // extension
    expect(await tokensEqual(secret.toUpperCase(), secret)).toBe(false);
    expect(await tokensEqual('', secret)).toBe(false);
    expect(await tokensEqual('x'.repeat(10_000), secret)).toBe(false); // any length is safe
  });

  it('differs in the last character as well as the first', async () => {
    const last = secret.slice(0, -1) + (secret.endsWith('u') ? 'v' : 'u');
    const first = (secret.startsWith('Z') ? 'Y' : 'Z') + secret.slice(1);
    expect(await tokensEqual(last, secret)).toBe(false);
    expect(await tokensEqual(first, secret)).toBe(false);
  });
});

describe('parseAccess', () => {
  const base = {
    PUBLIC_LOG: 'false',
    ADMIN_TOKEN: env.ADMIN_TOKEN,
    READ_TOKEN: env.READ_TOKEN,
  };

  it('parses the test configuration (private log, both tokens)', () => {
    expect(parseAccess(base)).toEqual({
      publicLog: false,
      adminToken: env.ADMIN_TOKEN,
      readToken: env.READ_TOKEN,
    });
  });

  it('does not need READ_TOKEN for a public log, and ignores it', () => {
    expect(parseAccess({ ...base, PUBLIC_LOG: 'true', READ_TOKEN: undefined })).toEqual({
      publicLog: true,
      adminToken: env.ADMIN_TOKEN,
      readToken: null,
    });
    expect(parseAccess({ ...base, PUBLIC_LOG: 'true' }).readToken).toBeNull();
  });

  it.each([
    ['PUBLIC_LOG that is not true/false', { PUBLIC_LOG: 'yes' }],
    ['PUBLIC_LOG with different case', { PUBLIC_LOG: 'False' }],
    ['a missing ADMIN_TOKEN', { ADMIN_TOKEN: undefined }],
    ['a short ADMIN_TOKEN', { ADMIN_TOKEN: 'a'.repeat(31) }],
    ['an ADMIN_TOKEN with a space', { ADMIN_TOKEN: `${'a'.repeat(32)} b` }],
    ['a private log without READ_TOKEN', { READ_TOKEN: undefined }],
    ['a short READ_TOKEN', { READ_TOKEN: 'short' }],
    ['READ_TOKEN equal to ADMIN_TOKEN', { READ_TOKEN: env.ADMIN_TOKEN }],
  ])('rejects %s', (_, override) => {
    expect(() => parseAccess({ ...base, ...override })).toThrow(ConfigError);
  });
});

// Access control for the HTTP routes (PLAN §5.5). Two bearer tokens: ADMIN_TOKEN for the admin
// API, READ_TOKEN for everything else when PUBLIC_LOG is "false". The admin token also reads.
// Parsed separately from `Config` so a missing token breaks only the fetch handler, never ingest or
// publication.

import { utf8Encode } from '@r2notary/core';
import { ConfigError } from './config.ts';

export interface Access {
  readonly publicLog: boolean;
  readonly adminToken: string;
  /** Null for a public log. */
  readonly readToken: string | null;
}

export interface AccessVars {
  readonly PUBLIC_LOG: string;
  readonly ADMIN_TOKEN?: unknown;
  readonly READ_TOKEN?: unknown;
}

// RFC 6750 b64token. At least 32 characters: `npm run keygen` makes 43 (32 random bytes, base64url).
const TOKEN_RE = /^[A-Za-z0-9\-._~+/]+=*$/;
const MIN_TOKEN_LENGTH = 32;

function token(name: string, v: unknown): string {
  if (typeof v !== 'string' || v.length < MIN_TOKEN_LENGTH || !TOKEN_RE.test(v)) {
    throw new ConfigError(
      `${name} must be at least ${String(MIN_TOKEN_LENGTH)} characters of [A-Za-z0-9-._~+/]`,
    );
  }
  return v;
}

export function parseAccess(vars: AccessVars): Access {
  if (vars.PUBLIC_LOG !== 'true' && vars.PUBLIC_LOG !== 'false') {
    throw new ConfigError('PUBLIC_LOG must be "true" or "false"');
  }
  const publicLog = vars.PUBLIC_LOG === 'true';
  const adminToken = token('ADMIN_TOKEN', vars.ADMIN_TOKEN);
  if (publicLog) return { publicLog, adminToken, readToken: null };
  const readToken = token('READ_TOKEN', vars.READ_TOKEN);
  // Distinct tokens, so handing out read access never hands out admin access.
  if (readToken === adminToken) throw new ConfigError('READ_TOKEN must differ from ADMIN_TOKEN');
  return { publicLog, adminToken, readToken };
}

const BEARER_RE = /^Bearer +([A-Za-z0-9\-._~+/]+=*)$/i;

/** The token from `Authorization: Bearer <token>`, or null if absent or malformed. */
export function bearerToken(request: Request): string | null {
  const header = request.headers.get('authorization');
  return header === null ? null : (BEARER_RE.exec(header)?.[1] ?? null);
}

async function digest(s: string): Promise<ArrayBuffer> {
  return crypto.subtle.digest('SHA-256', utf8Encode(s));
}

/**
 * Compares a presented token with the expected one in time that does not depend on their
 * contents. Both are hashed first, so the comparison is always of two 32-byte digests (Workers'
 * `timingSafeEqual` compares equal-length buffers), and neither the length of the expected token
 * nor the position of the first difference shows in the timing. Hashing the presented token takes
 * time linear in its own length, which the caller already knows.
 */
export async function tokensEqual(presented: string, expected: string): Promise<boolean> {
  const [a, b] = await Promise.all([digest(presented), digest(expected)]);
  return crypto.subtle.timingSafeEqual(a, b);
}

/** True if the request carries one of `accepted`. Every candidate is compared; no early exit. */
export async function hasToken(request: Request, accepted: readonly string[]): Promise<boolean> {
  const presented = bearerToken(request);
  if (presented === null) return false;
  const results = await Promise.all(accepted.map((t) => tokensEqual(presented, t)));
  return results.includes(true);
}

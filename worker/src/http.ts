// Response helpers. Every response states its caching explicitly: if Workers Cache is enabled
// (DECISIONS D4.3), a response without `no-store` could be served to later requests without running
// this Worker, so errors and API answers must never be cacheable.

export const NO_STORE = 'no-store';
/** Log routes are readable cross-origin, so a browser can verify the log itself (PLAN §5.5). */
export const CORS_HEADERS: Readonly<Record<string, string>> = {
  'access-control-allow-origin': '*',
};

export function text(
  status: number,
  body: string,
  headers: Readonly<Record<string, string>> = {},
): Response {
  return new Response(`${body}\n`, {
    status,
    headers: {
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': NO_STORE,
      'x-content-type-options': 'nosniff',
      ...headers,
    },
  });
}

export function json(status: number, body: unknown, head = false): Response {
  return new Response(head ? null : `${JSON.stringify(body, null, 2)}\n`, {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': NO_STORE,
      'x-content-type-options': 'nosniff',
    },
  });
}

export const notFound = (headers: Readonly<Record<string, string>> = {}): Response =>
  text(404, 'not found', headers);

export const methodNotAllowed = (
  allow: string,
  headers: Readonly<Record<string, string>> = {},
): Response => text(405, 'method not allowed', { allow, ...headers });

/** The same 401 for a missing, malformed or wrong token: nothing to tell them apart. */
export const unauthorized = (headers: Readonly<Record<string, string>> = {}): Response =>
  text(401, 'unauthorized', { 'www-authenticate': 'Bearer realm="r2notary"', ...headers });

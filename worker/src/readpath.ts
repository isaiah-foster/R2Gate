// The log read path (PLAN §5.5): GET/HEAD /log/<name>/<path> serves `<name>/<path>` from the log
// bucket. Paths are parsed strictly (core `parseLogPath`), so each resource has exactly one URL and
// nothing outside the log's resources (reports, other prefixes) is reachable through this route.
//
// Headers follow C2SP tlog-tiles: the checkpoint is `text/plain; charset=utf-8` and cacheable for
// a few seconds; tiles and entry bundles are `application/octet-stream` and long-lived. Every
// resource except the live checkpoint is immutable (DECISIONS D2.3), including partial tiles,
// which are kept after their full tile appears. Headers come from the resource kind, not from the
// object's stored metadata, so what is served does not depend on how an object was written.

import type { LogPath } from '@r2notary/core';
import { CORS_HEADERS, methodNotAllowed, notFound } from './http.ts';

export interface LogReader {
  get(key: string): Promise<R2ObjectBody | null>;
  head(key: string): Promise<R2Object | null>;
}

const ALLOW = 'GET, HEAD, OPTIONS';
const IMMUTABLE = 'max-age=31536000, immutable';

/** True if Accept-Encoding allows gzip (an explicit `gzip`, else `*`; q=0 refuses). */
export function acceptsGzip(header: string | null): boolean {
  if (header === null) return false;
  let gzip: number | null = null;
  let star: number | null = null;
  for (const part of header.split(',')) {
    const [coding = '', ...params] = part.split(';').map((s) => s.trim().toLowerCase());
    const q = params.find((p) => p.startsWith('q='));
    const weight = q === undefined ? 1 : Number(q.slice(2));
    if (coding === 'gzip') gzip = weight;
    else if (coding === '*') star = weight;
  }
  const w = gzip ?? star ?? 0;
  return Number.isFinite(w) && w > 0;
}

/**
 * The client's own Accept-Encoding. Cloudflare rewrites the header a Worker sees to a canonical
 * value (e.g. `gzip, br`) and keeps the original in `request.cf.clientAcceptEncoding` (Workers
 * Request docs), so negotiating on the header alone would gzip for every client.
 */
function clientAcceptEncoding(request: Request): string | null {
  const cf = request.cf as { clientAcceptEncoding?: unknown } | undefined;
  return typeof cf?.clientAcceptEncoding === 'string'
    ? cf.clientAcceptEncoding
    : request.headers.get('accept-encoding');
}

function headersFor(resource: LogPath, publicLog: boolean): Headers {
  // A private log's responses carry `private`, so no shared cache keeps them.
  const scope = publicLog ? 'public' : 'private';
  const h = new Headers({ ...CORS_HEADERS, 'x-content-type-options': 'nosniff' });
  switch (resource.kind) {
    case 'checkpoint':
      h.set('content-type', 'text/plain; charset=utf-8');
      h.set('cache-control', `${scope}, max-age=2`);
      break;
    case 'archived-checkpoint':
      h.set('content-type', 'text/plain; charset=utf-8');
      h.set('cache-control', `${scope}, ${IMMUTABLE}`);
      break;
    case 'tile':
    case 'bundle':
      h.set('content-type', 'application/octet-stream');
      h.set('cache-control', `${scope}, ${IMMUTABLE}`);
      break;
  }
  return h;
}

/** CORS preflight for log routes. Browsers send no credentials on a preflight, so none are asked. */
export function preflight(): Response {
  return new Response(null, {
    status: 204,
    headers: {
      ...CORS_HEADERS,
      'access-control-allow-methods': ALLOW,
      'access-control-allow-headers': 'Authorization',
      'access-control-max-age': '86400',
    },
  });
}

/** Rejects methods other than GET, HEAD and OPTIONS on a log route; null if the method is fine. */
export function checkMethod(request: Request): Response | null {
  return ['GET', 'HEAD', 'OPTIONS'].includes(request.method)
    ? null
    : methodNotAllowed(ALLOW, CORS_HEADERS);
}

/**
 * Serves one log resource for an authorized GET or HEAD. Entry bundles are gzip-encoded when the
 * client accepts it (tlog-tiles: bundles SHOULD be compressed at the HTTP layer); the runtime
 * compresses on the way out because the encoding is declared in the headers. Tiles are SHA-256
 * output and are never encoded.
 */
export async function serveResource(
  request: Request,
  resource: LogPath,
  key: string,
  deps: { readonly bucket: LogReader; readonly publicLog: boolean },
): Promise<Response> {
  const headers = headersFor(resource, deps.publicLog);
  const gzip = resource.kind === 'bundle' && acceptsGzip(clientAcceptEncoding(request));
  if (resource.kind === 'bundle') headers.set('vary', 'Accept-Encoding');
  if (gzip) headers.set('content-encoding', 'gzip');

  if (request.method === 'HEAD') {
    const obj = await deps.bucket.head(key);
    if (obj === null) return notFound(CORS_HEADERS);
    // The encoded length is not known without compressing, so it is only stated when unencoded.
    if (!gzip) headers.set('content-length', String(obj.size));
    return new Response(null, { status: 200, headers });
  }
  const obj = await deps.bucket.get(key);
  if (obj === null) return notFound(CORS_HEADERS);
  return new Response(obj.body, { status: 200, headers });
}

// The JSON API (PLAN §5.5): /api/v1/status, /api/v1/lookup, /api/v1/findings, and the admin
// routes. Nothing here is evidence: lookup is an unverified index into the log, and clients prove
// what it returns with inclusion proofs against a signed checkpoint.

import {
  MAX_OBJECT_KEY_BYTES,
  TILE_WIDTH,
  decodeBundle,
  entryBundlePath,
  utf8Decode,
  utf8Encode,
} from '@r2notary/core';
import type { Config } from './config.ts';
import { json, methodNotAllowed, notFound } from './http.ts';
import type { Sequencer } from './sequencer.ts';

export interface ApiDeps {
  readonly config: Config;
  readonly sequencer: DurableObjectStub<Sequencer>;
  readonly bucket: { get(key: string): Promise<R2ObjectBody | null> };
  /** Bundle reads per lookup page (default LOOKUP_MAX_BUNDLES); smaller in tests. */
  readonly maxBundles?: number;
}

export const LOOKUP_MAX_LIMIT = 100;
/**
 * Bundle reads per lookup request. R2 calls count as subrequests and the Free plan allows 50 per
 * invocation (Workers limits docs), so a page stops early, with a cursor, rather than fail.
 */
export const LOOKUP_MAX_BUNDLES = 32;

const iso = (ms: number | null): string | null => (ms === null ? null : new Date(ms).toISOString());

const badRequest = (error: string): Response => json(400, { error });

/** GET /api/v1/status: operational counters. The last audit summary joins in M6. */
export async function status(deps: ApiDeps, head: boolean): Promise<Response> {
  const s = await deps.sequencer.status();
  return json(
    200,
    {
      log: deps.config.logName,
      origin: deps.config.logOrigin,
      size: s.publishedSize,
      durableSize: s.durableSize,
      pending: s.pending,
      lastCheckpointAt: iso(s.lastPublishAt),
      nextPublishAt: iso(s.alarmAt),
      lastError: s.lastError,
      ingest: {
        ...s.ingest,
        lastInvalid:
          s.ingest.lastInvalid === null
            ? null
            : { at: iso(s.ingest.lastInvalid.at), reason: s.ingest.lastInvalid.reason },
      },
    },
    head,
  );
}

function decimal(v: string | null, min: number, max: number): number | null | undefined {
  if (v === null) return null;
  if (!/^(?:0|[1-9]\d*)$/.test(v)) return undefined;
  const n = Number(v);
  return Number.isSafeInteger(n) && n >= min && n <= max ? n : undefined;
}

/**
 * GET /api/v1/lookup?key=K[&after=I][&limit=N]: published entries naming K, oldest first, as
 * `{index, entry}`. `entry` is the parsed canonical JSON; since the encoding is canonical
 * (DECISIONS D1.5) it re-encodes to the exact leaf bytes. `next` is the cursor for `after`, or
 * null when there is nothing more. `size` is the tree size the indexes were read at.
 */
export async function lookup(url: URL, deps: ApiDeps, head: boolean): Promise<Response> {
  const keys = url.searchParams.getAll('key');
  if (keys.length !== 1) return badRequest('exactly one key parameter is required');
  const key = keys[0] ?? '';
  if (key === '' || !key.isWellFormed() || utf8Encode(key).length > MAX_OBJECT_KEY_BYTES) {
    return badRequest(`key must be 1-${String(MAX_OBJECT_KEY_BYTES)} bytes of UTF-8`);
  }
  const limit = decimal(url.searchParams.get('limit'), 1, LOOKUP_MAX_LIMIT);
  if (limit === undefined) return badRequest(`limit must be 1-${String(LOOKUP_MAX_LIMIT)}`);
  const after = decimal(url.searchParams.get('after'), 0, Number.MAX_SAFE_INTEGER);
  if (after === undefined) return badRequest('after must be a non-negative integer');

  const pageSize = limit ?? LOOKUP_MAX_LIMIT;
  const found = await deps.sequencer.lookup(key, {
    ...(after === null ? {} : { after }),
    limit: pageSize + 1,
  });
  let more = found.indexes.length > pageSize;
  let indexes = found.indexes.slice(0, pageSize);

  // Keep only as many indexes as maxBundles bundles cover (always at least one bundle).
  const maxBundles = deps.maxBundles ?? LOOKUP_MAX_BUNDLES;
  const bundles = [...new Set(indexes.map((i) => Math.floor(i / TILE_WIDTH)))];
  if (bundles.length > maxBundles) {
    const lastBundle = bundles[maxBundles - 1] ?? 0;
    indexes = indexes.filter((i) => Math.floor(i / TILE_WIDTH) <= lastBundle);
    more = true;
  }

  const entries: { index: number; entry: unknown }[] = [];
  // One bundle at a time: a bundle can be about 16 MB, and isolates have 128 MB.
  for (const n of bundles.slice(0, maxBundles)) {
    const width = Math.min(TILE_WIDTH, found.size - n * TILE_WIDTH);
    const obj = await deps.bucket.get(`${deps.config.logName}/${entryBundlePath(n, width)}`);
    if (obj === null)
      throw new Error(`entry bundle ${String(n)} at size ${String(found.size)} is missing`);
    const bundle = decodeBundle(new Uint8Array(await obj.arrayBuffer()));
    for (const index of indexes.filter((i) => Math.floor(i / TILE_WIDTH) === n)) {
      const bytes = bundle[index - n * TILE_WIDTH];
      if (bytes === undefined) throw new Error(`entry ${String(index)} is not in its bundle`);
      entries.push({ index, entry: JSON.parse(utf8Decode(bytes)) as unknown });
    }
  }
  const last = indexes.at(-1);
  return json(
    200,
    { key, size: found.size, entries, next: more && last !== undefined ? last : null },
    head,
  );
}

/** GET /api/v1/findings. The auditor (M6) is what produces findings; until then there are none. */
export function findings(head: boolean): Response {
  return json(200, { latestScan: null, findings: [] }, head);
}

/** /api/v1/admin/<op>, after the admin token has been checked. */
export async function admin(op: string, request: Request, deps: ApiDeps): Promise<Response> {
  if (!['publish', 'backfill', 'scan'].includes(op)) return notFound();
  if (request.method !== 'POST') return methodNotAllowed('POST');
  if (op !== 'publish') return json(501, { error: `${op} is not implemented yet (M6)` });
  const result = await deps.sequencer.publish();
  return json(200, result);
}

/** Routes /api/v1/<route> for reads (status, lookup, findings), after access has been checked. */
export async function readApi(
  route: string,
  request: Request,
  url: URL,
  deps: ApiDeps,
): Promise<Response> {
  const head = request.method === 'HEAD';
  switch (route) {
    case 'status':
      return status(deps, head);
    case 'lookup':
      return lookup(url, deps, head);
    case 'findings':
      return findings(head);
    default:
      return notFound();
  }
}

export const READ_ROUTES: readonly string[] = ['status', 'lookup', 'findings'];

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
import { newScanId, startScan, type ScanParams } from './audit/scan.ts';
import type { ScanMode, ScanSummary } from './audit/store.ts';
import type { Config } from './config.ts';
import { json, methodNotAllowed, notFound } from './http.ts';
import type { Sequencer } from './sequencer.ts';

export interface ApiDeps {
  readonly config: Config;
  readonly sequencer: DurableObjectStub<Sequencer>;
  readonly workflow: Pick<Workflow<ScanParams>, 'createBatch'>;
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

/** A scan as the API shows it: times as RFC 3339, and without the cursor (a key name). */
export function scanView(s: ScanSummary | null): Record<string, unknown> | null {
  if (s === null) return null;
  return {
    scanId: s.scanId,
    mode: s.mode,
    state: s.state,
    graceSeconds: s.graceSeconds,
    startedAt: iso(s.startedAt),
    updatedAt: iso(s.updatedAt),
    finishedAt: iso(s.finishedAt),
    logSizeAtStart: s.logSizeAtStart,
    pages: s.pages,
    objectsScanned: s.objectsScanned,
    pending: s.pending,
    findings: s.findings,
    dropped: s.dropped,
    observations: s.observations,
    snapshots: s.snapshots,
    startIndex: s.startIndex,
    endIndex: s.endIndex,
  };
}

/** GET /api/v1/status: operational counters, the latest audit and the latest backfill. */
export async function status(deps: ApiDeps, head: boolean): Promise<Response> {
  const s = await deps.sequencer.status();
  return json(
    200,
    {
      log: deps.config.logName,
      origin: deps.config.logOrigin,
      keyBlinding: deps.config.keyBlinding,
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
      audit: scanView(s.audit),
      backfill: scanView(s.backfill),
      witnesses: {
        quorum: s.witnesses.quorum,
        witnesses: s.witnesses.witnesses.map((w) => ({
          vkey: w.vkey,
          url: w.url,
          size: w.size,
          cosignedAt: iso(w.cosignedAt),
          failedAt: iso(w.failedAt),
          lastError: w.lastError,
        })),
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
 * `{index, entry}`. On a blinded log (M8) the parameter is `keyHmac` (64 lowercase hex), which a
 * client holding the blinding key computes itself; `key` is refused, because answering it would
 * let anyone who can call this route test guesses of key names. `entry` is the parsed canonical JSON; since the encoding is canonical
 * (DECISIONS D1.5) it re-encodes to the exact leaf bytes. `next` is the cursor for `after`, or
 * null when there is nothing more. `size` is the tree size the indexes were read at.
 */
export async function lookup(url: URL, deps: ApiDeps, head: boolean): Promise<Response> {
  const param = deps.config.keyBlinding ? 'keyHmac' : 'key';
  const other = deps.config.keyBlinding ? 'key' : 'keyHmac';
  if (url.searchParams.has(other)) {
    return badRequest(
      deps.config.keyBlinding
        ? 'this log blinds key names: look up keyHmac (HMAC-SHA256 of the key), not key'
        : 'this log does not blind key names: look up key, not keyHmac',
    );
  }
  const keys = url.searchParams.getAll(param);
  if (keys.length !== 1) return badRequest(`exactly one ${param} parameter is required`);
  const key = keys[0] ?? '';
  if (deps.config.keyBlinding) {
    if (!/^[0-9a-f]{64}$/.test(key)) return badRequest('keyHmac must be 64 lowercase hex digits');
  } else if (key === '' || !key.isWellFormed() || utf8Encode(key).length > MAX_OBJECT_KEY_BYTES) {
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
    { [param]: key, size: found.size, entries, next: more && last !== undefined ? last : null },
    head,
  );
}

export const FINDINGS_MAX_LIMIT = 1000;

/**
 * GET /api/v1/findings[?after=I][&limit=N]: findings of the most recent audit, oldest first, as
 * `{index, published, entry}`. Like lookup, this is an unverified index: `r2notary findings`
 * proves each one, and the scan's signed `audit.scan` end entry commits to how many there are.
 * `published` is false for a finding not yet covered by the live checkpoint.
 */
export async function findings(url: URL, deps: ApiDeps, head: boolean): Promise<Response> {
  const limit = decimal(url.searchParams.get('limit'), 1, FINDINGS_MAX_LIMIT);
  if (limit === undefined) return badRequest(`limit must be 1-${String(FINDINGS_MAX_LIMIT)}`);
  const after = decimal(url.searchParams.get('after'), 0, Number.MAX_SAFE_INTEGER);
  if (after === undefined) return badRequest('after must be a non-negative integer');
  const pageSize = limit ?? FINDINGS_MAX_LIMIT;
  const page = await deps.sequencer.scanFindings({
    ...(after === null ? {} : { after }),
    limit: Math.min(pageSize + 1, FINDINGS_MAX_LIMIT),
  });
  const items = page.findings.slice(0, pageSize);
  const more = page.findings.length > pageSize;
  return json(
    200,
    {
      scan: scanView(page.scan),
      size: page.size,
      findings: items.map((f) => ({
        index: f.index,
        published: f.index < page.size,
        entry: JSON.parse(utf8Decode(f.entry)) as unknown,
      })),
      next: more ? (items.at(-1)?.index ?? null) : null,
    },
    head,
  );
}

/** POST /api/v1/admin/{scan,backfill}: start a scan Workflow, or 409 if one is running. */
async function start(mode: ScanMode, deps: ApiDeps): Promise<Response> {
  const r = await startScan(
    { sequencer: deps.sequencer, workflow: deps.workflow },
    mode,
    newScanId(mode, Date.now()),
  );
  if (!r.started) {
    return json(409, { error: 'a scan is already in progress', active: scanView(r.active) });
  }
  return json(202, { scanId: r.scanId, mode });
}

/** /api/v1/admin/<op>, after the admin token has been checked. */
export async function admin(op: string, request: Request, deps: ApiDeps): Promise<Response> {
  if (!['publish', 'backfill', 'scan'].includes(op)) return notFound();
  if (request.method !== 'POST') return methodNotAllowed('POST');
  if (op === 'scan') return start('audit', deps);
  if (op === 'backfill') return start('backfill', deps);
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
      return findings(url, deps, head);
    default:
      return notFound();
  }
}

export const READ_ROUTES: readonly string[] = ['status', 'lookup', 'findings'];

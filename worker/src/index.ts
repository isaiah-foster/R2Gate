import { parseLogPath, type KeyBlinder } from '@r2notary/core';
import { READ_ROUTES, admin, readApi, type ApiDeps } from './api.ts';
import { startScan } from './audit/scan.ts';
import { hasToken, parseAccess, type Access } from './auth.ts';
import { loadBlinder } from './blinding.ts';
import { parseConfig, type Config } from './config.ts';
import { CORS_HEADERS, methodNotAllowed, notFound, text, unauthorized } from './http.ts';
import { consumeBatch } from './ingest.ts';
import { checkMethod, preflight, serveResource } from './readpath.ts';
import type { Sequencer } from './sequencer.ts';

export { Sequencer } from './sequencer.ts';
export { ScanWorkflow } from './audit/scan-workflow.ts';

// Vars are fixed for the life of an isolate, so they are parsed once per env object; a bad
// deployment fails on its first request or batch instead of misbehaving.
const configs = new WeakMap<Env, Config>();
function getConfig(env: Env): Config {
  let c = configs.get(env);
  if (c === undefined) {
    c = parseConfig(env);
    configs.set(env, c);
  }
  return c;
}

// Access (tokens, PUBLIC_LOG) is parsed separately: only the fetch handler needs it.
const accesses = new WeakMap<Env, Access>();
function getAccess(env: Env): Access {
  let a = accesses.get(env);
  if (a === undefined) {
    a = parseAccess(env);
    accesses.set(env, a);
  }
  return a;
}

// The key blinder (M8) is loaded once per env too; asynchronous, so the promise is kept.
const blinders = new WeakMap<Env, Promise<KeyBlinder | null>>();
function getBlinder(env: Env, cfg: Config): Promise<KeyBlinder | null> {
  let b = blinders.get(env);
  if (b === undefined) {
    b = loadBlinder(cfg, (env as { readonly KEY_BLINDING_KEY?: unknown }).KEY_BLINDING_KEY);
    b.catch(() => blinders.delete(env));
    blinders.set(env, b);
  }
  return b;
}

function sequencer(env: Env, cfg: Config): DurableObjectStub<Sequencer> {
  return env.SEQUENCER.getByName(cfg.logName);
}

/** Read access: anyone on a public log; the read or admin token on a private one. */
function canRead(request: Request, access: Access): Promise<boolean> {
  if (access.readToken === null) return Promise.resolve(true);
  return hasToken(request, [access.readToken, access.adminToken]);
}

function withCors(res: Response): Response {
  const headers = new Headers(res.headers);
  for (const [k, v] of Object.entries(CORS_HEADERS)) headers.set(k, v);
  return new Response(res.body, { status: res.status, headers });
}

const LOG_PREFIX = '/log/';
const API_PREFIX = '/api/v1/';
const ADMIN_PREFIX = '/api/v1/admin/';

/**
 * Routes (PLAN §5.5). Order of checks on each route: the path must be a real route (404), the
 * method allowed (405), then the token (401), then the resource looked up (404). Admin routes
 * check the token first, so nothing about them is visible without it.
 */
async function route(request: Request, env: Env): Promise<Response> {
  const cfg = getConfig(env);
  const access = getAccess(env);
  const url = new URL(request.url);
  const path = url.pathname;
  const deps: ApiDeps = {
    config: cfg,
    sequencer: sequencer(env, cfg),
    bucket: env.LOG,
    workflow: env.SCAN_WORKFLOW,
  };

  if (path.startsWith(ADMIN_PREFIX)) {
    if (!(await hasToken(request, [access.adminToken]))) return unauthorized();
    return admin(path.slice(ADMIN_PREFIX.length), request, deps);
  }

  if (path.startsWith(API_PREFIX)) {
    // The read API is readable cross-origin, like the log routes, so a browser verifier loaded
    // from somewhere other than this Worker can use it (M8). Bearer tokens, no cookies: a page on
    // another origin learns only what the token it was given can read anyway.
    const name = path.slice(API_PREFIX.length);
    if (!READ_ROUTES.includes(name)) return notFound();
    if (request.method === 'OPTIONS') return preflight();
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      return methodNotAllowed('GET, HEAD, OPTIONS', CORS_HEADERS);
    }
    if (!(await canRead(request, access))) return unauthorized(CORS_HEADERS);
    return withCors(await readApi(name, request, url, deps));
  }

  const logPrefix = `${LOG_PREFIX}${cfg.logName}/`;
  if (path.startsWith(logPrefix)) {
    const relative = path.slice(logPrefix.length);
    const resource = parseLogPath(relative);
    if (resource === null) return notFound(CORS_HEADERS);
    const refused = checkMethod(request);
    if (refused !== null) return refused;
    if (request.method === 'OPTIONS') return preflight();
    if (!(await canRead(request, access))) return unauthorized(CORS_HEADERS);
    return serveResource(request, resource, `${cfg.logName}/${relative}`, {
      bucket: env.LOG,
      publicLog: access.publicLog,
    });
  }
  return notFound(path.startsWith(LOG_PREFIX) ? CORS_HEADERS : {});
}

export default {
  async fetch(request, env): Promise<Response> {
    try {
      return await route(request, env);
    } catch (e) {
      // Details go to the logs, not to the client (a config error names secrets' variables).
      console.error(
        `r2notary fetch failed: ${e instanceof Error ? `${e.name}: ${e.message}` : String(e)}`,
      );
      return text(500, 'internal error');
    }
  },

  async queue(batch, env): Promise<void> {
    const cfg = getConfig(env);
    const stub = sequencer(env, cfg);
    await consumeBatch(batch, {
      config: cfg,
      sink: { ingest: (items, report) => stub.ingest(items, report) },
      blinder: await getBlinder(env, cfg),
      now: Date.now,
    });
  },

  /**
   * Cron trigger: start an audit unless one is running. The ID is derived from the scheduled time,
   * so a trigger delivered twice starts one scan (createBatch is idempotent per ID).
   */
  async scheduled(controller, env): Promise<void> {
    const cfg = getConfig(env);
    const scanId = `audit-cron-${String(controller.scheduledTime)}`;
    const r = await startScan(
      { sequencer: sequencer(env, cfg), workflow: env.SCAN_WORKFLOW },
      'audit',
      scanId,
    );
    if (!r.started) {
      console.warn(`r2notary cron: ${r.active.scanId} is still running; not starting ${scanId}`);
    }
  },
} satisfies ExportedHandler<Env>;

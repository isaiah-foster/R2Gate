import { parseConfig, type Config } from './config.ts';
import { consumeBatch } from './ingest.ts';
import type { Sequencer } from './sequencer.ts';

export { Sequencer } from './sequencer.ts';
export { ScanWorkflow } from './scan-workflow.ts';

// Vars are fixed for the life of an isolate, so they are parsed once; a bad deployment fails on
// its first request or batch instead of misbehaving.
let config: Config | undefined;
function getConfig(env: Env): Config {
  config ??= parseConfig(env);
  return config;
}

function sequencer(env: Env, cfg: Config): DurableObjectStub<Sequencer> {
  return env.SEQUENCER.getByName(cfg.logName);
}

const iso = (ms: number | null): string | null => (ms === null ? null : new Date(ms).toISOString());

/**
 * GET /api/v1/status (PLAN §5.5). Operational counters only; the log's contents are served by the
 * read path (M4). The last audit summary joins in M6.
 */
async function status(env: Env, cfg: Config, head: boolean): Promise<Response> {
  const s = await sequencer(env, cfg).status();
  const body = {
    log: cfg.logName,
    origin: cfg.logOrigin,
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
  };
  return new Response(head ? null : `${JSON.stringify(body, null, 2)}\n`, {
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  });
}

export default {
  async fetch(request, env): Promise<Response> {
    const cfg = getConfig(env);
    const { pathname } = new URL(request.url);
    if (pathname === '/api/v1/status') {
      if (request.method !== 'GET' && request.method !== 'HEAD') {
        return new Response('method not allowed\n', {
          status: 405,
          headers: { allow: 'GET, HEAD', 'content-type': 'text/plain; charset=utf-8' },
        });
      }
      return status(env, cfg, request.method === 'HEAD');
    }
    // The log read path and the rest of the API land in M4.
    return new Response('r2notary: not implemented yet\n', {
      status: 501,
      headers: { 'content-type': 'text/plain; charset=utf-8' },
    });
  },

  async queue(batch, env): Promise<void> {
    const cfg = getConfig(env);
    const stub = sequencer(env, cfg);
    await consumeBatch(batch, {
      config: cfg,
      sink: { ingest: (items, report) => stub.ingest(items, report) },
      now: Date.now,
    });
  },
} satisfies ExportedHandler<Env>;

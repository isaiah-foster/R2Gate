// r2notary-witness: a C2SP tlog-witness (M8). Routes, with the submission and monitoring prefixes
// both at the root of the Worker's URL:
//
//   POST /add-checkpoint            cosign a checkpoint consistent with the last one (spec codes)
//   GET  /<sha256(origin)>/checkpoint   the latest cosigned checkpoint of a log, or 404
//
// There is no authentication, as the spec says: the log's signature on the checkpoint is what is
// checked, and only logs in WITNESS_LOGS are accepted.

import { MAX_BODY_BYTES } from './limits.ts';
import type { WitnessState } from './state.ts';

export { WitnessState } from './state.ts';

const CHECKPOINT_RE = /^\/([0-9a-f]{64})\/checkpoint$/;

function text(status: number, body: string, headers: Record<string, string> = {}): Response {
  return new Response(body, {
    status,
    headers: {
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      ...headers,
    },
  });
}

function witness(env: Env): DurableObjectStub<WitnessState> {
  return env.WITNESS.getByName('witness');
}

/** The request body as text, or null if it is longer than MAX_BODY_BYTES. */
async function readBody(request: Request): Promise<string | null> {
  const declared = Number(request.headers.get('content-length') ?? '0');
  if (declared > MAX_BODY_BYTES) return null;
  const body = new Uint8Array(await request.arrayBuffer());
  if (body.length > MAX_BODY_BYTES) return null;
  try {
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(body);
  } catch {
    return '';
  }
}

async function route(request: Request, env: Env): Promise<Response> {
  const path = new URL(request.url).pathname;
  if (path === '/add-checkpoint') {
    if (request.method !== 'POST') return text(405, 'method not allowed\n', { allow: 'POST' });
    const body = await readBody(request);
    if (body === null) return text(413, 'request body too large\n');
    const r = await witness(env).addCheckpoint(body);
    return new Response(r.body, {
      status: r.status,
      headers: {
        'content-type': r.contentType,
        'cache-control': 'no-store',
        'x-content-type-options': 'nosniff',
      },
    });
  }
  const m = CHECKPOINT_RE.exec(path);
  if (m?.[1] !== undefined) {
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      return text(405, 'method not allowed\n', { allow: 'GET, HEAD' });
    }
    const note = await witness(env).checkpoint(m[1]);
    if (note === null) return text(404, 'not found\n');
    // The spec lets monitors read this through a cache and lets it lag by up to an hour.
    return text(200, request.method === 'HEAD' ? '' : note, { 'cache-control': 'max-age=10' });
  }
  return text(404, 'not found\n');
}

export default {
  async fetch(request, env): Promise<Response> {
    try {
      return await route(request, env);
    } catch (e) {
      console.error(
        `r2notary-witness failed: ${e instanceof Error ? `${e.name}: ${e.message}` : String(e)}`,
      );
      return text(500, 'internal error\n');
    }
  },
} satisfies ExportedHandler<Env>;

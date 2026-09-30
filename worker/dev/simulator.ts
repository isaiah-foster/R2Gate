// Dev-only producer for local end-to-end runs and benchmarks (never deployed). Local R2 emits no
// event notifications, so this Worker stands in for R2's side of the pipeline. Every request it
// does not handle is forwarded to r2notary, so its routes are reachable on the same port.
//
//   POST /__simulate/send     JSON array of 1-100 message bodies, put on the local
//                             `r2notary-events` queue as they are (scripts/simulate-events.ts)
//   POST /__simulate/objects  JSON array of 1-100 object operations on the local monitored bucket:
//                             {op: "put", key, text? | size?, notify?} or {op: "delete", key, notify?}.
//                             With notify (the default) the notification R2 would send is queued,
//                             built from the stored object; with notify: false the change happens
//                             "behind the log's back", as when a notification rule is disabled.
//   POST /__simulate/append   {start, count, keys?}: `count` (1-1000) synthetic object.event
//                             entries appended straight to the Sequencer by RPC, bypassing the
//                             queue (bench/sequencer.ts measures the Sequencer alone with it)
//
//   npm run dev:sim       # this Worker (primary, port 8787) + r2notary, one wrangler process

import { encodeEntry } from '@r2notary/core';
import type { Sequencer } from '../src/sequencer.ts';

interface SimulatorEnv {
  readonly EVENTS: Queue;
  readonly R2NOTARY: Fetcher;
  readonly MONITORED: R2Bucket;
  readonly SEQUENCER: DurableObjectNamespace<Sequencer>;
  readonly MONITORED_BUCKET_NAME: string;
  readonly LOG_NAME: string;
}

// Paths are also in scripts/simulate-events.ts and bench/. Not exported: a Worker module may only
// export handlers.
const PREFIX = '/__simulate/';
/** Queues accept at most 100 messages per sendBatch call. */
const MAX_BATCH = 100;
const MAX_APPEND = 1000;
/** Placeholder account ID, as in scripts/simulate/events.ts; the consumer never logs it. */
const ACCOUNT = '0123456789abcdef0123456789abcdef';
const MAX_OBJECT_BYTES = 64 * 1024 * 1024;

const bad = (message: string): Response => new Response(`${message}\n`, { status: 400 });

async function jsonArray(request: Request): Promise<unknown[] | Response> {
  const body: unknown = await request.json();
  if (!Array.isArray(body) || body.length === 0 || body.length > MAX_BATCH) {
    return bad(`expected a JSON array of 1-${String(MAX_BATCH)} items`);
  }
  return body as unknown[];
}

/** `size` bytes of filler that differs per key, so equal sizes still give different ETags. */
function filler(key: string, size: number): Uint8Array {
  const out = new Uint8Array(size);
  const seed = new TextEncoder().encode(key);
  for (let i = 0; i < size; i++) out[i] = (seed[i % seed.length] ?? 0) ^ (i & 0xff);
  return out;
}

interface ObjectOp {
  readonly op: 'put' | 'delete';
  readonly key: string;
  readonly text?: string;
  readonly size?: number;
  readonly notify?: boolean;
}

function parseOp(v: unknown): ObjectOp | null {
  if (typeof v !== 'object' || v === null) return null;
  const o = v as Record<string, unknown>;
  if ((o.op !== 'put' && o.op !== 'delete') || typeof o.key !== 'string' || o.key === '') {
    return null;
  }
  if (o.text !== undefined && typeof o.text !== 'string') return null;
  if (
    o.size !== undefined &&
    (typeof o.size !== 'number' ||
      !Number.isSafeInteger(o.size) ||
      o.size < 0 ||
      o.size > MAX_OBJECT_BYTES)
  ) {
    return null;
  }
  if (o.notify !== undefined && typeof o.notify !== 'boolean') return null;
  return o as unknown as ObjectOp;
}

async function objects(ops: readonly unknown[], env: SimulatorEnv): Promise<Response> {
  const parsed = ops.map(parseOp);
  if (parsed.some((o) => o === null)) {
    return bad('each item is {op: "put"|"delete", key, text?, size?, notify?}');
  }
  const messages: unknown[] = [];
  // In order: a put and a delete of one key in a batch must happen in that order.
  for (const o of parsed as ObjectOp[]) {
    let message: unknown;
    if (o.op === 'put') {
      const body = o.text ?? filler(o.key, o.size ?? 0);
      const stored = await env.MONITORED.put(o.key, body);
      if (stored === null) throw new Error('unconditional put returned null');
      message = {
        account: ACCOUNT,
        action: 'PutObject',
        bucket: env.MONITORED_BUCKET_NAME,
        object: { key: o.key, size: stored.size, eTag: stored.etag },
        eventTime: stored.uploaded.toISOString(),
      };
    } else {
      await env.MONITORED.delete(o.key);
      message = {
        account: ACCOUNT,
        action: 'DeleteObject',
        bucket: env.MONITORED_BUCKET_NAME,
        object: { key: o.key },
        eventTime: new Date().toISOString(),
      };
    }
    if (o.notify !== false) messages.push(message);
  }
  if (messages.length > 0) {
    await env.EVENTS.sendBatch(messages.map((body) => ({ body, contentType: 'json' })));
  }
  return Response.json({ applied: parsed.length, notified: messages.length });
}

async function append(request: Request, env: SimulatorEnv): Promise<Response> {
  const body = await request.json<Record<string, unknown> | null>();
  const start = body?.start;
  const count = body?.count;
  const keys = body?.keys ?? MAX_APPEND;
  if (
    typeof start !== 'number' ||
    !Number.isSafeInteger(start) ||
    start < 0 ||
    typeof count !== 'number' ||
    !Number.isInteger(count) ||
    count < 1 ||
    count > MAX_APPEND ||
    typeof keys !== 'number' ||
    !Number.isInteger(keys) ||
    keys < 1
  ) {
    return bad(`expected {start, count: 1-${String(MAX_APPEND)}, keys?}`);
  }
  const at = new Date().toISOString();
  const items = Array.from({ length: count }, (_, j) => {
    const i = start + j;
    return {
      eventId: `bench-${String(i)}`,
      // Shaped like an ingested PutObject (32-hex ETag, as R2 sends for single-part uploads).
      entry: encodeEntry({
        v: 1,
        type: 'object.event',
        bucket: env.MONITORED_BUCKET_NAME,
        key: `bench/${String(i % keys)}`,
        action: 'PutObject',
        size: 1024 + (i % 1024),
        etag: (i >>> 0).toString(16).padStart(32, '0'),
        eventTime: at,
        ingestedAt: at,
      }),
    };
  });
  const result = await env.SEQUENCER.getByName(env.LOG_NAME).append(items);
  return Response.json(result);
}

export default {
  async fetch(request: Request, env: SimulatorEnv): Promise<Response> {
    const path = new URL(request.url).pathname;
    if (!path.startsWith(PREFIX)) return env.R2NOTARY.fetch(request);
    if (request.method !== 'POST') return new Response('POST only\n', { status: 405 });
    switch (path.slice(PREFIX.length)) {
      case 'send': {
        const bodies = await jsonArray(request);
        if (bodies instanceof Response) return bodies;
        await env.EVENTS.sendBatch(bodies.map((body: unknown) => ({ body, contentType: 'json' })));
        return Response.json({ sent: bodies.length });
      }
      case 'objects': {
        const ops = await jsonArray(request);
        return ops instanceof Response ? ops : objects(ops, env);
      }
      case 'append':
        return append(request, env);
      default:
        return new Response('not found\n', { status: 404 });
    }
  },
};

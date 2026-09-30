// PLAN §14.1: event -> visible latency. How long from an event entering the queue until a signed
// checkpoint covers it, at CHECKPOINT_INTERVAL_MS = 1000, 5000 and 15000?
//
//   npm run bench:latency [-- --events 1000 --rates 25,50 --intervals 1000,5000,15000]
//
// Two rates: at 25 events/s, BATCH_MAX_ENTRIES (500) is never reached within 15 s, so every
// publication waits for the interval; at 50/s it is reached after 10 s, so with a 15 s interval
// the batch limit triggers publication instead.
//
// For each rate and interval, a fresh `wrangler dev` (local queue, Worker, Sequencer, R2) receives `events`
// PutObject notifications for distinct keys at `rate` per second through the dev simulator's
// /__simulate/send, which puts them on the local queue exactly as R2 would. This process polls
// /api/v1/status every 50 ms. Afterwards it reads the published bundles to find each event's log
// index; an event is visible at the first poll whose published size exceeds its index.
//
// Start: when the send request for the event's group was issued. NOT included: the time R2 takes
// to deliver a notification to the queue after the object write, which a local run cannot see.
// The local queue's batching (max_batch_size 100, max_batch_timeout 5 s, as configured) is.
// Resolution: the poll interval plus one localhost request.

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import {
  TILE_WIDTH,
  decodeBundle,
  decodeEntry,
  entryBundlePath,
  generateKey,
} from '../packages/core/src/index.ts';
import { randomToken, sleep, startDev, type DevServer } from '../scripts/lib/dev.ts';
import { environment, intList, nowMs, summarize, writeResult } from './lib.ts';

const { values } = parseArgs({
  options: {
    events: { type: 'string', default: '1000' },
    rates: { type: 'string', default: '25,50' },
    intervals: { type: 'string', default: '1000,5000,15000' },
  },
});
const EVENTS = Number(values.events);
const POLL_MS = 50;

const tmp = mkdtempSync(join(tmpdir(), 'r2notary-bench-latency-'));
const readToken = randomToken();
const adminToken = randomToken();
const skey = (await generateKey('r2notary.example.com/log/example-log')).skey;
// Typed through `as`: TypeScript would otherwise narrow it to null in the finally block.
let dev = null as DevServer | null;

const keyOf = (i: number): string => `latency/object-${String(i).padStart(6, '0')}`;

try {
  const results: Record<string, unknown>[] = [];
  for (const [rate, interval] of intList(values.rates).flatMap((r) =>
    intList(values.intervals).map((i) => [r, i] as const),
  )) {
    /** Events per send request: one request every 100 ms. */
    const group = Math.max(1, Math.round(rate / 10));
    dev = await startDev({
      dir: tmp,
      persistTo: join(tmp, `state-${String(rate)}-${String(interval)}`),
      readToken,
      vars: {
        SIGNING_KEY: skey,
        ADMIN_TOKEN: adminToken,
        READ_TOKEN: readToken,
        CHECKPOINT_INTERVAL_MS: String(interval),
      },
    });
    const base = dev.base;
    const auth = { authorization: `Bearer ${readToken}` };
    const published = async (): Promise<number> => {
      const res = await fetch(`${base}/api/v1/status`, { headers: auth });
      return ((await res.json()) as { size: number }).size;
    };

    const sentAt = new Array<number>(EVENTS);
    const polls: { t: number; size: number }[] = [];
    let sending = true as boolean; // cleared below; read by the poller
    const poller = (async () => {
      while (sending || (polls.at(-1)?.size ?? 0) < EVENTS) {
        const t = nowMs();
        polls.push({ t, size: await published() });
        await sleep(Math.max(0, POLL_MS - (nowMs() - t)));
        if (nowMs() - (sentAt[EVENTS - 1] ?? nowMs()) > 120_000) throw new Error('timed out');
      }
    })();
    const t0 = nowMs();
    for (let i = 0; i < EVENTS; i += group) {
      const due = t0 + (i / rate) * 1000;
      await sleep(Math.max(0, due - nowMs()));
      const messages = Array.from({ length: Math.min(group, EVENTS - i) }, (_, j) => ({
        account: '0123456789abcdef0123456789abcdef',
        action: 'PutObject',
        bucket: 'example-monitored-bucket',
        object: { key: keyOf(i + j), size: 1024, eTag: (i + j).toString(16).padStart(32, '0') },
        eventTime: new Date().toISOString(),
      }));
      const t = nowMs();
      for (let j = 0; j < messages.length; j++) sentAt[i + j] = t;
      const res = await fetch(`${base}/__simulate/send`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(messages),
      });
      if (!res.ok) throw new Error(`send: HTTP ${String(res.status)}`);
    }
    sending = false;
    await poller;

    // Log index of every event, from the published bundles.
    const indexOf = new Map<string, number>();
    for (let n = 0; n * TILE_WIDTH < EVENTS; n++) {
      const width = Math.min(TILE_WIDTH, EVENTS - n * TILE_WIDTH);
      const res = await fetch(`${base}/log/example-log/${entryBundlePath(n, width)}`, {
        headers: auth,
      });
      if (!res.ok) throw new Error(`bundle ${String(n)}: HTTP ${String(res.status)}`);
      decodeBundle(new Uint8Array(await res.arrayBuffer())).forEach((e, j) => {
        const d = decodeEntry(e);
        if (d.known && d.entry.type === 'object.event')
          indexOf.set(d.entry.key, n * TILE_WIDTH + j);
      });
    }
    const latencies: number[] = [];
    for (let i = 0; i < EVENTS; i++) {
      const index = indexOf.get(keyOf(i));
      const sent = sentAt[i];
      if (index === undefined || sent === undefined)
        throw new Error(`event ${String(i)} not logged`);
      const visible = polls.find((p) => p.size > index && p.t >= sent);
      if (visible === undefined) throw new Error(`event ${String(i)} never visible`);
      latencies.push(visible.t - sent);
    }
    const checkpoints = new Set(polls.map((p) => p.size)).size - 1;
    const s = summarize(latencies, 0);
    results.push({
      checkpointIntervalMs: interval,
      events: EVENTS,
      ratePerSecond: rate,
      latencyMs: s,
      distinctPublishedSizesSeen: checkpoints,
    });
    console.log(
      `${String(rate)}/s, interval ${String(interval)} ms: median ${String(s.median)} ms, p95 ${String(s.p95)}, p99 ${String(s.p99)}`,
    );
    dev.stop();
  }
  writeResult('latency', {
    benchmark: 'PLAN §14.1 event -> visible latency',
    environment: environment(
      'wrangler dev (local Queues, workerd, DO SQLite, R2), timed from Node over localhost HTTP',
    ),
    config: {
      events: EVENTS,
      eventsPerSendRequest: 'rate / 10 (one request every 100 ms)',
      pollMs: POLL_MS,
      queue: 'max_batch_size 100, max_batch_timeout 5 s (worker/wrangler.jsonc)',
      batchMaxEntries: 500,
      start: 'send request to the local queue issued (excludes R2 -> queue notification delay)',
      end: 'first /api/v1/status poll whose published size covers the event',
    },
    results,
  });
} finally {
  dev?.stop();
  rmSync(tmp, { recursive: true, force: true });
}

// PLAN §14.2: Sequencer throughput. Runs the real Worker and Sequencer under `wrangler dev` (local
// workerd, local DO SQLite, local R2) and times them from this process:
//
//   1. append: one Sequencer.append RPC of n entries (n = 1, 10, 100), alone. Publication is kept
//      out of the way: the interval is an hour and the backlog is published (untimed) between
//      groups of calls, so it never reaches BATCH_MAX_ENTRIES.
//   2. publish: one publication of k entries (k = 1 ... 1000), through POST /api/v1/admin/publish.
//   3. sustained: c clients append batches of 100 as fast as they can for a fixed time while the
//      alarm publishes (CHECKPOINT_INTERVAL_MS = 1000, BATCH_MAX_ENTRIES = 500). Accepted and
//      published rates, and the backlog left at the end, show where the Sequencer saturates.
//
//   npm run bench:sequencer [-- --samples 30 --seconds 20 --clients 1,2,4,8,16]
//
// Appends go straight to the Sequencer by RPC through the dev simulator (/__simulate/append),
// bypassing the queue, so the queue's batching does not cap the rate. Every timing includes a
// localhost HTTP request and a Worker-to-DO call. Local SQLite and R2 are not Cloudflare's: on the
// network, each DO write waits for replication and each R2 write is a network call, so these are
// local figures, not production capacity.

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { generateKey } from '../packages/core/src/index.ts';
import { randomToken, sleep, startDev, type DevServer } from '../scripts/lib/dev.ts';
import { environment, intList, nowMs, round, summarize, writeResult } from './lib.ts';

const { values } = parseArgs({
  options: {
    samples: { type: 'string', default: '30' },
    seconds: { type: 'string', default: '20' },
    clients: { type: 'string', default: '1,2,4,8,16' },
    'append-sizes': { type: 'string', default: '1,10,100' },
    'publish-sizes': { type: 'string', default: '1,10,100,500,1000' },
  },
});
const SAMPLES = Number(values.samples);
const SECONDS = Number(values.seconds);

const tmp = mkdtempSync(join(tmpdir(), 'r2notary-bench-seq-'));
const readToken = randomToken();
const adminToken = randomToken();
const skey = (await generateKey('r2notary.example.com/log/example-log')).skey;
// Typed through `as`: TypeScript would otherwise narrow it to null in the finally block.
let dev = null as DevServer | null;

async function post(path: string, body: unknown, token?: string): Promise<unknown> {
  if (dev === null) throw new Error('not running');
  const res = await fetch(`${dev.base}${path}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...(token === undefined ? {} : { authorization: `Bearer ${token}` }),
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${path}: HTTP ${String(res.status)} ${await res.text()}`);
  return res.json();
}

interface Status {
  size: number;
  durableSize: number;
  pending: number;
  lastError: string | null;
}
async function status(): Promise<Status> {
  if (dev === null) throw new Error('not running');
  const res = await fetch(`${dev.base}/api/v1/status`, {
    headers: { authorization: `Bearer ${readToken}` },
  });
  return (await res.json()) as Status;
}

let next = 0;
async function append(count: number): Promise<void> {
  const start = next;
  next += count; // reserved before the await: concurrent clients must not reuse event IDs
  const r = (await post('/__simulate/append', { start, count })) as { accepted: number };
  if (r.accepted !== count) throw new Error(`accepted ${String(r.accepted)} of ${String(count)}`);
}
const publish = (): Promise<unknown> => post('/api/v1/admin/publish', {}, adminToken);

const vars = (extra: Record<string, string>): Record<string, string> => ({
  SIGNING_KEY: skey,
  ADMIN_TOKEN: adminToken,
  READ_TOKEN: readToken,
  ...extra,
});

try {
  // 1 and 2: one server, publication only on request.
  dev = await startDev({
    dir: tmp,
    readToken,
    vars: vars({ CHECKPOINT_INTERVAL_MS: '3600000', BATCH_MAX_ENTRIES: '1000' }),
  });
  for (let i = 0; i < 5; i++) {
    await append(10); // warm up the isolate, the DO and the signer
    await publish();
  }

  const appendResults: Record<string, unknown>[] = [];
  for (const n of intList(values['append-sizes'])) {
    const ms: number[] = [];
    for (let i = 0; i < SAMPLES; i++) {
      if ((await status()).pending + n > 900) await publish();
      const t = nowMs();
      await append(n);
      ms.push(nowMs() - t);
    }
    const s = summarize(ms);
    appendResults.push({
      entriesPerCall: n,
      ms: s,
      entriesPerSecondAtMedian: Math.round((n / s.median) * 1000),
    });
    console.log(`append ${String(n)}: median ${String(s.median)} ms`);
  }
  await publish();

  const publishResults: Record<string, unknown>[] = [];
  for (const k of intList(values['publish-sizes'])) {
    const ms: number[] = [];
    // With k = BATCH_MAX_ENTRIES (1000) the alarm is due as soon as the entries are appended, and
    // can finish the publication before the timed admin call arrives (which then has nothing to
    // do). Such samples are discarded and counted; if the alarm has only started, the admin call
    // joins it (single flight) and the sample stands.
    let discarded = 0;
    while (ms.length < Math.max(10, Math.floor(SAMPLES / 2))) {
      for (let left = k; left > 0; left -= Math.min(left, 1000)) await append(Math.min(left, 1000));
      const t = nowMs();
      const r = (await publish()) as { previousSize: number; size: number };
      const elapsed = nowMs() - t;
      if (r.size === r.previousSize && (await status()).pending === 0 && discarded < 20) {
        discarded++;
        continue;
      }
      if (r.size - r.previousSize !== k) throw new Error(`published ${JSON.stringify(r)}`);
      ms.push(elapsed);
    }
    const s = summarize(ms);
    publishResults.push({
      entriesPerPublication: k,
      ms: s,
      entriesPerSecondAtMedian: Math.round((k / s.median) * 1000),
      discardedAlarmPublished: discarded,
    });
    console.log(`publish ${String(k)}: median ${String(s.median)} ms`);
  }
  dev.stop();

  // 3: sustained load, the alarm publishing on its own. A fresh server (and state) per run.
  const sustained: Record<string, unknown>[] = [];
  for (const clients of intList(values.clients)) {
    dev = await startDev({
      dir: tmp,
      persistTo: join(tmp, `state-sustained-${String(clients)}`),
      readToken,
      vars: vars({ CHECKPOINT_INTERVAL_MS: '1000', BATCH_MAX_ENTRIES: '500' }),
    });
    next = 0;
    await append(10);
    await sleep(2000);
    const before = await status();
    const t0 = nowMs();
    const deadline = t0 + SECONDS * 1000;
    const callMs: number[] = [];
    const worker = async (): Promise<void> => {
      while (nowMs() < deadline) {
        const t = nowMs();
        await append(100);
        callMs.push(nowMs() - t);
      }
    };
    const samples: { t: number; size: number; durable: number }[] = [];
    const poller = (async () => {
      while (nowMs() < deadline) {
        const s = await status();
        samples.push({ t: (nowMs() - t0) / 1000, size: s.size, durable: s.durableSize });
        await sleep(500);
      }
    })();
    await Promise.all([...Array.from({ length: clients }, worker), poller]);
    const elapsed = (nowMs() - t0) / 1000;
    const after = await status();
    // Time for the alarm to drain what was left.
    const drainStart = nowMs();
    let drained = after;
    while (drained.pending > 0 && nowMs() - drainStart < 120_000) {
      await sleep(250);
      drained = await status();
    }
    const accepted = after.durableSize - before.durableSize;
    const published = after.size - before.size;
    sustained.push({
      clients,
      entriesPerCall: 100,
      seconds: round(elapsed, 2),
      accepted,
      published,
      acceptedPerSecond: Math.round(accepted / elapsed),
      publishedPerSecond: Math.round(published / elapsed),
      backlogAtEnd: after.pending,
      drainSeconds: drained.pending === 0 ? round((nowMs() - drainStart) / 1000, 2) : null,
      appendCallMs: summarize(callMs),
      lastError: drained.lastError,
      timeline: samples,
    });
    console.log(
      `sustained, ${String(clients)} clients: accepted ${String(Math.round(accepted / elapsed))}/s, published ${String(Math.round(published / elapsed))}/s, backlog ${String(after.pending)}`,
    );
    dev.stop();
  }

  writeResult('sequencer', {
    benchmark: 'PLAN §14.2 Sequencer throughput',
    environment: environment(
      'wrangler dev (local workerd, local DO SQLite, local R2), timed from Node over localhost HTTP',
    ),
    config: {
      samples: SAMPLES,
      sustainedSeconds: SECONDS,
      append: 'Sequencer.append via /__simulate/append (synthetic PutObject entries)',
      publish: 'POST /api/v1/admin/publish, CHECKPOINT_INTERVAL_MS=3600000, BATCH_MAX_ENTRIES=1000',
      sustained: 'CHECKPOINT_INTERVAL_MS=1000, BATCH_MAX_ENTRIES=500, 100 entries per append call',
    },
    append: appendResults,
    publish: publishResults,
    sustained,
  });
} finally {
  dev?.stop();
  rmSync(tmp, { recursive: true, force: true });
}

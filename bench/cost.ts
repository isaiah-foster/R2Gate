// PLAN §14.7: cost model. Estimates the monthly Cloudflare bill of the write path (ingest and
// publication) for 1M, 10M and 100M object events per month, from the operation counts measured
// by bench/amplification.ts and the list prices below. Nothing is measured here; this is
// arithmetic over bench/results/amplification.json under the stated arrival model.
//
//   npm run bench:cost        # after npm run bench:amplification
//
// Arrival model (an assumption, not a measurement): events arrive as a Poisson process at a
// constant rate lambda = events / 30 days.
//   - Publication (worker/src/sequencer.ts publicationDue): the alarm fires CHECKPOINT_INTERVAL_MS
//     after the oldest pending entry arrived, or at once when BATCH_MAX_ENTRIES (500) are waiting.
//     A cycle is an idle wait for the first event (mean 1/lambda) plus the interval T, so there are
//     month / (1/lambda + T) publications of 1 + lambda*T entries on average (capped at 500).
//   - Queue batches: assumed to close max_batch_timeout (5 s) after their first message or at
//     max_batch_size (100), so a batch carries min(100, 1 + 5*lambda) messages.
//   - Per-publication and per-batch counts are linearly interpolated between the measured sizes.
//
// Not estimated: Durable Object duration (GB-s), Workers CPU time, and Workflow steps (auditor),
// which depend on wall and CPU time on Cloudflare's network that no local run measures; reads by
// verifiers (Class B, client-driven; Workers Cache can absorb them for a public log, D4.3).

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { RESULTS, environment, round, writeResult } from './lib.ts';

/** List prices, Workers Paid plan. Page dates are each page's "last updated" line, read 2026-10-03. */
const PRICES = {
  r2: {
    source: 'https://developers.cloudflare.com/r2/pricing/ (last updated 2026-10-01)',
    storagePerGBMonth: 0.015,
    classAPerMillion: 4.5,
    classBPerMillion: 0.36,
    included: { storageGBMonth: 10, classA: 1e6, classB: 10e6 },
  },
  durableObjects: {
    source:
      'https://developers.cloudflare.com/durable-objects/platform/pricing/ (last updated 2026-09-30)',
    requestsPerMillion: 0.15,
    rowsWrittenPerMillion: 1.0,
    rowsReadPerMillion: 0.001,
    included: { requests: 1e6, rowsWritten: 50e6, rowsRead: 25e9 },
  },
  queues: {
    source: 'https://developers.cloudflare.com/queues/platform/pricing/ (as of 2026-04-21)',
    operationsPerMillion: 0.4,
    operationsPerMessage: 3, // write, read, delete; each per 64 KB, and notifications are small
    included: { operations: 1e6 },
  },
  workers: {
    source: 'https://developers.cloudflare.com/workers/platform/pricing/ (last updated 2026-10-02)',
    requestsPerMillion: 0.3,
    baseMonthly: 5,
    included: { requests: 10e6 },
  },
} as const;

const MONTH_SECONDS = 30 * 24 * 3600;
const BATCH_MAX = 500;
const QUEUE_BATCH = 100;
const QUEUE_TIMEOUT_S = 5;
const EVENTS = [1e6, 10e6, 100e6];
const INTERVALS_MS = [1000, 5000, 15000];

interface Measured {
  entriesPerPublication: number;
  messagesPerQueueBatch: number;
  perPublication: {
    classA: number;
    classB: number;
    rowsRead: number;
    rowsWritten: number;
    setAlarm: number;
    r2BytesRetained: number;
  };
  perQueueBatch: { rowsRead: number; rowsWritten: number; setAlarm: number };
  perEntryPrune: { rowsWritten: number };
}

const amp = JSON.parse(readFileSync(join(RESULTS, 'amplification.json'), 'utf8')) as {
  environment: { date: string; commit: string | null };
  results: Measured[];
};

/** Linear interpolation over measured points (clamped to the measured range). */
function interpolate(points: readonly (readonly [number, number])[], x: number): number {
  const p = [...points].sort((a, b) => a[0] - b[0]);
  const first = p[0];
  const last = p.at(-1);
  if (first === undefined || last === undefined) throw new Error('no points');
  if (x <= first[0]) return first[1];
  if (x >= last[0]) return last[1];
  for (let i = 1; i < p.length; i++) {
    const [x1, y1] = p[i] ?? [0, 0];
    const [x0, y0] = p[i - 1] ?? [0, 0];
    if (x <= x1) return y0 + ((y1 - y0) * (x - x0)) / (x1 - x0);
  }
  return last[1];
}

const byPublication = (f: (m: Measured) => number): [number, number][] =>
  amp.results.map((m) => [m.entriesPerPublication, f(m)]);
// One row per distinct batch size (publications of 100+ entries all used batches of 100).
const byBatch = (f: (m: Measured) => number): [number, number][] => [
  ...new Map(amp.results.map((m) => [m.messagesPerQueueBatch, f(m)])).entries(),
];
const prunePerEntry =
  amp.results.reduce((a, m) => a + m.perEntryPrune.rowsWritten, 0) / amp.results.length;

const money = (x: number): number => round(x, 2);
const beyond = (used: number, included: number): number => Math.max(0, used - included);

const scenarios = [];
for (const events of EVENTS) {
  const lambda = events / MONTH_SECONDS;
  for (const intervalMs of INTERVALS_MS) {
    const t = intervalMs / 1000;
    const k = Math.min(BATCH_MAX, 1 + lambda * t);
    const publications = k >= BATCH_MAX ? events / BATCH_MAX : MONTH_SECONDS / (1 / lambda + t);
    const q = Math.min(QUEUE_BATCH, 1 + lambda * QUEUE_TIMEOUT_S);
    const batches = events / q;

    const pub = (f: (m: Measured) => number): number =>
      publications * interpolate(byPublication(f), k);
    const bat = (f: (m: Measured) => number): number => batches * interpolate(byBatch(f), q);

    const usage = {
      r2ClassA: pub((m) => m.perPublication.classA),
      r2ClassB: pub((m) => m.perPublication.classB),
      r2GBAddedPerMonth: pub((m) => m.perPublication.r2BytesRetained) / 1e9,
      doRequests: batches + publications, // one ingest RPC per batch, one alarm per publication
      doRowsWritten:
        pub((m) => m.perPublication.rowsWritten + m.perPublication.setAlarm) +
        bat((m) => m.perQueueBatch.rowsWritten + m.perQueueBatch.setAlarm) +
        events * prunePerEntry,
      doRowsRead: pub((m) => m.perPublication.rowsRead) + bat((m) => m.perQueueBatch.rowsRead),
      queueOperations: events * PRICES.queues.operationsPerMessage,
      workerInvocations: batches, // queue consumer invocations
    };
    const p = PRICES;
    const listPrice = {
      r2ClassA: money((usage.r2ClassA / 1e6) * p.r2.classAPerMillion),
      r2StorageAddedThisMonth: money(usage.r2GBAddedPerMonth * p.r2.storagePerGBMonth),
      doRequests: money((usage.doRequests / 1e6) * p.durableObjects.requestsPerMillion),
      doRowsWritten: money((usage.doRowsWritten / 1e6) * p.durableObjects.rowsWrittenPerMillion),
      doRowsRead: money((usage.doRowsRead / 1e6) * p.durableObjects.rowsReadPerMillion),
      queues: money((usage.queueOperations / 1e6) * p.queues.operationsPerMillion),
      workerRequests: money((usage.workerInvocations / 1e6) * p.workers.requestsPerMillion),
    };
    const paidPlan = {
      base: p.workers.baseMonthly,
      r2ClassA: money((beyond(usage.r2ClassA, p.r2.included.classA) / 1e6) * p.r2.classAPerMillion),
      doRequests: money(
        (beyond(usage.doRequests, p.durableObjects.included.requests) / 1e6) *
          p.durableObjects.requestsPerMillion,
      ),
      doRowsWritten: money(
        (beyond(usage.doRowsWritten, p.durableObjects.included.rowsWritten) / 1e6) *
          p.durableObjects.rowsWrittenPerMillion,
      ),
      queues: money(
        (beyond(usage.queueOperations, p.queues.included.operations) / 1e6) *
          p.queues.operationsPerMillion,
      ),
      workerRequests: money(
        (beyond(usage.workerInvocations, p.workers.included.requests) / 1e6) *
          p.workers.requestsPerMillion,
      ),
    };
    scenarios.push({
      eventsPerMonth: events,
      checkpointIntervalMs: intervalMs,
      model: {
        eventsPerSecond: round(lambda, 4),
        entriesPerPublication: round(k, 2),
        publications: Math.round(publications),
        messagesPerQueueBatch: round(q, 2),
        queueBatches: Math.round(batches),
      },
      usage: Object.fromEntries(Object.entries(usage).map(([n, v]) => [n, round(v, 3)])),
      listPriceUSD: {
        ...listPrice,
        total: money(Object.values(listPrice).reduce((a, b) => a + b, 0)),
      },
      // Storage is cumulative (the log is append-only), so its included 10 GB is not netted here.
      paidPlanUSD: {
        ...paidPlan,
        total: money(Object.values(paidPlan).reduce((a, b) => a + b, 0)),
      },
    });
    console.log(
      `${String(events / 1e6)}M events, ${String(intervalMs)} ms: list ${String(scenarios.at(-1)?.listPriceUSD.total)} USD`,
    );
  }
}

writeResult('cost', {
  benchmark: 'PLAN §14.7 cost model (arithmetic over amplification.json; not a measurement)',
  environment: environment('Node.js; computation only'),
  inputs: {
    amplification: `bench/results/amplification.json (${amp.environment.date}, commit ${String(amp.environment.commit)})`,
    monthSeconds: MONTH_SECONDS,
    batchMaxEntries: BATCH_MAX,
    queueMaxBatchSize: QUEUE_BATCH,
    queueMaxBatchTimeoutSeconds: QUEUE_TIMEOUT_S,
    pruneRowsWrittenPerEntry: round(prunePerEntry, 4),
    prices: PRICES,
  },
  assumptions: [
    'Poisson arrivals at a constant rate (events / 30 days); real traffic is burstier, which means fewer, larger publications for the same total',
    'publications: month / (1/rate + interval), each of 1 + rate*interval entries (capped at 500)',
    'queue batches close 5 s after their first message or at 100 messages',
    'per-publication and per-batch counts interpolated linearly between measured sizes',
    'every partial tile and partial bundle is kept (DECISIONS D4.5), so R2 storage grows by the bytes written per publication',
    'excluded: DO duration, Workers CPU, Workflow steps (auditor), verifier reads, R2 Class B by clients',
  ],
  scenarios,
});

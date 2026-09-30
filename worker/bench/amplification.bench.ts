// PLAN §14.3: operation amplification, counted on the real code path inside workerd (local DO
// SQLite and local R2). Not part of `npm test`; run by `npm run bench:amplification`, which reads
// the counts from the JSON reporter (each test stores its result in `task.meta`).
//
// For each publication size k, synthetic R2 notifications go through the real queue handler
// (`worker.queue` -> `Sequencer.ingest`, in batches of min(k, 100) like the configured consumer)
// and then the Sequencer's real alarm publishes them. Counted, separately for the ingest and the
// publish phase of every cycle:
//
//   - R2 operations by class (R2 pricing: put and list are Class A, get and head Class B, delete
//     free), counted by wrapping the R2Bucket prototype, so the Sequencer's own calls are seen;
//   - SQLite rows read and written, summed from `SqlStorageCursor.rowsRead/rowsWritten` (the
//     values the DO docs say are billed), by wrapping `SqlStorage.prototype.exec`;
//   - setAlarm calls (billed as one row written each) and alarm invocations;
//   - bytes written to R2, and the database size.
//
// Counts are exact and deterministic; nothing here is a timing.

import { env } from 'cloudflare:workers';
import {
  createMessageBatch,
  reset,
  runDurableObjectAlarm,
  runInDurableObject,
} from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import worker from '../src/index.ts';
import { SequencerStore } from '../src/store.ts';

interface Tally {
  classA: number;
  classB: number;
  r2Deletes: number;
  r2BytesWritten: number;
  /** Bytes of everything but the live checkpoint: create-if-absent objects, never deleted. */
  r2BytesRetained: number;
  rowsRead: number;
  rowsWritten: number;
  setAlarm: number;
}

const zero = (): Tally => ({
  classA: 0,
  classB: 0,
  r2Deletes: 0,
  r2BytesWritten: 0,
  r2BytesRetained: 0,
  rowsRead: 0,
  rowsWritten: 0,
  setAlarm: 0,
});

const tally = zero();
const cursors: SqlStorageCursor<Record<string, SqlStorageValue>>[] = [];
let installed = false;

/** Wraps the binding prototypes once. Every isolate-local caller (the DO included) is counted. */
async function install(): Promise<void> {
  if (installed) return;
  installed = true;
  const r2 = Object.getPrototypeOf(env.LOG) as Record<string, unknown>;
  const wrap = (name: string, count: (args: unknown[]) => void): void => {
    const orig = r2[name] as (...a: unknown[]) => unknown;
    r2[name] = function (this: unknown, ...args: unknown[]) {
      count(args);
      return orig.apply(this, args);
    };
  };
  wrap('put', (a) => {
    tally.classA++;
    const v = a[1];
    const n =
      v instanceof Uint8Array
        ? v.byteLength
        : typeof v === 'string'
          ? new TextEncoder().encode(v).length
          : 0;
    tally.r2BytesWritten += n;
    if (!String(a[0]).endsWith('/checkpoint')) tally.r2BytesRetained += n;
  });
  wrap('list', () => tally.classA++);
  wrap('get', () => tally.classB++);
  wrap('head', () => tally.classB++);
  wrap('delete', () => tally.r2Deletes++);

  await runInDurableObject(env.SEQUENCER.getByName('bench-probe'), (_i, state) => {
    const sql = Object.getPrototypeOf(state.storage.sql) as { exec: (...a: unknown[]) => unknown };
    const exec = sql.exec;
    sql.exec = function (this: unknown, ...args: unknown[]) {
      const c = exec.apply(this, args) as SqlStorageCursor<Record<string, SqlStorageValue>>;
      cursors.push(c);
      return c;
    };
    const storage = Object.getPrototypeOf(state.storage) as {
      setAlarm: (...a: unknown[]) => unknown;
    };
    const setAlarm = storage.setAlarm;
    storage.setAlarm = function (this: unknown, ...args: unknown[]) {
      tally.setAlarm++;
      return setAlarm.apply(this, args);
    };
  });
}

/** Counts since the previous call. SQL cursors are summed when read, after they were consumed. */
function take(): Tally {
  for (const c of cursors.splice(0)) {
    tally.rowsRead += c.rowsRead;
    tally.rowsWritten += c.rowsWritten;
  }
  const out = { ...tally };
  Object.assign(tally, zero());
  return out;
}

function add(a: Tally, b: Tally): void {
  for (const k of Object.keys(a) as (keyof Tally)[]) a[k] += b[k];
}

/** A PutObject notification for a new key, shaped as the R2 docs give it. */
function message(i: number): unknown {
  return {
    account: '0123456789abcdef0123456789abcdef',
    action: 'PutObject',
    bucket: env.MONITORED_BUCKET_NAME,
    object: {
      key: `data/2026/10/03/object-${String(i).padStart(7, '0')}.bin`,
      size: 1024 + (i % 4096),
      eTag: (i >>> 0).toString(16).padStart(32, '0'),
    },
    eventTime: new Date(Date.UTC(2026, 9, 3, 12) + i).toISOString(),
  };
}

const QUEUE = 'r2notary-events';
const QUEUE_MAX_BATCH = 100; // max_batch_size in wrangler.jsonc
const MIN_ENTRIES = 2560; // ten full tiles, so full tile and bundle writes are amortized
/** Set by worker/vitest.bench.config.ts. */
const SIZES = String((env as unknown as Record<string, unknown>).BENCH_SIZES)
  .split(',')
  .map(Number);

describe('amplification', () => {
  for (const k of SIZES) {
    it(`publications of ${String(k)} entries`, { timeout: 600_000 }, async ({ task }) => {
      await reset();
      await install();
      const q = Math.min(k, QUEUE_MAX_BATCH);
      const total = Math.ceil(MIN_ENTRIES / k) * k;
      const stub = env.SEQUENCER.getByName(env.LOG_NAME);
      take();

      const ingest = zero();
      const publish = zero();
      let batches = 0;
      let alarms = 0;
      for (let done = 0; done < total; done += k) {
        for (let i = 0; i < k; i += q) {
          const batch = createMessageBatch(
            QUEUE,
            Array.from({ length: Math.min(q, k - i) }, (_, j) => ({
              id: `m${String(done + i + j)}`,
              timestamp: new Date(0),
              attempts: 1,
              body: message(done + i + j),
            })),
          );
          await worker.queue(batch, env);
          batches++;
        }
        add(ingest, take());
        expect(await runDurableObjectAlarm(stub)).toBe(true);
        alarms++;
        add(publish, take());
      }
      const status = await stub.status();
      expect(status.publishedSize).toBe(total);
      expect(status.lastError).toBeNull();

      // Steady state also deletes every dedupe record once its window passes (pruned on alarms).
      const prune = await runInDurableObject(stub, (_i, state) => {
        new SequencerStore(state.storage).pruneSeen(Number.MAX_SAFE_INTEGER);
        return state.storage.sql.databaseSize;
      });
      const pruned = take();
      const dbBytes = await runInDurableObject(stub, (_i, state) => state.storage.sql.databaseSize);
      take();

      const per = (x: number, n: number): number => Number((x / n).toFixed(4));
      (task.meta as Record<string, unknown>).amplification = {
        entriesPerPublication: k,
        messagesPerQueueBatch: q,
        entries: total,
        publications: alarms,
        queueBatches: batches,
        ingest,
        publish,
        prune: pruned,
        perEntry: {
          classA: per(ingest.classA + publish.classA, total),
          classB: per(ingest.classB + publish.classB, total),
          r2BytesWritten: per(publish.r2BytesWritten, total),
          r2BytesRetained: per(publish.r2BytesRetained, total),
          rowsRead: per(ingest.rowsRead + publish.rowsRead + pruned.rowsRead, total),
          // SQL rows plus setAlarm calls, which the DO pricing page bills as one row written each
          rowsWrittenBilled: per(
            ingest.rowsWritten +
              publish.rowsWritten +
              pruned.rowsWritten +
              ingest.setAlarm +
              publish.setAlarm,
            total,
          ),
        },
        perPublication: {
          classA: per(publish.classA, alarms),
          classB: per(publish.classB, alarms),
          rowsRead: per(publish.rowsRead, alarms),
          rowsWritten: per(publish.rowsWritten, alarms),
          setAlarm: per(publish.setAlarm, alarms),
          r2BytesRetained: per(publish.r2BytesRetained, alarms),
        },
        perQueueBatch: {
          rowsRead: per(ingest.rowsRead, batches),
          rowsWritten: per(ingest.rowsWritten, batches),
          setAlarm: per(ingest.setAlarm, batches),
        },
        // pruning the dedupe window: deletes count as rows written
        perEntryPrune: { rowsWritten: per(pruned.rowsWritten, total) },
        sqliteBytes: { beforePrune: prune, afterPrune: dbBytes },
      };
    });
  }
});

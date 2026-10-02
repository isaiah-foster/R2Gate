// Ingest (PLAN §5.4, M3): message validation, eventId, loop protection (I8), dedupe through the
// queue path (I5), out-of-order and duplicate delivery, retries, and the counters /status shows.
import {
  decodeBundle,
  decodeEntry,
  entryBundlePath,
  toHex,
  utf8Encode,
  type ObjectEvent,
} from '@r2notary/core';
import { env, exports } from 'cloudflare:workers';
import {
  createExecutionContext,
  createMessageBatch,
  getQueueResult,
  reset,
  runInDurableObject,
} from 'cloudflare:test';
import { afterEach, describe, expect, it } from 'vitest';
import { SIM_ACCOUNT, simulate, type R2EventMessage } from '../../scripts/simulate/events.ts';
import { parseConfig } from '../src/config.ts';
import worker from '../src/index.ts';
import {
  classifyMessage,
  consumeBatch,
  eventId,
  retryDelaySeconds,
  type IngestSink,
} from '../src/ingest.ts';
import { AppendError } from '../src/sequencer.ts';
import type { AppendItem, AppendResult, IngestReport } from '../src/store.ts';
import { readBytes } from './helpers.ts';

afterEach(() => reset());

const config = parseConfig(env);
const MONITORED = env.MONITORED_BUCKET_NAME;
const LOG_BUCKET = env.LOG_BUCKET_NAME;
const QUEUE = 'r2notary-events';
const DLQ = env.EVENTS_DLQ_NAME;
const INGESTED_AT = '2026-10-02T12:00:05.000Z';
const ETAG = 'c846ff7a18f28c2e262116d6e8719ef0';

function put(key: string, eventTime: string, o: Partial<R2EventMessage> = {}): R2EventMessage {
  return {
    account: SIM_ACCOUNT,
    action: 'PutObject',
    bucket: MONITORED,
    object: { key, size: 65536, eTag: ETAG },
    eventTime,
    ...o,
  };
}

function del(key: string, eventTime: string, action = 'DeleteObject'): R2EventMessage {
  return { account: SIM_ACCOUNT, action, bucket: MONITORED, object: { key }, eventTime };
}

async function classifyEvent(body: unknown): Promise<ObjectEvent> {
  const c = await classifyMessage(body, config, INGESTED_AT);
  if (c.kind !== 'event') throw new Error(`expected an event, got ${JSON.stringify(c)}`);
  const d = decodeEntry(c.item.entry);
  if (!d.known || d.entry.type !== 'object.event') throw new Error('not an object.event');
  return d.entry;
}

let msgId = 0;
function batchOf(messages: readonly unknown[], queue = QUEUE, attempts = 1): MessageBatch {
  return createMessageBatch(
    queue,
    messages.map((body) => ({ id: `m${String(msgId++)}`, timestamp: new Date(0), attempts, body })),
  );
}

/** Delivers messages to the real queue handler in batches of at most 100 (the queue maximum). */
async function deliver(messages: readonly unknown[], queue = QUEUE): Promise<void> {
  for (let i = 0; i < messages.length; i += 100) {
    const batch = batchOf(messages.slice(i, i + 100), queue);
    const ctx = createExecutionContext();
    await worker.queue(batch, env);
    const result = await getQueueResult(batch, ctx);
    expect(result.ackAll).toBe(true);
    expect(result.retryBatch.retry).toBe(false);
    expect(result.retryMessages).toEqual([]);
  }
}

const sequencer = (): DurableObjectStub<import('../src/sequencer.ts').Sequencer> =>
  env.SEQUENCER.getByName(env.LOG_NAME);

/** Every entry published under LOG_NAME, decoded from the entry bundles in R2. */
async function publishedEntries(size: number): Promise<Uint8Array[]> {
  const out: Uint8Array[] = [];
  for (let n = 0; n * 256 < size; n++) {
    const width = Math.min(256, size - n * 256);
    const bytes = await readBytes(`${env.LOG_NAME}/${entryBundlePath(n, width)}`);
    if (bytes === null) throw new Error(`bundle ${String(n)} missing`);
    out.push(...decodeBundle(bytes));
  }
  return out;
}

describe('eventId', () => {
  const fields = {
    bucket: MONITORED,
    key: 'k',
    action: 'PutObject',
    etag: 'e',
    eventTime: '2026-10-02T12:00:00.000Z',
  };

  it('is hex SHA-256 of the canonical JSON array [bucket, key, action, etag, eventTime]', async () => {
    const preimage = `["${MONITORED}","k","PutObject","e","2026-10-02T12:00:00.000Z"]`;
    const want = toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', utf8Encode(preimage))));
    expect(await eventId(fields)).toBe(want);
    // Deletes have no etag; it is encoded as null, not as an empty or "null" string.
    const noEtag = `["${MONITORED}","k","DeleteObject",null,"2026-10-02T12:00:00.000Z"]`;
    expect(await eventId({ ...fields, action: 'DeleteObject', etag: undefined })).toBe(
      toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', utf8Encode(noEtag)))),
    );
  });

  it('depends on every field', async () => {
    const base = await eventId(fields);
    for (const [k, v] of Object.entries({
      bucket: 'other-bucket',
      key: 'k2',
      action: 'CopyObject',
      etag: 'f',
      eventTime: '2026-10-02T12:00:00.001Z',
    })) {
      expect(await eventId({ ...fields, [k]: v })).not.toBe(base);
    }
    expect(await eventId({ ...fields, etag: undefined })).not.toBe(base);
    expect(await eventId({ ...fields, etag: 'null' })).not.toBe(
      await eventId({ ...fields, etag: undefined }),
    );
  });

  it('cannot be forged by moving a separator between key and etag', async () => {
    // With "bucket|key|action|etag|eventTime" (PLAN §5.4) these two events collide, because keys
    // and ETags may both contain '|'. A collision would make the second event a "duplicate".
    const a = await eventId({ ...fields, key: 'a', etag: 'b|PutObject|c' });
    const b = await eventId({ ...fields, key: 'a|PutObject|b', etag: 'c' });
    expect(a).not.toBe(b);
  });
});

describe('classifyMessage', () => {
  it('turns a PutObject notification into an object.event entry without the account', async () => {
    const c = await classifyMessage(
      put('photos/cat.jpg', '2024-05-24T19:36:44.379Z'),
      config,
      INGESTED_AT,
    );
    if (c.kind !== 'event') throw new Error('expected an event');
    expect(c.item.eventId).toMatch(/^[0-9a-f]{64}$/);
    expect(new TextDecoder().decode(c.item.entry)).not.toContain(SIM_ACCOUNT);
    expect(decodeEntry(c.item.entry)).toEqual({
      known: true,
      entry: {
        v: 1,
        type: 'object.event',
        bucket: MONITORED,
        key: 'photos/cat.jpg',
        action: 'PutObject',
        size: 65536,
        etag: ETAG,
        eventTime: '2024-05-24T19:36:44.379Z',
        ingestedAt: INGESTED_AT,
      },
    });
  });

  it('accepts delete events, which carry no size or eTag', async () => {
    for (const action of ['DeleteObject', 'LifecycleDeletion']) {
      const e = await classifyEvent(del('gone', '2026-10-02T12:00:00Z', action));
      expect(e.action).toBe(action);
      expect('size' in e || 'etag' in e).toBe(false);
    }
  });

  it('maps copySource {bucket, object} to {bucket, key} on CopyObject', async () => {
    const e = await classifyEvent(
      put('dst', '2026-10-02T12:00:00Z', {
        action: 'CopyObject',
        copySource: { bucket: 'source-bucket', object: 'src/key' },
      }),
    );
    expect(e.copySource).toEqual({ bucket: 'source-bucket', key: 'src/key' });
  });

  it('accepts multipart completions with a non-MD5 ETag', async () => {
    const e = await classifyEvent(
      put('big', '2026-10-02T12:00:00Z', {
        action: 'CompleteMultipartUpload',
        object: { key: 'big', size: 1 << 30, eTag: `${ETAG}-12` },
      }),
    );
    expect(e.etag).toBe(`${ETAG}-12`);
  });

  it('ignores fields it does not know, and does not log them', async () => {
    const e = await classifyEvent({
      ...put('k', '2026-10-02T12:00:00Z'),
      futureField: 'x',
      object: { key: 'k', size: 1, eTag: ETAG, versionId: 'v1' },
    });
    expect(Object.keys(e).sort()).toEqual(
      ['action', 'bucket', 'etag', 'eventTime', 'ingestedAt', 'key', 'size', 'type', 'v'].sort(),
    );
  });

  it('drops events from the log bucket before anything else is checked (I8)', async () => {
    expect(
      await classifyMessage(put('t', 'x', { bucket: LOG_BUCKET }), config, INGESTED_AT),
    ).toEqual({
      kind: 'loop',
    });
    expect(
      await classifyMessage({ bucket: LOG_BUCKET, action: 'nonsense' }, config, INGESTED_AT),
    ).toEqual({ kind: 'loop' });
  });

  it('drops events from buckets it does not monitor', async () => {
    const c = await classifyMessage(
      put('k', '2026-10-02T12:00:00Z', { bucket: 'some-other-bucket' }),
      config,
      INGESTED_AT,
    );
    expect(c).toEqual({ kind: 'foreign' });
  });

  it('rejects every malformed shape, with a reason that does not echo the input', async () => {
    const { messages } = simulate({ count: 0, bucket: MONITORED, malformed: 12 });
    const extra: unknown[] = [
      [],
      { ...put('k', '2026-10-02T12:00:00Z'), object: 'k' },
      { ...put('k', '2026-10-02T12:00:00Z'), object: { key: 7 } },
      { ...put('k', '2026-10-02T12:00:00Z'), object: { key: 'k', size: '5', eTag: ETAG } },
      { ...put('k', '2026-10-02T12:00:00Z'), object: { key: 'k', size: 5, eTag: null } },
      { ...put('k', '2026-10-02T12:00:00Z'), eventTime: 1716579404379 },
      { ...put('k', '2026-10-02T12:00:00Z'), action: 'CopyObject', copySource: 'src' },
      {
        ...put('k', '2026-10-02T12:00:00Z'),
        object: { key: 'k'.repeat(1025), size: 1, eTag: ETAG },
      },
      { ...put('k', '2026-10-02T13:00:00+25:00') },
      { ...put('secret/name', '2026-10-02T12:00:00Z'), object: { key: 'secret/name', size: -1 } },
    ];
    for (const body of [...messages, ...extra]) {
      const c = await classifyMessage(body, config, INGESTED_AT);
      expect(c, JSON.stringify(body)).toMatchObject({ kind: 'invalid' });
      if (c.kind === 'invalid') {
        expect(c.reason).not.toContain('bad/');
        expect(c.reason).not.toContain('secret');
        expect(c.reason.length).toBeLessThanOrEqual(200);
      }
    }
  });
});

describe('consumeBatch', () => {
  class FakeSink implements IngestSink {
    readonly calls: { items: AppendItem[]; report: IngestReport }[] = [];
    fail = false;
    ingest(items: AppendItem[], report: IngestReport): Promise<AppendResult> {
      this.calls.push({ items, report });
      if (this.fail) return Promise.reject(new Error('sequencer unavailable'));
      return Promise.resolve({ accepted: items.length, duplicates: 0, firstSeq: 0 });
    }
  }
  const deps = (sink: IngestSink) => ({
    config,
    sink,
    blinder: null,
    now: () => Date.parse(INGESTED_AT),
  });

  it('sends valid events and counts the rest in one call, then acks the batch', async () => {
    const sink = new FakeSink();
    const batch = batchOf([
      put('a', '2026-10-02T12:00:00Z'),
      'garbage',
      put('b', '2026-10-02T12:00:01Z', { bucket: LOG_BUCKET }),
      del('c', '2026-10-02T12:00:02Z'),
      put('d', '2026-10-02T12:00:03Z', { bucket: 'some-other-bucket' }),
    ]);
    await consumeBatch(batch, deps(sink));
    expect(sink.calls).toHaveLength(1);
    const [call] = sink.calls;
    expect(call?.items).toHaveLength(2);
    expect(call?.report).toMatchObject({
      invalid: 1,
      loopDropped: 1,
      foreignDropped: 1,
      deadLettered: 0,
    });
    expect(call?.report.lastInvalid).toBeTypeOf('string');
    const result = await getQueueResult(batch, createExecutionContext());
    expect(result.ackAll).toBe(true);
    expect(result.retryBatch.retry).toBe(false);
  });

  it('still records the counts when nothing in the batch is loggable', async () => {
    const sink = new FakeSink();
    await consumeBatch(batchOf(['x', null]), deps(sink));
    expect(sink.calls).toEqual([
      {
        items: [],
        report: expect.objectContaining({ invalid: 2, loopDropped: 0 }) as IngestReport,
      },
    ]);
  });

  it('retries the whole batch with backoff if the sequencer call fails', async () => {
    const sink = new FakeSink();
    sink.fail = true;
    const batch = batchOf([put('a', '2026-10-02T12:00:00Z'), 'garbage'], QUEUE, 3);
    // The test pool's retryAll() ignores its options (plugin 1.3.6), so record them here.
    const retryOptions: (QueueRetryOptions | undefined)[] = [];
    const spy: MessageBatch = {
      queue: batch.queue,
      metadata: batch.metadata,
      messages: batch.messages,
      ackAll: () => {
        batch.ackAll();
      },
      retryAll: (o) => {
        retryOptions.push(o);
        batch.retryAll(o);
      },
    };
    await consumeBatch(spy, deps(sink)); // does not throw: the retry is explicit
    const result = await getQueueResult(batch, createExecutionContext());
    expect(result.ackAll).toBe(false);
    expect(result.explicitAcks).toEqual([]);
    expect(result.retryBatch.retry).toBe(true);
    expect(retryOptions).toEqual([{ delaySeconds: retryDelaySeconds(3) }]);
  });

  it('counts messages arriving from the dead-letter queue and logs them like any other', async () => {
    const sink = new FakeSink();
    await consumeBatch(batchOf([put('a', '2026-10-02T12:00:00Z'), 'garbage'], DLQ), deps(sink));
    expect(sink.calls[0]?.items).toHaveLength(1);
    expect(sink.calls[0]?.report).toMatchObject({ deadLettered: 2, invalid: 1 });
  });

  it('backs off exponentially from 10 s, capped at 5 minutes', () => {
    expect([1, 2, 3, 4, 5, 6, 7, 100].map(retryDelaySeconds)).toEqual([
      10, 20, 40, 80, 160, 300, 300, 300,
    ]);
  });
});

describe('queue handler end to end (real Sequencer)', () => {
  it('logs simulated traffic exactly once despite duplicates, reordering and junk (I5, I8)', async () => {
    const { messages, manifest } = simulate({
      count: 300,
      bucket: MONITORED,
      seed: 7,
      duplicateRate: 0.2,
      shuffleWindow: 25,
      malformed: 12,
      loop: 5,
      logBucket: LOG_BUCKET,
      foreign: 4,
    });
    expect(manifest.duplicates).toBeGreaterThan(0);
    expect(manifest.deletes).toBeGreaterThan(0);
    await deliver(messages);

    const s = sequencer();
    await s.publish();
    const status = await s.status();
    expect(status.publishedSize).toBe(manifest.accepted);
    expect(status.ingest).toMatchObject({
      accepted: manifest.accepted,
      duplicates: manifest.duplicates,
      invalid: manifest.invalid,
      loopDropped: manifest.loopDropped,
      foreignDropped: manifest.foreignDropped,
      deadLettered: 0,
    });

    // Out-of-order delivery does not change the expected state: the latest eventTime wins.
    const objects = await s.getObjectStates({ limit: 1000 });
    expect(objects.map(({ key, deleted, etag, size }) => ({ key, deleted, etag, size }))).toEqual(
      manifest.objects,
    );

    // I8, checked on what was actually published: only the monitored bucket, and no account IDs.
    const entries = await publishedEntries(status.publishedSize);
    expect(entries).toHaveLength(manifest.accepted);
    for (const bytes of entries) {
      const d = decodeEntry(bytes);
      expect(d.known && d.entry.type === 'object.event' && d.entry.bucket).toBe(MONITORED);
      expect(new TextDecoder().decode(bytes)).not.toContain(SIM_ACCOUNT);
    }

    // Replaying the whole stream (e.g. a consumer restart) adds nothing to the log.
    await deliver(messages);
    await s.publish();
    const after = await s.status();
    expect(after.publishedSize).toBe(manifest.accepted);
    expect(after.ingest.duplicates).toBe(
      manifest.duplicates + manifest.accepted + manifest.duplicates,
    );
  });

  it('records each event once when overlapping batches are delivered concurrently (I5)', async () => {
    const { messages, manifest } = simulate({ count: 60, bucket: MONITORED, seed: 3 });
    const batches = [messages, messages.slice(10), messages.slice(0, 40), messages.slice(30)];
    await Promise.all(batches.map((b) => deliver(b)));
    const status = await sequencer().status();
    expect(status.durableSize).toBe(manifest.accepted);
    expect(status.ingest.accepted).toBe(manifest.accepted);
  });

  it('applies a delete delivered before the put it follows', async () => {
    await deliver([del('k', '2026-10-02T12:00:02Z'), put('k', '2026-10-02T12:00:01Z')]);
    const s = sequencer();
    await s.publish();
    expect(await s.getObjectStates({ limit: 10 })).toMatchObject([
      { key: 'k', deleted: true, etag: null, size: null, seq: 0 },
    ]);
    expect((await s.lookup('k')).indexes).toEqual([0, 1]); // log order is ingestion order
  });

  it('never logs events from the log bucket (I8)', async () => {
    const { messages } = simulate({ count: 0, bucket: MONITORED, loop: 30, logBucket: LOG_BUCKET });
    await deliver(messages);
    const status = await sequencer().status();
    expect(status.durableSize).toBe(0);
    expect(status.ingest.loopDropped).toBe(30);
    expect(status.alarmAt).toBeNull();
  });

  it('logs dead-lettered events that were never appended, and dedupes those that were', async () => {
    await deliver([put('a', '2026-10-02T12:00:00Z')]);
    await deliver([put('a', '2026-10-02T12:00:00Z'), put('b', '2026-10-02T12:00:01Z')], DLQ);
    const status = await sequencer().status();
    expect(status.durableSize).toBe(2);
    expect(status.ingest).toMatchObject({ accepted: 2, duplicates: 1, deadLettered: 2 });
  });

  it('keeps the last rejection reason for /status', async () => {
    await deliver([{ ...put('k', '2026-10-02T12:00:00Z'), action: 'PutObjectAcl' }]);
    const { ingest } = await sequencer().status();
    expect(ingest.invalid).toBe(1);
    expect(ingest.lastInvalid?.reason).toMatch(/action/);
    expect(ingest.lastInvalid?.at).toBeTypeOf('number');
  });
});

describe('Sequencer.ingest validation', () => {
  it('rejects malformed reports without storing anything', async () => {
    await runInDurableObject(sequencer(), async (instance, state) => {
      const zero = { invalid: 0, loopDropped: 0, foreignDropped: 0, deadLettered: 0 };
      const bad: unknown[] = [
        { ...zero, invalid: -1 },
        { ...zero, loopDropped: 1.5 },
        { ...zero, deadLettered: '1' },
        { ...zero, lastInvalid: 'x'.repeat(201) },
        { invalid: 0 },
      ];
      for (const report of bad) {
        await expect(instance.ingest([], report as IngestReport)).rejects.toThrow(AppendError);
      }
      expect(state.storage.sql.exec('SELECT COUNT(*) AS n FROM counters').one().n).toBe(0);
      // An empty batch with a valid report is fine (a batch of nothing but junk).
      expect(await instance.ingest([], { ...zero, invalid: 3 })).toEqual({
        accepted: 0,
        duplicates: 0,
        firstSeq: null,
      });
    });
  });
});

describe('GET /api/v1/status', () => {
  it('reports log size, staging depth and ingest counters as JSON', async () => {
    await deliver([
      put('a', '2026-10-02T12:00:00Z'),
      'junk',
      put('b', 'x', { bucket: LOG_BUCKET }),
    ]);
    const res = await exports.default.fetch(
      new Request('https://r2notary.example.com/api/v1/status', {
        headers: { authorization: `Bearer ${env.READ_TOKEN}` },
      }),
    );
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toBe('application/json; charset=utf-8');
    expect(res.headers.get('cache-control')).toBe('no-store');
    const body: unknown = await res.json();
    expect(body).toMatchObject({
      log: env.LOG_NAME,
      origin: env.LOG_ORIGIN,
      size: 0,
      durableSize: 1,
      pending: 1,
      lastCheckpointAt: null,
      lastError: null,
      ingest: {
        accepted: 1,
        duplicates: 0,
        invalid: 1,
        loopDropped: 1,
        foreignDropped: 0,
        deadLettered: 0,
      },
    });
  });

  it('only answers GET and HEAD (and CORS preflights)', async () => {
    const res = await exports.default.fetch(
      new Request('https://r2notary.example.com/api/v1/status', { method: 'POST' }),
    );
    expect(res.status).toBe(405);
    expect(res.headers.get('allow')).toBe('GET, HEAD, OPTIONS');
  });
});

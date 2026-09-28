// The Sequencer DO through its RPC surface: append/dedupe (I5), validation, alarm scheduling, the
// single-flight publish, and the objects/key_index view.
import { encodeEntry, utf8Encode } from '@r2notary/core';
import { env } from 'cloudflare:workers';
import { reset, runDurableObjectAlarm, runInDurableObject } from 'cloudflare:test';
import { afterEach, describe, expect, it } from 'vitest';
import {
  AppendError,
  MAX_APPEND_ITEMS,
  PUBLISH_RETRY_MS,
  publicationDue,
} from '../src/sequencer.ts';
import { SCHEMA_VERSION, SequencerStore, eventMillis } from '../src/store.ts';
import { BUCKET, items, liveCheckpoint, objectEvent, withStore } from './helpers.ts';

// Every Sequencer here publishes under the configured LOG_NAME, so wipe R2 and DO storage between
// tests to keep one test's tiles from colliding with another's.
afterEach(() => reset());

const LOG = env.LOG_NAME;
let unique = 0;
function stub(): DurableObjectStub<import('../src/sequencer.ts').Sequencer> {
  unique++;
  return env.SEQUENCER.getByName(`seq-${String(unique)}`);
}

describe('append and dedupe (I5)', () => {
  it('assigns consecutive sequence numbers and reports duplicates', async () => {
    const s = stub();
    expect(await s.append(items(3))).toEqual({ accepted: 3, duplicates: 0, firstSeq: 0 });
    // Redelivery of the same batch, a batch with a repeat inside it, and a mix.
    expect(await s.append(items(3))).toEqual({ accepted: 0, duplicates: 3, firstSeq: null });
    const repeat = [...items(1, 10), ...items(1, 10)];
    expect(await s.append(repeat)).toEqual({ accepted: 1, duplicates: 1, firstSeq: 3 });
    expect(await s.append(items(4, 2))).toEqual({ accepted: 3, duplicates: 1, firstSeq: 4 });
    expect((await s.status()).durableSize).toBe(7);
  });

  it('records each event once under concurrent duplicate deliveries', async () => {
    const s = stub();
    const results = await Promise.all(
      Array.from({ length: 8 }, (_, k) => s.append(items(50, k * 10))),
    );
    // Batches overlap: ids 0..119 in total.
    expect(results.reduce((n, r) => n + r.accepted, 0)).toBe(120);
    expect((await s.status()).durableSize).toBe(120);
  });

  it('keeps dedupe records after the entries are published', async () => {
    const s = stub();
    await s.append(items(5));
    await s.publish();
    expect(await s.append(items(5))).toMatchObject({ accepted: 0, duplicates: 5 });
  });

  it('accepts an event again once its dedupe window has passed, and prunes old records', async () => {
    await withStore('ttl', (store) => {
      const [item] = items(1);
      if (item === undefined) throw new Error('unreachable');
      expect(store.append([item], 1_000, 500).accepted).toBe(1);
      expect(store.append([item], 1_499, 500).duplicates).toBe(1);
      expect(store.append([item], 1_500, 500).accepted).toBe(1); // window is [t, t + ttl)
      store.pruneSeen(10_000);
      expect(store.append([item], 10_000, 500).accepted).toBe(1);
      expect(store.nextSeq()).toBe(3);
    });
  });

  it('rejects malformed calls without storing anything', async () => {
    const s = stub();
    const bad: [string, unknown][] = [
      ['empty batch', []],
      ['too many items', items(MAX_APPEND_ITEMS + 1)],
      ['empty eventId', [{ eventId: '', entry: objectEvent(0) }]],
      ['eventId with a space', [{ eventId: 'a b', entry: objectEvent(0) }]],
      ['entry not bytes', [{ eventId: 'x', entry: 'nope' }]],
      ['non-canonical entry', [{ eventId: 'x', entry: utf8Encode('{ "v":1}') }]],
      ['unknown type', [{ eventId: 'x', entry: utf8Encode('{"type":"future","v":1}') }]],
      [
        'foreign bucket',
        [
          {
            eventId: 'x',
            entry: encodeEntry({
              v: 1,
              type: 'object.event',
              bucket: 'some-other-bucket',
              key: 'k',
              action: 'DeleteObject',
              eventTime: '2026-10-02T12:00:00Z',
              ingestedAt: '2026-10-02T12:00:00Z',
            }),
          },
        ],
      ],
    ];
    // A valid item alongside an invalid one is rejected too: the call is all-or-nothing.
    bad.push(['one bad item', [...items(1), { eventId: 'y', entry: utf8Encode('{}') }]]);
    // Called on the instance, not over RPC: the test pool reports every rejected RPC call as an
    // unhandled rejection even when the test awaits it (DECISIONS D2.9).
    await runInDurableObject(s, async (instance) => {
      for (const [what, arg] of bad) {
        await expect(instance.append(arg as never), what).rejects.toThrow(AppendError);
      }
    });
    expect((await s.status()).durableSize).toBe(0);
  });
});

describe('alarm-driven publication', () => {
  it('computes the deadline from the oldest pending entry', () => {
    const base = { now: 10_000, batchMaxEntries: 500, checkpointIntervalMs: 5000 };
    expect(publicationDue({ ...base, pending: 0, oldestPendingAt: null })).toBeNull();
    expect(publicationDue({ ...base, pending: 3, oldestPendingAt: 9_000 })).toBe(14_000);
    // Leftovers of a drained backlog are already overdue: publish now, not one interval later.
    expect(publicationDue({ ...base, pending: 3, oldestPendingAt: 1_000 })).toBe(10_000);
    expect(publicationDue({ ...base, pending: 500, oldestPendingAt: 9_999 })).toBe(10_000);
  });

  it('schedules a publication one interval after entries arrive', async () => {
    const s = stub();
    const before = Date.now();
    await s.append(items(3));
    const { alarmAt } = await s.status();
    expect(alarmAt).not.toBeNull();
    expect(alarmAt ?? 0).toBeGreaterThanOrEqual(before + Number(env.CHECKPOINT_INTERVAL_MS));

    // A later append keeps the earlier deadline.
    await s.append(items(1, 3));
    expect((await s.status()).alarmAt).toBe(alarmAt);

    expect(await runDurableObjectAlarm(s)).toBe(true);
    const status = await s.status();
    expect(status).toMatchObject({ publishedSize: 4, pending: 0, alarmAt: null, lastError: null });
    expect((await liveCheckpoint(LOG))?.size).toBe(4);
  });

  it('publishes immediately once a full batch is waiting, and drains a backlog', async () => {
    const s = stub();
    const batch = Number(env.BATCH_MAX_ENTRIES);
    for (let i = 0; i < 2 * batch + 100; i += MAX_APPEND_ITEMS) {
      await s.append(items(Math.min(MAX_APPEND_ITEMS, 2 * batch + 100 - i), i));
    }
    // Due now (the runtime may already have started it, so it can also be gone).
    expect((await s.status()).alarmAt ?? 0).toBeLessThanOrEqual(Date.now());
    // Each run publishes one batch and re-arms the alarm while a backlog remains. The runtime
    // may also fire the due alarm by itself, so drive it until done rather than counting runs.
    for (let tries = 0; (await s.status()).pending > 0 && tries < 20; tries++) {
      if (!(await runDurableObjectAlarm(s))) await scheduler.wait(50);
    }
    expect(await s.status()).toMatchObject({ publishedSize: 2 * batch + 100, pending: 0 });
    const archived = await env.LOG.list({ prefix: `${LOG}/x-checkpoints/` });
    expect(archived.objects.map((o) => o.key).sort()).toEqual(
      [batch, 2 * batch, 2 * batch + 100].map((n) => `${LOG}/x-checkpoints/${String(n)}`).sort(),
    );
  });

  it('sets no alarm when every item was a duplicate of a published event', async () => {
    const s = stub();
    await s.append(items(2));
    await s.publish();
    await runInDurableObject(s, (_, state) => state.storage.deleteAlarm());
    await s.append(items(2));
    expect((await s.status()).alarmAt).toBeNull();
  });

  it('shares one run between overlapping publish calls', async () => {
    const s = stub();
    await s.append(items(10));
    const [a, b] = await runInDurableObject(s, (instance) => {
      const first = instance.publish();
      const second = instance.publish();
      expect(second).toBe(first);
      return Promise.all([first, second]);
    });
    expect(a).toEqual(b);
    expect(a.size).toBe(10);
    const archived = await env.LOG.list({ prefix: `${LOG}/x-checkpoints/` });
    expect(archived.objects.map((o) => o.key)).toEqual([`${LOG}/x-checkpoints/10`]);
  });

  it('surfaces a failed publication in status, and the alarm schedules its own retry', async () => {
    const s = stub();
    await env.LOG.put(`${LOG}/tile/0/000.p/2`, 'conflict');
    await s.append(items(2));
    await runInDurableObject(s, async (instance) => {
      await expect(instance.publish()).rejects.toThrow(/TILE_DIVERGENCE/);
      expect((await instance.status()).lastError).toMatch(/TILE_DIVERGENCE/);
      const before = Date.now();
      await instance.alarm();
      const status = await instance.status();
      expect(status.lastError).toMatch(/TILE_DIVERGENCE/);
      expect(status.alarmAt ?? 0).toBeGreaterThanOrEqual(before + PUBLISH_RETRY_MS);
    });
    expect((await s.status()).publishedSize).toBe(0);
  });
});

describe('objects view and key index', () => {
  const at = (s: string) => `2026-10-02T12:00:${s}Z`;

  it('applies published events in order, keeping the newest eventTime per key', async () => {
    const s = stub();
    const ev = (i: number, key: string, o: Parameters<typeof objectEvent>[1] = {}) => ({
      eventId: `e${String(i)}`,
      entry: objectEvent(i, { key, ...o }),
    });
    await s.append([
      ev(0, 'a', { etag: 'a1', eventTime: at('01') }),
      ev(1, 'a', { etag: 'a2', eventTime: at('03') }),
      ev(2, 'a', { etag: 'late', eventTime: at('02') }), // delivered late: ignored
      ev(3, 'b', { etag: 'b1', eventTime: at('01') }),
      ev(4, 'b', { action: 'DeleteObject', eventTime: at('05') }),
      ev(5, 'c', { etag: 'c1', eventTime: at('07') }),
      ev(6, 'c', { etag: 'c2', eventTime: '2026-10-02T13:00:07+01:00' }), // same instant: later seq wins
    ]);
    // Not visible to the auditor until published.
    expect(await s.getObjectStates({ limit: 10 })).toEqual([]);
    await s.publish();

    expect(await s.getObjectStates({ limit: 10 })).toEqual([
      { key: 'a', etag: 'a2', size: 1, eventTime: at('03'), seq: 1, deleted: false },
      { key: 'b', etag: null, size: null, eventTime: at('05'), seq: 4, deleted: true },
      {
        key: 'c',
        etag: 'c2',
        size: 6,
        eventTime: '2026-10-02T13:00:07+01:00',
        seq: 6,
        deleted: false,
      },
    ]);
    expect(await s.lookup('a')).toEqual({ size: 7, indexes: [0, 1, 2] });
    expect((await s.lookup('a', { after: 0, limit: 1 })).indexes).toEqual([1]);
    expect((await s.lookup('missing')).indexes).toEqual([]);
    expect(await s.getObjectStates({ after: 'a', through: 'b', limit: 10 })).toHaveLength(1);
    expect(await s.getObjectStates({ after: 'a', limit: 1 })).toMatchObject([{ key: 'b' }]);
    await runInDurableObject(s, (instance) => {
      expect(() => instance.getObjectStates({ limit: 0 })).toThrow(RangeError);
    });
  });

  it('records snapshots and indexes findings without changing the expected state', async () => {
    const s = stub();
    await s.append([
      {
        eventId: 'snap',
        entry: encodeEntry({
          v: 1,
          type: 'object.snapshot',
          bucket: BUCKET,
          key: 'k',
          size: 9,
          etag: 'snap-etag',
          uploaded: at('00'),
          snapshotId: 'backfill-1',
        }),
      },
      {
        eventId: 'finding',
        entry: encodeEntry({
          v: 1,
          type: 'audit.finding',
          kind: 'UNLOGGED_OBJECT',
          bucket: BUCKET,
          key: 'k',
          observed: { etag: 'other', size: 1, uploaded: at('09') },
          scanId: 'scan-1',
          observedAt: at('10'),
          graceSeconds: 300,
        }),
      },
      {
        eventId: 'scan',
        entry: encodeEntry({ v: 1, type: 'audit.scan', scanId: 'scan-1', phase: 'start' }),
      },
    ]);
    await s.publish();
    expect(await s.getObjectStates({ limit: 10 })).toMatchObject([
      { key: 'k', etag: 'snap-etag', size: 9, seq: 0, deleted: false },
    ]);
    expect((await s.lookup('k')).indexes).toEqual([0, 1]);
  });
});

/** Removes what schema v3 (M6) added, as a database written by M3-M5 would look. */
function rollBackV3(sql: SqlStorage): void {
  for (const t of ['scrub_state', 'scans', 'scan_candidates', 'scan_findings']) {
    sql.exec(`DROP TABLE ${t}`);
  }
  sql.exec('DROP INDEX objects_live');
}

describe('store internals', () => {
  it('migrations are idempotent and record the schema version', async () => {
    const s = stub();
    await runInDurableObject(s, (_, state) => {
      const store = new SequencerStore(state.storage);
      store.migrate();
      store.migrate();
      expect(
        state.storage.sql.exec('SELECT v FROM meta WHERE k = ?', 'schema_version').one().v,
      ).toBe(SCHEMA_VERSION);
    });
  });

  it('upgrades a v1 database to v2 (counters) without touching its entries', async () => {
    const s = stub();
    await s.append(items(3));
    await runInDurableObject(s, (_, state) => {
      // Roll the schema back to what M2 shipped.
      rollBackV3(state.storage.sql);
      state.storage.sql.exec('DROP TABLE counters');
      state.storage.sql.exec("UPDATE meta SET v = 1 WHERE k = 'schema_version'");
      const store = new SequencerStore(state.storage);
      store.migrate();
      expect(store.nextSeq()).toBe(3);
      expect(store.readEntries(0, 3)).toHaveLength(3);
      expect(store.ingestCounters()).toMatchObject({ accepted: 0, invalid: 0, lastInvalid: null });
    });
  });

  it('upgrades a v2 database to v3 (auditor tables) and serves its objects view', async () => {
    const s = stub();
    await s.append([
      ...items(2),
      {
        eventId: 'del',
        entry: objectEvent(9, {
          key: 'obj/1',
          action: 'DeleteObject',
          eventTime: '2026-10-02T13:00:00Z',
        }),
      },
    ]);
    await s.publish();
    await runInDurableObject(s, (_, state) => {
      rollBackV3(state.storage.sql);
      state.storage.sql.exec("UPDATE meta SET v = 2 WHERE k = 'schema_version'");
      const store = new SequencerStore(state.storage);
      store.migrate();
      expect(store.objectStates({ limit: 10, liveOnly: true }).map((o) => o.key)).toEqual([
        'obj/0',
      ]);
      expect(store.objectState('obj/1')).toMatchObject({ deleted: true, seq: 2 });
      expect(store.scrubState('obj/0')).toBeNull();
    });
  });

  it('refuses to open a database written by a newer schema', async () => {
    const s = stub();
    await runInDurableObject(s, (_, state) => {
      state.storage.sql.exec("UPDATE meta SET v = 99 WHERE k = 'schema_version'");
      expect(() => {
        new SequencerStore(state.storage).migrate();
      }).toThrow(/newer/);
    });
  });

  it('rolls back a commit that fails part-way', async () => {
    await withStore('rollback', (store) => {
      store.append(items(3), 0, 1000);
      const tree = { size: 3, partials: [new Uint8Array(96)] };
      // The third entry is not a valid entry, so applying it throws after tile_state was replaced.
      const entries = [...store.readEntries(0, 2), utf8Encode('{}')];
      expect(() => {
        store.commitPublish(0, tree, entries, 0);
      }).toThrow();
      expect(store.publishedSize()).toBe(0);
      expect(store.loadLogState().tree.partials).toEqual([]);
      expect(store.readEntries(0, 3)).toHaveLength(3);
      // And a commit from the wrong starting size is refused outright.
      expect(() => {
        store.commitPublish(1, tree, entries, 0);
      }).toThrow(/published_size/);
    });
  });

  it('parses RFC 3339 times independently of Date.parse', () => {
    expect(eventMillis('1970-01-01T00:00:00Z')).toBe(0);
    expect(eventMillis('1970-01-01T01:00:00.5+01:00')).toBe(500);
    expect(eventMillis('1969-12-31T23:59:59.999999999-00:00')).toBe(-1);
    expect(eventMillis('0001-01-01T00:00:00Z')).toBe(-62_135_596_800_000); // not 1901
    expect(() => eventMillis('2026-10-02 12:00:00Z')).toThrow();
  });
});

// The auditor's state machine in the Sequencer's SQLite (worker/src/audit/store.ts), driven with
// explicit clocks: scan lifecycle, exactly-once pages, confirmation after the grace window,
// deep-scrub drift, reports, and backfill.
import { decodeEntry, utf8Decode, type DecodedEntry } from '@r2notary/core';
import { env } from 'cloudflare:workers';
import { reset, runInDurableObject } from 'cloudflare:test';
import { afterEach, describe, expect, it } from 'vitest';
import {
  AuditInputError,
  AuditStore,
  STALE_SCAN_MS,
  type ScanContext,
  type ScrubObservation,
} from '../src/audit/store.ts';
import type { ListedObject } from '../src/audit/reconcile.ts';
import { SequencerStore } from '../src/store.ts';
import { BUCKET, objectEvent } from './helpers.ts';

afterEach(() => reset());

const T = Date.parse('2026-10-02T12:00:00.000Z');
const OLD = '2026-01-01T00:00:00.000Z';
const SHA_A = 'a'.repeat(64);
const SHA_B = 'b'.repeat(64);
let unique = 0;

function ctx(now: number): ScanContext {
  return { now, ttlMs: 86_400_000, bucket: BUCKET };
}

function obj(key: string, o: Partial<ListedObject> = {}): ListedObject {
  return { key, etag: 'e1', size: 1, uploaded: Date.parse(OLD), ...o };
}

/** A fresh Sequencer, its log seeded with `events` (published), and a function to run in it. */
async function sequencer(events: Uint8Array[] = []): Promise<{
  stub: DurableObjectStub<import('../src/sequencer.ts').Sequencer>;
  run: <R>(fn: (audit: AuditStore, log: SequencerStore) => R) => Promise<R>;
}> {
  unique++;
  const stub = env.SEQUENCER.getByName(`audit-store-${String(unique)}`);
  if (events.length > 0) {
    await stub.append(events.map((entry, i) => ({ eventId: `seed-${String(i)}`, entry })));
    await stub.publish();
  }
  return {
    stub,
    run: (fn) =>
      runInDurableObject(stub, (_, state) => {
        const log = new SequencerStore(state.storage);
        return fn(new AuditStore(state.storage, log), log);
      }),
  };
}

function entryAt(log: SequencerStore, seq: number): DecodedEntry {
  const [bytes] = log.readEntries(seq, seq + 1);
  if (bytes === undefined) throw new Error(`no entry ${String(seq)}`);
  return decodeEntry(bytes);
}

describe('scan lifecycle', () => {
  it('start records audit.scan start with the published size, and is idempotent', async () => {
    const s = await sequencer([objectEvent(0), objectEvent(1)]);
    await s.run((audit, log) => {
      const r = audit.start('scan-a', 'audit', 300, ctx(T));
      expect(r).toMatchObject({
        ok: true,
        scan: { scanId: 'scan-a', state: 'listing', logSizeAtStart: 2, startIndex: 2, pages: 0 },
      });
      expect(entryAt(log, 2)).toEqual({
        known: true,
        entry: { v: 1, type: 'audit.scan', scanId: 'scan-a', phase: 'start', logSizeAtStart: 2 },
      });
      // A retried start returns the same scan and appends nothing.
      expect(audit.start('scan-a', 'audit', 300, ctx(T + 1))).toEqual(r);
      expect(log.nextSeq()).toBe(3);
      expect(audit.start('scan-a', 'backfill', 300, ctx(T))).toMatchObject({ ok: false });
    });
  });

  it('allows one active scan, and lets a new one abandon a scan idle for a day', async () => {
    const s = await sequencer();
    await s.run((audit) => {
      audit.start('scan-a', 'audit', 300, ctx(T));
      audit.page(
        {
          scanId: 'scan-a',
          page: 0,
          after: null,
          listed: [obj('k')],
          listTruncated: true,
          liveLimit: 10,
        },
        ctx(T),
      );
      expect(audit.start('scan-b', 'backfill', 300, ctx(T + STALE_SCAN_MS - 1))).toEqual({
        ok: false,
        reason: 'scan scan-a is in progress',
      });
      expect(audit.start('scan-b', 'audit', 300, ctx(T + STALE_SCAN_MS))).toMatchObject({
        ok: true,
      });
      expect(audit.get('scan-a')).toMatchObject({ state: 'abandoned', pending: 0 });
      expect(audit.active()?.scanId).toBe('scan-b');
    });
  });

  it('rejects scan IDs that cannot be an R2 key segment or Workflow instance ID', async () => {
    const s = await sequencer();
    await s.run((audit) => {
      for (const id of ['', 'a.b', 'a/b', '-a', 'x'.repeat(65), 'é']) {
        expect(() => audit.start(id, 'audit', 300, ctx(T)), id).toThrow(AuditInputError);
      }
    });
  });
});

describe('pages', () => {
  it('applies each page once: a repeated page returns its stored result', async () => {
    const s = await sequencer([objectEvent(0, { key: 'logged', eventTime: OLD })]);
    await s.run((audit, log) => {
      audit.start('scan-a', 'audit', 0, ctx(T));
      const req = {
        scanId: 'scan-a',
        page: 0,
        after: null,
        listed: [obj('a'), obj('b')],
        listTruncated: true,
        liveLimit: 10,
      };
      const first = audit.page(req, ctx(T));
      expect(first).toEqual({
        ok: true,
        end: 'b',
        state: 'listing',
        scanned: 2,
        candidates: 2,
        snapshots: 0,
      });
      const seq = log.nextSeq();
      expect(audit.page({ ...req, listed: [] }, ctx(T + 5))).toEqual(first);
      expect(audit.get('scan-a')).toMatchObject({ pages: 1, objectsScanned: 2, pending: 2 });
      expect(log.nextSeq()).toBe(seq);

      // Out of sequence: a skipped page, or the right page from the wrong cursor.
      expect(audit.page({ ...req, page: 2, after: 'b' }, ctx(T))).toMatchObject({ ok: false });
      expect(audit.page({ ...req, page: 1, after: 'a' }, ctx(T))).toMatchObject({ ok: false });
      const last = audit.page(
        { ...req, page: 1, after: 'b', listed: [obj('m')], listTruncated: false },
        ctx(T),
      );
      // 'logged' (between b and m) is live in the log and absent from the bucket.
      expect(last).toMatchObject({ ok: true, end: null, state: 'confirming', candidates: 2 });
      expect(audit.page({ ...req, page: 2, after: null }, ctx(T))).toEqual({
        ok: false,
        reason: 'scan scan-a is confirming',
      });
    });
  });

  it('rejects malformed listings before touching state', async () => {
    const s = await sequencer();
    await s.run((audit) => {
      audit.start('scan-a', 'audit', 0, ctx(T));
      const base = { scanId: 'scan-a', page: 0, after: null, listTruncated: false, liveLimit: 10 };
      for (const listed of [
        [obj('a', { etag: '"quoted"' })],
        [obj('a', { size: -1 })],
        [obj('')],
        [obj('a\ud800')],
      ]) {
        expect(() => audit.page({ ...base, listed }, ctx(T))).toThrow(AuditInputError);
      }
      expect(() => audit.page({ ...base, listed: [], liveLimit: 0 }, ctx(T))).toThrow(
        AuditInputError,
      );
      expect(audit.get('scan-a')?.pages).toBe(0);
    });
  });
});

describe('confirmation after the grace window', () => {
  it('waits out the grace window, then records the finding exactly as observed', async () => {
    const s = await sequencer([objectEvent(0, { key: 'missing', eventTime: OLD, etag: 'm1' })]);
    await s.run((audit, log) => {
      audit.start('scan-a', 'audit', 300, ctx(T));
      audit.page(
        { scanId: 'scan-a', page: 0, after: null, listed: [], listTruncated: false, liveLimit: 10 },
        ctx(T),
      );
      expect(audit.confirm('scan-a', 10, ctx(T + 299_000))).toEqual({
        ok: true,
        state: 'confirming',
        confirmed: 0,
        dropped: 0,
        remaining: 1,
        waitMs: 1000,
      });
      expect(audit.confirm('scan-a', 10, ctx(T + 300_000))).toMatchObject({
        confirmed: 1,
        remaining: 0,
        state: 'finishing',
      });
      expect(entryAt(log, 2)).toEqual({
        known: true,
        entry: {
          v: 1,
          type: 'audit.finding',
          kind: 'MISSING_OBJECT',
          bucket: BUCKET,
          key: 'missing',
          expected: { etag: 'm1', size: 0, eventTime: OLD, seq: 0 },
          scanId: 'scan-a',
          observedAt: new Date(T).toISOString(), // when it was seen, not when confirmed
          graceSeconds: 300,
        },
      });
      expect(audit.findings('scan-a', null, 10).map((f) => f.seq)).toEqual([2]);
      expect(audit.get('scan-a')).toMatchObject({ findings: 1, dropped: 0 });
    });
  });

  it('drops a candidate that an event published during the grace window explains', async () => {
    const s = await sequencer();
    await s.run((audit) => {
      audit.start('scan-a', 'audit', 0, ctx(T));
      audit.page(
        {
          scanId: 'scan-a',
          page: 0,
          after: null,
          listed: [obj('late'), obj('lost')],
          listTruncated: false,
          liveLimit: 10,
        },
        ctx(T),
      );
    });
    // The notification for 'late' arrives after the listing; 'lost' never gets one.
    await s.stub.append([{ eventId: 'late', entry: objectEvent(1, { key: 'late', etag: 'e1' }) }]);
    await s.stub.publish();
    await s.run((audit) => {
      expect(audit.confirm('scan-a', 10, ctx(T + 1))).toMatchObject({
        confirmed: 1,
        dropped: 1,
        remaining: 0,
      });
      expect(audit.get('scan-a')).toMatchObject({ findings: 1, dropped: 1 });
      const [f] = audit.findings('scan-a', null, 10);
      expect(f && decodeEntry(f.entry)).toMatchObject({
        entry: { kind: 'UNLOGGED_OBJECT', key: 'lost' },
      });
    });
  });

  it('confirms in batches and reports when to call again', async () => {
    const s = await sequencer();
    await s.run((audit) => {
      audit.start('scan-a', 'audit', 0, ctx(T));
      const listed = ['a', 'b', 'c'].map((k) => obj(k));
      audit.page(
        { scanId: 'scan-a', page: 0, after: null, listed, listTruncated: false, liveLimit: 10 },
        ctx(T),
      );
      expect(audit.confirm('scan-a', 2, ctx(T))).toMatchObject({
        confirmed: 2,
        remaining: 1,
        waitMs: 0,
      });
      expect(audit.confirm('scan-a', 2, ctx(T))).toMatchObject({ confirmed: 1, remaining: 0 });
      // Once finished, confirming again is a no-op.
      expect(audit.confirm('scan-a', 2, ctx(T))).toMatchObject({
        ok: true,
        confirmed: 0,
        state: 'finishing',
      });
    });
  });
});

describe('deep scrub observations', () => {
  const observation = (o: Partial<ScrubObservation> = {}): ScrubObservation => ({
    key: 'k',
    etag: 'e1',
    size: 1,
    uploaded: Date.parse(OLD),
    sha256: SHA_A,
    storedSha256: null,
    observedAt: T,
    ...o,
  });

  async function scanWith(
    s: Awaited<ReturnType<typeof sequencer>>,
    scanId: string,
    obs: ScrubObservation[],
  ): Promise<void> {
    await s.run((audit) => {
      expect(audit.start(scanId, 'audit', 0, ctx(T)).ok).toBe(true);
      audit.page(
        { scanId, page: 0, after: null, listed: [obj('k')], listTruncated: false, liveLimit: 10 },
        ctx(T),
      );
      expect(audit.observe(scanId, 0, obs, ctx(T))).toMatchObject({ ok: true });
      // A retried scrub step changes nothing.
      expect(audit.observe(scanId, 0, obs, ctx(T))).toEqual({
        ok: true,
        observations: 0,
        findings: 0,
      });
      audit.confirm(scanId, 10, ctx(T));
      audit.finish(scanId, ctx(T));
      audit.markDone(scanId, T);
    });
    await s.stub.publish();
  }

  it('logs an observation, then CONTENT_DRIFT when the same ETag later hashes differently', async () => {
    const s = await sequencer([objectEvent(0, { key: 'k', etag: 'e1', size: 1, eventTime: OLD })]);
    await scanWith(s, 'scan-1', [observation()]);
    await s.run((_, log) => {
      expect(log.scrubState('k')).toEqual({
        etag: 'e1',
        size: 1,
        sha256: SHA_A,
        observedAt: new Date(T).toISOString(),
        seq: 2,
      });
    });
    await scanWith(s, 'scan-2', [observation({ sha256: SHA_B })]);
    await s.run((audit) => {
      const [f] = audit.findings('scan-2', null, 10);
      expect(f && decodeEntry(f.entry)).toMatchObject({
        entry: {
          kind: 'CONTENT_DRIFT',
          key: 'k',
          observed: { etag: 'e1', sha256: SHA_B },
          expected: { etag: 'e1', sha256: SHA_A, seq: 2 },
        },
      });
      expect(audit.get('scan-2')).toMatchObject({ observations: 1, findings: 1 });
    });
  });

  it('does not report drift when the ETag changed too', async () => {
    const s = await sequencer([objectEvent(0, { key: 'k', etag: 'e1', size: 1, eventTime: OLD })]);
    await scanWith(s, 'scan-1', [observation()]);
    await scanWith(s, 'scan-2', [observation({ etag: 'e2', sha256: SHA_B })]);
    await s.run((audit) => {
      // The ETag change itself is an ETAG_MISMATCH against the log, not drift.
      expect(audit.findings('scan-2', null, 10)).toHaveLength(0);
    });
  });

  it('reports CONTENT_DRIFT against the SHA-256 R2 stored at upload', async () => {
    const s = await sequencer([objectEvent(0, { key: 'k', etag: 'e1', size: 1, eventTime: OLD })]);
    await scanWith(s, 'scan-1', [observation({ storedSha256: SHA_B })]);
    await s.run((audit) => {
      const [f] = audit.findings('scan-1', null, 10);
      const d = f && decodeEntry(f.entry);
      expect(d).toMatchObject({ entry: { kind: 'CONTENT_DRIFT', expected: { sha256: SHA_B } } });
      expect(
        d?.known === true && d.entry.type === 'audit.finding' && d.entry.expected,
      ).not.toHaveProperty('seq');
    });
  });

  it('only accepts observations for pages already applied', async () => {
    const s = await sequencer();
    await s.run((audit) => {
      audit.start('scan-a', 'audit', 0, ctx(T));
      expect(audit.observe('scan-a', 0, [observation()], ctx(T))).toMatchObject({ ok: false });
      expect(() => audit.observe('scan-a', 0, [observation({ sha256: 'X' })], ctx(T))).toThrow(
        AuditInputError,
      );
    });
  });
});

describe('finish and report', () => {
  it('appends audit.scan end, builds a deterministic report, and prunes older findings', async () => {
    const s = await sequencer([objectEvent(0, { key: 'gone', eventTime: OLD })]);
    await s.run((audit, log) => {
      audit.start('scan-a', 'audit', 0, ctx(T));
      audit.page(
        {
          scanId: 'scan-a',
          page: 0,
          after: null,
          listed: [obj('new')],
          listTruncated: false,
          liveLimit: 10,
        },
        ctx(T),
      );
      expect(audit.finish('scan-a', ctx(T))).toMatchObject({ ok: false }); // still confirming
      audit.confirm('scan-a', 10, ctx(T));
      const f = audit.finish('scan-a', ctx(T + 7));
      expect(f).toMatchObject({ ok: true, scan: { state: 'reporting', endIndex: 4 } });
      expect(entryAt(log, 4)).toEqual({
        known: true,
        entry: {
          v: 1,
          type: 'audit.scan',
          scanId: 'scan-a',
          phase: 'end',
          objectsScanned: 1,
          findings: 2,
        },
      });
      expect(audit.finish('scan-a', ctx(T + 8))).toEqual(f); // idempotent
      const report = audit.report('scan-a', 'origin.example/log');
      expect(report).toEqual({
        v: 1,
        origin: 'origin.example/log',
        scanId: 'scan-a',
        startedAt: new Date(T).toISOString(),
        finishedAt: new Date(T + 7).toISOString(),
        graceSeconds: 0,
        logSizeAtStart: 1,
        startIndex: 1,
        endIndex: 4,
        objectsScanned: 1,
        findings: 2,
        dropped: 0,
        observations: 0,
        byKind: { MISSING_OBJECT: 1, UNLOGGED_OBJECT: 1 },
        // Candidates are recorded in key order, and confirmed in that order.
        entries: [
          { index: 2, kind: 'MISSING_OBJECT', key: 'gone' },
          { index: 3, kind: 'UNLOGGED_OBJECT', key: 'new' },
        ],
        truncated: false,
      });
      audit.markDone('scan-a', T + 9);
      expect(audit.report('scan-a', 'origin.example/log')).toEqual(report);
      expect(audit.get('scan-a')?.state).toBe('done');

      // The next scan's completion prunes scan-a's findings (the log keeps them).
      audit.start('scan-b', 'audit', 0, ctx(T + 10));
      audit.page(
        { scanId: 'scan-b', page: 0, after: null, listed: [], listTruncated: false, liveLimit: 10 },
        ctx(T + 10),
      );
      audit.confirm('scan-b', 10, ctx(T + 10));
      audit.finish('scan-b', ctx(T + 10));
      audit.markDone('scan-b', T + 10);
      expect(audit.findings('scan-a', null, 10)).toEqual([]);
      expect(audit.latest('audit')?.scanId).toBe('scan-b');
    });
  });
});

describe('backfill', () => {
  it('snapshots only objects the log has never named, once per page', async () => {
    const s = await sequencer([
      objectEvent(0, { key: 'known', eventTime: OLD }),
      objectEvent(1, { key: 'deleted', eventTime: OLD }),
      objectEvent(2, { key: 'deleted', action: 'DeleteObject', eventTime: '2026-02-01T00:00:00Z' }),
    ]);
    await s.run((audit, log) => {
      expect(audit.start('fill-1', 'backfill', 0, ctx(T))).toMatchObject({
        ok: true,
        scan: { startIndex: null },
      });
      const req = {
        scanId: 'fill-1',
        page: 0,
        after: null,
        listed: [obj('deleted'), obj('known'), obj('new-a', { etag: 'n1', size: 5 })],
        listTruncated: true,
        liveLimit: 10,
      };
      expect(audit.page(req, ctx(T))).toMatchObject({ ok: true, snapshots: 1, end: 'new-a' });
      expect(audit.page(req, ctx(T))).toMatchObject({ snapshots: 1 }); // replay: stored result
      expect(entryAt(log, 3)).toEqual({
        known: true,
        entry: {
          v: 1,
          type: 'object.snapshot',
          bucket: BUCKET,
          key: 'new-a',
          size: 5,
          etag: 'n1',
          uploaded: OLD,
          snapshotId: 'fill-1',
        },
      });
      expect(log.nextSeq()).toBe(4);
      expect(
        audit.page(
          { ...req, page: 1, after: 'new-a', listed: [obj('new-b')], listTruncated: false },
          ctx(T),
        ),
      ).toMatchObject({ snapshots: 1, state: 'finishing' });
      expect(audit.finish('fill-1', ctx(T))).toMatchObject({
        ok: true,
        scan: { state: 'done', snapshots: 2, endIndex: null },
      });
      expect(audit.report('fill-1', 'o')).toBeNull();
      expect(utf8Decode(log.readEntries(4, 5)[0] ?? new Uint8Array())).toContain('"new-b"');
    });
  });
});

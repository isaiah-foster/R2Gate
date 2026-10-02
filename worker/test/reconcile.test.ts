// The auditor's merge-join (PLAN §5.6): one page of the bucket listing against the log's expected
// state. Pure; every finding kind, the grace window, page boundaries and Unicode key order.
import { compareUtf8 } from '@r2notary/core';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
  ReconcileError,
  reconcilePage,
  type Candidate,
  type ListedObject,
  type PageInput,
} from '../src/audit/reconcile.ts';
import { eventMillis, type ObjectState } from '../src/store.ts';

const T0 = Date.parse('2026-10-01T00:00:00.000Z');
const MIN = 60_000;
const GRACE = 5 * MIN;
const NOW = T0 + 60 * MIN;
const iso = (ms: number): string => new Date(ms).toISOString();

function obj(key: string, o: Partial<ListedObject> = {}): ListedObject {
  return { key, etag: 'e1', size: 10, uploaded: T0, ...o };
}

function row(key: string, o: Partial<ObjectState> = {}): ObjectState {
  return {
    key,
    etag: 'e1',
    size: 10,
    eventTime: iso(T0),
    keyHmac: null,
    seq: 7,
    deleted: false,
    ...o,
  };
}

/** One page holding everything: no truncation on either side. */
function single(listed: ListedObject[], rows: ObjectState[], now = NOW): Candidate[] {
  return reconcilePage({
    after: null,
    listed,
    listTruncated: false,
    live: rows.filter((r) => !r.deleted),
    liveTruncated: false,
    rows: new Map(rows.map((r) => [r.key, r])),
    now,
    graceMs: GRACE,
  }).candidates;
}

describe('finding kinds', () => {
  it('reports nothing when the bucket matches the log', () => {
    expect(single([obj('a'), obj('b')], [row('a'), row('b', { seq: 8 })])).toEqual([]);
  });

  it('UNLOGGED_OBJECT: in the bucket, never logged', () => {
    expect(single([obj('a', { uploaded: T0 + 1 })], [])).toEqual([
      {
        kind: 'UNLOGGED_OBJECT',
        key: 'a',
        basisSeq: null,
        observed: { etag: 'e1', size: 10, uploaded: iso(T0 + 1) },
      },
    ]);
  });

  it('MISSING_OBJECT: live in the log, absent from the bucket', () => {
    expect(single([], [row('a', { seq: 3 })])).toEqual([
      {
        kind: 'MISSING_OBJECT',
        key: 'a',
        basisSeq: 3,
        expected: { etag: 'e1', size: 10, eventTime: iso(T0), seq: 3 },
      },
    ]);
  });

  it('ETAG_MISMATCH: overwritten without a logged event', () => {
    const later = T0 + 10 * MIN;
    expect(single([obj('a', { etag: 'e2', uploaded: later })], [row('a')])).toEqual([
      {
        kind: 'ETAG_MISMATCH',
        key: 'a',
        basisSeq: 7,
        observed: { etag: 'e2', size: 10, uploaded: iso(later) },
        expected: { etag: 'e1', size: 10, eventTime: iso(T0), seq: 7 },
      },
    ]);
  });

  it('SIZE_MISMATCH: same ETag, different size', () => {
    expect(single([obj('a', { size: 11 })], [row('a')])).toMatchObject([
      { kind: 'SIZE_MISMATCH', key: 'a', observed: { size: 11 }, expected: { size: 10 } },
    ]);
  });

  it('reports a key once, preferring ETAG_MISMATCH when both differ', () => {
    expect(single([obj('a', { etag: 'e2', size: 11 })], [row('a')])).toMatchObject([
      { kind: 'ETAG_MISMATCH' },
    ]);
  });

  it('compares only what the log recorded (creates may lack etag or size)', () => {
    expect(
      single([obj('a', { etag: 'zz', size: 99 })], [row('a', { etag: null, size: null })]),
    ).toEqual([]);
    expect(single([obj('a', { etag: 'zz', size: 99 })], [row('a', { etag: null })])).toMatchObject([
      { kind: 'SIZE_MISMATCH', expected: { size: 10, seq: 7 } },
    ]);
    // The absent field is absent from `expected` too (the entry schema has no nulls).
    const [c] = single([obj('a', { size: 99 })], [row('a', { etag: null })]);
    expect(c?.expected).toEqual({ size: 10, eventTime: iso(T0), seq: 7 });
  });

  it('PHANTOM_DELETE: the log says deleted, the object is there', () => {
    const del = row('a', { etag: null, size: null, deleted: true, seq: 9 });
    // Re-created after the delete (its create event never arrived) ...
    expect(single([obj('a', { uploaded: T0 + MIN })], [del])).toEqual([
      {
        kind: 'PHANTOM_DELETE',
        key: 'a',
        basisSeq: 9,
        observed: { etag: 'e1', size: 10, uploaded: iso(T0 + MIN) },
        expected: { eventTime: iso(T0), seq: 9 },
      },
    ]);
    // ... or never actually deleted: uploaded before the logged delete. Both contradict the log.
    expect(single([obj('a', { uploaded: T0 - MIN })], [del])).toMatchObject([
      { kind: 'PHANTOM_DELETE' },
    ]);
  });

  it('a deleted row with no object is consistent, not missing', () => {
    expect(single([], [row('a', { deleted: true })])).toEqual([]);
  });
});

describe('grace window', () => {
  const edge = NOW - GRACE;

  it('UNLOGGED_OBJECT only for uploads at least the grace window old', () => {
    expect(single([obj('a', { uploaded: edge })], [])).toHaveLength(1);
    expect(single([obj('a', { uploaded: edge + 1 })], [])).toEqual([]);
  });

  it('MISSING_OBJECT only when the logged state is at least the grace window old', () => {
    expect(single([], [row('a', { eventTime: iso(edge) })])).toHaveLength(1);
    expect(single([], [row('a', { eventTime: iso(edge + 1) })])).toEqual([]);
  });

  it('mismatches and phantom deletes wait for both the upload and the logged event', () => {
    const cases: [ListedObject, ObjectState][] = [
      [obj('a', { etag: 'e2', uploaded: edge + 1 }), row('a')], // fresh overwrite, event in flight
      [obj('a', { etag: 'e2' }), row('a', { eventTime: iso(edge + 1) })], // fresh logged event
      [obj('a', { uploaded: edge + 1 }), row('a', { deleted: true })],
      [obj('a'), row('a', { deleted: true, eventTime: iso(edge + 1) })],
    ];
    for (const [o, r] of cases) expect(single([o], [r])).toEqual([]);
    expect(single([obj('a', { etag: 'e2', uploaded: edge })], [row('a')])).toHaveLength(1);
  });

  it('a grace window of 0 reports anything not explained at `now`', () => {
    const r = reconcilePage({
      after: null,
      listed: [obj('a', { uploaded: NOW })],
      listTruncated: false,
      live: [],
      liveTruncated: false,
      rows: new Map(),
      now: NOW,
      graceMs: 0,
    });
    expect(r.candidates).toHaveLength(1);
  });

  it('compares instants, not strings, across UTC offsets', () => {
    // 01:55+01:00 is 00:55Z: exactly at the edge, so reported. As text it sorts after it.
    const t = '2026-10-01T01:55:00+01:00';
    expect(eventMillis(t)).toBe(edge);
    expect(single([], [row('a', { eventTime: t })])).toHaveLength(1);
  });
});

describe('pages', () => {
  const base = (o: Partial<PageInput>): PageInput => ({
    after: null,
    listed: [],
    listTruncated: false,
    live: [],
    liveTruncated: false,
    rows: new Map(),
    now: NOW,
    graceMs: GRACE,
    ...o,
  });

  it('ends at the last listed key when the listing is truncated', () => {
    const r = reconcilePage(
      base({
        listed: [obj('a'), obj('c')],
        listTruncated: true,
        live: [row('b'), row('d')], // d is beyond the page: left for the next one
        rows: new Map(),
      }),
    );
    expect(r.end).toBe('c');
    expect(r.scanned).toBe(2);
    expect(r.candidates.map((c) => `${c.kind} ${c.key}`)).toEqual([
      'UNLOGGED_OBJECT a',
      'MISSING_OBJECT b',
      'UNLOGGED_OBJECT c',
    ]);
  });

  it('ends at the last live row when that comes first, leaving later listed keys', () => {
    const r = reconcilePage(
      base({
        listed: [obj('a'), obj('z')],
        live: [row('b'), row('c')],
        liveTruncated: true,
      }),
    );
    expect(r.end).toBe('c');
    expect(r.scanned).toBe(1); // z is listed again by the next page
    expect(r.candidates.map((c) => c.key)).toEqual(['a', 'b', 'c']);
  });

  it('is done (end null) only when neither side is truncated', () => {
    expect(reconcilePage(base({ listed: [obj('a')] })).end).toBeNull();
  });

  it('merges in UTF-8 byte order, where astral keys sort after U+E000', () => {
    const keys = ['a', '', '\u{1F600}'];
    expect([...keys].sort()).not.toEqual(keys); // JavaScript's order differs
    const r = reconcilePage(
      base({
        listed: [obj('a'), obj('\u{1F600}')],
        live: [row(''), row('\u{1F600}')],
        rows: new Map([['\u{1F600}', row('\u{1F600}')]]),
      }),
    );
    expect(r.candidates.map((c) => `${c.kind} ${c.key}`)).toEqual([
      'UNLOGGED_OBJECT a',
      'MISSING_OBJECT ',
    ]);
  });

  it('rejects input that would make the merge silently wrong', () => {
    const bad: [string, Partial<PageInput>][] = [
      ['listing in UTF-16 order', { listed: [obj('\u{1F600}'), obj('')] }],
      ['duplicate listed key', { listed: [obj('a'), obj('a')] }],
      ['listed key not after the cursor', { after: 'b', listed: [obj('b')] }],
      ['live rows out of order', { live: [row('b'), row('a')] }],
      ['live row not after the cursor', { after: 'b', live: [row('a')] }],
      ['deleted row in the live stream', { live: [row('a', { deleted: true })] }],
      ['truncated listing with no objects', { listTruncated: true }],
      ['truncated live stream with no rows', { liveTruncated: true }],
    ];
    for (const [what, o] of bad) {
      expect(() => reconcilePage(base(o)), what).toThrow(ReconcileError);
    }
  });
});

describe('merge-join under any pagination (property)', () => {
  // Each key is in the bucket or not, and in the log as live, deleted, or absent; states are
  // drawn so that every kind occurs. The paginated result must equal an oracle that classifies
  // each key on its own, whatever page sizes the bucket and the log are read with.
  const KEYS = ['a', 'b', 'é', '', '�', '\u{10000}', '\u{1F600}', 'z', 'zz', '~'];
  const state = fc.record({
    inBucket: fc.boolean(),
    log: fc.constantFrom('none', 'live', 'deleted'),
    etag: fc.constantFrom('e1', 'e2'),
    size: fc.constantFrom(10, 11),
    old: fc.boolean(), // outside the grace window
  });

  function oracle(bucket: Map<string, ListedObject>, rows: Map<string, ObjectState>): string[] {
    const out: string[] = [];
    const keys = [...new Set([...bucket.keys(), ...rows.keys()])].sort(compareUtf8);
    const quiet = (ms: number): boolean => ms <= NOW - GRACE;
    for (const k of keys) {
      const o = bucket.get(k);
      const r = rows.get(k);
      if (o && !r && quiet(o.uploaded)) out.push(`UNLOGGED_OBJECT ${k}`);
      if (!o && r && !r.deleted && quiet(eventMillis(r.eventTime))) out.push(`MISSING_OBJECT ${k}`);
      if (o && r && quiet(Math.max(o.uploaded, eventMillis(r.eventTime)))) {
        if (r.deleted) out.push(`PHANTOM_DELETE ${k}`);
        else if (r.etag !== null && r.etag !== o.etag) out.push(`ETAG_MISMATCH ${k}`);
        else if (r.size !== null && r.size !== o.size) out.push(`SIZE_MISMATCH ${k}`);
      }
    }
    return out;
  }

  it('equals the per-key oracle', () => {
    fc.assert(
      fc.property(
        fc.array(state, { minLength: KEYS.length, maxLength: KEYS.length }),
        fc.integer({ min: 1, max: 4 }),
        fc.integer({ min: 1, max: 4 }),
        (states, listLimit, liveLimit) => {
          const bucket = new Map<string, ListedObject>();
          const rows = new Map<string, ObjectState>();
          states.forEach((s, i) => {
            const key = KEYS[i] ?? '';
            const t = s.old ? T0 : NOW;
            if (s.inBucket) bucket.set(key, obj(key, { uploaded: t }));
            if (s.log !== 'none') {
              rows.set(
                key,
                row(key, {
                  etag: s.etag,
                  size: s.size,
                  eventTime: iso(t),
                  deleted: s.log === 'deleted',
                  seq: i,
                }),
              );
            }
          });
          const sortedBucket = [...bucket.values()].sort((x, y) => compareUtf8(x.key, y.key));
          const sortedLive = [...rows.values()]
            .filter((r) => !r.deleted)
            .sort((x, y) => compareUtf8(x.key, y.key));
          const found: string[] = [];
          let scanned = 0;
          let after: string | null = null;
          for (let pages = 0; ; pages++) {
            expect(pages).toBeLessThan(50);
            const gt = (k: string): boolean => after === null || compareUtf8(k, after) > 0;
            const listedAll = sortedBucket.filter((o) => gt(o.key));
            const liveAll = sortedLive.filter((r) => gt(r.key));
            const listed = listedAll.slice(0, listLimit);
            const r = reconcilePage({
              after,
              listed,
              listTruncated: listedAll.length > listLimit,
              live: liveAll.slice(0, liveLimit),
              liveTruncated: liveAll.length > liveLimit,
              rows: new Map(
                listed.flatMap((o) =>
                  rows.has(o.key) ? [[o.key, rows.get(o.key) as ObjectState]] : [],
                ),
              ),
              now: NOW,
              graceMs: GRACE,
            });
            found.push(...r.candidates.map((c) => `${c.kind} ${c.key}`));
            scanned += r.scanned;
            if (r.end === null) break;
            after = r.end;
          }
          expect(found).toEqual(oracle(bucket, rows));
          expect(scanned).toBe(bucket.size); // every object counted exactly once
        },
      ),
      { numRuns: 500 },
    );
  });
});

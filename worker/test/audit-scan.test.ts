// The scan driver (worker/src/audit/scan.ts) against the real Sequencer and local R2, with a step
// runner that replays like Workflows do: finished steps return their stored result, and a crash
// re-runs `runScan` from the top. Covers every finding kind end to end, resumability after a kill
// at every step (PLAN M6), hand-off between instances, the grace window, and deep scrub.
import { decodeEntry, sha256, toHex, utf8Encode, type Entry } from '@r2notary/core';
import { env } from 'cloudflare:workers';
import { reset } from 'cloudflare:test';
import { afterEach, describe, expect, it } from 'vitest';
import {
  DEFAULT_BUDGET,
  runScan,
  type ScanDeps,
  type ScanOutcome,
  type ScanParams,
  type StepConfig,
  type StepLike,
} from '../src/audit/scan.ts';
import type { Sequencer } from '../src/sequencer.ts';
import { objectEvent, publishedEntries, putObject, readBytes } from './helpers.ts';

afterEach(() => reset());

const LOG = env.LOG_NAME;
const OLD = '2026-01-01T00:00:00.000Z';
const LATER = '2026-02-01T00:00:00.000Z';

class Killed extends Error {
  override name = 'Killed';
}

/**
 * Replays like the Workflows engine: results are stored by step name (serialized, as Workflows
 * persists them) and returned without running the step again. `kill` throws once, either before
 * the step body runs or after it ran but before its result was stored: the second case is a crash
 * after the Sequencer committed, which the Sequencer must recognise when the step is re-run.
 */
class ReplayStep implements StepLike {
  readonly results = new Map<string, string>();
  readonly executed: string[] = [];
  readonly slept: number[] = [];
  #calls = 0;

  constructor(
    private kill: { readonly at: number; readonly when: 'before' | 'after' } | null = null,
    private readonly before: (name: string) => Promise<void> = () => Promise.resolve(),
  ) {}

  async do<T>(name: string, _config: StepConfig, fn: () => Promise<T>): Promise<T> {
    const stored = this.results.get(name);
    if (stored !== undefined) return JSON.parse(stored) as T;
    const call = this.#calls++;
    const kill = this.kill?.at === call ? this.kill : null;
    if (kill?.when === 'before') {
      this.kill = null;
      throw new Killed(`before ${name}`);
    }
    await this.before(name);
    const result = await fn();
    if (kill?.when === 'after') {
      this.kill = null;
      throw new Killed(`after ${name}`);
    }
    this.results.set(name, JSON.stringify(result));
    this.executed.push(name);
    return result;
  }

  sleep(_name: string, ms: number): Promise<void> {
    this.slept.push(ms);
    return Promise.resolve();
  }
}

/** Runs one instance to completion, restarting it after each simulated crash. */
async function drive(p: ScanParams, step: ReplayStep, d: ScanDeps): Promise<ScanOutcome> {
  for (let restarts = 0; restarts < 5; restarts++) {
    try {
      return await runScan(p, step, d);
    } catch (e) {
      if (!(e instanceof Killed)) throw e;
    }
  }
  throw new Error('too many restarts');
}

let unique = 0;
function newSequencer(): DurableObjectStub<Sequencer> {
  unique++;
  return env.SEQUENCER.getByName(`audit-scan-${String(unique)}`);
}

function deps(stub: DurableObjectStub<Sequencer>, o: Partial<ScanDeps> = {}) {
  const next: ScanParams[] = [];
  const d: ScanDeps = {
    sequencer: stub,
    bucket: env.MONITORED,
    continueIn: (p) => {
      next.push(p);
      return Promise.resolve();
    },
    alert: null,
    origin: env.LOG_ORIGIN,
    scrubRate: 1,
    scrubMaxBytes: 1 << 20,
    pageSize: 2,
    budget: DEFAULT_BUDGET,
    now: Date.now,
    ...o,
  };
  return { d, next };
}

const put = async (key: string, body: string): Promise<string> =>
  (await putObject(env.MONITORED, key, body)).etag;

/**
 * A bucket and a log that disagree in every way the auditor detects, with keys whose UTF-8 and
 * UTF-16 orders differ. Returns the findings a scan must report, as "KIND key".
 */
async function seedScenario(stub: DurableObjectStub<Sequencer>): Promise<string[]> {
  const ok = await put('ok', 'ok-body');
  await put('unlogged', 'u');
  await put('etag', 'rewritten');
  const sized = await put('size', 'size-body');
  await put('phantom', 'p');
  const pua = await put('-ok', 'x');
  await put('\u{1F600}-unlogged', 'y');
  const acute = await put('é-ok', 'z');
  const ev = (key: string, o: Parameters<typeof objectEvent>[1] = {}): Uint8Array =>
    objectEvent(0, { key, eventTime: OLD, ...o });
  const events = [
    ev('ok', { etag: ok, size: 7 }),
    ev('etag', { etag: '0'.repeat(32), size: 9 }),
    ev('size', { etag: sized, size: 10 }), // the object is 9 bytes
    ev('phantom', { etag: 'p0', size: 1 }),
    ev('phantom', { action: 'DeleteObject', eventTime: LATER }),
    ev('missing', { etag: 'm0', size: 1 }),
    ev('-ok', { etag: pua, size: 1 }),
    ev('é-ok', { etag: acute, size: 1 }),
    ev('gone', { etag: 'g0', size: 1 }),
    ev('gone', { action: 'DeleteObject', eventTime: LATER }),
  ];
  await stub.append(events.map((entry, i) => ({ eventId: `seed-${String(i)}`, entry })));
  await stub.publish();
  return [
    'ETAG_MISMATCH etag',
    'MISSING_OBJECT missing',
    'PHANTOM_DELETE phantom',
    'SIZE_MISMATCH size',
    'UNLOGGED_OBJECT unlogged',
    'UNLOGGED_OBJECT \u{1F600}-unlogged',
  ].sort();
}

const SEEDED = 10;
const OBJECTS = 8;

function label(e: Entry): string {
  switch (e.type) {
    case 'object.event':
      return `${e.type} ${e.action} ${e.key}`;
    case 'audit.finding':
      return `${e.type} ${e.kind} ${e.key}`;
    case 'audit.scan':
      return `${e.type} ${e.phase}`;
    default:
      return `${e.type} ${e.key}`;
  }
}

/** The published log, as labels, with every entry decoded under the strict schema. */
async function logLabels(): Promise<string[]> {
  return (await publishedEntries(LOG)).map((b) => {
    const d = decodeEntry(b);
    if (!d.known) throw new Error('unknown entry');
    return label(d.entry);
  });
}

function findingLabels(labels: string[]): string[] {
  return labels
    .filter((l) => l.startsWith('audit.finding '))
    .map((l) => l.slice('audit.finding '.length))
    .sort();
}

const PARAMS: ScanParams = { scanId: 'scan-t', mode: 'audit', part: 0 };

describe('a full audit', () => {
  it('reports every finding kind, logs start, end and observations, and writes a report', async () => {
    const stub = newSequencer();
    const expected = await seedScenario(stub);
    const step = new ReplayStep();
    const out = await drive(PARAMS, step, deps(stub).d);
    expect(out).toEqual({
      scanId: 'scan-t',
      part: 0,
      status: 'done',
      objectsScanned: OBJECTS,
      findings: expected.length,
      reportKey: `${LOG}/x-reports/scan-t.json`,
    });

    const labels = await logLabels();
    expect(findingLabels(labels)).toEqual(expected);
    expect(labels.slice(SEEDED, SEEDED + 1)).toEqual(['audit.scan start']);
    expect(labels.at(-1)).toBe('audit.scan end');
    expect(labels.filter((l) => l.startsWith('audit.observation'))).toHaveLength(OBJECTS);
    expect(labels).toHaveLength(SEEDED + 1 + OBJECTS + expected.length + 1);
    expect((await stub.status()).pending).toBe(0); // finish published everything

    const end = decodeEntry((await publishedEntries(LOG)).at(-1) ?? new Uint8Array());
    expect(end).toMatchObject({ entry: { objectsScanned: OBJECTS, findings: expected.length } });

    const report = JSON.parse(
      new TextDecoder().decode((await readBytes(`${LOG}/x-reports/scan-t.json`)) ?? undefined),
    ) as { findings: number; entries: { kind: string; key: string }[] };
    expect(report.findings).toBe(expected.length);
    expect(report.entries.map((e) => `${e.kind} ${e.key}`).sort()).toEqual(expected);
    expect((await stub.status()).audit).toMatchObject({ scanId: 'scan-t', state: 'done' });
  });

  it('hashes scrubbed bodies with DigestStream', async () => {
    const stub = newSequencer();
    await seedScenario(stub);
    await drive(PARAMS, new ReplayStep(), deps(stub).d);
    const okObservation = (await publishedEntries(LOG))
      .map((b) => decodeEntry(b))
      .find((d) => d.known && d.entry.type === 'audit.observation' && d.entry.key === 'ok');
    expect(okObservation).toMatchObject({
      entry: { size: 7, sha256: toHex(await sha256(utf8Encode('ok-body'))), scanId: 'scan-t' },
    });
  });

  it('a scan with deep scrub off logs no observations', async () => {
    const stub = newSequencer();
    await seedScenario(stub);
    await drive(PARAMS, new ReplayStep(), deps(stub, { scrubRate: 0 }).d);
    expect((await logLabels()).filter((l) => l.startsWith('audit.observation'))).toEqual([]);
  });

  it('drops a candidate whose event is published during the grace window', async () => {
    const stub = newSequencer();
    const expected = await seedScenario(stub);
    const step = new ReplayStep(null, async (name) => {
      if (name !== 'confirm-0') return;
      // The notification for 'unlogged' was merely late.
      await stub.append([
        { eventId: 'late', entry: objectEvent(0, { key: 'unlogged', etag: 'late', size: 1 }) },
      ]);
    });
    const out = await drive(PARAMS, step, deps(stub).d);
    expect(out.findings).toBe(expected.length - 1);
    expect(findingLabels(await logLabels())).toEqual(
      expected.filter((f) => f !== 'UNLOGGED_OBJECT unlogged'),
    );
    expect((await stub.status()).audit).toMatchObject({ dropped: 1 });
  });

  it('alerts once with counts and indexes, never key names', async () => {
    const stub = newSequencer();
    const expected = await seedScenario(stub);
    const alerts: unknown[] = [];
    await drive(
      PARAMS,
      new ReplayStep(),
      deps(stub, {
        alert: (a) => {
          alerts.push(a);
          return Promise.resolve();
        },
      }).d,
    );
    expect(alerts).toEqual([
      {
        type: 'r2notary.audit',
        origin: env.LOG_ORIGIN,
        scanId: 'scan-t',
        objectsScanned: OBJECTS,
        findings: expected.length,
        startIndex: SEEDED,
        endIndex: expect.any(Number) as number,
        reportKey: `${LOG}/x-reports/scan-t.json`,
      },
    ]);
    expect(JSON.stringify(alerts)).not.toContain('unlogged');
  });

  it('a failing webhook does not fail the scan', async () => {
    const stub = newSequencer();
    await seedScenario(stub);
    const out = await drive(
      PARAMS,
      new ReplayStep(),
      deps(stub, { alert: () => Promise.reject(new Error('webhook down')) }).d,
    );
    expect(out.status).toBe('done');
  });

  it('does not alert when nothing was found', async () => {
    const stub = newSequencer();
    let alerted = false;
    const out = await drive(
      PARAMS,
      new ReplayStep(),
      deps(stub, {
        alert: () => {
          alerted = true;
          return Promise.resolve();
        },
      }).d,
    );
    expect(out).toMatchObject({ status: 'done', objectsScanned: 0, findings: 0 });
    expect(alerted).toBe(false);
  });

  it('refuses to run a second scan while one is active', async () => {
    const stub = newSequencer();
    await stub.scanStart('other', 'audit');
    await expect(drive(PARAMS, new ReplayStep(), deps(stub).d)).rejects.toThrow(/in progress/);
  });
});

describe('resumability (kill and resume mid-scan)', () => {
  // Learn the step sequence of an uninterrupted run, then crash at every step, before and after
  // its body, and require the same log as the uninterrupted run: nothing lost, nothing twice.
  it('produces the same log whichever step is killed', async () => {
    const reference = new ReplayStep();
    let stub = newSequencer();
    const expected = await seedScenario(stub);
    await drive(PARAMS, reference, deps(stub).d);
    const want = (await logLabels()).sort();
    const steps = reference.executed;
    expect(steps).toContain('confirm-0');
    expect(steps.filter((s) => s.startsWith('page-')).length).toBeGreaterThan(3);

    for (const when of ['before', 'after'] as const) {
      for (let at = 0; at < steps.length; at++) {
        await reset();
        stub = newSequencer();
        await seedScenario(stub);
        const step = new ReplayStep({ at, when });
        const out = await drive(PARAMS, step, deps(stub).d);
        const what = `killed ${when} ${steps[at] ?? '?'}`;
        expect(out.findings, what).toBe(expected.length);
        expect((await logLabels()).sort(), what).toEqual(want);
        expect(step.executed, what).toEqual(steps);
      }
    }
  });
});

describe('hand-off between instances', () => {
  it('continues in a new instance when the budget runs out, with the same result', async () => {
    const stub = newSequencer();
    const expected = await seedScenario(stub);
    // The smallest budget that fits a page: one page per instance.
    const { d, next } = deps(stub, { scrubRate: 0, budget: { subrequests: 6, steps: 1000 } });
    const outcomes: ScanOutcome[] = [await drive(PARAMS, new ReplayStep(), d)];
    while (next.length > 0) {
      const p = next.shift();
      if (p === undefined) break;
      outcomes.push(await drive(p, new ReplayStep(), d));
    }
    expect(outcomes.length).toBeGreaterThan(2);
    expect(outcomes.map((o) => o.part)).toEqual(outcomes.map((_, i) => i));
    expect(outcomes.slice(0, -1).every((o) => o.status === 'handed-off')).toBe(true);
    expect(outcomes.at(-1)).toMatchObject({ status: 'done', objectsScanned: OBJECTS });
    expect(findingLabels(await logLabels())).toEqual(expected);
  });

  it('rejects a budget that cannot fit one page', async () => {
    const stub = newSequencer();
    const { d } = deps(stub, { budget: { subrequests: 20, steps: 1000 } }); // scrub needs 21+
    await expect(runScan(PARAMS, new ReplayStep(), d)).rejects.toThrow(RangeError);
  });
});

describe('backfill', () => {
  it('snapshots unlogged objects, after which an audit finds them logged', async () => {
    const stub = newSequencer();
    await seedScenario(stub);
    const out = await drive(
      { scanId: 'fill-t', mode: 'backfill', part: 0 },
      new ReplayStep(),
      deps(stub).d,
    );
    expect(out).toMatchObject({ status: 'done', objectsScanned: OBJECTS, reportKey: null });
    await stub.publish();
    const snapshots = (await logLabels()).filter((l) => l.startsWith('object.snapshot'));
    expect(snapshots.sort()).toEqual([
      'object.snapshot unlogged',
      'object.snapshot \u{1F600}-unlogged',
    ]);
    const audit = await drive(PARAMS, new ReplayStep(), deps(stub).d);
    expect(audit.findings).toBe(4); // the two unlogged objects are now accounted for
  });
});

// The scan driver (PLAN §5.6): walks the monitored bucket page by page as Workflow steps. The scan's
// state lives in the Sequencer (store.ts), so this function holds nothing between steps that a
// replay could not rebuild from step results, which is what makes it resumable:
//
//   - Workflows persist each step's result and, after a crash, re-run `run()` from the top,
//     returning stored results for finished steps. Control flow depends only on those results, so
//     a replay takes the same path and step names.
//   - A step interrupted after its Sequencer call committed is re-run; the Sequencer recognises the
//     repeated page (or confirmation) and does nothing twice (DECISIONS D6.5).
//   - Steps are budgeted (subrequests, step count). Before running out, the scan hands off to a new
//     Workflow instance, which resumes from the Sequencer's cursor.
//
// Flow: start -> page-0..n (+ scrub-i) -> confirm-0..m (sleeping out the grace window) -> finish
// -> alert (optional).

import { compareUtf8 } from '@r2notary/core';
import { NonRetryableError } from 'cloudflare:workflows';
import type { Sequencer } from '../sequencer.ts';
import type { AlertSummary } from './alert.ts';
import type { ListedObject } from './reconcile.ts';
import { MAX_SCRUB_PER_PAGE, scrubObject, selectForScrub, type ScrubTarget } from './scrub.ts';
import {
  MAX_PAGE_OBJECTS,
  SCAN_ID_RE,
  SCAN_MODES,
  type ConfirmResult,
  type Outcome,
  type PageRequest,
  type PageResult,
  type ScanMode,
  type ScanState,
  type ScanSummary,
  type ScrubObservation,
} from './store.ts';

export interface ScanParams {
  readonly scanId: string;
  readonly mode: ScanMode;
  /** 0 for the instance that starts the scan, then 1, 2, ... for each hand-off. */
  readonly part: number;
}

export interface ScanOutcome {
  readonly scanId: string;
  readonly part: number;
  readonly status: 'done' | 'handed-off';
  readonly objectsScanned: number;
  readonly findings: number;
  readonly reportKey: string | null;
}

/** The subset of WorkflowStepConfig used here. */
export interface StepConfig {
  readonly retries?: {
    readonly limit: number;
    readonly delay: string | number;
    readonly backoff?: 'constant' | 'linear' | 'exponential';
  };
  readonly timeout?: string | number;
}

/** The part of WorkflowStep the driver uses, so tests can replay it deterministically. */
export interface StepLike {
  do<T>(name: string, config: StepConfig, fn: () => Promise<T>): Promise<T>;
  sleep(name: string, ms: number): Promise<void>;
}

/** The Sequencer RPCs a scan uses (a DurableObjectStub<Sequencer> satisfies it). */
export interface ScanSequencer {
  scanStart(scanId: string, mode: ScanMode): Promise<Outcome<{ scan: ScanSummary }>>;
  scanState(scanId: string): Promise<ScanSummary | null>;
  scanPage(req: PageRequest): Promise<Outcome<PageResult>>;
  scanObserve(
    scanId: string,
    page: number,
    observations: ScrubObservation[],
  ): Promise<Outcome<{ observations: number; findings: number }>>;
  scanConfirm(scanId: string, limit: number): Promise<Outcome<ConfirmResult>>;
  scanFinish(scanId: string): Promise<Outcome<{ scan: ScanSummary; reportKey: string | null }>>;
}

export interface ScanBudget {
  readonly subrequests: number;
  readonly steps: number;
}

/**
 * Per Workflow instance. Workflows' Free plan allows 1,024 steps and 1,000 subrequests to
 * Cloudflare services per instance (50 to the Internet); Paid allows 10,000 of each by default.
 * The Free limits are used everywhere: a larger bucket just takes more hand-offs (D6.7).
 */
export const DEFAULT_BUDGET: ScanBudget = { subrequests: 900, steps: 1000 };

export interface ScanDeps {
  readonly sequencer: ScanSequencer;
  readonly bucket: {
    list(options: R2ListOptions): Promise<R2Objects>;
    get(key: string, options: R2GetOptions): Promise<R2ObjectBody | R2Object | null>;
  };
  /** Starts the next instance of this scan (idempotently: the step may be retried). */
  continueIn(next: ScanParams): Promise<void>;
  readonly alert: ((summary: AlertSummary) => Promise<void>) | null;
  readonly origin: string;
  readonly scrubRate: number;
  readonly scrubMaxBytes: number;
  /** Objects per listed page and live log rows per merge (1..1000). */
  readonly pageSize: number;
  readonly budget: ScanBudget;
  readonly now: () => number;
}

const STEP: StepConfig = {
  retries: { limit: 5, delay: '10 seconds', backoff: 'exponential' },
  timeout: '15 minutes',
};
const ALERT_STEP: StepConfig = {
  retries: { limit: 3, delay: '30 seconds', backoff: 'exponential' },
};
/** Candidates confirmed per step. */
export const CONFIRM_BATCH = 500;
/** Kept free for finish, alert and hand-off. */
const RESERVE = 3;

/** Workflow instance ID for a part of a scan: the scan ID, then `-p<part>` for hand-offs. */
export function instanceId(p: ScanParams): string {
  return p.part === 0 ? p.scanId : `${p.scanId}-p${String(p.part)}`;
}

/** Checks a Workflow event payload (created only by this Worker, but it crosses a boundary). */
export function parseScanParams(v: unknown): ScanParams {
  const o = v as Partial<Record<keyof ScanParams, unknown>> | null;
  if (
    typeof o !== 'object' ||
    o === null ||
    typeof o.scanId !== 'string' ||
    !SCAN_ID_RE.test(o.scanId) ||
    !SCAN_MODES.includes(o.mode as ScanMode) ||
    typeof o.part !== 'number' ||
    !Number.isSafeInteger(o.part) ||
    o.part < 0
  ) {
    failed('invalid scan parameters');
  }
  return { scanId: o.scanId, mode: o.mode as ScanMode, part: o.part };
}

function toListed(o: R2Object): ListedObject {
  return { key: o.key, etag: o.etag, size: o.size, uploaded: o.uploaded.getTime() };
}

/**
 * Ends the instance without retries. The engine reports such an instance as errored with a generic
 * message, so the reason is logged here too.
 */
function failed(reason: string): never {
  console.error(`r2notary scan failed: ${reason}`);
  throw new NonRetryableError(reason);
}

export async function runScan(p: ScanParams, step: StepLike, d: ScanDeps): Promise<ScanOutcome> {
  if (!Number.isInteger(d.pageSize) || d.pageSize < 1 || d.pageSize > MAX_PAGE_OBJECTS) {
    throw new RangeError(`pageSize must be 1..${String(MAX_PAGE_OBJECTS)}`);
  }
  const scrubbing = p.mode === 'audit' && d.scrubRate > 0;
  const pageCost = 2 + (scrubbing ? MAX_SCRUB_PER_PAGE + 1 : 0);
  // Each instance must fit its first step and one page, or hand-offs would never make progress.
  if (d.budget.subrequests < 1 + pageCost + RESERVE || d.budget.steps < 3 + RESERVE) {
    throw new RangeError('scan budget too small for one page per instance');
  }
  const used = { subrequests: 0, steps: 0 };
  const run = <T>(name: string, subrequests: number, fn: () => Promise<T>, config = STEP) => {
    used.steps++;
    used.subrequests += subrequests;
    return step.do(name, config, fn);
  };
  const fits = (subrequests: number): boolean =>
    used.subrequests + subrequests + RESERVE <= d.budget.subrequests &&
    used.steps + 2 + RESERVE <= d.budget.steps;

  const begun =
    p.part === 0
      ? await run('start', 1, () => d.sequencer.scanStart(p.scanId, p.mode))
      : await run('resume', 1, async () => {
          const scan = await d.sequencer.scanState(p.scanId);
          return scan === null
            ? { ok: false as const, reason: 'no such scan' }
            : { ok: true as const, scan };
        });
  if (!begun.ok) failed(begun.reason);
  let state: ScanState = begun.scan.state;
  let after = begun.scan.cursor;
  let page = begun.scan.pages;

  const handOff = async (): Promise<ScanOutcome> => {
    const next = { ...p, part: p.part + 1 };
    await run('handoff', 1, async () => {
      await d.continueIn(next);
      return instanceId(next);
    });
    return {
      scanId: p.scanId,
      part: p.part,
      status: 'handed-off',
      objectsScanned: 0,
      findings: 0,
      reportKey: null,
    };
  };

  while (state === 'listing') {
    if (!fits(pageCost)) return handOff();
    const n = page;
    const from = after;
    const r = await run(`page-${String(n)}`, 2, async () => {
      const listing = await d.bucket.list({
        limit: d.pageSize,
        ...(from === null ? {} : { startAfter: from }),
      });
      const listed = listing.objects.map(toListed);
      const res = await d.sequencer.scanPage({
        scanId: p.scanId,
        page: n,
        after: from,
        listed,
        listTruncated: listing.truncated,
        liveLimit: d.pageSize,
      });
      if (!res.ok) return { ...res, scrub: [] as ScrubTarget[] };
      const covered = listed.filter((o) => res.end === null || compareUtf8(o.key, res.end) <= 0);
      const scrub = scrubbing
        ? await selectForScrub(p.scanId, covered, d.scrubRate, d.scrubMaxBytes)
        : [];
      return { ...res, scrub };
    });
    if (!r.ok) failed(r.reason);
    if (r.scrub.length > 0) {
      const o = await run(`scrub-${String(n)}`, r.scrub.length + 1, async () => {
        const observations: ScrubObservation[] = [];
        for (const t of r.scrub) {
          const obs = await scrubObject(d.bucket, t, d.now);
          if (obs !== null) observations.push(obs);
        }
        return d.sequencer.scanObserve(p.scanId, n, observations);
      });
      if (!o.ok) failed(o.reason);
    }
    after = r.end;
    page++;
    state = r.state;
  }

  for (let i = 0; state === 'confirming'; i++) {
    if (!fits(1)) return handOff();
    const c = await run(`confirm-${String(i)}`, 1, () =>
      d.sequencer.scanConfirm(p.scanId, CONFIRM_BATCH),
    );
    if (!c.ok) failed(c.reason);
    state = c.state;
    // The newest candidates are not out of their grace window yet. Sleeping is free: it uses no
    // subrequests, does not count as a step, and a sleeping instance is not "running".
    if (state === 'confirming' && c.waitMs > 0) await step.sleep(`grace-${String(i)}`, c.waitMs);
  }

  const f = await run('finish', 1, () => d.sequencer.scanFinish(p.scanId));
  if (!f.ok) failed(f.reason);
  const scan = f.scan;
  if (d.alert !== null && scan.mode === 'audit' && scan.findings > 0) {
    const alert = d.alert;
    const summary: AlertSummary = {
      type: 'r2notary.audit',
      origin: d.origin,
      scanId: scan.scanId,
      objectsScanned: scan.objectsScanned,
      findings: scan.findings,
      startIndex: scan.startIndex,
      endIndex: scan.endIndex,
      reportKey: f.reportKey,
    };
    try {
      await run(
        'alert',
        1,
        async () => {
          await alert(summary);
          return true;
        },
        ALERT_STEP,
      );
    } catch (e) {
      // The findings are in the log either way; a dead webhook must not fail the scan.
      console.error(
        `r2notary audit ${scan.scanId}: webhook failed: ${e instanceof Error ? e.message : String(e)}`,
      );
    }
  }
  return {
    scanId: p.scanId,
    part: p.part,
    status: 'done',
    objectsScanned: scan.objectsScanned,
    findings: scan.findings,
    reportKey: f.reportKey,
  };
}

export type StartResult =
  | { readonly started: true; readonly scanId: string }
  | { readonly started: false; readonly active: ScanSummary };

export interface StartDeps {
  readonly sequencer: Pick<DurableObjectStub<Sequencer>, 'activeScan'>;
  readonly workflow: Pick<Workflow<ScanParams>, 'createBatch'>;
}

/** A fresh scan ID: mode, time, and random bits so two admin requests in one ms differ. */
export function newScanId(mode: ScanMode, now: number): string {
  const rand = Array.from(crypto.getRandomValues(new Uint8Array(4)), (b) =>
    b.toString(16).padStart(2, '0'),
  ).join('');
  return `${mode}-${String(now)}-${rand}`;
}

/**
 * Starts a scan unless one is already running. The check is advisory (two callers can pass it
 * together); the Sequencer's start step is what refuses a second active scan. createBatch is
 * idempotent per instance ID, so a cron trigger delivered twice starts one scan.
 */
export async function startScan(
  d: StartDeps,
  mode: ScanMode,
  scanId: string,
): Promise<StartResult> {
  const active = await d.sequencer.activeScan();
  if (active !== null) return { started: false, active };
  await d.workflow.createBatch([{ id: scanId, params: { scanId, mode, part: 0 } }]);
  return { started: true, scanId };
}

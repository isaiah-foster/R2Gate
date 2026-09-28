// Auditor state in the Sequencer's SQLite (schema v3), and every step of a scan as one synchronous
// transaction. The scan Workflow (scan.ts) only drives these steps; the state lives here, next to
// the objects view the merge-join reads and the log the results are appended to. That gives:
//
//   - exactly-once effects per step: a step's log entries, counters and cursor commit together, and
//     a step re-run after a crash finds its own effects already recorded (DECISIONS D6.5);
//   - no race between reading the expected state and recording what it implied: a publication
//     cannot commit in the middle of a synchronous transaction;
//   - resumability from any Worker or Workflow instance: the cursor is here, not in memory.
//
// Lifecycle of a scan: listing -> confirming (audit only) -> finishing -> reporting (audit only)
// -> done. A scan that makes no progress for STALE_SCAN_MS may be marked abandoned by a new one.
//
// Expected conditions (wrong state, page out of sequence, another scan running) are returned as
// `{ok: false}` rather than thrown: they cross RPC, and the Workflow turns them into non-retryable
// failures. Malformed input is a caller bug and throws.

import {
  MAX_OBJECT_KEY_BYTES,
  encodeEntry,
  utf8Encode,
  type AuditFinding,
  type FindingKind,
} from '@r2notary/core';
import type { AppendItem, SequencerStore } from '../store.ts';
import {
  checkOrder,
  pageEnd,
  reconcilePage,
  type Candidate,
  type ListedObject,
} from './reconcile.ts';

export const SCAN_MODES = ['audit', 'backfill'] as const;
export type ScanMode = (typeof SCAN_MODES)[number];
export type ScanState = 'listing' | 'confirming' | 'finishing' | 'reporting' | 'done' | 'abandoned';

/** Valid as an entry `scanId`, an R2 key segment and a Workflow instance ID (with a suffix). */
export const SCAN_ID_RE = /^[A-Za-z0-9_][A-Za-z0-9_-]{0,63}$/;
/** A scan with no progress for this long may be superseded by a new one. */
export const STALE_SCAN_MS = 24 * 3600_000;
export const MAX_PAGE_OBJECTS = 1000;
/** Findings listed by name in a report; the log holds them all. */
export const REPORT_MAX_FINDINGS = 10_000;
/** Scans whose summary rows are kept (findings are kept only for the latest finished scan). */
const KEEP_SCANS = 50;

export interface ScanSummary {
  readonly scanId: string;
  readonly mode: ScanMode;
  readonly state: ScanState;
  readonly graceSeconds: number;
  readonly startedAt: number;
  readonly updatedAt: number;
  readonly finishedAt: number | null;
  /** Published log size when the scan started (after flushing pending entries). */
  readonly logSizeAtStart: number;
  /** Pages applied so far, and the last key they covered (null before the first page). */
  readonly pages: number;
  readonly cursor: string | null;
  readonly objectsScanned: number;
  /** Candidates still waiting for confirmation. */
  readonly pending: number;
  readonly findings: number;
  /** Candidates explained by an event during the grace window. */
  readonly dropped: number;
  readonly observations: number;
  readonly snapshots: number;
  /** Log indexes of the scan's audit.scan start and end entries. */
  readonly startIndex: number | null;
  readonly endIndex: number | null;
}

/** One deep-scrub read (scrub.ts). Times are epoch milliseconds. */
export interface ScrubObservation {
  readonly key: string;
  readonly etag: string;
  readonly size: number;
  readonly uploaded: number;
  readonly sha256: string;
  /** SHA-256 R2 stored for the object at upload, if the uploader supplied one. */
  readonly storedSha256: string | null;
  readonly observedAt: number;
}

export interface PageRequest {
  readonly scanId: string;
  /** Page number, from 0; pages are applied strictly in order. */
  readonly page: number;
  readonly after: string | null;
  readonly listed: readonly ListedObject[];
  readonly listTruncated: boolean;
  /** How many live log rows to merge against (the same limit the listing used). */
  readonly liveLimit: number;
}

export interface PageResult {
  readonly end: string | null;
  readonly state: ScanState;
  readonly scanned: number;
  readonly candidates: number;
  readonly snapshots: number;
}

export type Outcome<T> =
  ({ readonly ok: true } & T) | { readonly ok: false; readonly reason: string };

export interface ConfirmResult {
  readonly state: ScanState;
  readonly confirmed: number;
  readonly dropped: number;
  readonly remaining: number;
  /** How long until the oldest remaining candidate is out of its grace window (0: call again). */
  readonly waitMs: number;
}

export interface ScanContext {
  readonly now: number;
  /** Dedupe window for appended entries (DEDUPE_TTL_SECONDS). */
  readonly ttlMs: number;
  readonly bucket: string;
}

export interface ScanReport {
  readonly v: 1;
  readonly origin: string;
  readonly scanId: string;
  readonly startedAt: string;
  readonly finishedAt: string | null;
  readonly graceSeconds: number;
  readonly logSizeAtStart: number;
  readonly startIndex: number | null;
  readonly endIndex: number | null;
  readonly objectsScanned: number;
  readonly findings: number;
  readonly dropped: number;
  readonly observations: number;
  readonly byKind: Readonly<Record<string, number>>;
  /** The first REPORT_MAX_FINDINGS findings in log order. */
  readonly entries: readonly { index: number; kind: string; key: string }[];
  readonly truncated: boolean;
}

export class AuditInputError extends Error {
  override name = 'AuditInputError';
}

interface ScanRow {
  [column: string]: SqlStorageValue;
  scan_id: string;
  mode: string;
  state: string;
  grace_seconds: number;
  started_at: number;
  updated_at: number;
  finished_at: number | null;
  log_size_at_start: number;
  cursor: string | null;
  pages: number;
  last_after: string | null;
  last_result: string | null;
  observed_through: number;
  objects_scanned: number;
  candidates: number;
  findings: number;
  dropped: number;
  observations: number;
  snapshots: number;
  start_seq: number | null;
  end_seq: number | null;
}

const ACTIVE = "state NOT IN ('done', 'abandoned')";
const iso = (ms: number): string => new Date(ms).toISOString();
const ETAG_RE = /^[\x21\x23-\x7e]{1,256}$/;
const SHA256_RE = /^[0-9a-f]{64}$/;

function checkKey(key: unknown, what: string): asserts key is string {
  if (
    typeof key !== 'string' ||
    key === '' ||
    !key.isWellFormed() ||
    utf8Encode(key).length > MAX_OBJECT_KEY_BYTES
  ) {
    throw new AuditInputError(`${what}: not a valid object key`);
  }
}

function checkUint(v: unknown, what: string): void {
  if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 0) {
    throw new AuditInputError(`${what} must be a non-negative integer`);
  }
}

function checkListed(listed: readonly ListedObject[]): void {
  const list: unknown = listed; // from RPC: check the shape, not the declared type
  if (!Array.isArray(list) || listed.length > MAX_PAGE_OBJECTS) {
    throw new AuditInputError(`a page lists at most ${String(MAX_PAGE_OBJECTS)} objects`);
  }
  listed.forEach((o, i) => {
    checkKey(o.key, `listed[${String(i)}].key`);
    if (typeof o.etag !== 'string' || !ETAG_RE.test(o.etag)) {
      throw new AuditInputError(`listed[${String(i)}].etag is not an unquoted ETag`);
    }
    checkUint(o.size, `listed[${String(i)}].size`);
    checkUint(o.uploaded, `listed[${String(i)}].uploaded`);
  });
}

function checkObservation(o: ScrubObservation, i: number): void {
  checkKey(o.key, `observations[${String(i)}].key`);
  if (typeof o.etag !== 'string' || !ETAG_RE.test(o.etag)) {
    throw new AuditInputError(`observations[${String(i)}].etag is not an unquoted ETag`);
  }
  for (const f of ['size', 'uploaded', 'observedAt'] as const) {
    checkUint(o[f], `observations[${String(i)}].${f}`);
  }
  if (typeof o.sha256 !== 'string' || !SHA256_RE.test(o.sha256)) {
    throw new AuditInputError(`observations[${String(i)}].sha256 is not lowercase hex SHA-256`);
  }
  if (o.storedSha256 !== null && !SHA256_RE.test(o.storedSha256)) {
    throw new AuditInputError(
      `observations[${String(i)}].storedSha256 is not lowercase hex SHA-256`,
    );
  }
}

export class AuditStore {
  readonly #storage: DurableObjectStorage;
  readonly #sql: SqlStorage;
  readonly #log: SequencerStore;

  constructor(storage: DurableObjectStorage, log: SequencerStore) {
    this.#storage = storage;
    this.#sql = storage.sql;
    this.#log = log;
  }

  #row(scanId: string): ScanRow | null {
    return (
      this.#sql.exec<ScanRow>('SELECT * FROM scans WHERE scan_id = ?', scanId).toArray()[0] ?? null
    );
  }

  #summary(r: ScanRow): ScanSummary {
    const pending = this.#sql
      .exec<{ n: number }>('SELECT count(*) AS n FROM scan_candidates WHERE scan_id = ?', r.scan_id)
      .one().n;
    return {
      scanId: r.scan_id,
      mode: r.mode as ScanMode,
      state: r.state as ScanState,
      graceSeconds: r.grace_seconds,
      startedAt: r.started_at,
      updatedAt: r.updated_at,
      finishedAt: r.finished_at,
      logSizeAtStart: r.log_size_at_start,
      pages: r.pages,
      cursor: r.cursor,
      objectsScanned: r.objects_scanned,
      pending,
      findings: r.findings,
      dropped: r.dropped,
      observations: r.observations,
      snapshots: r.snapshots,
      startIndex: r.start_seq,
      endIndex: r.end_seq,
    };
  }

  get(scanId: string): ScanSummary | null {
    const r = this.#row(scanId);
    return r === null ? null : this.#summary(r);
  }

  /** The scan in progress, if any (at most one is). */
  active(): ScanSummary | null {
    const r = this.#sql.exec<ScanRow>(`SELECT * FROM scans WHERE ${ACTIVE} LIMIT 1`).toArray()[0];
    return r === undefined ? null : this.#summary(r);
  }

  /** The most recently started scan of a mode, in any state. */
  latest(mode: ScanMode): ScanSummary | null {
    const r = this.#sql
      .exec<ScanRow>(
        'SELECT * FROM scans WHERE mode = ? ORDER BY started_at DESC, scan_id DESC LIMIT 1',
        mode,
      )
      .toArray()[0];
    return r === undefined ? null : this.#summary(r);
  }

  /** Appends one entry inside the caller's transaction and returns its log index. */
  #append(eventId: string, entry: Uint8Array, ctx: ScanContext): number {
    const item: AppendItem = { eventId, entry };
    const r = this.#log.insertInTransaction([item], ctx.now, ctx.ttlMs);
    // Audit event IDs are unique per scan step, and every step runs once (its effects and its
    // progress commit together), so a duplicate here means that invariant broke.
    if (r.firstSeq === null) throw new Error(`audit entry ${eventId} was deduplicated`);
    return r.firstSeq;
  }

  #recordFinding(
    scanId: string,
    kind: FindingKind,
    key: string,
    seq: number,
    entry: Uint8Array,
  ): void {
    this.#sql.exec(
      'INSERT INTO scan_findings(scan_id, seq, kind, key, entry) VALUES (?, ?, ?, ?, ?)',
      scanId,
      seq,
      kind,
      key,
      entry,
    );
  }

  /**
   * Starts a scan, or returns it if it already exists (a retried start). Refuses while another
   * scan is active, unless that one has been idle for STALE_SCAN_MS, in which case it is
   * abandoned. An audit records `audit.scan` start with the published size the scan compares
   * against; the caller flushes publication first so that size includes every durable entry.
   */
  start(
    scanId: string,
    mode: ScanMode,
    graceSeconds: number,
    ctx: ScanContext,
  ): Outcome<{ scan: ScanSummary }> {
    if (!SCAN_ID_RE.test(scanId))
      throw new AuditInputError('scanId must match ' + SCAN_ID_RE.source);
    if (!SCAN_MODES.includes(mode)) throw new AuditInputError('unknown scan mode');
    return this.#storage.transactionSync(() => {
      const existing = this.#row(scanId);
      if (existing !== null) {
        if (existing.mode !== mode) return { ok: false, reason: `${scanId} is a ${existing.mode}` };
        return { ok: true, scan: this.#summary(existing) };
      }
      const active = this.#sql.exec<ScanRow>(`SELECT * FROM scans WHERE ${ACTIVE}`).toArray()[0];
      if (active !== undefined) {
        if (active.updated_at > ctx.now - STALE_SCAN_MS) {
          return { ok: false, reason: `scan ${active.scan_id} is in progress` };
        }
        this.#sql.exec(
          "UPDATE scans SET state = 'abandoned', updated_at = ? WHERE scan_id = ?",
          ctx.now,
          active.scan_id,
        );
        this.#sql.exec('DELETE FROM scan_candidates WHERE scan_id = ?', active.scan_id);
      }
      const logSize = this.#log.publishedSize();
      let startSeq: number | null = null;
      if (mode === 'audit') {
        startSeq = this.#append(
          `scan:${scanId}:start`,
          encodeEntry({
            v: 1,
            type: 'audit.scan',
            scanId,
            phase: 'start',
            logSizeAtStart: logSize,
          }),
          ctx,
        );
      }
      this.#sql.exec(
        `INSERT INTO scans(scan_id, mode, state, grace_seconds, started_at, updated_at,
           log_size_at_start, start_seq)
         VALUES (?, ?, 'listing', ?, ?, ?, ?, ?)`,
        scanId,
        mode,
        graceSeconds,
        ctx.now,
        ctx.now,
        logSize,
        startSeq,
      );
      const row = this.#row(scanId);
      if (row === null) throw new Error('unreachable');
      return { ok: true, scan: this.#summary(row) };
    });
  }

  /**
   * Applies one page of the listing. Audit: merge-join against the objects view and record the
   * divergences as candidates. Backfill: append an `object.snapshot` for each listed object the
   * log has never named. Re-applying the last page (a step retried after it committed) returns the
   * stored result without doing anything; any other page out of sequence is refused.
   */
  page(req: PageRequest, ctx: ScanContext): Outcome<PageResult> {
    checkListed(req.listed);
    if (!Number.isInteger(req.liveLimit) || req.liveLimit < 1 || req.liveLimit > MAX_PAGE_OBJECTS) {
      throw new AuditInputError(`liveLimit must be 1..${String(MAX_PAGE_OBJECTS)}`);
    }
    return this.#storage.transactionSync((): Outcome<PageResult> => {
      const s = this.#row(req.scanId);
      if (s === null) return { ok: false, reason: `no scan ${req.scanId}` };
      if (req.page === s.pages - 1 && req.after === s.last_after && s.last_result !== null) {
        return { ok: true, ...(JSON.parse(s.last_result) as PageResult) };
      }
      if (s.state !== 'listing') return { ok: false, reason: `scan ${req.scanId} is ${s.state}` };
      if (req.page !== s.pages || req.after !== s.cursor) {
        return { ok: false, reason: `page ${String(req.page)} is out of sequence` };
      }

      let end: string | null;
      let scanned: number;
      let candidates: Candidate[] = [];
      let snapshots = 0;
      if (s.mode === 'audit') {
        const live = this.#log.objectStates({
          ...(req.after === null ? {} : { after: req.after }),
          limit: req.liveLimit + 1,
          liveOnly: true,
        });
        const rows = new Map(
          req.listed.flatMap((o) => {
            const r = this.#log.objectState(o.key);
            return r === null ? [] : [[o.key, r] as const];
          }),
        );
        const r = reconcilePage({
          after: req.after,
          listed: req.listed,
          listTruncated: req.listTruncated,
          live: live.slice(0, req.liveLimit),
          liveTruncated: live.length > req.liveLimit,
          rows,
          now: ctx.now,
          graceMs: s.grace_seconds * 1000,
        });
        ({ end, scanned, candidates } = r);
        for (const c of candidates) {
          this.#sql.exec(
            `INSERT INTO scan_candidates(scan_id, kind, key, basis_seq, observed_at, entry)
             VALUES (?, ?, ?, ?, ?, ?)`,
            req.scanId,
            c.kind,
            c.key,
            c.basisSeq,
            ctx.now,
            encodeEntry(this.#finding(c, s, ctx)),
          );
        }
      } else {
        checkOrder(
          req.listed.map((o) => o.key),
          req.after,
          'listing',
        );
        end = pageEnd(req.listed, req.listTruncated, [], false);
        scanned = req.listed.length;
        req.listed.forEach((o, i) => {
          // Only objects the log has never named. A key the log knows (even as deleted) is the
          // auditor's business: snapshotting it would paper over a divergence.
          if (this.#log.objectState(o.key) !== null) return;
          this.#append(
            `snap:${req.scanId}:${String(req.page)}:${String(i)}`,
            encodeEntry({
              v: 1,
              type: 'object.snapshot',
              bucket: ctx.bucket,
              key: o.key,
              size: o.size,
              etag: o.etag,
              uploaded: iso(o.uploaded),
              snapshotId: req.scanId,
            }),
            ctx,
          );
          snapshots++;
        });
      }

      const state: ScanState =
        end !== null ? 'listing' : s.mode === 'audit' ? 'confirming' : 'finishing';
      const result: PageResult = { end, state, scanned, candidates: candidates.length, snapshots };
      this.#sql.exec(
        `UPDATE scans SET state = ?, cursor = ?, pages = pages + 1, last_after = ?, last_result = ?,
           objects_scanned = objects_scanned + ?, candidates = candidates + ?,
           snapshots = snapshots + ?, updated_at = ?
         WHERE scan_id = ?`,
        state,
        end,
        req.after,
        JSON.stringify(result),
        scanned,
        candidates.length,
        snapshots,
        ctx.now,
        req.scanId,
      );
      return { ok: true, ...result };
    });
  }

  #finding(c: Candidate, s: ScanRow, ctx: ScanContext): AuditFinding {
    return {
      v: 1,
      type: 'audit.finding',
      kind: c.kind,
      bucket: ctx.bucket,
      key: c.key,
      ...(c.observed === undefined ? {} : { observed: c.observed }),
      ...(c.expected === undefined ? {} : { expected: c.expected }),
      scanId: s.scan_id,
      observedAt: iso(ctx.now),
      graceSeconds: s.grace_seconds,
    };
  }

  /**
   * Records deep-scrub results for an applied page: an `audit.observation` per object, and a
   * CONTENT_DRIFT finding when the body's SHA-256 differs from the last published observation
   * with the same ETag, or from the SHA-256 R2 stored at upload. Runs at most once per page.
   */
  observe(
    scanId: string,
    page: number,
    observations: readonly ScrubObservation[],
    ctx: ScanContext,
  ): Outcome<{ observations: number; findings: number }> {
    const list: unknown = observations;
    if (!Array.isArray(list) || observations.length > MAX_PAGE_OBJECTS) {
      throw new AuditInputError(`at most ${String(MAX_PAGE_OBJECTS)} observations per page`);
    }
    observations.forEach(checkObservation);
    return this.#storage.transactionSync(() => {
      const s = this.#row(scanId);
      if (s === null) return { ok: false, reason: `no scan ${scanId}` };
      if (page <= s.observed_through) return { ok: true, observations: 0, findings: 0 };
      if (s.mode !== 'audit' || (s.state !== 'listing' && s.state !== 'confirming')) {
        return { ok: false, reason: `scan ${scanId} is ${s.state}` };
      }
      if (!Number.isInteger(page) || page >= s.pages) {
        return { ok: false, reason: `page ${String(page)} has not been applied` };
      }
      let findings = 0;
      observations.forEach((o, i) => {
        const id = `${scanId}:${String(page)}:${String(i)}`;
        this.#append(
          `obs:${id}`,
          encodeEntry({
            v: 1,
            type: 'audit.observation',
            bucket: ctx.bucket,
            key: o.key,
            etag: o.etag,
            size: o.size,
            sha256: o.sha256,
            scanId,
            observedAt: iso(o.observedAt),
          }),
          ctx,
        );
        const observed = {
          etag: o.etag,
          size: o.size,
          uploaded: iso(o.uploaded),
          sha256: o.sha256,
        };
        const drift = (suffix: string, expected: AuditFinding['expected']): void => {
          const entry = encodeEntry({
            v: 1,
            type: 'audit.finding',
            kind: 'CONTENT_DRIFT',
            bucket: ctx.bucket,
            key: o.key,
            observed,
            ...(expected === undefined ? {} : { expected }),
            scanId,
            observedAt: iso(o.observedAt),
            graceSeconds: s.grace_seconds,
          });
          this.#recordFinding(
            scanId,
            'CONTENT_DRIFT',
            o.key,
            this.#append(`drift:${id}:${suffix}`, entry, ctx),
            entry,
          );
          findings++;
        };
        const prev = this.#log.scrubState(o.key);
        if (prev !== null && prev.etag === o.etag && prev.sha256 !== o.sha256) {
          drift('prev', {
            etag: prev.etag,
            size: prev.size,
            eventTime: prev.observedAt,
            seq: prev.seq,
            sha256: prev.sha256,
          });
        }
        if (o.storedSha256 !== null && o.storedSha256 !== o.sha256) {
          drift('stored', { etag: o.etag, eventTime: iso(o.uploaded), sha256: o.storedSha256 });
        }
      });
      this.#sql.exec(
        `UPDATE scans SET observed_through = ?, observations = observations + ?,
           findings = findings + ?, updated_at = ? WHERE scan_id = ?`,
        page,
        observations.length,
        findings,
        ctx.now,
        scanId,
      );
      return { ok: true, observations: observations.length, findings };
    });
  }

  /**
   * Confirms up to `limit` candidates whose grace window has passed. A candidate becomes a finding
   * only if the log's state for its key is still the one it was judged against: any event that
   * arrived (and was published) since then explains it, and it is dropped instead. The caller
   * flushes publication first, so every durable event is in the objects view.
   */
  confirm(scanId: string, limit: number, ctx: ScanContext): Outcome<ConfirmResult> {
    if (!Number.isInteger(limit) || limit < 1 || limit > MAX_PAGE_OBJECTS) {
      throw new AuditInputError(`limit must be 1..${String(MAX_PAGE_OBJECTS)}`);
    }
    return this.#storage.transactionSync((): Outcome<ConfirmResult> => {
      const s = this.#row(scanId);
      if (s === null) return { ok: false, reason: `no scan ${scanId}` };
      if (s.state === 'finishing' || s.state === 'reporting' || s.state === 'done') {
        return { ok: true, state: s.state, confirmed: 0, dropped: 0, remaining: 0, waitMs: 0 };
      }
      if (s.state !== 'confirming') return { ok: false, reason: `scan ${scanId} is ${s.state}` };
      const graceMs = s.grace_seconds * 1000;
      const due = this.#sql
        .exec<{
          id: number;
          kind: string;
          key: string;
          basis_seq: number | null;
          entry: ArrayBuffer;
        }>(
          `SELECT id, kind, key, basis_seq, entry FROM scan_candidates
           WHERE scan_id = ? AND observed_at <= ? ORDER BY id LIMIT ?`,
          scanId,
          ctx.now - graceMs,
          limit,
        )
        .toArray();
      let confirmed = 0;
      for (const c of due) {
        const current = this.#log.objectState(c.key)?.seq ?? null;
        if (current === c.basis_seq) {
          const entry = new Uint8Array(c.entry);
          const seq = this.#append(`find:${scanId}:${String(c.id)}`, entry, ctx);
          this.#recordFinding(scanId, c.kind as FindingKind, c.key, seq, entry);
          confirmed++;
        }
        this.#sql.exec('DELETE FROM scan_candidates WHERE id = ?', c.id);
      }
      const dropped = due.length - confirmed;
      const next = this.#sql
        .exec<{ n: number; oldest: number | null }>(
          'SELECT count(*) AS n, min(observed_at) AS oldest FROM scan_candidates WHERE scan_id = ?',
          scanId,
        )
        .one();
      const state: ScanState = next.n === 0 ? 'finishing' : 'confirming';
      const waitMs =
        next.n === 0 || due.length === limit || next.oldest === null
          ? 0
          : Math.max(0, next.oldest + graceMs - ctx.now);
      this.#sql.exec(
        `UPDATE scans SET state = ?, findings = findings + ?, dropped = dropped + ?, updated_at = ?
         WHERE scan_id = ?`,
        state,
        confirmed,
        dropped,
        ctx.now,
        scanId,
      );
      return { ok: true, state, confirmed, dropped, remaining: next.n, waitMs };
    });
  }

  /**
   * Ends a scan whose confirmation is complete. An audit appends `audit.scan` end (objects
   * scanned, findings) and moves to `reporting`; the caller then writes the report and calls
   * `markDone`. A backfill is done at once. Idempotent.
   */
  finish(scanId: string, ctx: ScanContext): Outcome<{ scan: ScanSummary }> {
    return this.#storage.transactionSync((): Outcome<{ scan: ScanSummary }> => {
      const s = this.#row(scanId);
      if (s === null) return { ok: false, reason: `no scan ${scanId}` };
      if (s.state === 'finishing') {
        if (s.mode === 'audit') {
          const endSeq = this.#append(
            `scan:${scanId}:end`,
            encodeEntry({
              v: 1,
              type: 'audit.scan',
              scanId,
              phase: 'end',
              objectsScanned: s.objects_scanned,
              findings: s.findings,
            }),
            ctx,
          );
          this.#sql.exec(
            `UPDATE scans SET state = 'reporting', end_seq = ?, finished_at = ?, updated_at = ?
             WHERE scan_id = ?`,
            endSeq,
            ctx.now,
            ctx.now,
            scanId,
          );
        } else {
          this.#sql.exec(
            "UPDATE scans SET state = 'done', finished_at = ?, updated_at = ? WHERE scan_id = ?",
            ctx.now,
            ctx.now,
            scanId,
          );
        }
      } else if (s.state !== 'reporting' && s.state !== 'done') {
        return { ok: false, reason: `scan ${scanId} is ${s.state}` };
      }
      const row = this.#row(scanId);
      if (row === null) throw new Error('unreachable');
      return { ok: true, scan: this.#summary(row) };
    });
  }

  /**
   * The report for a finished audit (`x-reports/<scanId>.json`). Built only from committed state
   * that no longer changes once the scan is `reporting`, so a retried write produces the same bytes.
   */
  report(scanId: string, origin: string): ScanReport | null {
    const s = this.#row(scanId);
    if (s === null || s.mode !== 'audit' || (s.state !== 'reporting' && s.state !== 'done')) {
      return null;
    }
    const byKind: Record<string, number> = {};
    for (const r of this.#sql.exec<{ kind: string; n: number }>(
      'SELECT kind, count(*) AS n FROM scan_findings WHERE scan_id = ? GROUP BY kind ORDER BY kind',
      scanId,
    )) {
      byKind[r.kind] = r.n;
    }
    const entries = this.#sql
      .exec<{ seq: number; kind: string; key: string }>(
        'SELECT seq, kind, key FROM scan_findings WHERE scan_id = ? ORDER BY seq LIMIT ?',
        scanId,
        REPORT_MAX_FINDINGS,
      )
      .toArray()
      .map((r) => ({ index: r.seq, kind: r.kind, key: r.key }));
    return {
      v: 1,
      origin,
      scanId,
      startedAt: iso(s.started_at),
      finishedAt: s.finished_at === null ? null : iso(s.finished_at),
      graceSeconds: s.grace_seconds,
      logSizeAtStart: s.log_size_at_start,
      startIndex: s.start_seq,
      endIndex: s.end_seq,
      objectsScanned: s.objects_scanned,
      findings: s.findings,
      dropped: s.dropped,
      observations: s.observations,
      byKind,
      entries,
      truncated: s.findings > entries.length,
    };
  }

  /** `reporting` -> `done`, then prunes findings of older scans and old summary rows. */
  markDone(scanId: string, now: number): void {
    this.#storage.transactionSync(() => {
      this.#sql.exec(
        "UPDATE scans SET state = 'done', updated_at = ? WHERE scan_id = ? AND state = 'reporting'",
        now,
        scanId,
      );
      this.#sql.exec(
        `DELETE FROM scan_findings WHERE scan_id IN
           (SELECT scan_id FROM scans WHERE scan_id != ? AND state IN ('done', 'abandoned'))`,
        scanId,
      );
      this.#sql.exec(
        `DELETE FROM scans WHERE state IN ('done', 'abandoned') AND scan_id NOT IN
           (SELECT scan_id FROM scans ORDER BY started_at DESC LIMIT ?)`,
        KEEP_SCANS,
      );
    });
  }

  /** Findings recorded by a scan, in log order, after index `after`. */
  findings(
    scanId: string,
    after: number | null,
    limit: number,
  ): { seq: number; entry: Uint8Array }[] {
    return this.#sql
      .exec<{ seq: number; entry: ArrayBuffer }>(
        `SELECT seq, entry FROM scan_findings WHERE scan_id = ?1 AND (?2 IS NULL OR seq > ?2)
         ORDER BY seq LIMIT ?3`,
        scanId,
        after,
        limit,
      )
      .toArray()
      .map((r) => ({ seq: r.seq, entry: new Uint8Array(r.entry) }));
  }
}

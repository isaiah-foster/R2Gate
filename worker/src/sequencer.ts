import { decodeEntry, newSigner, type NoteSigner } from '@r2notary/core';
import { DurableObject } from 'cloudflare:workers';
import { parseConfig, type Config } from './config.ts';
import { publish, type PublishResult } from './publish.ts';
import {
  SCHEMA_VERSION,
  SequencerStore,
  type AppendItem,
  type AppendResult,
  type ObjectRange,
  type ObjectState,
} from './store.ts';

/** Upper bound on one append call (a queue batch is at most 100 messages). */
export const MAX_APPEND_ITEMS = 1000;
export const MAX_RANGE_LIMIT = 1000;
/** Delay before an alarm retries a failed publication. */
export const PUBLISH_RETRY_MS = 30_000;

// Event IDs are hex SHA-256 from ingest (M3); the DO only needs them to be short and printable.
const EVENT_ID_RE = /^[\x21-\x7e]{1,128}$/;

export interface SequencerStatus {
  readonly schemaVersion: number;
  /** Entries durable in SQLite (the next sequence number). */
  readonly durableSize: number;
  /** Entries covered by the last committed publication. */
  readonly publishedSize: number;
  readonly pending: number;
  readonly lastPublishAt: number | null;
  readonly lastError: string | null;
  readonly alarmAt: number | null;
}

export class AppendError extends Error {
  override name = 'AppendError';
}

/**
 * Rejects the whole call if any item is malformed: the caller (ingest, auditor) builds entries
 * with the core encoder, so a bad item is a bug, and refusing it keeps the log and the objects
 * view free of entries the schema does not allow.
 */
export function validateAppendItems(items: readonly AppendItem[], monitoredBucket: string): void {
  if (!Array.isArray(items) || items.length === 0 || items.length > MAX_APPEND_ITEMS) {
    throw new AppendError(`append takes 1..${String(MAX_APPEND_ITEMS)} items`);
  }
  items.forEach(({ eventId, entry }, i) => {
    if (typeof eventId !== 'string' || !EVENT_ID_RE.test(eventId)) {
      throw new AppendError(`item ${String(i)}: eventId must be 1-128 printable ASCII characters`);
    }
    if (!(entry instanceof Uint8Array))
      throw new AppendError(`item ${String(i)}: entry must be bytes`);
    let decoded;
    try {
      decoded = decodeEntry(entry);
    } catch (e) {
      throw new AppendError(`item ${String(i)}: ${e instanceof Error ? e.message : String(e)}`);
    }
    if (!decoded.known)
      throw new AppendError(`item ${String(i)}: unknown entry type ${decoded.type}`);
    // The objects view is per bucket; one deployment monitors one bucket (PLAN §7).
    const e = decoded.entry;
    if ('bucket' in e && e.bucket !== monitoredBucket) {
      throw new AppendError(`item ${String(i)}: bucket ${e.bucket} is not the monitored bucket`);
    }
  });
}

/**
 * When the next publication is due (ms), or null if nothing is pending: one interval after the
 * oldest pending entry arrived, or now if a full batch is waiting. Never in the past.
 */
export function publicationDue(p: {
  readonly now: number;
  readonly pending: number;
  readonly oldestPendingAt: number | null;
  readonly batchMaxEntries: number;
  readonly checkpointIntervalMs: number;
}): number | null {
  if (p.pending === 0 || p.oldestPendingAt === null) return null;
  if (p.pending >= p.batchMaxEntries) return p.now;
  return Math.max(p.now, p.oldestPendingAt + p.checkpointIntervalMs);
}

/**
 * Single-writer sequencer, one instance per log (`getByName(LOG_NAME)`). Appends are durable when
 * they return; an alarm publishes them within CHECKPOINT_INTERVAL_MS, or as soon as
 * BATCH_MAX_ENTRIES are waiting.
 */
export class Sequencer extends DurableObject<Env> {
  readonly #config: Config;
  readonly #store: SequencerStore;
  #signer: Promise<NoteSigner> | null = null;
  #inflight: Promise<PublishResult> | null = null;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.#config = parseConfig(env);
    this.#store = new SequencerStore(ctx.storage);
    // Synchronous SQL in the constructor completes before any request is delivered, so it needs
    // no blockConcurrencyWhile.
    this.#store.migrate();
  }

  async append(items: AppendItem[]): Promise<AppendResult> {
    validateAppendItems(items, this.#config.monitoredBucket);
    const result = this.#store.append(items, Date.now(), this.#config.dedupeTtlSeconds * 1000);
    await this.#scheduleAlarm(false);
    return result;
  }

  /** Publishes pending entries now. Single-flight: concurrent callers share one run. */
  publish(): Promise<PublishResult> {
    this.#inflight ??= this.#publishOnce().finally(() => {
      this.#inflight = null;
    });
    return this.#inflight;
  }

  async #publishOnce(): Promise<PublishResult> {
    try {
      return await publish({
        store: this.#store,
        bucket: this.env.LOG,
        signer: await this.#getSigner(),
        config: this.#config,
        now: Date.now,
      });
    } catch (e) {
      const message = e instanceof Error ? `${e.name}: ${e.message}` : String(e);
      console.error(`r2notary publish failed: ${message}`);
      this.#store.setLastError(message);
      throw e;
    }
  }

  #getSigner(): Promise<NoteSigner> {
    this.#signer ??= newSigner(this.env.SIGNING_KEY).catch((e: unknown) => {
      this.#signer = null;
      throw e;
    });
    return this.#signer;
  }

  /**
   * Publishes, then re-arms while entries remain. A failed publication is retried by this DO
   * rather than by rethrowing: the runtime gives up after 6 alarm retries, which would leave
   * durable entries unpublished until the next append. The failure stays visible in
   * `status().lastError` and the logs, and a divergence keeps failing on every retry.
   */
  override async alarm(): Promise<void> {
    this.#store.pruneSeen(Date.now());
    try {
      await this.publish();
    } catch {
      await this.ctx.storage.setAlarm(Date.now() + PUBLISH_RETRY_MS);
      return;
    }
    await this.#scheduleAlarm(true);
  }

  /**
   * Publication is due CHECKPOINT_INTERVAL_MS after the oldest pending entry arrived, or at once
   * when a full batch is waiting, so every entry is published within one interval of arrival
   * (while publication keeps up). Outside the alarm handler an earlier alarm is kept; inside it
   * the running alarm is being consumed, so a new one is always set while entries remain.
   */
  async #scheduleAlarm(inAlarm: boolean): Promise<void> {
    const due = publicationDue({
      now: Date.now(),
      pending: this.#store.pendingCount(),
      oldestPendingAt: this.#store.oldestPendingAt(),
      batchMaxEntries: this.#config.batchMaxEntries,
      checkpointIntervalMs: this.#config.checkpointIntervalMs,
    });
    if (due === null) return;
    const current = inAlarm ? null : await this.ctx.storage.getAlarm();
    if (current === null || current > due) await this.ctx.storage.setAlarm(due);
  }

  async status(): Promise<SequencerStatus> {
    return {
      schemaVersion: SCHEMA_VERSION,
      durableSize: this.#store.nextSeq(),
      publishedSize: this.#store.publishedSize(),
      pending: this.#store.pendingCount(),
      lastPublishAt: this.#store.lastPublishAt(),
      lastError: this.#store.lastError(),
      alarmAt: await this.ctx.storage.getAlarm(),
    };
  }

  /** Expected object state for the auditor's merge-join (M6). */
  getObjectStates(range: ObjectRange): ObjectState[] {
    if (!Number.isInteger(range.limit) || range.limit < 1 || range.limit > MAX_RANGE_LIMIT) {
      throw new RangeError(`limit must be 1..${String(MAX_RANGE_LIMIT)}`);
    }
    return this.#store.objectStates(range);
  }

  /** Log indexes of published entries for `key` (unverified; clients check inclusion proofs). */
  lookup(key: string): number[] {
    return this.#store.lookup(key, MAX_RANGE_LIMIT);
  }
}

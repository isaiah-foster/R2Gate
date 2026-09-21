// The Sequencer's SQLite state (PLAN §5.3) and every query against it. All methods are synchronous:
// DO SQLite calls run in-process, and keeping them free of awaits means a multi-statement update is
// wrapped in one `transactionSync` and either commits whole or not at all.
//
// Tables:
//   meta        key/value: schema_version, next_seq, published_size, publishing_size, ...
//   entries     every entry not yet published, plus the published entries of the current partial
//               bundle (seq >= 256 * floor(published_size / 256)); see DECISIONS D2.2
//   seen        dedupe window: event_id -> seq, expiring at expires_at (ms)
//   tile_state  the partial tile at each level for published_size
//   objects     latest logged state per key (the auditor's "expected state")
//   key_index   (key, seq) for every published entry that names a key
//   counters    ingest counters shown by /status (v2)

import {
  TILE_WIDTH,
  decodeEntry,
  type DecodedEntry,
  type LogState,
  type TreeState,
} from '@r2notary/core';

export interface AppendItem {
  readonly eventId: string;
  readonly entry: Uint8Array;
}

export interface AppendResult {
  readonly accepted: number;
  readonly duplicates: number;
  /** Sequence number of the first accepted item, or null if every item was a duplicate. */
  readonly firstSeq: number | null;
}

/** What a queue batch contained besides loggable events (PLAN §5.4). */
export interface IngestReport {
  readonly invalid: number;
  /** Events from the log bucket (I8). */
  readonly loopDropped: number;
  /** Events from a bucket other than MONITORED_BUCKET_NAME. */
  readonly foreignDropped: number;
  /** Messages delivered from the dead-letter queue. */
  readonly deadLettered: number;
  /** Why the batch's last invalid message was rejected. Never contains message content. */
  readonly lastInvalid?: string;
}

export interface IngestCounters {
  readonly accepted: number;
  readonly duplicates: number;
  readonly invalid: number;
  readonly loopDropped: number;
  readonly foreignDropped: number;
  readonly deadLettered: number;
  readonly lastInvalid: { readonly at: number; readonly reason: string } | null;
}

const COUNTERS = [
  'accepted',
  'duplicates',
  'invalid',
  'loopDropped',
  'foreignDropped',
  'deadLettered',
] as const;

export interface ObjectState {
  readonly key: string;
  readonly etag: string | null;
  readonly size: number | null;
  /** RFC 3339 time of the entry that set this state (eventTime, or uploaded for a snapshot). */
  readonly eventTime: string;
  /** Log index of that entry. */
  readonly seq: number;
  readonly deleted: boolean;
}

export interface ObjectRange {
  /** Exclusive lower bound (keys strictly greater). */
  readonly after?: string;
  /** Inclusive upper bound. */
  readonly through?: string;
  readonly limit: number;
}

export class StoreError extends Error {
  override name = 'StoreError';
}

const MIGRATIONS: readonly (readonly string[])[] = [
  // v1
  [
    `CREATE TABLE entries(
       seq INTEGER PRIMARY KEY,
       entry BLOB NOT NULL,
       received_at INTEGER NOT NULL)`,
    `CREATE TABLE seen(
       event_id TEXT PRIMARY KEY,
       seq INTEGER NOT NULL,
       expires_at INTEGER NOT NULL)`,
    `CREATE INDEX seen_expiry ON seen(expires_at)`,
    `CREATE TABLE tile_state(level INTEGER PRIMARY KEY, hashes BLOB NOT NULL)`,
    `CREATE TABLE objects(
       key TEXT PRIMARY KEY,
       etag TEXT,
       size INTEGER,
       event_time TEXT NOT NULL,
       event_ms INTEGER NOT NULL,
       seq INTEGER NOT NULL,
       deleted INTEGER NOT NULL DEFAULT 0)`,
    `CREATE TABLE key_index(key TEXT NOT NULL, seq INTEGER NOT NULL, PRIMARY KEY(key, seq))`,
  ],
  // v2 (M3)
  [`CREATE TABLE counters(name TEXT PRIMARY KEY, value INTEGER NOT NULL)`],
];

export const SCHEMA_VERSION = MIGRATIONS.length;

const RFC3339 =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(?:Z|([+-])(\d{2}):(\d{2}))$/;

/**
 * Milliseconds since the epoch for an RFC 3339 timestamp already validated by the entry schema.
 * Parsed by hand rather than with Date.parse so the result does not depend on the engine's date
 * parser. Sub-millisecond digits are truncated; equal times are ordered by seq.
 */
export function eventMillis(ts: string): number {
  const m = RFC3339.exec(ts);
  if (!m) throw new StoreError(`not an RFC 3339 timestamp: ${ts}`);
  const n = (i: number): number => Number(m[i] ?? 0);
  const d = new Date(0);
  d.setUTCFullYear(n(1), n(2) - 1, n(3)); // not Date.UTC, which maps years 0-99 to 1900-1999
  d.setUTCHours(n(4), n(5), n(6), Number((m[7] ?? '').padEnd(3, '0').slice(0, 3)));
  const offset = (n(9) * 60 + n(10)) * 60_000;
  return d.getTime() - (m[8] === '-' ? -offset : offset);
}

function blob(v: unknown, what: string): Uint8Array {
  if (!(v instanceof ArrayBuffer)) throw new StoreError(`${what} is not a BLOB`);
  return new Uint8Array(v);
}

function int(v: unknown, what: string): number {
  if (typeof v !== 'number' || !Number.isSafeInteger(v)) {
    throw new StoreError(`${what} is not an integer`);
  }
  return v;
}

/** The key an entry is about, if any (indexed in key_index). */
function entryKey(d: DecodedEntry): string | null {
  if (!d.known) return null;
  return d.entry.type === 'audit.scan' ? null : d.entry.key;
}

export class SequencerStore {
  readonly #storage: DurableObjectStorage;
  readonly #sql: SqlStorage;

  constructor(storage: DurableObjectStorage) {
    this.#storage = storage;
    this.#sql = storage.sql;
  }

  /** Creates or upgrades the schema. Idempotent; run in blockConcurrencyWhile on construction. */
  migrate(): void {
    this.#storage.transactionSync(() => {
      this.#sql.exec('CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v)');
      const version = this.#metaInt('schema_version', 0);
      if (version > SCHEMA_VERSION) {
        throw new StoreError(
          `stored schema v${String(version)} is newer than this code (v${String(SCHEMA_VERSION)})`,
        );
      }
      for (const statements of MIGRATIONS.slice(version)) {
        for (const s of statements) this.#sql.exec(s);
      }
      this.#setMeta('schema_version', SCHEMA_VERSION);
    });
  }

  #meta(k: string): SqlStorageValue | undefined {
    const row = this.#sql.exec<{ v: SqlStorageValue }>('SELECT v FROM meta WHERE k = ?', k).next();
    return row.done === true ? undefined : row.value.v;
  }

  #metaInt(k: string, fallback: number): number {
    const v = this.#meta(k);
    return v === undefined || v === null ? fallback : int(v, `meta.${k}`);
  }

  #setMeta(k: string, v: SqlStorageValue): void {
    this.#sql.exec('INSERT OR REPLACE INTO meta(k, v) VALUES (?, ?)', k, v);
  }

  /** Number of entries covered by the last committed publication. */
  publishedSize(): number {
    return this.#metaInt('published_size', 0);
  }

  /** Sequence number the next accepted entry gets; also the number of durable entries. */
  nextSeq(): number {
    return this.#metaInt('next_seq', 0);
  }

  /**
   * Size a publication has started writing to R2 but not committed (null if none). A retry must
   * publish at least this size, so the live checkpoint can never move backwards (DECISIONS D2.4).
   */
  publishingSize(): number | null {
    const v = this.#meta('publishing_size');
    return v === undefined || v === null ? null : int(v, 'meta.publishing_size');
  }

  setPublishingSize(size: number): void {
    this.#setMeta('publishing_size', size);
  }

  lastPublishAt(): number | null {
    const v = this.#meta('last_publish_at');
    return v === undefined || v === null ? null : int(v, 'meta.last_publish_at');
  }

  lastError(): string | null {
    const v = this.#meta('last_error');
    return typeof v === 'string' ? v : null;
  }

  setLastError(message: string | null): void {
    this.#setMeta('last_error', message);
  }

  /**
   * Durably records new entries, skipping event IDs seen within the dedupe window (I5). One
   * transaction: either the whole batch gets sequence numbers or none of it does. The entries must
   * already be validated by the caller.
   */
  append(items: readonly AppendItem[], now: number, ttlMs: number): AppendResult {
    return this.#storage.transactionSync(() => this.#insert(items, now, ttlMs));
  }

  /**
   * A queue batch: its events and its counters in one transaction, so the counters move exactly
   * when the events become durable. `items` may be empty (a batch of nothing but junk).
   */
  ingest(
    items: readonly AppendItem[],
    report: IngestReport,
    now: number,
    ttlMs: number,
  ): AppendResult {
    return this.#storage.transactionSync(() => {
      const result = this.#insert(items, now, ttlMs);
      const add = { ...report, accepted: result.accepted, duplicates: result.duplicates };
      for (const name of COUNTERS) {
        if (add[name] === 0) continue;
        this.#sql.exec(
          `INSERT INTO counters(name, value) VALUES (?1, ?2)
           ON CONFLICT(name) DO UPDATE SET value = value + ?2`,
          name,
          add[name],
        );
      }
      if (report.lastInvalid !== undefined) {
        this.#setMeta('last_invalid_at', now);
        this.#setMeta('last_invalid', report.lastInvalid);
      }
      return result;
    });
  }

  #insert(items: readonly AppendItem[], now: number, ttlMs: number): AppendResult {
    let next = this.nextSeq();
    let firstSeq: number | null = null;
    let duplicates = 0;
    for (const { eventId, entry } of items) {
      const seen = this.#sql
        .exec<{ expires_at: number }>('SELECT expires_at FROM seen WHERE event_id = ?', eventId)
        .next();
      if (seen.done !== true && seen.value.expires_at > now) {
        duplicates++;
        continue;
      }
      firstSeq ??= next;
      this.#sql.exec(
        'INSERT INTO entries(seq, entry, received_at) VALUES (?, ?, ?)',
        next,
        entry,
        now,
      );
      this.#sql.exec(
        'INSERT OR REPLACE INTO seen(event_id, seq, expires_at) VALUES (?, ?, ?)',
        eventId,
        next,
        now + ttlMs,
      );
      next++;
    }
    this.#setMeta('next_seq', next);
    return { accepted: items.length - duplicates, duplicates, firstSeq };
  }

  ingestCounters(): IngestCounters {
    const values = new Map<string, number>();
    for (const row of this.#sql.exec<{ name: string; value: number }>(
      'SELECT name, value FROM counters',
    )) {
      values.set(row.name, int(row.value, `counter ${row.name}`));
    }
    const at = this.#meta('last_invalid_at');
    const reason = this.#meta('last_invalid');
    const count = (name: (typeof COUNTERS)[number]): number => values.get(name) ?? 0;
    return {
      accepted: count('accepted'),
      duplicates: count('duplicates'),
      invalid: count('invalid'),
      loopDropped: count('loopDropped'),
      foreignDropped: count('foreignDropped'),
      deadLettered: count('deadLettered'),
      lastInvalid:
        typeof reason === 'string' && at !== undefined && at !== null
          ? { at: int(at, 'meta.last_invalid_at'), reason }
          : null,
    };
  }

  /** Deletes dedupe records whose window has passed. */
  pruneSeen(now: number): void {
    this.#sql.exec('DELETE FROM seen WHERE expires_at <= ?', now);
  }

  /** Entries [from, to), which must all be present. */
  readEntries(from: number, to: number): Uint8Array[] {
    const out: Uint8Array[] = [];
    for (const row of this.#sql.exec<{ seq: number; entry: ArrayBuffer }>(
      'SELECT seq, entry FROM entries WHERE seq >= ? AND seq < ? ORDER BY seq',
      from,
      to,
    )) {
      if (row.seq !== from + out.length)
        throw new StoreError(`entry ${String(row.seq)} out of place`);
      out.push(blob(row.entry, `entry ${String(row.seq)}`));
    }
    if (out.length !== to - from) {
      throw new StoreError(
        `expected entries [${String(from)}, ${String(to)}), found ${String(out.length)}`,
      );
    }
    return out;
  }

  /** The writer state at published_size: partial tiles plus the partial bundle's entries. */
  loadLogState(): LogState {
    const size = this.publishedSize();
    const partials: Uint8Array[] = [];
    for (const row of this.#sql.exec<{ level: number; hashes: ArrayBuffer }>(
      'SELECT level, hashes FROM tile_state ORDER BY level',
    )) {
      if (row.level !== partials.length)
        throw new StoreError('tile_state levels are not contiguous');
      partials.push(blob(row.hashes, `tile_state level ${String(row.level)}`));
    }
    const bundleStart = size - (size % TILE_WIDTH);
    // appendEntries validates the widths against `size` before using this state.
    return { tree: { size, partials }, bundle: this.readEntries(bundleStart, size) };
  }

  /**
   * Step 5 of publication, in one transaction: persist the new tree state, apply the published
   * entries to `objects`/`key_index`, advance published_size, and drop entries no longer needed.
   * Refuses to run unless published_size still equals `fromSize` (single-writer guard).
   */
  commitPublish(
    fromSize: number,
    tree: TreeState,
    entries: readonly Uint8Array[],
    now: number,
  ): void {
    this.#storage.transactionSync(() => {
      const current = this.publishedSize();
      if (current !== fromSize) {
        throw new StoreError(`published_size is ${String(current)}, expected ${String(fromSize)}`);
      }
      if (tree.size !== fromSize + entries.length || tree.size < current) {
        throw new StoreError('new tree size does not match the published entries');
      }
      this.#sql.exec('DELETE FROM tile_state');
      tree.partials.forEach((hashes, level) => {
        this.#sql.exec('INSERT INTO tile_state(level, hashes) VALUES (?, ?)', level, hashes);
      });
      entries.forEach((e, i) => {
        this.#applyEntry(fromSize + i, e);
      });
      this.#setMeta('published_size', tree.size);
      this.#setMeta('publishing_size', null);
      this.#setMeta('last_publish_at', now);
      this.#setMeta('last_error', null);
      this.#sql.exec('DELETE FROM entries WHERE seq < ?', tree.size - (tree.size % TILE_WIDTH));
    });
  }

  /**
   * Updates the expected-state view for one published entry. Events are applied in seq order, but
   * an event older (by eventTime) than the stored state for its key does not replace it, which
   * tolerates out-of-order delivery; ties go to the later seq.
   */
  #applyEntry(seq: number, bytes: Uint8Array): void {
    const decoded = decodeEntry(bytes);
    const key = entryKey(decoded);
    if (key === null || !decoded.known) return;
    this.#sql.exec('INSERT OR IGNORE INTO key_index(key, seq) VALUES (?, ?)', key, seq);

    const e = decoded.entry;
    let state: { etag: string | null; size: number | null; time: string; deleted: number };
    if (e.type === 'object.event') {
      const deleted = e.action === 'DeleteObject' || e.action === 'LifecycleDeletion';
      state = {
        etag: e.etag ?? null,
        size: e.size ?? null,
        time: e.eventTime,
        deleted: deleted ? 1 : 0,
      };
    } else if (e.type === 'object.snapshot') {
      state = { etag: e.etag, size: e.size, time: e.uploaded, deleted: 0 };
    } else {
      return; // findings and observations are indexed but do not change the expected state
    }
    this.#sql.exec(
      `INSERT INTO objects(key, etag, size, event_time, event_ms, seq, deleted)
         VALUES (?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(key) DO UPDATE SET
         etag = excluded.etag, size = excluded.size, event_time = excluded.event_time,
         event_ms = excluded.event_ms, seq = excluded.seq, deleted = excluded.deleted
       WHERE excluded.event_ms >= objects.event_ms`,
      key,
      state.etag,
      state.size,
      state.time,
      eventMillis(state.time),
      seq,
      state.deleted,
    );
  }

  /** Expected state for keys in (after, through], in key order (SQLite BINARY = UTF-8 byte order). */
  objectStates(range: ObjectRange): ObjectState[] {
    const rows = this.#sql.exec<{
      key: string;
      etag: string | null;
      size: number | null;
      event_time: string;
      seq: number;
      deleted: number;
    }>(
      `SELECT key, etag, size, event_time, seq, deleted FROM objects
       WHERE (?1 IS NULL OR key > ?1) AND (?2 IS NULL OR key <= ?2)
       ORDER BY key LIMIT ?3`,
      range.after ?? null,
      range.through ?? null,
      range.limit,
    );
    return rows.toArray().map((r) => ({
      key: r.key,
      etag: r.etag,
      size: r.size,
      eventTime: r.event_time,
      seq: r.seq,
      deleted: r.deleted !== 0,
    }));
  }

  /** Log indexes of published entries naming `key`, oldest first. */
  lookup(key: string, limit: number): number[] {
    return this.#sql
      .exec<{ seq: number }>(
        'SELECT seq FROM key_index WHERE key = ? ORDER BY seq LIMIT ?',
        key,
        limit,
      )
      .toArray()
      .map((r) => r.seq);
  }

  /** When the oldest unpublished entry was accepted (ms), or null if none is pending. */
  oldestPendingAt(): number | null {
    const row = this.#sql
      .exec<{ received_at: number }>(
        'SELECT received_at FROM entries WHERE seq >= ? ORDER BY seq LIMIT 1',
        this.publishedSize(),
      )
      .next();
    return row.done === true ? null : row.value.received_at;
  }

  /** Entries durable but not yet covered by a committed publication. */
  pendingCount(): number {
    return this.nextSeq() - this.publishedSize();
  }
}

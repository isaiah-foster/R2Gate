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
//   scrub_state last published deep-scrub observation per key (v3)
//   scans, scan_candidates, scan_findings   auditor state (v3; worker/src/audit/store.ts)
//   witnesses   per witness: the size it last cosigned, and the last error (v4, M8)
//
// Key blinding (v4, M8): a blinded entry names its object by keyHmac only, but the expected-state
// view and the auditor work on real keys. So `entries.object_key` keeps the plaintext key of a
// blinded entry (private: never published, dropped with the row), `objects.key_hmac` keeps the
// name the log uses, and key_index is keyed by that name, which is what lookups receive.

import {
  TILE_WIDTH,
  decodeEntry,
  loggedName,
  type DecodedEntry,
  type LogState,
  type TreeState,
} from '@r2notary/core';

export interface AppendItem {
  readonly eventId: string;
  readonly entry: Uint8Array;
  /**
   * The plaintext key of a blinded entry (M8), kept privately so the expected-state view can be
   * maintained; absent for an entry that names its key itself or names none.
   */
  readonly key?: string;
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
  /** How the log names the key on a blinded log (M8); null on a log that is not blinded. */
  readonly keyHmac: string | null;
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
  /** Only keys the log shows as present (not deleted). */
  readonly liveOnly?: boolean;
}

/** The last published deep-scrub observation of a key (for CONTENT_DRIFT). */
export interface ScrubState {
  readonly etag: string;
  readonly size: number;
  readonly sha256: string;
  readonly observedAt: string;
  readonly seq: number;
}

export interface WitnessStatus {
  readonly vkey: string;
  /** Size of the last checkpoint it cosigned for this log, or null if it never has. */
  readonly size: number | null;
  readonly cosignedAt: number | null;
  readonly failedAt: number | null;
  readonly lastError: string | null;
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
  // v3 (M6): the auditor. The partial index serves the merge-join's range scan of live keys.
  [
    `CREATE INDEX objects_live ON objects(key) WHERE deleted = 0`,
    `CREATE TABLE scrub_state(
       key TEXT PRIMARY KEY,
       etag TEXT NOT NULL,
       size INTEGER NOT NULL,
       sha256 TEXT NOT NULL,
       observed_at TEXT NOT NULL,
       seq INTEGER NOT NULL)`,
    `CREATE TABLE scans(
       scan_id TEXT PRIMARY KEY,
       mode TEXT NOT NULL,
       state TEXT NOT NULL,
       grace_seconds INTEGER NOT NULL,
       started_at INTEGER NOT NULL,
       updated_at INTEGER NOT NULL,
       finished_at INTEGER,
       log_size_at_start INTEGER NOT NULL,
       cursor TEXT,
       pages INTEGER NOT NULL DEFAULT 0,
       last_after TEXT,
       last_result TEXT,
       observed_through INTEGER NOT NULL DEFAULT -1,
       objects_scanned INTEGER NOT NULL DEFAULT 0,
       candidates INTEGER NOT NULL DEFAULT 0,
       findings INTEGER NOT NULL DEFAULT 0,
       dropped INTEGER NOT NULL DEFAULT 0,
       observations INTEGER NOT NULL DEFAULT 0,
       snapshots INTEGER NOT NULL DEFAULT 0,
       start_seq INTEGER,
       end_seq INTEGER)`,
    `CREATE INDEX scans_state ON scans(state)`,
    `CREATE TABLE scan_candidates(
       id INTEGER PRIMARY KEY,
       scan_id TEXT NOT NULL,
       kind TEXT NOT NULL,
       key TEXT NOT NULL,
       basis_seq INTEGER,
       observed_at INTEGER NOT NULL,
       entry BLOB NOT NULL,
       UNIQUE(scan_id, kind, key))`,
    `CREATE TABLE scan_findings(
       scan_id TEXT NOT NULL,
       seq INTEGER NOT NULL,
       kind TEXT NOT NULL,
       key TEXT NOT NULL,
       entry BLOB NOT NULL,
       PRIMARY KEY(scan_id, seq))`,
  ],
  // v4 (M8): witness progress. `size` is only a hint for the next submission (a witness answers
  // 409 with its real size when it is wrong); the times and error are for /status. Key blinding:
  // the plaintext key of a blinded entry, and the blinded name of each key in the view.
  [
    `ALTER TABLE entries ADD COLUMN object_key TEXT`,
    `ALTER TABLE objects ADD COLUMN key_hmac TEXT`,
    `CREATE TABLE witnesses(
       vkey TEXT PRIMARY KEY,
       size INTEGER,
       cosigned_at INTEGER,
       failed_at INTEGER,
       last_error TEXT)`,
  ],
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

interface ObjectRow {
  [column: string]: SqlStorageValue;
  key: string;
  etag: string | null;
  size: number | null;
  event_time: string;
  seq: number;
  deleted: number;
  key_hmac: string | null;
}

const OBJECT_COLUMNS = 'key, etag, size, event_time, seq, deleted, key_hmac';

function toObjectState(r: ObjectRow): ObjectState {
  return {
    key: r.key,
    etag: r.etag,
    size: r.size,
    eventTime: r.event_time,
    keyHmac: r.key_hmac,
    seq: r.seq,
    deleted: r.deleted !== 0,
  };
}

/**
 * The name an entry is indexed under (key_index: what lookups receive) and the real key it is
 * about (the objects view), if it names an object. A blinded entry's real key comes from the
 * `object_key` kept with it.
 */
function entryNames(
  d: DecodedEntry,
  objectKey: string | null,
): { logged: string; key: string; keyHmac: string | null } | null {
  if (!d.known) return null;
  const n = loggedName(d.entry);
  if (n === null) return null;
  if (!n.blinded) return { logged: n.name, key: n.name, keyHmac: null };
  if (objectKey === null) throw new StoreError('a blinded entry was stored without its key');
  return { logged: n.name, key: objectKey, keyHmac: n.name };
}

export class SequencerStore {
  readonly #storage: DurableObjectStorage;
  readonly #sql: SqlStorage;
  #expectedBlinding: string | null = null;
  #blindingChecked = false;

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

  /**
   * How this log names keys (M8): "off", or "hmac-sha256:<fingerprint of the secret>". Null for a
   * log that has not recorded it; a log with entries but no record predates blinding ("off").
   */
  keyBlinding(): string | null {
    const v = this.#meta('key_blinding');
    if (typeof v === 'string') return v;
    return this.nextSeq() > 0 ? 'off' : null;
  }

  /**
   * Sets the blinding state the configuration implies (worker/src/blinding.ts). From then on, the
   * first append records it, and every append checks it, inside the append's transaction: a log
   * whose entries name keys one way never gets entries that name them another way.
   */
  expectKeyBlinding(state: string): void {
    if (state !== this.#expectedBlinding) this.#blindingChecked = false;
    this.#expectedBlinding = state;
  }

  #checkKeyBlinding(): void {
    const want = this.#expectedBlinding;
    // Once checked, the record cannot change under this instance (only this method writes it), so
    // later appends skip the read: the check costs no rows read per append (D8.9).
    if (want === null || this.#blindingChecked) return;
    const have = this.keyBlinding();
    if (have === null) {
      // Not cached as checked: if this transaction rolls back, the record goes with it.
      this.#setMeta('key_blinding', want);
      return;
    }
    if (have !== want) {
      throw new StoreError(
        `this log's key blinding is ${have}, but the configuration says ${want}: ` +
          'KEY_BLINDING and KEY_BLINDING_KEY cannot change for an existing log',
      );
    }
    this.#blindingChecked = true;
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
    return this.#storage.transactionSync(() => this.insertInTransaction(items, now, ttlMs));
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
      const result = this.insertInTransaction(items, now, ttlMs);
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

  /**
   * `append` without its transaction, for callers that must commit entries together with their
   * own state (the auditor, worker/src/audit/store.ts). The caller holds the transaction.
   */
  insertInTransaction(items: readonly AppendItem[], now: number, ttlMs: number): AppendResult {
    if (items.length > 0) this.#checkKeyBlinding();
    let next = this.nextSeq();
    let firstSeq: number | null = null;
    let duplicates = 0;
    for (const item of items) {
      const { eventId, entry } = item;
      const seen = this.#sql
        .exec<{ expires_at: number }>('SELECT expires_at FROM seen WHERE event_id = ?', eventId)
        .next();
      if (seen.done !== true && seen.value.expires_at > now) {
        duplicates++;
        continue;
      }
      firstSeq ??= next;
      this.#sql.exec(
        'INSERT INTO entries(seq, entry, received_at, object_key) VALUES (?, ?, ?, ?)',
        next,
        entry,
        now,
        item.key ?? null,
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
    return this.readBatch(from, to).entries;
  }

  /**
   * Entries [from, to) and, aligned with them, the private key of each blinded one (null for the
   * rest): what a publication commits. One read of the rows publication needs anyway.
   */
  readBatch(from: number, to: number): { entries: Uint8Array[]; keys: (string | null)[] } {
    const entries: Uint8Array[] = [];
    const keys: (string | null)[] = [];
    for (const row of this.#sql.exec<{
      seq: number;
      entry: ArrayBuffer;
      object_key: string | null;
    }>(
      'SELECT seq, entry, object_key FROM entries WHERE seq >= ? AND seq < ? ORDER BY seq',
      from,
      to,
    )) {
      if (row.seq !== from + entries.length)
        throw new StoreError(`entry ${String(row.seq)} out of place`);
      entries.push(blob(row.entry, `entry ${String(row.seq)}`));
      keys.push(row.object_key);
    }
    if (entries.length !== to - from) {
      throw new StoreError(
        `expected entries [${String(from)}, ${String(to)}), found ${String(entries.length)}`,
      );
    }
    return { entries, keys };
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
    keys: readonly (string | null)[] = [],
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
        this.#applyEntry(fromSize + i, e, keys[i] ?? null);
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
  #applyEntry(seq: number, bytes: Uint8Array, objectKey: string | null): void {
    const decoded = decodeEntry(bytes);
    const names = entryNames(decoded, objectKey);
    if (names === null || !decoded.known) return;
    const { key, keyHmac } = names;
    this.#sql.exec('INSERT OR IGNORE INTO key_index(key, seq) VALUES (?, ?)', names.logged, seq);

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
    } else if (e.type === 'audit.observation') {
      // Deep scrub's last word on the key; the next scrub compares against it (CONTENT_DRIFT).
      this.#sql.exec(
        `INSERT OR REPLACE INTO scrub_state(key, etag, size, sha256, observed_at, seq)
         VALUES (?, ?, ?, ?, ?, ?)`,
        key,
        e.etag,
        e.size,
        e.sha256,
        e.observedAt,
        seq,
      );
      return;
    } else {
      return; // findings are indexed but do not change the expected state
    }
    this.#sql.exec(
      `INSERT INTO objects(key, etag, size, event_time, event_ms, seq, deleted, key_hmac)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(key) DO UPDATE SET
         etag = excluded.etag, size = excluded.size, event_time = excluded.event_time,
         event_ms = excluded.event_ms, seq = excluded.seq, deleted = excluded.deleted,
         key_hmac = excluded.key_hmac
       WHERE excluded.event_ms >= objects.event_ms`,
      key,
      state.etag,
      state.size,
      state.time,
      eventMillis(state.time),
      seq,
      state.deleted,
      keyHmac,
    );
  }

  /** Expected state for keys in (after, through], in key order (SQLite BINARY = UTF-8 byte order). */
  objectStates(range: ObjectRange): ObjectState[] {
    const rows = this.#sql.exec<ObjectRow>(
      `SELECT ${OBJECT_COLUMNS} FROM objects
       WHERE (?1 IS NULL OR key > ?1) AND (?2 IS NULL OR key <= ?2) AND (?4 = 0 OR deleted = 0)
       ORDER BY key LIMIT ?3`,
      range.after ?? null,
      range.through ?? null,
      range.limit,
      range.liveOnly === true ? 1 : 0,
    );
    return rows.toArray().map(toObjectState);
  }

  /** Expected state of one key, live or deleted, or null if the log has never named it. */
  objectState(key: string): ObjectState | null {
    const rows = this.#sql
      .exec<ObjectRow>(`SELECT ${OBJECT_COLUMNS} FROM objects WHERE key = ?`, key)
      .toArray();
    const r = rows[0];
    return r === undefined ? null : toObjectState(r);
  }

  scrubState(key: string): ScrubState | null {
    const r = this.#sql
      .exec<{ etag: string; size: number; sha256: string; observed_at: string; seq: number }>(
        'SELECT etag, size, sha256, observed_at, seq FROM scrub_state WHERE key = ?',
        key,
      )
      .toArray()[0];
    return r === undefined
      ? null
      : { etag: r.etag, size: r.size, sha256: r.sha256, observedAt: r.observed_at, seq: r.seq };
  }

  /**
   * Log indexes of published entries naming `key` after index `after`, oldest first. On a blinded
   * log `key` is the keyHmac, the name the entries use.
   */
  lookup(key: string, after: number | null, limit: number): number[] {
    return this.#sql
      .exec<{ seq: number }>(
        'SELECT seq FROM key_index WHERE key = ?1 AND (?2 IS NULL OR seq > ?2) ORDER BY seq LIMIT ?3',
        key,
        after,
        limit,
      )
      .toArray()
      .map((r) => r.seq);
  }

  // ---- witnesses (M8) -------------------------------------------------------------------------

  witnessSize(vkey: string): number | null {
    const r = this.#sql
      .exec<{ size: number | null }>('SELECT size FROM witnesses WHERE vkey = ?', vkey)
      .toArray()[0];
    return r?.size ?? null;
  }

  recordWitnessSuccess(vkey: string, size: number, at: number): void {
    this.#sql.exec(
      `INSERT INTO witnesses(vkey, size, cosigned_at) VALUES (?1, ?2, ?3)
       ON CONFLICT(vkey) DO UPDATE SET size = ?2, cosigned_at = ?3`,
      vkey,
      size,
      at,
    );
  }

  recordWitnessFailure(vkey: string, error: string, at: number): void {
    this.#sql.exec(
      `INSERT INTO witnesses(vkey, failed_at, last_error) VALUES (?1, ?2, ?3)
       ON CONFLICT(vkey) DO UPDATE SET failed_at = ?2, last_error = ?3`,
      vkey,
      at,
      error,
    );
  }

  witnessStatus(vkey: string): WitnessStatus {
    const r = this.#sql
      .exec<{
        size: number | null;
        cosigned_at: number | null;
        failed_at: number | null;
        last_error: string | null;
      }>('SELECT size, cosigned_at, failed_at, last_error FROM witnesses WHERE vkey = ?', vkey)
      .toArray()[0];
    return {
      vkey,
      size: r?.size ?? null,
      cosignedAt: r?.cosigned_at ?? null,
      failedAt: r?.failed_at ?? null,
      lastError: r?.last_error ?? null,
    };
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

// The witness's state: for each log, the latest checkpoint it cosigned (C2SP tlog-witness). One
// SQLite-backed Durable Object per witness, so every submission for every log is serialized
// through one place.
//
// The spec requires the "old size matches what I last cosigned" check and the update to be atomic,
// or two concurrent submissions could roll the record back. Verifying the signature and the proof,
// and cosigning, are asynchronous (WebCrypto), so other requests can interleave with them. The
// check is therefore done twice: once by evaluateAddCheckpoint against the record it read, and
// again, with the update, in one synchronous transaction after all the awaits. Sizes never
// decrease and a record only changes size, so an unchanged size means an unchanged record.

import {
  SIZE_CONTENT_TYPE,
  evaluateAddCheckpoint,
  formatSizeBody,
  newCosigner,
  sha256,
  toHex,
  utf8Encode,
  type Cosigner,
  type NoteVerifier,
  type WitnessedLogRecord,
} from '@r2notary/core';
import { DurableObject } from 'cloudflare:workers';
import { parseWitnessLogs } from './config.ts';

export interface WitnessResponse {
  readonly status: number;
  readonly body: string;
  readonly contentType: string;
}

/** Rejected submissions with a valid log signature are kept as evidence; this many at most. */
export const MAX_EVIDENCE = 100;

const TEXT = 'text/plain; charset=utf-8';

interface LogRow {
  [column: string]: SqlStorageValue;
  size: number;
  root: ArrayBuffer;
}

export interface Cosigned {
  readonly origin: string;
  readonly originHash: string;
  /** The old size the submission was checked against. */
  readonly oldSize: number;
  readonly size: number;
  readonly rootHash: Uint8Array;
  /** The checkpoint with the log's signatures and this witness's cosignature. */
  readonly note: string;
  /** The cosignature line returned to the log. */
  readonly line: string;
  readonly now: number;
}

/**
 * The atomic part of add-checkpoint: in one synchronous transaction, check that the record still
 * has the old size the submission was verified against, and store the new checkpoint. Otherwise
 * answer 409 with the current size and store nothing.
 */
export function storeIfUnchanged(storage: DurableObjectStorage, c: Cosigned): WitnessResponse {
  const sql = storage.sql;
  return storage.transactionSync((): WitnessResponse => {
    const row = sql
      .exec<{ size: number }>('SELECT size FROM logs WHERE origin = ?', c.origin)
      .toArray()[0];
    const current = row?.size ?? 0;
    if (current !== c.oldSize) {
      return { status: 409, body: formatSizeBody(current), contentType: SIZE_CONTENT_TYPE };
    }
    sql.exec(
      `INSERT INTO logs(origin, origin_hash, size, root, note, updated_at)
         VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT(origin) DO UPDATE SET
         size = excluded.size, root = excluded.root, note = excluded.note,
         updated_at = excluded.updated_at`,
      c.origin,
      c.originHash,
      c.size,
      c.rootHash,
      c.note,
      c.now,
    );
    return { status: 200, body: c.line, contentType: TEXT };
  });
}

export class WitnessState extends DurableObject<Env> {
  readonly #sql: SqlStorage;
  #logs: Promise<ReadonlyMap<string, readonly NoteVerifier[]>> | null = null;
  #cosigner: Promise<Cosigner> | null = null;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.#sql = ctx.storage.sql;
    // Synchronous SQL completes before any request is delivered (as in the Sequencer).
    ctx.storage.transactionSync(() => {
      this.#sql.exec(`CREATE TABLE IF NOT EXISTS logs(
        origin TEXT PRIMARY KEY,
        origin_hash TEXT NOT NULL UNIQUE,
        size INTEGER NOT NULL,
        root BLOB NOT NULL,
        note TEXT NOT NULL,
        updated_at INTEGER NOT NULL)`);
      this.#sql.exec(`CREATE TABLE IF NOT EXISTS evidence(
        id INTEGER PRIMARY KEY,
        at INTEGER NOT NULL,
        origin TEXT NOT NULL,
        error TEXT NOT NULL,
        body TEXT NOT NULL)`);
    });
  }

  #trusted(): Promise<ReadonlyMap<string, readonly NoteVerifier[]>> {
    this.#logs ??= parseWitnessLogs(this.env.WITNESS_LOGS).catch((e: unknown) => {
      this.#logs = null;
      throw e;
    });
    return this.#logs;
  }

  #key(): Promise<Cosigner> {
    this.#cosigner ??= newCosigner(this.env.WITNESS_KEY).catch((e: unknown) => {
      this.#cosigner = null;
      throw e;
    });
    return this.#cosigner;
  }

  #record(origin: string): WitnessedLogRecord | null {
    const r = this.#sql
      .exec<LogRow>('SELECT size, root FROM logs WHERE origin = ?', origin)
      .toArray()[0];
    return r === undefined ? null : { size: r.size, rootHash: new Uint8Array(r.root) };
  }

  /** POST add-checkpoint. */
  async addCheckpoint(body: string): Promise<WitnessResponse> {
    const [logs, cosigner] = await Promise.all([this.#trusted(), this.#key()]);
    const r = await evaluateAddCheckpoint(
      body,
      (origin) => logs.get(origin),
      (origin) => this.#record(origin),
    );
    if (!r.ok) {
      if (r.status === 409) {
        return { status: 409, body: formatSizeBody(r.size ?? 0), contentType: SIZE_CONTENT_TYPE };
      }
      // A 422 comes after the log's signature verified: a signed checkpoint that does not extend
      // what this witness saw is evidence of a fork (the spec allows logging it).
      if (r.status === 422) this.#keepEvidence(body, r.error);
      return { status: r.status, body: `${r.error}\n`, contentType: TEXT };
    }

    const { origin, size, rootHash } = r.checkpoint;
    const timestamp = Math.floor(Date.now() / 1000);
    const line = await cosigner.cosign(r.text, timestamp);
    const originHash = toHex(await sha256(utf8Encode(origin)));
    const note = `${r.text}\n${r.logSignatures.join('')}${line}`;

    return storeIfUnchanged(this.ctx.storage, {
      origin,
      originHash,
      oldSize: r.oldSize,
      size,
      rootHash,
      note,
      line,
      now: Date.now(),
    });
  }

  #keepEvidence(body: string, error: string): void {
    const origin = body.slice(body.indexOf('\n\n') + 2).split('\n', 1)[0] ?? '';
    this.ctx.storage.transactionSync(() => {
      this.#sql.exec(
        'INSERT INTO evidence(at, origin, error, body) VALUES (?, ?, ?, ?)',
        Date.now(),
        origin,
        error,
        body,
      );
      this.#sql.exec(
        'DELETE FROM evidence WHERE id NOT IN (SELECT id FROM evidence ORDER BY id DESC LIMIT ?)',
        MAX_EVIDENCE,
      );
    });
  }

  /** GET <origin hash>/checkpoint: the latest cosigned checkpoint, with the log's signatures. */
  checkpoint(originHash: string): string | null {
    const r = this.#sql
      .exec<{ note: string }>('SELECT note FROM logs WHERE origin_hash = ?', originHash)
      .toArray()[0];
    return r?.note ?? null;
  }

  /** Rejected submissions kept as evidence, newest first (for operators; not served over HTTP). */
  evidence(): { at: number; origin: string; error: string; body: string }[] {
    return this.#sql
      .exec<{ at: number; origin: string; error: string; body: string }>(
        'SELECT at, origin, error, body FROM evidence ORDER BY id DESC',
      )
      .toArray();
  }
}

// Shared fixtures for the Sequencer tests (all run inside workerd against local DO SQLite and R2).
import {
  CHECKPOINT_PATH,
  encodeEntry,
  entryBundlePath,
  newSigner,
  newVerifier,
  openCheckpoint,
  tilePath,
  tilesForTreeSize,
  type Checkpoint,
  type NoteSigner,
  type ObjectAction,
} from '@r2notary/core';
import { env } from 'cloudflare:workers';
import { runInDurableObject } from 'cloudflare:test';
import type { LogBucket } from '../src/publish.ts';
import { SequencerStore, type AppendItem } from '../src/store.ts';

export const ORIGIN = env.LOG_ORIGIN;

/**
 * The test env with some vars replaced. `wrangler types` gives each var its committed literal type
 * (PUBLIC_LOG: "false"), so a different value needs this one cast.
 */
export function envWith(vars: Partial<Record<keyof Env, string | undefined>>): Env {
  return { ...env, ...vars } as unknown as Env;
}
export const BUCKET = env.MONITORED_BUCKET_NAME;

let signerPromise: Promise<NoteSigner> | null = null;
export function testSigner(): Promise<NoteSigner> {
  signerPromise ??= newSigner(env.SIGNING_KEY);
  return signerPromise;
}

export interface EventOptions {
  readonly key?: string;
  readonly action?: ObjectAction;
  readonly etag?: string;
  readonly size?: number;
  readonly eventTime?: string;
  readonly copySource?: { readonly bucket: string; readonly key: string };
}

/** A valid object.event entry for the monitored bucket; `i` makes it unique. */
export function objectEvent(i: number, o: EventOptions = {}): Uint8Array {
  const action = o.action ?? 'PutObject';
  const isDelete = action === 'DeleteObject' || action === 'LifecycleDeletion';
  return encodeEntry({
    v: 1,
    type: 'object.event',
    bucket: BUCKET,
    key: o.key ?? `obj/${String(i)}`,
    action,
    ...(isDelete ? {} : { size: o.size ?? i, etag: o.etag ?? `etag-${String(i)}` }),
    eventTime: o.eventTime ?? '2026-10-02T12:00:00.000Z',
    ingestedAt: '2026-10-02T12:00:01.000Z',
    ...(o.copySource === undefined ? {} : { copySource: o.copySource }),
  });
}

export function items(n: number, start = 0): AppendItem[] {
  return Array.from({ length: n }, (_, j) => ({
    eventId: `ev-${String(start + j)}`,
    entry: objectEvent(start + j),
  }));
}

/** Runs `fn` with a store over the named Sequencer's real SQLite storage. */
export function withStore<R>(
  name: string,
  fn: (store: SequencerStore) => R | Promise<R>,
): Promise<R> {
  return runInDurableObject(env.SEQUENCER.getByName(name), (_instance, state) =>
    fn(new SequencerStore(state.storage)),
  );
}

export async function readBytes(key: string): Promise<Uint8Array | null> {
  const o = await env.LOG.get(key);
  return o === null ? null : new Uint8Array(await o.arrayBuffer());
}

/** Every object under `prefix/`, keyed by full key. */
export async function snapshotBucket(prefix: string): Promise<Map<string, string>> {
  const out = new Map<string, string>();
  let cursor: string | undefined;
  do {
    const page = await env.LOG.list({
      prefix: `${prefix}/`,
      ...(cursor === undefined ? {} : { cursor }),
    });
    for (const o of page.objects) {
      const bytes = await readBytes(o.key);
      out.set(
        o.key,
        bytes === null
          ? '<gone>'
          : Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join(''),
      );
    }
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor !== undefined);
  return out;
}

/** R2 keys of every tile and bundle a checkpoint of `size` depends on. */
export function dependencies(prefix: string, size: number): string[] {
  const keys = tilesForTreeSize(size).map(
    (t) => `${prefix}/${tilePath(t.level, t.index, t.width)}`,
  );
  for (const t of tilesForTreeSize(size).filter((t) => t.level === 0)) {
    keys.push(`${prefix}/${entryBundlePath(t.index, t.width)}`);
  }
  return keys;
}

export async function missingDependencies(prefix: string, size: number): Promise<string[]> {
  const missing: string[] = [];
  for (const k of dependencies(prefix, size)) if ((await env.LOG.head(k)) === null) missing.push(k);
  return missing;
}

/** Opens a checkpoint note with the test key and checks its origin (I9). */
export async function openTestCheckpoint(note: Uint8Array | string): Promise<Checkpoint> {
  return openCheckpoint(note, await newVerifier((await testSigner()).vkey), ORIGIN);
}

/** The live checkpoint under `prefix`, verified, or null if none has been published. */
export async function liveCheckpoint(prefix: string): Promise<Checkpoint | null> {
  const bytes = await readBytes(`${prefix}/${CHECKPOINT_PATH}`);
  return bytes === null ? null : openTestCheckpoint(bytes);
}

export interface PutRecord {
  readonly key: string;
  readonly bytes: Uint8Array;
  readonly conditional: boolean;
}

/**
 * Wraps the log bucket to record every put. On each write of the live checkpoint it asserts I2:
 * every tile and bundle the new checkpoint depends on is already durable in R2.
 */
export class ObservedBucket implements LogBucket {
  readonly puts: PutRecord[] = [];
  readonly checkpointSizes: number[] = [];
  readonly violations: string[] = [];

  constructor(private readonly prefix: string) {}

  async put(key: string, value: Uint8Array, options: R2PutOptions): Promise<R2Object | null> {
    if (key === `${this.prefix}/${CHECKPOINT_PATH}`) {
      const cp = await openTestCheckpoint(value);
      const missing = await missingDependencies(this.prefix, cp.size);
      if (missing.length > 0)
        this.violations.push(`checkpoint ${String(cp.size)} before ${missing.join(', ')}`);
      this.checkpointSizes.push(cp.size);
    }
    this.puts.push({ key, bytes: value.slice(), conditional: options.onlyIf !== undefined });
    return env.LOG.put(key, value, options);
  }

  get(key: string): Promise<R2ObjectBody | null> {
    return env.LOG.get(key);
  }
}

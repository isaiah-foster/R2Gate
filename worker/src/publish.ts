// Publication (PLAN §5.3): turn staged entries into tiles, bundles and a signed checkpoint in R2,
// then commit the new state to SQLite.
//
// Why a crash anywhere is safe (I2, I6): every resource is a pure function of the log prefix it
// covers, and the prefix is fixed once its entries are durable in SQLite. A retry recomputes the
// same bytes (Ed25519 signatures are deterministic too), immutable writes are create-if-absent and
// accept "already there, identical", and the checkpoint is written only after everything it
// depends on. Nothing in memory is trusted across calls: each run reloads state from SQLite.

import {
  CHECKPOINT_PATH,
  appendEntries,
  archivedCheckpointPath,
  bytesEqual,
  entryBundlePath,
  partialTiles,
  sha256,
  signCheckpoint,
  tilePath,
  toHex,
  utf8Encode,
  type NoteSigner,
} from '@r2notary/core';
import type { Config } from './config.ts';
import type { SequencerStore } from './store.ts';
import type { Cosign } from './witness.ts';

/** The R2 operations publication needs; narrowed so tests can observe or wrap them. */
export interface LogBucket {
  put(key: string, value: Uint8Array, options: R2PutOptions): Promise<R2Object | null>;
  get(key: string): Promise<R2ObjectBody | null>;
}

/** Points between which a crash can happen. Hooks run after each one (tests inject faults). */
export type PublishStep =
  | 'planned' // publishing_size recorded
  | 'computed' // tiles, bundles and checkpoint built in memory
  | 'immutable-written' // (a) full bundles and full tiles
  | 'partials-written' // (b) partial bundle and partial tiles
  | 'archive-written' // (c) x-checkpoints/<size>
  | 'witnessed' // cosignatures collected (M8; a no-op without witnesses)
  | 'checkpoint-written' // (d) live checkpoint
  | 'committed'; // (5) SQLite state advanced

export interface PublishHooks {
  afterStep?(step: PublishStep): void | Promise<void>;
  beforeWrite?(key: string): void | Promise<void>;
}

export interface PublishDeps {
  readonly store: SequencerStore;
  readonly bucket: LogBucket;
  readonly signer: NoteSigner;
  readonly config: Pick<Config, 'logName' | 'logOrigin' | 'batchMaxEntries'>;
  readonly now: () => number;
  readonly hooks?: PublishHooks;
  /** Collects witness cosignatures for the new checkpoint (worker/src/witness.ts), if any. */
  readonly cosign?: Cosign;
}

export interface PublishResult {
  readonly previousSize: number;
  readonly size: number;
  /**
   * The live checkpoint as published: the log-signed note plus any witness cosignatures, or null
   * if there was nothing to publish.
   */
  readonly checkpoint: string | null;
}

/** An immutable resource already exists in R2 with different content (I4). Never retried away. */
export class LogDivergenceError extends Error {
  override name = 'LogDivergenceError';
  readonly code = 'TILE_DIVERGENCE';
  constructor(readonly key: string) {
    super(`TILE_DIVERGENCE: ${key} already exists in the log bucket with different content`);
  }
}

/** R2 reported a failed create-if-absent precondition, but the object is not there. */
export class ConditionalWriteError extends Error {
  override name = 'ConditionalWriteError';
}

/** Create-only precondition. See DECISIONS D2.1 for how `'*'` was verified. */
export const CREATE_ONLY: R2Conditional = { etagDoesNotMatch: '*' };

const IMMUTABLE_METADATA: R2HTTPMetadata = {
  contentType: 'application/octet-stream',
  cacheControl: 'public, max-age=31536000, immutable',
};
const ARCHIVE_METADATA: R2HTTPMetadata = {
  contentType: 'text/plain; charset=utf-8',
  cacheControl: 'public, max-age=31536000, immutable',
};
const REPORT_METADATA: R2HTTPMetadata = {
  contentType: 'application/json; charset=utf-8',
  cacheControl: 'public, max-age=31536000, immutable',
};
const CHECKPOINT_METADATA: R2HTTPMetadata = {
  contentType: 'text/plain; charset=utf-8',
  cacheControl: 'max-age=2',
};

/** The signed text of a note, without its signature lines. */
function noteText(note: Uint8Array): string {
  const s = new TextDecoder().decode(note);
  const end = s.indexOf('\n\n');
  return end < 0 ? s : s.slice(0, end + 1);
}

/**
 * Writes `data` at `key` only if nothing is there. If something is, it must be identical, or this
 * throws LogDivergenceError. For archived checkpoints only the signed text is compared, so a key
 * rotation between a crash and its retry does not count as divergence (D2.5). Audit reports
 * (`x-reports/`, M6) are compared byte for byte like tiles.
 */
export async function putImmutable(
  bucket: LogBucket,
  key: string,
  data: Uint8Array,
  kind: 'tile' | 'checkpoint' | 'report' = 'tile',
): Promise<'created' | 'existed'> {
  const metadata = {
    tile: IMMUTABLE_METADATA,
    checkpoint: ARCHIVE_METADATA,
    report: REPORT_METADATA,
  };
  const created = await bucket.put(key, data, {
    onlyIf: CREATE_ONLY,
    httpMetadata: metadata[kind],
    // R2 rejects the upload if the received bytes do not hash to this.
    sha256: toHex(await sha256(data)),
  });
  if (created !== null) return 'created';
  const existing = await bucket.get(key);
  if (existing === null) {
    throw new ConditionalWriteError(`create-only put of ${key} failed, but the object is absent`);
  }
  const bytes = new Uint8Array(await existing.arrayBuffer());
  const same = kind === 'checkpoint' ? noteText(bytes) === noteText(data) : bytesEqual(bytes, data);
  if (!same) throw new LogDivergenceError(key);
  return 'existed';
}

// Workers allow 6 simultaneous outgoing connections per request; stay within that.
const WRITE_CONCURRENCY = 6;

export async function publish(d: PublishDeps): Promise<PublishResult> {
  const { store, bucket, config, hooks } = d;
  const step = async (s: PublishStep): Promise<void> => {
    await hooks?.afterStep?.(s);
  };
  const key = (path: string): string => `${config.logName}/${path}`;

  // 1. Plan. A recorded publishing_size from an interrupted run is a floor, so a retry never
  // publishes a smaller checkpoint than one that may already be live.
  const from = store.publishedSize();
  const pending = store.nextSeq() - from;
  const target = Math.max(
    store.publishingSize() ?? 0,
    from + Math.min(pending, config.batchMaxEntries),
  );
  if (target === from) return { previousSize: from, size: from, checkpoint: null };
  if (target < from)
    throw new Error(`refusing to regress from ${String(from)} to ${String(target)}`);
  store.setPublishingSize(target);
  await step('planned');

  // 2-3. Compute everything in memory, from SQLite state only.
  const state = store.loadLogState();
  const { entries, keys } = store.readBatch(from, target);
  const update = await appendEntries(state, entries);
  const checkpoint = await signCheckpoint(
    { origin: config.logOrigin, size: target, rootHash: update.root, extensions: [] },
    d.signer,
  );
  await step('computed');

  const writeAll = async (resources: readonly (readonly [string, Uint8Array])[]): Promise<void> => {
    for (let i = 0; i < resources.length; i += WRITE_CONCURRENCY) {
      await Promise.all(
        resources.slice(i, i + WRITE_CONCURRENCY).map(async ([path, data]) => {
          await hooks?.beforeWrite?.(key(path));
          await putImmutable(bucket, key(path), data);
        }),
      );
    }
  };

  // 4a. Full bundles and tiles.
  await writeAll([
    ...update.fullBundles.map((b) => [entryBundlePath(b.index, b.width), b.data] as const),
    ...update.fullTiles.map((t) => [tilePath(t.level, t.index, t.width), t.data] as const),
  ]);
  await step('immutable-written');

  // 4b. Partial bundle and partial tiles. Partials are immutable by path too (a partial tile is
  // fixed by the prefix it covers), so they are create-if-absent like everything else. A partial
  // tile unchanged since the last commit was already written by that publication; skip it.
  const unchanged = new Set(
    partialTiles(state.tree).map((t) => tilePath(t.level, t.index, t.width)),
  );
  const partials: (readonly [string, Uint8Array])[] = [];
  if (update.partialBundle !== null) {
    const b = update.partialBundle;
    partials.push([entryBundlePath(b.index, b.width), b.data]);
  }
  for (const t of update.partialTiles) {
    const path = tilePath(t.level, t.index, t.width);
    if (!unchanged.has(path)) partials.push([path, t.data]);
  }
  await writeAll(partials);
  await step('partials-written');

  // 4c. Archived checkpoint: the log's signature only, so it stays a pure function of the prefix.
  const archive = key(archivedCheckpointPath(target));
  await hooks?.beforeWrite?.(archive);
  await putImmutable(bucket, archive, utf8Encode(checkpoint), 'checkpoint');
  await step('archive-written');

  // 4c'. Witness cosignatures (M8), appended to the live checkpoint only. Witnesses are asked
  // after the tiles exist (the proofs are read from them) and before anyone can see the size; a
  // missing quorum throws here, before the live checkpoint moves.
  const cosignatures =
    d.cosign === undefined
      ? []
      : await d.cosign(checkpoint, target, async (t) => {
          const obj = await bucket.get(key(tilePath(t.level, t.index, t.width)));
          if (obj === null) throw new Error(`tile ${tilePath(t.level, t.index, t.width)} missing`);
          return new Uint8Array(await obj.arrayBuffer());
        });
  const published = `${checkpoint}${cosignatures.join('')}`;
  await step('witnessed');

  // 4d. Live checkpoint, last: everything it references is now durable (R2 is strongly consistent).
  const live = key(CHECKPOINT_PATH);
  await hooks?.beforeWrite?.(live);
  await bucket.put(live, utf8Encode(published), { httpMetadata: CHECKPOINT_METADATA });
  await step('checkpoint-written');

  // 5. Commit.
  store.commitPublish(from, update.state.tree, entries, d.now(), keys);
  await step('committed');
  return { previousSize: from, size: target, checkpoint: published };
}

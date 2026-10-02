// Publication invariants (PLAN §8): I2 checkpoint after its dependencies, I3 monotonic and mutually
// consistent checkpoints, I4 immutable resources never change, I6 crash anywhere -> identical
// recovery. Each test uses its own Sequencer storage and its own log prefix in the shared bucket.
import {
  archivedCheckpointPath,
  decodeBundle,
  entryBundlePath,
  generateKey,
  hashLeaves,
  merkleRoot,
  newSigner,
  signCheckpoint,
  tileNodeReader,
  tilePath,
  toHex,
  consistencyProof,
  verifyConsistency,
  type Checkpoint,
} from '@r2notary/core';
import { env } from 'cloudflare:workers';
import { describe, expect, it } from 'vitest';
import {
  LogDivergenceError,
  publish,
  type LogBucket,
  type PublishHooks,
  type PublishResult,
  type PublishStep,
} from '../src/publish.ts';
import {
  ORIGIN,
  ObservedBucket,
  items,
  liveCheckpoint,
  missingDependencies,
  objectEvent,
  openTestCheckpoint,
  readBytes,
  snapshotBucket,
  testSigner,
  withStore,
} from './helpers.ts';

let unique = 0;
/** A fresh DO name and log prefix per scenario. */
function fresh(label: string): string {
  unique++;
  return `${label}-${String(unique)}`;
}

async function runPublish(
  name: string,
  bucket: LogBucket,
  opts: { batch?: number; hooks?: PublishHooks } = {},
): Promise<PublishResult> {
  const signer = await testSigner();
  return withStore(name, (store) =>
    publish({
      store,
      bucket,
      signer,
      config: { logName: name, logOrigin: ORIGIN, batchMaxEntries: opts.batch ?? 500 },
      now: Date.now,
      ...(opts.hooks === undefined ? {} : { hooks: opts.hooks }),
    }),
  );
}

async function append(name: string, n: number, start: number): Promise<void> {
  await withStore(name, (store) => store.append(items(n, start), Date.now(), 86_400_000));
}

/** Publishes until nothing is pending; returns every result. */
async function drain(name: string, bucket: LogBucket, batch = 500): Promise<PublishResult[]> {
  const out: PublishResult[] = [];
  for (;;) {
    const r = await runPublish(name, bucket, { batch });
    if (r.checkpoint === null) return out;
    out.push(r);
  }
}

async function archivedCheckpoints(prefix: string): Promise<Checkpoint[]> {
  const list = await env.LOG.list({ prefix: `${prefix}/x-checkpoints/` });
  expect(list.truncated).toBe(false);
  const out: Checkpoint[] = [];
  for (const o of list.objects) {
    const bytes = await readBytes(o.key);
    if (bytes !== null) out.push(await openTestCheckpoint(bytes));
  }
  return out.sort((a, b) => a.size - b.size);
}

describe('publish: output', () => {
  it('publishes tiles, bundles and a signed checkpoint whose root is the RFC 6962 root', async () => {
    const name = fresh('basic');
    await append(name, 600, 0);
    const bucket = new ObservedBucket(name);
    const results = await drain(name, bucket, 250);
    expect(results.map((r) => [r.previousSize, r.size])).toEqual([
      [0, 250],
      [250, 500],
      [500, 600],
    ]);

    const entries = items(600).map((i) => i.entry);
    const cp = await liveCheckpoint(name);
    expect(cp?.size).toBe(600);
    expect(toHex(cp?.rootHash ?? new Uint8Array())).toBe(
      toHex(await merkleRoot(await hashLeaves(entries))),
    );

    const bundles = [
      ...decodeBundle((await readBytes(`${name}/${entryBundlePath(0, 256)}`)) ?? new Uint8Array()),
      ...decodeBundle((await readBytes(`${name}/${entryBundlePath(1, 256)}`)) ?? new Uint8Array()),
      ...decodeBundle((await readBytes(`${name}/${entryBundlePath(2, 88)}`)) ?? new Uint8Array()),
    ];
    expect(bundles.map(toHex)).toEqual(entries.map(toHex));
    expect(await missingDependencies(name, 600)).toEqual([]);
    await withStore(name, (store) => {
      expect(store.publishedSize()).toBe(600);
      expect(store.publishingSize()).toBeNull();
      // Only the current partial bundle's entries (512..599) are retained.
      expect(() => store.readEntries(511, 512)).toThrow();
      expect(store.readEntries(512, 600)).toHaveLength(88);
    });
  });

  it('does nothing when nothing is pending', async () => {
    const name = fresh('empty');
    const bucket = new ObservedBucket(name);
    expect(await runPublish(name, bucket)).toEqual({ previousSize: 0, size: 0, checkpoint: null });
    expect(bucket.puts).toEqual([]);
  });

  it('skips partial tiles that did not change since the last checkpoint', async () => {
    const name = fresh('skip');
    await append(name, 300, 0);
    const bucket = new ObservedBucket(name);
    await runPublish(name, bucket, { batch: 290 });
    bucket.puts.length = 0;
    await runPublish(name, bucket);
    // 290 -> 300: level 1 still holds one hash (tile 1/000.p/1), so only level 0 is rewritten.
    expect(bucket.puts.map((p) => p.key.slice(name.length + 1))).toEqual([
      entryBundlePath(1, 44),
      tilePath(0, 1, 44),
      archivedCheckpointPath(300),
      'checkpoint',
    ]);
  });

  it('handles a partial bundle bigger than the 2 MB SQLite row limit (D0.5)', async () => {
    const name = fresh('big');
    // Worst-case valid entries: CopyObject with two 1,024-byte keys of control characters, each
    // escaped to 6 bytes in JSON. 255 of them in one partial bundle is well over 2 MB.
    const key = (i: number) => `${String(i).padStart(4, '0')}${'\u0001'.repeat(1020)}`;
    const big = Array.from({ length: 256 }, (_, i) => ({
      eventId: `big-${String(i)}`,
      entry: objectEvent(i, {
        key: key(i),
        action: 'CopyObject',
        copySource: { bucket: 'source-bucket', key: key(i + 1) },
      }),
    }));
    const partialBytes = big.slice(0, 255).reduce((n, i) => n + i.entry.length, 0);
    expect(partialBytes).toBeGreaterThan(2 * 1024 * 1024);

    await withStore(name, (store) => store.append(big.slice(0, 255), Date.now(), 60_000));
    const bucket = new ObservedBucket(name);
    await runPublish(name, bucket);
    await withStore(name, (store) => store.append(big.slice(255), Date.now(), 60_000));
    await runPublish(name, bucket);
    const bundle = decodeBundle(
      (await readBytes(`${name}/${entryBundlePath(0, 256)}`)) ?? new Uint8Array(),
    );
    expect(bundle.map(toHex)).toEqual(big.map((i) => toHex(i.entry)));
  });
});

describe('I2: a checkpoint is never visible before its dependencies', () => {
  it('every live-checkpoint write finds all of its tiles and bundles already in R2', async () => {
    const name = fresh('i2');
    const bucket = new ObservedBucket(name);
    let next = 0;
    for (const n of [1, 255, 1, 300, 7, 512, 3]) {
      await append(name, n, next);
      next += n;
      await drain(name, bucket, 200);
    }
    expect(bucket.violations).toEqual([]);
    expect(bucket.checkpointSizes.at(-1)).toBe(next);
    // Within each publication the live checkpoint is the last write.
    const isLive = bucket.puts.map((p) => p.key === `${name}/checkpoint`);
    isLive.forEach((live, i) => {
      if (!live) expect(isLive.slice(i + 1).includes(true)).toBe(true);
    });
  });
});

describe('I3: sizes are monotonic and any two archived checkpoints are consistent', () => {
  it('verifies a consistency proof, computed from the published tiles, between every pair', async () => {
    const name = fresh('i3');
    const bucket = new ObservedBucket(name);
    // Uneven appends and batch sizes so checkpoints land on, before and after tile boundaries.
    let next = 0;
    const plan: [number, number][] = [
      [1, 500],
      [2, 500],
      [253, 500],
      [1, 500],
      [300, 100],
      [700, 256],
      [5, 500],
    ];
    for (const [n, batch] of plan) {
      await append(name, n, next);
      next += n;
      await drain(name, bucket, batch);
    }
    const sizes = bucket.checkpointSizes;
    expect(sizes.every((s, i) => i === 0 || s > (sizes[i - 1] ?? 0))).toBe(true);

    const archived = await archivedCheckpoints(name);
    expect(archived.map((c) => c.size)).toEqual(sizes);
    for (const cp of archived) expect(await missingDependencies(name, cp.size)).toEqual([]);

    const readTile = async (t: { level: number; index: number; width: number }) =>
      (await readBytes(`${name}/${tilePath(t.level, t.index, t.width)}`)) ??
      Promise.reject(new Error(`missing tile ${tilePath(t.level, t.index, t.width)}`));
    for (const newer of archived) {
      const reader = tileNodeReader(newer.size, readTile);
      for (const older of archived.filter((c) => c.size <= newer.size)) {
        const proof = await consistencyProof(older.size, newer.size, reader);
        await verifyConsistency(older.size, newer.size, older.rootHash, newer.rootHash, proof);
      }
    }
  });
});

describe('I4: immutable resources never change', () => {
  /** Plants `bytes` at `path` before the first publication of `n` entries, then publishes. */
  async function conflict(path: string, n: number, bytes: Uint8Array | string): Promise<string> {
    const name = fresh('i4');
    await env.LOG.put(`${name}/${path}`, bytes);
    await append(name, n, 0);
    await expect(runPublish(name, new ObservedBucket(name))).rejects.toThrow(LogDivergenceError);
    // Loud and persistent: retrying diverges again, and nothing became visible.
    await expect(runPublish(name, new ObservedBucket(name))).rejects.toThrow(/TILE_DIVERGENCE/);
    expect(await readBytes(`${name}/checkpoint`)).toBeNull();
    await withStore(name, (store) => {
      expect(store.publishedSize()).toBe(0);
    });
    const after = await env.LOG.get(`${name}/${path}`);
    expect(await after?.text()).toBe(
      typeof bytes === 'string' ? bytes : new TextDecoder().decode(bytes),
    );
    return name;
  }

  it('detects a conflicting full tile', () => conflict(tilePath(0, 0, 256), 256, 'not a tile'));
  it('detects a conflicting full bundle', () => conflict(entryBundlePath(0, 256), 256, 'x'));
  it('detects a conflicting partial tile', () => conflict(tilePath(0, 0, 10), 10, 'y'.repeat(320)));
  it('detects a conflicting partial bundle', () => conflict(entryBundlePath(0, 10), 10, 'z'));

  it('detects a conflicting archived checkpoint, but accepts one re-signed by another key', async () => {
    const forged = await signCheckpoint(
      { origin: ORIGIN, size: 10, rootHash: new Uint8Array(32), extensions: [] },
      await testSigner(),
    );
    await conflict(archivedCheckpointPath(10), 10, forged);

    // Same signed text, different key (e.g. a key rotation between a crash and its retry).
    const name = fresh('i4-resign');
    await append(name, 10, 0);
    const root = await merkleRoot(await hashLeaves(items(10).map((i) => i.entry)));
    const other = await newSigner((await generateKey(ORIGIN)).skey);
    const resigned = await signCheckpoint(
      { origin: ORIGIN, size: 10, rootHash: root, extensions: [] },
      other,
    );
    await env.LOG.put(`${name}/${archivedCheckpointPath(10)}`, resigned);
    expect((await runPublish(name, new ObservedBucket(name))).size).toBe(10);
  });

  it('accepts pre-existing identical resources and writes everything else create-only', async () => {
    const a = fresh('i4-same-a');
    const b = fresh('i4-same-b');
    for (const name of [a, b]) await append(name, 700, 0);
    const bucketA = new ObservedBucket(a);
    await drain(a, bucketA, 300);
    // Copy log A's resources into B's prefix, then let B publish the same entries over them.
    for (const [key, hex] of await snapshotBucket(a)) {
      const bytes = Uint8Array.from(hex.match(/../g) ?? [], (h) => parseInt(h, 16));
      await env.LOG.put(`${b}${key.slice(a.length)}`, bytes);
    }
    await drain(b, new ObservedBucket(b), 300);
    const strip = (m: Map<string, string>, p: string) =>
      new Map([...m].map(([k, v]) => [k.slice(p.length), v]));
    expect(strip(await snapshotBucket(b), b)).toEqual(strip(await snapshotBucket(a), a));

    // Across the whole run: only the live checkpoint is written unconditionally, and no key was
    // ever written with two different contents.
    const byKey = new Map<string, string>();
    for (const p of bucketA.puts) {
      if (p.key === `${a}/checkpoint`) {
        expect(p.conditional).toBe(false);
        continue;
      }
      expect(p.conditional).toBe(true);
      const hex = toHex(p.bytes);
      expect(byKey.get(p.key) ?? hex).toBe(hex);
      byKey.set(p.key, hex);
    }
  });
});

describe('I6: a crash between any two publication steps recovers byte-identically', () => {
  const STEPS: PublishStep[] = [
    'planned',
    'computed',
    'immutable-written',
    'partials-written',
    'archive-written',
    'witnessed',
    'checkpoint-written',
    'committed',
  ];

  class Crash extends Error {}

  /**
   * Scenario: 250 entries already published, 300 more pending, one publication of up to 500.
   * 250 -> 550 completes bundles 0..1 and tiles 0/000..0/001, so every kind of write happens.
   */
  async function setup(name: string, bucket: LogBucket): Promise<void> {
    await append(name, 250, 0);
    await runPublish(name, bucket);
    await append(name, 300, 250);
  }

  const relative = async (name: string) =>
    new Map([...(await snapshotBucket(name))].map(([k, v]) => [k.slice(name.length), v]));

  async function reference(): Promise<{ snapshot: Map<string, string>; writes: string[] }> {
    const name = fresh('i6-ref');
    const bucket = new ObservedBucket(name);
    await setup(name, bucket);
    const writes: string[] = [];
    await runPublish(name, bucket, { hooks: { beforeWrite: (k) => void writes.push(k) } });
    return { snapshot: await relative(name), writes };
  }

  async function crashAndRecover(crash: PublishHooks): Promise<string> {
    const name = fresh('i6');
    const bucket = new ObservedBucket(name);
    await setup(name, bucket);
    await expect(runPublish(name, bucket, { hooks: crash })).rejects.toThrow(Crash);
    await runPublish(name, bucket); // recovery: fresh store, state reloaded from SQLite
    expect(bucket.violations).toEqual([]);
    const cp = await liveCheckpoint(name);
    expect(cp?.size).toBe(550);
    return name;
  }

  it('after every step', async () => {
    const ref = await reference();
    for (const at of STEPS) {
      const name = await crashAndRecover({
        afterStep: (s) => {
          if (s === at) throw new Crash(at);
        },
      });
      expect(await relative(name), `crash after ${at}`).toEqual(ref.snapshot);
    }
  });

  it('before every individual R2 write', async () => {
    const ref = await reference();
    expect(ref.writes.length).toBeGreaterThanOrEqual(8);
    for (let k = 0; k < ref.writes.length; k++) {
      let seen = 0;
      const name = await crashAndRecover({
        beforeWrite: () => {
          if (seen++ === k) throw new Crash(String(k));
        },
      });
      expect(await relative(name), `crash before write ${String(k)}`).toEqual(ref.snapshot);
    }
  });

  it('never moves the live checkpoint backwards, even if the batch size shrinks before recovery', async () => {
    const name = fresh('i6-shrink');
    const bucket = new ObservedBucket(name);
    await setup(name, bucket);
    await expect(
      runPublish(name, bucket, {
        hooks: {
          afterStep: (s) => {
            if (s === 'checkpoint-written') throw new Crash(s);
          },
        },
      }),
    ).rejects.toThrow(Crash);
    expect((await liveCheckpoint(name))?.size).toBe(550);
    // Recovery with a batch of 10 still publishes 550, the size that may already be visible.
    expect((await runPublish(name, bucket, { batch: 10 })).size).toBe(550);
    expect(bucket.checkpointSizes).toEqual([250, 550, 550]);
  });

  it('recovers when more entries arrive between the crash and the retry', async () => {
    const name = fresh('i6-grow');
    const bucket = new ObservedBucket(name);
    await setup(name, bucket);
    await expect(
      runPublish(name, bucket, {
        hooks: {
          afterStep: (s) => {
            if (s === 'archive-written') throw new Crash(s);
          },
        },
      }),
    ).rejects.toThrow(Crash);
    await append(name, 100, 550);
    expect((await runPublish(name, bucket, { batch: 1000 })).size).toBe(650);
    // The orphaned archive at 550 is still a valid prefix of the new log.
    const archived = await archivedCheckpoints(name);
    expect(archived.map((c) => c.size)).toEqual([250, 550, 650]);
    const reader = tileNodeReader(
      650,
      async (t) =>
        (await readBytes(`${name}/${tilePath(t.level, t.index, t.width)}`)) ?? new Uint8Array(),
    );
    for (const old of archived) {
      const proof = await consistencyProof(old.size, 650, reader);
      await verifyConsistency(
        old.size,
        650,
        old.rootHash,
        archived[2]?.rootHash ?? new Uint8Array(),
        proof,
      );
    }
    expect(bucket.violations).toEqual([]);
  });
});

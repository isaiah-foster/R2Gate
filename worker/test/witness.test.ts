// Witness cosigning on the log side (M8, C2SP tlog-witness): publish() submits each checkpoint to
// the configured witnesses before it becomes live. The witnesses here are in memory, built from the
// same core checks the witness Worker uses (evaluateAddCheckpoint), behind a fake fetch.
import {
  evaluateAddCheckpoint,
  formatSizeBody,
  fromBase64,
  generateCosignerKey,
  newCosignatureVerifier,
  newCosigner,
  newVerifier,
  openCosignedCheckpoint,
  parseAddCheckpoint,
  toBase64,
  type WitnessedLogRecord,
} from '@r2notary/core';
import { describe, expect, it } from 'vitest';
import { publish, type PublishHooks, type PublishResult } from '../src/publish.ts';
import { SequencerStore } from '../src/store.ts';
import {
  WitnessQuorumError,
  loadWitnesses,
  witnessCosigner,
  type LoadedWitness,
} from '../src/witness.ts';
import {
  ORIGIN,
  ObservedBucket,
  items,
  liveCheckpoint,
  readBytes,
  testSigner,
  withStore,
} from './helpers.ts';

let unique = 0;
const fresh = (label: string): string => `${label}-${String(++unique)}`;

type Mode = 'ok' | 'down' | 'error' | 'bad-signature' | 'zero-time' | 'other-key-only';

/** An in-memory tlog-witness for the test log's key. */
async function memoryWitness(name: string) {
  const keys = await generateCosignerKey(name);
  const cosigner = await newCosigner(keys.skey);
  const stranger = await newCosigner((await generateCosignerKey(name)).skey);
  const logKey = await newVerifier((await testSigner()).vkey);
  const w = {
    vkey: keys.vkey,
    url: `https://${name}`,
    record: null as WitnessedLogRecord | null,
    mode: 'ok' as Mode,
    /** Old sizes of every submission, in order. */
    submissions: [] as number[],
    async handle(body: string): Promise<Response> {
      if (w.mode === 'down') throw new TypeError('network error');
      if (w.mode === 'error') return new Response('overloaded\n', { status: 503 });
      w.submissions.push(parseAddCheckpoint(body).oldSize);
      const r = await evaluateAddCheckpoint(
        body,
        (o) => (o === ORIGIN ? [logKey] : undefined),
        () => w.record,
      );
      if (!r.ok) {
        const text = r.status === 409 ? formatSizeBody(r.size ?? 0) : `${r.error}\n`;
        return new Response(text, { status: r.status });
      }
      w.record = { size: r.checkpoint.size, rootHash: r.checkpoint.rootHash };
      const time = w.mode === 'zero-time' ? 0 : 1_791_000_000;
      if (w.mode === 'other-key-only') return new Response(await stranger.cosign(r.text, time));
      let line = await cosigner.cosign(r.text, time);
      if (w.mode === 'bad-signature') {
        // A well-formed line from the witness's key whose Ed25519 signature is wrong.
        const [prefix = '', b64 = ''] = line.trimEnd().split(/ (?=\S+$)/);
        const raw = fromBase64(b64);
        raw[40] = (raw[40] ?? 0) ^ 0x01;
        line = `${prefix} ${toBase64(raw)}\n`;
      }
      return new Response(line);
    },
  };
  return w;
}
type MemoryWitness = Awaited<ReturnType<typeof memoryWitness>>;

async function setup(witnesses: MemoryWitness[], quorum: number) {
  const loaded: LoadedWitness[] = await loadWitnesses(
    witnesses.map((w) => ({ vkey: w.vkey, url: w.url })),
  );
  const fetch = async (url: string, init: RequestInit): Promise<Response> => {
    const w = witnesses.find((x) => url === `${x.url}/add-checkpoint`);
    if (w === undefined) throw new Error(`no witness at ${url}`);
    return w.handle(typeof init.body === 'string' ? init.body : '');
  };
  return (store: SequencerStore) =>
    witnessCosigner({ witnesses: loaded, quorum, fetch, state: store, now: () => 1000 });
}

async function run(
  name: string,
  bucket: ObservedBucket,
  witnesses: MemoryWitness[],
  quorum: number,
  hooks?: PublishHooks,
): Promise<PublishResult> {
  const cosignFor = await setup(witnesses, quorum);
  const signer = await testSigner();
  return withStore(name, (store) =>
    publish({
      store,
      bucket,
      signer,
      config: { logName: name, logOrigin: ORIGIN, batchMaxEntries: 500 },
      now: Date.now,
      cosign: cosignFor(store),
      ...(hooks === undefined ? {} : { hooks }),
    }),
  );
}

async function append(name: string, n: number, start: number): Promise<void> {
  await withStore(name, (store) => store.append(items(n, start), Date.now(), 86_400_000));
}

/** The live checkpoint's verified cosignatures from the given witnesses. */
async function cosignedBy(name: string, witnesses: MemoryWitness[]) {
  const live = await readBytes(`${name}/checkpoint`);
  if (live === null) return null;
  const r = await openCosignedCheckpoint(
    live,
    await newVerifier((await testSigner()).vkey),
    ORIGIN,
    await Promise.all(witnesses.map((w) => newCosignatureVerifier(w.vkey))),
  );
  return { size: r.checkpoint.size, names: r.cosignatures.map((c) => c.name) };
}

describe('publishing with witnesses', () => {
  it('appends a verified cosignature to the live checkpoint, not to the archive', async () => {
    const name = fresh('wit');
    const w = await memoryWitness('w1.example');
    const bucket = new ObservedBucket(name);
    await append(name, 300, 0);
    const r = await run(name, bucket, [w], 1);
    expect(r.size).toBe(300);
    expect(await cosignedBy(name, [w])).toEqual({ size: 300, names: ['w1.example'] });
    const archive = new TextDecoder().decode(
      (await readBytes(`${name}/x-checkpoints/300`)) ?? new Uint8Array(),
    );
    expect(archive.split('\n— ')).toHaveLength(2); // the log's line only
    expect(r.checkpoint?.startsWith(archive)).toBe(true);
    expect(bucket.violations).toEqual([]); // I2 still holds
    await withStore(name, (store) => {
      expect(store.witnessStatus(w.vkey)).toMatchObject({ size: 300, cosignedAt: 1000 });
    });
  });

  it('sends each witness a proof from the size it last cosigned', async () => {
    const name = fresh('wit-seq');
    const w = await memoryWitness('w1.example');
    const bucket = new ObservedBucket(name);
    for (const [n, start] of [
      [1, 0],
      [255, 1],
      [300, 256],
      [70, 556],
    ] as const) {
      await append(name, n, start);
      await run(name, bucket, [w], 1);
    }
    // A witness accepts only a consistency proof that verifies, so these are proofs it checked.
    expect(w.submissions).toEqual([0, 1, 256, 556]);
    expect(w.record?.size).toBe(626);
  });

  it('follows a 409 when its record of the witness is wrong (lost state, earlier crash)', async () => {
    const name = fresh('wit-409');
    const w = await memoryWitness('w1.example');
    const bucket = new ObservedBucket(name);
    await append(name, 10, 0);
    await run(name, bucket, [w], 1);
    await withStore(name, (store) => {
      store.recordWitnessSuccess(w.vkey, 0, 0); // forget what the witness has
    });
    await append(name, 10, 10);
    await run(name, bucket, [w], 1);
    expect(w.submissions).toEqual([0, 0, 10]);
    expect(await cosignedBy(name, [w])).toEqual({ size: 20, names: ['w1.example'] });
  });

  it('does not publish without a quorum, and publishes the same size once it has one', async () => {
    const name = fresh('wit-quorum');
    const w = await memoryWitness('w1.example');
    const bucket = new ObservedBucket(name);
    await append(name, 10, 0);
    await run(name, bucket, [w], 1);
    await append(name, 10, 10);
    for (const mode of ['down', 'error', 'bad-signature', 'zero-time', 'other-key-only'] as const) {
      w.mode = mode;
      await expect(run(name, bucket, [w], 1), mode).rejects.toThrow(WitnessQuorumError);
      expect((await liveCheckpoint(name))?.size, mode).toBe(10);
    }
    await withStore(name, (store) => {
      expect(store.publishingSize()).toBe(20);
      expect(store.witnessStatus(w.vkey).lastError).toMatch(/no cosignature from the witness key/);
    });
    w.mode = 'ok';
    expect((await run(name, bucket, [w], 1)).size).toBe(20);
    expect(await cosignedBy(name, [w])).toEqual({ size: 20, names: ['w1.example'] });
    expect(bucket.checkpointSizes).toEqual([10, 20]);
  });

  it('with quorum 0, publishes whatever cosignatures it got', async () => {
    const name = fresh('wit-best-effort');
    const [a, b] = [await memoryWitness('a.example'), await memoryWitness('b.example')];
    const bucket = new ObservedBucket(name);
    b.mode = 'down';
    await append(name, 5, 0);
    await run(name, bucket, [a, b], 0);
    expect(await cosignedBy(name, [a, b])).toEqual({ size: 5, names: ['a.example'] });
    a.mode = 'down';
    await append(name, 5, 5);
    await run(name, bucket, [a, b], 0);
    expect(await cosignedBy(name, [a, b])).toEqual({ size: 10, names: [] });
  });

  it('needs every witness in the quorum, in configuration order', async () => {
    const name = fresh('wit-two');
    const [a, b] = [await memoryWitness('a.example'), await memoryWitness('b.example')];
    const bucket = new ObservedBucket(name);
    await append(name, 5, 0);
    await run(name, bucket, [a, b], 2);
    expect(await cosignedBy(name, [a, b])).toEqual({ size: 5, names: ['a.example', 'b.example'] });
    b.mode = 'error';
    await append(name, 5, 5);
    await expect(run(name, bucket, [a, b], 2)).rejects.toThrow(/1 of 2 required/);
    expect((await run(name, bucket, [a, b], 1)).size).toBe(10);
  });

  it('refuses a witness that has cosigned beyond this checkpoint (a fork, or lost log state)', async () => {
    const name = fresh('wit-ahead');
    const w = await memoryWitness('w1.example');
    const bucket = new ObservedBucket(name);
    await append(name, 5, 0);
    await withStore(name, (store) => {
      store.recordWitnessSuccess(w.vkey, 50, 0);
    });
    await expect(run(name, bucket, [w], 1)).rejects.toThrow(/beyond 5/);
  });

  it('recovers from a crash after cosigning, before the live checkpoint was written', async () => {
    const name = fresh('wit-crash');
    const w = await memoryWitness('w1.example');
    const bucket = new ObservedBucket(name);
    await append(name, 300, 0);
    class Crash extends Error {}
    await expect(
      run(name, bucket, [w], 1, {
        afterStep: (s) => {
          if (s === 'witnessed') throw new Crash(s);
        },
      }),
    ).rejects.toThrow(Crash);
    expect(await liveCheckpoint(name)).toBeNull();
    // The witness already holds 300; the retry resubmits 300 -> 300 and gets a new cosignature.
    expect((await run(name, bucket, [w], 1)).size).toBe(300);
    expect(w.submissions).toEqual([0, 300]);
    expect(await cosignedBy(name, [w])).toEqual({ size: 300, names: ['w1.example'] });
  });
});

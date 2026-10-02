// The witness Worker (M8, C2SP tlog-witness), end to end inside workerd: HTTP routes, the
// Durable Object's record, and the atomic old-size check under concurrent submissions.
import {
  SIZE_CONTENT_TYPE,
  consistencyProof,
  formatAddCheckpoint,
  generateKey,
  hashLeaves,
  merkleRoot,
  newCosignatureVerifier,
  newSigner,
  newVerifier,
  openCosignedCheckpoint,
  sha256,
  signCheckpoint,
  toHex,
  utf8Encode,
  type NoteSigner,
} from '@r2notary/core';
import { env, exports } from 'cloudflare:workers';
import { reset, runInDurableObject } from 'cloudflare:test';
import { afterEach, describe, expect, it } from 'vitest';
import { MAX_BODY_BYTES } from '../src/limits.ts';
import { parseWitnessLogs } from '../src/config.ts';
import { storeIfUnchanged } from '../src/state.ts';

interface TestEnv {
  readonly TEST_ORIGIN: string;
  readonly TEST_LOG_KEY: string;
  readonly TEST_WITNESS_VKEY: string;
}
const T = env as unknown as Env & TestEnv;
const ORIGIN = T.TEST_ORIGIN;

const leaves = await hashLeaves(
  Array.from({ length: 64 }, (_, i) => utf8Encode(`entry ${String(i)}`)),
);
const root = (n: number): Promise<Uint8Array> => merkleRoot(leaves.slice(0, n));
const proof = (m: number, n: number): Promise<Uint8Array[]> =>
  consistencyProof(m, n, (nodes) =>
    Promise.all(
      nodes.map(({ height, index }) =>
        merkleRoot(leaves.slice(index * 2 ** height, (index + 1) * 2 ** height)),
      ),
    ),
  );

let logSigner: Promise<NoteSigner> | null = null;
async function checkpoint(n: number, signer?: NoteSigner, rootHash?: Uint8Array): Promise<string> {
  logSigner ??= newSigner(T.TEST_LOG_KEY);
  return signCheckpoint(
    { origin: ORIGIN, size: n, rootHash: rootHash ?? (await root(n)), extensions: [] },
    signer ?? (await logSigner),
  );
}

async function add(oldSize: number, n: number, note?: string): Promise<Response> {
  const body = formatAddCheckpoint({
    oldSize,
    proof: oldSize === 0 || oldSize >= n ? [] : await proof(oldSize, n),
    checkpoint: note ?? (await checkpoint(n)),
  });
  return exports.default.fetch(
    new Request('https://witness.example.com/add-checkpoint', { method: 'POST', body }),
  );
}

const originHash = async (): Promise<string> => toHex(await sha256(utf8Encode(ORIGIN)));

afterEach(() => reset());

describe('add-checkpoint', () => {
  it('cosigns a first checkpoint and then its extensions', async () => {
    const first = await add(0, 5);
    expect(first.status).toBe(200);
    const line = await first.text();
    const cosigned = `${await checkpoint(5)}${line}`;
    const logV = await newVerifier((await newSigner(T.TEST_LOG_KEY)).vkey);
    const witV = await newCosignatureVerifier(T.TEST_WITNESS_VKEY);
    const r = await openCosignedCheckpoint(cosigned, logV, ORIGIN, [witV]);
    expect(r.checkpoint.size).toBe(5);
    expect(r.cosignatures).toHaveLength(1);
    expect(r.cosignatures[0]?.timestamp).toBeGreaterThan(0);

    expect((await add(5, 13)).status).toBe(200);
    expect((await add(13, 13)).status).toBe(200); // the same checkpoint again (a retry)
    expect((await add(13, 64)).status).toBe(200);
  });

  it('answers 409 with its latest size in text/x.tlog.size', async () => {
    expect((await add(0, 5)).status).toBe(200);
    const r = await add(0, 13);
    expect(r.status).toBe(409);
    expect(r.headers.get('content-type')).toBe(SIZE_CONTENT_TYPE);
    expect(await r.text()).toBe('5\n');
    expect(await (await add(3, 13)).text()).toBe('5\n');
  });

  it('answers 400, 403, 404 and 422 as the spec says, and keeps 422s as evidence', async () => {
    const body = (b: string) =>
      exports.default.fetch(
        new Request('https://witness.example.com/add-checkpoint', { method: 'POST', body: b }),
      );
    expect((await body('old 1\n')).status).toBe(400);
    expect((await add(6, 5)).status).toBe(400);

    const impostor = await newSigner((await generateKey(ORIGIN)).skey);
    expect((await add(0, 5, await checkpoint(5, impostor))).status).toBe(403);

    const other = await generateKey('example.com/other');
    const foreign = await signCheckpoint(
      { origin: 'example.com/other', size: 1, rootHash: await root(1), extensions: [] },
      await newSigner(other.skey),
    );
    expect((await add(0, 1, foreign)).status).toBe(404);

    expect((await add(0, 5)).status).toBe(200);
    // A signed checkpoint of size 13 that does not extend the cosigned size-5 tree: a fork.
    const fork = await checkpoint(13, undefined, await root(14));
    const r = await add(5, 13, fork);
    expect(r.status).toBe(422);
    const evidence = await env.WITNESS.getByName('witness').evidence();
    expect(evidence).toHaveLength(1);
    expect(evidence[0]).toMatchObject({ origin: ORIGIN });
    expect(evidence[0]?.body).toContain(fork);
  });

  it('accepts exactly one of two concurrent submissions from the same old size', async () => {
    expect((await add(0, 5)).status).toBe(200);
    const [a, b] = await Promise.all([add(5, 13), add(5, 40)]);
    const statuses = [a.status, b.status].sort();
    expect(statuses).toEqual([200, 409]);
    const won = a.status === 200 ? 13 : 40;
    const loser = a.status === 200 ? b : a;
    expect(await loser.text()).toBe(`${String(won)}\n`);
    // The record is the winner's, and never moves back.
    const note = await env.WITNESS.getByName('witness').checkpoint(await originHash());
    expect(note?.split('\n')[1]).toBe(String(won));
    expect((await add(5, 13)).status).toBe(409);
  });

  // The two requests above do not actually interleave in local workerd (WebCrypto completes without
  // letting another request in), so the transaction's re-check is tested directly: a submission
  // verified against size 5 must not be stored once the record has moved on to 13.
  it('stores nothing when the record changed after the submission was verified', async () => {
    expect((await add(0, 5)).status).toBe(200);
    expect((await add(5, 13)).status).toBe(200);
    const stub = env.WITNESS.getByName('witness');
    const r = await runInDurableObject(stub, (_instance, state) =>
      storeIfUnchanged(state.storage, {
        origin: ORIGIN,
        originHash: 'unused',
        oldSize: 5,
        size: 40,
        rootHash: new Uint8Array(32),
        note: 'unused',
        line: 'unused',
        now: 0,
      }),
    );
    expect(r).toEqual({ status: 409, body: '13\n', contentType: SIZE_CONTENT_TYPE });
    expect((await stub.checkpoint(await originHash()))?.split('\n')[1]).toBe('13');
  });

  it('refuses other methods and oversized bodies', async () => {
    const get = await exports.default.fetch(
      new Request('https://witness.example.com/add-checkpoint'),
    );
    expect(get.status).toBe(405);
    expect(get.headers.get('allow')).toBe('POST');
    const big = await exports.default.fetch(
      new Request('https://witness.example.com/add-checkpoint', {
        method: 'POST',
        body: 'x'.repeat(MAX_BODY_BYTES + 1),
      }),
    );
    expect(big.status).toBe(413);
    expect((await exports.default.fetch(new Request('https://witness.example.com/'))).status).toBe(
      404,
    );
  });
});

describe('GET <origin hash>/checkpoint', () => {
  it('serves the latest cosigned checkpoint with the log signature and the cosignature', async () => {
    const url = `https://witness.example.com/${await originHash()}/checkpoint`;
    expect((await exports.default.fetch(new Request(url))).status).toBe(404);
    expect((await add(0, 5)).status).toBe(200);
    expect((await add(5, 13)).status).toBe(200);
    const res = await exports.default.fetch(new Request(url));
    expect(res.status).toBe(200);
    const note = await res.text();
    const logV = await newVerifier((await newSigner(T.TEST_LOG_KEY)).vkey);
    const witV = await newCosignatureVerifier(T.TEST_WITNESS_VKEY);
    const r = await openCosignedCheckpoint(note, logV, ORIGIN, [witV]);
    expect(r.checkpoint.size).toBe(13);
    expect(r.cosignatures).toHaveLength(1);
    const post = await exports.default.fetch(new Request(url, { method: 'POST' }));
    expect(post.status).toBe(405);
  });
});

describe('WITNESS_LOGS', () => {
  it('accepts the documented shape and rejects anything else', async () => {
    const vkey = (await newSigner(T.TEST_LOG_KEY)).vkey;
    const ok = await parseWitnessLogs(JSON.stringify([{ origin: ORIGIN, vkeys: [vkey] }]));
    expect([...ok.keys()]).toEqual([ORIGIN]);
    expect((await parseWitnessLogs('[]')).size).toBe(0);
    for (const bad of [
      '{}',
      'not json',
      JSON.stringify([{ origin: ORIGIN, vkeys: [] }]),
      JSON.stringify([{ origin: ORIGIN }]),
      JSON.stringify([{ origin: '', vkeys: [vkey] }]),
      JSON.stringify([{ origin: 'a\nb', vkeys: [vkey] }]),
      JSON.stringify([{ origin: ORIGIN, vkeys: [vkey], extra: 1 }]),
      JSON.stringify([
        { origin: ORIGIN, vkeys: [vkey] },
        { origin: ORIGIN, vkeys: [vkey] },
      ]),
      JSON.stringify([{ origin: ORIGIN, vkeys: [T.TEST_WITNESS_VKEY] }]), // a cosigner key
    ]) {
      await expect(parseWitnessLogs(bad), bad).rejects.toThrow();
    }
  });
});

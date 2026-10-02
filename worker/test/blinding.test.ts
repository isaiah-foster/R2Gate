// Key blinding (M8, PLAN §9 item 3): a blinded log names objects by keyHmac. The Sequencer here is
// constructed over a real Durable Object's storage with KEY_BLINDING on (the test pool's own
// binding has the committed config, off). The central property: no key name reaches the log
// bucket, while the objects view, lookups and the auditor still work on real keys.
import { decodeEntry, encodeEntry, newKeyBlinder, toBase64, type KeyBlinder } from '@r2notary/core';
import { env } from 'cloudflare:workers';
import { createMessageBatch, reset, runInDurableObject } from 'cloudflare:test';
import { afterEach, describe, expect, it } from 'vitest';
import { DEFAULT_BUDGET, runScan, type ScanSequencer, type StepLike } from '../src/audit/scan.ts';
import { parseConfig } from '../src/config.ts';
import { consumeBatch } from '../src/ingest.ts';
import { AppendError, Sequencer, checkNames } from '../src/sequencer.ts';
import { lookup } from '../src/api.ts';
import { BUCKET, envWith, objectEvent, publishedEntries, putObject, readBytes } from './helpers.ts';

afterEach(() => reset());

const secret = (fill: number): string =>
  toBase64(new Uint8Array(32).fill(fill))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
const SECRET = secret(7);
const KEYS = ['photos/cat.jpg', 'docs/ünïcødé ファイル', 'tax/2026 return.pdf'];

let unique = 0;
const fresh = (): string => `blind-${String(++unique)}`;

/** Runs `fn` with a Sequencer over the named DO's storage, configured with `e`. */
function withSequencer<R>(name: string, e: Env, fn: (s: Sequencer) => Promise<R>): Promise<R> {
  return runInDurableObject(env.SEQUENCER.getByName(name), (_i, state) =>
    fn(new Sequencer(state, e)),
  );
}

function message(body: Record<string, unknown>) {
  return { id: crypto.randomUUID(), timestamp: new Date(), attempts: 1, body };
}

const event = (key: string, action = 'PutObject', extra: Record<string, unknown> = {}) => ({
  account: 'acct',
  action,
  bucket: BUCKET,
  object:
    action === 'DeleteObject' ? { key } : { key, size: 3, eTag: `etag-${String(key.length)}` },
  eventTime: '2026-10-02T12:00:00.000Z',
  ...extra,
});

/** Every object under the log's prefix in R2, as text (bundles, tiles, checkpoints, reports). */
async function everythingPublished(prefix: string): Promise<string> {
  const out: string[] = [];
  const page = await env.LOG.list({ prefix: `${prefix}/` });
  for (const o of page.objects) {
    out.push(new TextDecoder().decode((await readBytes(o.key)) ?? new Uint8Array()));
  }
  return out.join('\n');
}

let blinder: Promise<KeyBlinder> | null = null;
const blind = async (k: string): Promise<string> => {
  blinder ??= newKeyBlinder(SECRET);
  return (await blinder).blind(k);
};

describe('checkNames', () => {
  it('on a blinded log, accepts only keyHmac entries that carry the matching key', async () => {
    const b = await newKeyBlinder(SECRET);
    const blinded = (key: string, keyHmac: string) =>
      encodeEntry({
        v: 1,
        type: 'object.event',
        bucket: BUCKET,
        keyHmac,
        action: 'DeleteObject',
        eventTime: '2026-10-02T12:00:00Z',
        ingestedAt: '2026-10-02T12:00:00Z',
      });
    const h = await b.blind('a');
    await checkNames([{ eventId: 'e', entry: blinded('a', h), key: 'a' }], b);
    for (const item of [
      { eventId: 'e', entry: objectEvent(1, { key: 'a' }) }, // would publish the name
      { eventId: 'e', entry: blinded('a', h) }, // no key: the view could not be kept
      { eventId: 'e', entry: blinded('a', h), key: 'b' }, // the wrong key
      { eventId: 'e', entry: blinded('a', h), key: '' },
    ]) {
      await expect(checkNames([item], b)).rejects.toThrow(AppendError);
    }
    // And the reverse on a log that is not blinded.
    await checkNames([{ eventId: 'e', entry: objectEvent(1, { key: 'a' }) }], null);
    await expect(
      checkNames([{ eventId: 'e', entry: blinded('a', h), key: 'a' }], null),
    ).rejects.toThrow(AppendError);
  });
});

describe('a blinded log', () => {
  it('publishes no key name, and keeps the objects view and lookups working', async () => {
    const name = fresh();
    const e = envWith({ KEY_BLINDING: 'true', KEY_BLINDING_KEY: SECRET, LOG_NAME: name });
    await withSequencer(name, e, async (seq) => {
      const batch = createMessageBatch('r2notary-events', [
        ...KEYS.map((k) => message(event(k))),
        message(event('photos/cat.jpg', 'DeleteObject')),
        message(
          event('copy/of cat.jpg', 'CopyObject', {
            copySource: { bucket: BUCKET, object: 'photos/cat.jpg' },
          }),
        ),
      ]);
      const cfg = parseConfig(e);
      await consumeBatch(batch, {
        config: cfg,
        sink: { ingest: (items, report) => seq.ingest(items, report) },
        blinder: await newKeyBlinder(SECRET),
        now: Date.now,
      });
      expect((await seq.publish()).size).toBe(5);

      // Nothing published names a key: not the entries, the copy source, or anything else.
      const published = await everythingPublished(name);
      for (const k of [...KEYS, 'copy/of cat.jpg', 'cat.jpg', 'ファイル']) {
        expect(published).not.toContain(k);
      }
      expect(published).toContain(await blind('photos/cat.jpg'));

      // The objects view is keyed by real keys and knows each key's blinded name.
      const states = seq.getObjectStates({ limit: 10 });
      expect(states.map((s) => s.key).sort()).toEqual(['copy/of cat.jpg', ...KEYS].sort());
      const cat = states.find((s) => s.key === 'photos/cat.jpg');
      expect(cat).toMatchObject({ deleted: true, keyHmac: await blind('photos/cat.jpg') });

      // Lookups use the blinded name: the API takes keyHmac and refuses plaintext keys.
      expect(seq.lookup(await blind('photos/cat.jpg')).indexes).toEqual([0, 3]);
      expect(seq.lookup('photos/cat.jpg').indexes).toEqual([]);
      const api = (q: string) =>
        lookup(
          new URL(`https://h/api/v1/lookup?${q}`),
          {
            config: cfg,
            sequencer: {
              lookup: (k: string, o: object) => Promise.resolve(seq.lookup(k, o)),
            } as unknown as DurableObjectStub<Sequencer>,
            workflow: { createBatch: () => Promise.reject(new Error('unused')) },
            bucket: env.LOG,
          },
          false,
        );
      expect((await api('key=photos%2Fcat.jpg')).status).toBe(400);
      const found = await api(`keyHmac=${await blind('photos/cat.jpg')}`);
      expect(found.status).toBe(200);
      const body = await found.json<{ entries: { index: number; entry: unknown }[] }>();
      expect(body.entries.map((x) => x.index)).toEqual([0, 3]);
      expect((await api('keyHmac=NOTHEX')).status).toBe(400);
    });
  });

  it('refuses to change blinding, or its secret, once the log has entries', async () => {
    const name = fresh();
    const blindedEnv = envWith({ KEY_BLINDING: 'true', KEY_BLINDING_KEY: SECRET, LOG_NAME: name });
    const item = async (k: string, i: number) => ({
      eventId: `e${String(i)}`,
      key: k,
      entry: encodeEntry({
        v: 1,
        type: 'object.event',
        bucket: BUCKET,
        keyHmac: await blind(k),
        action: 'DeleteObject',
        eventTime: '2026-10-02T12:00:00Z',
        ingestedAt: '2026-10-02T12:00:00Z',
      }),
    });
    await withSequencer(name, blindedEnv, async (seq) => {
      await seq.append([await item('a', 1)]);
    });
    // The same log under a configuration that does not blind, or blinds with another secret.
    const plain = envWith({ KEY_BLINDING: 'false', LOG_NAME: name });
    await withSequencer(name, plain, async (seq) => {
      await expect(seq.append([{ eventId: 'p', entry: objectEvent(2) }])).rejects.toThrow(
        /key blinding is hmac-sha256:/,
      );
    });
    const other = envWith({ KEY_BLINDING: 'true', KEY_BLINDING_KEY: secret(8), LOG_NAME: name });
    await withSequencer(name, other, async (seq) => {
      const b = await newKeyBlinder(secret(8));
      const entry = encodeEntry({
        v: 1,
        type: 'object.event',
        bucket: BUCKET,
        keyHmac: await b.blind('a'),
        action: 'DeleteObject',
        eventTime: '2026-10-02T12:00:00Z',
        ingestedAt: '2026-10-02T12:00:00Z',
      });
      await expect(seq.append([{ eventId: 'o', entry, key: 'a' }])).rejects.toThrow(
        /cannot change for an existing log/,
      );
    });
    // A log written before M8 (entries, no record) counts as not blinded.
    const old = fresh();
    await withSequencer(old, envWith({ LOG_NAME: old }), async (seq) => {
      await seq.append([{ eventId: 'x', entry: objectEvent(1) }]);
    });
    await withSequencer(
      old,
      envWith({ KEY_BLINDING: 'true', KEY_BLINDING_KEY: SECRET, LOG_NAME: old }),
      async (seq) => {
        await expect(seq.append([await item('b', 2)])).rejects.toThrow(/key blinding is off/);
      },
    );
  });

  it('audits with real keys and records findings, observations and reports by keyHmac', async () => {
    const name = fresh();
    const e = envWith({
      KEY_BLINDING: 'true',
      KEY_BLINDING_KEY: SECRET,
      LOG_NAME: name,
      AUDIT_GRACE_SECONDS: '0',
      DEEP_SCRUB_SAMPLE_RATE: '1',
    });
    // The log knows photos/cat.jpg (live) and tax/... (live); the bucket has cat.jpg changed and
    // an object the log never saw. tax/... is missing from the bucket.
    await putObject(env.MONITORED, 'photos/cat.jpg', 'changed');
    await putObject(env.MONITORED, 'secret/plans.txt', 'unlogged');
    await withSequencer(name, e, async (seq) => {
      const batch = createMessageBatch('r2notary-events', [
        message(event('photos/cat.jpg')),
        message(event('tax/2026 return.pdf')),
      ]);
      await consumeBatch(batch, {
        config: parseConfig(e),
        sink: { ingest: (items, report) => seq.ingest(items, report) },
        blinder: await newKeyBlinder(SECRET),
        now: Date.now,
      });
      await seq.publish();

      const steps: StepLike = {
        do: (_name, _config, fn) => fn(),
        sleep: () => Promise.resolve(),
      };
      const outcome = await runScan({ scanId: 'blind-audit', mode: 'audit', part: 0 }, steps, {
        // A local instance answers some calls synchronously; runScan awaits them all, so the
        // RPC-shaped interface is satisfied at run time.
        sequencer: seq as unknown as ScanSequencer,
        bucket: env.MONITORED,
        continueIn: () => Promise.reject(new Error('no hand-off expected')),
        alert: null,
        origin: env.LOG_ORIGIN,
        scrubRate: 1,
        scrubMaxBytes: 1 << 20,
        pageSize: 1,
        budget: DEFAULT_BUDGET,
        now: Date.now,
      });
      expect(outcome).toMatchObject({ status: 'done', findings: 3 });

      const findings = seq.scanFindings().findings.map((f) => decodeEntry(f.entry));
      const named = findings.map((d) => {
        if (!d.known || d.entry.type !== 'audit.finding') throw new Error('not a finding');
        return `${d.entry.kind} ${String(d.entry.keyHmac)}`;
      });
      expect(named.sort()).toEqual(
        [
          `ETAG_MISMATCH ${await blind('photos/cat.jpg')}`,
          `MISSING_OBJECT ${await blind('tax/2026 return.pdf')}`,
          `UNLOGGED_OBJECT ${await blind('secret/plans.txt')}`,
        ].sort(),
      );
      await seq.publish();
      const published = await everythingPublished(name);
      for (const k of ['photos/cat.jpg', 'secret/plans.txt', 'tax/2026 return.pdf']) {
        expect(published).not.toContain(k);
      }
      // The report (x-reports/) is in the log bucket too; it lists findings by keyHmac.
      expect(published).toContain(`"key":"${await blind('secret/plans.txt')}"`);
      // Deep scrub observed both listed objects, by keyHmac.
      const observations = (await publishedEntries(name))
        .map((b) => decodeEntry(b))
        .flatMap((d) => (d.known && d.entry.type === 'audit.observation' ? [d.entry] : []));
      expect(observations.map((o) => o.keyHmac).sort()).toEqual(
        [await blind('photos/cat.jpg'), await blind('secret/plans.txt')].sort(),
      );
    });
  });
});

it('status reports whether the log blinds keys', async () => {
  const { default: worker } = await import('../src/index.ts');
  for (const [e, want] of [
    [envWith({ PUBLIC_LOG: 'true' }), false],
    [envWith({ PUBLIC_LOG: 'true', ...{ KEY_BLINDING: 'true', KEY_BLINDING_KEY: SECRET } }), true],
  ] as const) {
    const res = await worker.fetch(new Request('https://h/api/v1/status'), e);
    expect((await res.json<{ keyBlinding: boolean }>()).keyBlinding).toBe(want);
  }
});

it('records the blinding state with the first entry, even after a rolled-back first attempt', async () => {
  const name = fresh();
  const e = envWith({ KEY_BLINDING: 'true', KEY_BLINDING_KEY: SECRET, LOG_NAME: name });
  await runInDurableObject(env.SEQUENCER.getByName(name), async (_i, state) => {
    const seq = new Sequencer(state, e);
    // The first append's transaction fails after the state check (a bad ingest report is checked
    // first, so use a store-level failure instead: an entry row that already exists).
    state.storage.sql.exec("INSERT INTO entries(seq, entry, received_at) VALUES (0, x'00', 0)");
    const item = {
      eventId: 'first',
      key: 'a',
      entry: encodeEntry({
        v: 1,
        type: 'object.event',
        bucket: BUCKET,
        keyHmac: await blind('a'),
        action: 'DeleteObject',
        eventTime: '2026-10-02T12:00:00Z',
        ingestedAt: '2026-10-02T12:00:00Z',
      }),
    };
    await expect(seq.append([item])).rejects.toThrow();
    expect(state.storage.sql.exec("SELECT v FROM meta WHERE k = 'key_blinding'").toArray()).toEqual(
      [],
    );
    state.storage.sql.exec('DELETE FROM entries');
    await seq.append([item]);
    const rec = state.storage.sql.exec("SELECT v FROM meta WHERE k = 'key_blinding'").one().v;
    expect(typeof rec === 'string' ? rec : null).toMatch(/^hmac-sha256:[0-9a-f]{16}$/);
  });
});

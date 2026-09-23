// The JSON API (PLAN §5.5, M4): status, lookup, findings, and the bearer-protected admin routes.
import { decodeBundle, entryBundlePath, utf8Decode } from '@r2notary/core';
import { env } from 'cloudflare:workers';
import { reset } from 'cloudflare:test';
import { afterEach, describe, expect, it } from 'vitest';
import { lookup } from '../src/api.ts';
import { parseConfig } from '../src/config.ts';
import worker from '../src/index.ts';
import { envWith, objectEvent, readBytes } from './helpers.ts';

const LOG = env.LOG_NAME;
const PUBLIC_ENV = envWith({ PUBLIC_LOG: 'true' });

function call(
  path: string,
  o: { method?: string; token?: string; env?: Env } = {},
): Promise<Response> {
  const headers = new Headers();
  if (o.token !== undefined) headers.set('authorization', `Bearer ${o.token}`);
  return worker.fetch(
    new Request(`https://r2notary.example.com${path}`, { method: o.method ?? 'GET', headers }),
    o.env ?? PUBLIC_ENV,
  );
}

async function json(res: Response): Promise<unknown> {
  expect(res.headers.get('content-type')).toBe('application/json; charset=utf-8');
  expect(res.headers.get('cache-control')).toBe('no-store');
  return res.json();
}

const sequencer = () => env.SEQUENCER.getByName(LOG);

afterEach(() => reset());

describe('GET /api/v1/status', () => {
  it('is public on a public log and needs a token on a private one', async () => {
    expect((await call('/api/v1/status')).status).toBe(200);
    expect((await call('/api/v1/status', { env })).status).toBe(401);
    const res = await call('/api/v1/status', { env, token: env.READ_TOKEN });
    expect(res.status).toBe(200);
    expect(await json(res)).toMatchObject({ log: LOG, origin: env.LOG_ORIGIN, size: 0 });
  });

  it('only answers GET and HEAD', async () => {
    const res = await call('/api/v1/status', { method: 'POST' });
    expect(res.status).toBe(405);
    expect(res.headers.get('allow')).toBe('GET, HEAD');
  });
});

describe('GET /api/v1/lookup', () => {
  // 300 published entries, every third one for key "hot" (indexes 0, 3, ..., 297: across a full
  // and a partial bundle), then 5 more for "hot" that are durable but not yet published.
  async function seed(): Promise<void> {
    const s = sequencer();
    await s.append(
      Array.from({ length: 300 }, (_, i) => ({
        eventId: `ev-${String(i)}`,
        entry: objectEvent(i, i % 3 === 0 ? { key: 'hot' } : {}),
      })),
    );
    await s.publish();
    await s.append(
      Array.from({ length: 5 }, (_, i) => ({
        eventId: `late-${String(i)}`,
        entry: objectEvent(300 + i, { key: 'hot' }),
      })),
    );
  }

  interface LookupBody {
    key: string;
    size: number;
    entries: { index: number; entry: Record<string, unknown> }[];
    next: number | null;
  }

  it('returns the published entries for a key, page by page, as found in the bundles', async () => {
    await seed();
    const bundles = [
      ...decodeBundle((await readBytes(`${LOG}/${entryBundlePath(0, 256)}`)) ?? new Uint8Array()),
      ...decodeBundle((await readBytes(`${LOG}/${entryBundlePath(1, 44)}`)) ?? new Uint8Array()),
    ];
    const seen: LookupBody['entries'] = [];
    let after: number | null = null;
    let pages = 0;
    do {
      const q: string = after === null ? '' : `&after=${String(after)}`;
      const res = await call(`/api/v1/lookup?key=hot&limit=40${q}`);
      expect(res.status).toBe(200);
      const body = (await json(res)) as LookupBody;
      expect(body.key).toBe('hot');
      expect(body.size).toBe(300);
      seen.push(...body.entries);
      after = body.next;
      pages++;
    } while (after !== null);
    expect(pages).toBe(3);
    expect(seen.map((e) => e.index)).toEqual(Array.from({ length: 100 }, (_, i) => i * 3));
    for (const { index, entry } of seen) {
      expect(entry).toEqual(JSON.parse(utf8Decode(bundles[index] ?? new Uint8Array())));
      expect(entry.key).toBe('hot');
    }
  });

  it('defaults to 100 per page, and returns nothing for an unknown key', async () => {
    await seed();
    const all = (await json(await call('/api/v1/lookup?key=hot'))) as LookupBody;
    expect(all.entries).toHaveLength(100);
    expect(all.next).toBeNull();
    const none = (await json(await call('/api/v1/lookup?key=nope'))) as LookupBody;
    expect(none).toEqual({ key: 'nope', size: 300, entries: [], next: null });
  });

  it('handles keys that need URL encoding', async () => {
    const key = 'dir/ünï code&x=1?#';
    await sequencer().append([{ eventId: 'odd', entry: objectEvent(0, { key }) }]);
    await sequencer().publish();
    const body = (await json(
      await call(`/api/v1/lookup?key=${encodeURIComponent(key)}`),
    )) as LookupBody;
    expect(body.entries.map((e) => e.entry.key)).toEqual([key]);
  });

  it.each([
    ['no key', ''],
    ['an empty key', '?key='],
    ['a key over 1,024 bytes', `?key=${'é'.repeat(513)}`],
    ['a repeated key', '?key=a&key=b'],
    ['limit 0', '?key=a&limit=0'],
    ['limit 101', '?key=a&limit=101'],
    ['a non-decimal limit', '?key=a&limit=1e2'],
    ['a negative cursor', '?key=a&after=-1'],
    ['a non-decimal cursor', '?key=a&after=0x10'],
  ])('rejects %s with 400', async (_, query) => {
    const res = await call(`/api/v1/lookup${query}`);
    expect(res.status).toBe(400);
    expect(await json(res)).toHaveProperty('error');
  });

  it('stops a page early, with a cursor, before reading too many bundles', async () => {
    await seed(); // "hot" entries sit in bundles 0 and 1
    const reads: string[] = [];
    const deps = {
      config: parseConfig(env),
      sequencer: sequencer(),
      bucket: {
        get: (key: string) => {
          reads.push(key);
          return env.LOG.get(key);
        },
      },
      maxBundles: 1,
    };
    const first = await (
      await lookup(new URL('https://x/api/v1/lookup?key=hot'), deps, false)
    ).json<LookupBody>();
    expect(reads).toHaveLength(1);
    expect(first.entries.at(-1)?.index).toBe(255); // the last "hot" index in bundle 0
    expect(first.next).toBe(255);
    const second = await (
      await lookup(new URL('https://x/api/v1/lookup?key=hot&after=255'), deps, false)
    ).json<LookupBody>();
    expect(second.entries.map((e) => e.index)).toEqual(
      Array.from({ length: 14 }, (_, i) => 258 + i * 3),
    );
    expect(second.next).toBeNull();
    expect(reads).toHaveLength(2);
  });

  it('needs a token on a private log', async () => {
    expect((await call('/api/v1/lookup?key=a', { env })).status).toBe(401);
    expect((await call('/api/v1/lookup?key=a', { env, token: env.READ_TOKEN })).status).toBe(200);
  });
});

describe('GET /api/v1/findings', () => {
  it('reports that no audit has run (the auditor arrives in M6)', async () => {
    const res = await call('/api/v1/findings');
    expect(res.status).toBe(200);
    expect(await json(res)).toEqual({ latestScan: null, findings: [] });
    expect((await call('/api/v1/findings', { env })).status).toBe(401);
  });
});

describe('admin routes', () => {
  it('publish requires the admin token, even on a public log', async () => {
    await sequencer().append(
      Array.from({ length: 3 }, (_, i) => ({ eventId: `e${String(i)}`, entry: objectEvent(i) })),
    );
    for (const token of [undefined, env.READ_TOKEN, `${env.ADMIN_TOKEN}x`, 'x']) {
      const res = await call('/api/v1/admin/publish', {
        method: 'POST',
        ...(token === undefined ? {} : { token }),
      });
      expect(res.status).toBe(401);
      expect(res.headers.get('www-authenticate')).toBe('Bearer realm="r2notary"');
      expect(res.headers.get('cache-control')).toBe('no-store');
    }
    expect((await sequencer().status()).publishedSize).toBe(0);

    const res = await call('/api/v1/admin/publish', { method: 'POST', token: env.ADMIN_TOKEN });
    expect(res.status).toBe(200);
    const body = (await json(res)) as { previousSize: number; size: number; checkpoint: string };
    expect(body).toMatchObject({ previousSize: 0, size: 3 });
    expect(body.checkpoint).toContain(`${env.LOG_ORIGIN}\n3\n`);
    expect((await sequencer().status()).publishedSize).toBe(3);
  });

  it('never accepts the read token on a private log', async () => {
    const res = await call('/api/v1/admin/publish', { method: 'POST', env, token: env.READ_TOKEN });
    expect(res.status).toBe(401);
    const ok = await call('/api/v1/admin/publish', { method: 'POST', env, token: env.ADMIN_TOKEN });
    expect(ok.status).toBe(200);
  });

  it('checks the token before revealing anything about the route', async () => {
    for (const path of ['/api/v1/admin/publish', '/api/v1/admin/nope', '/api/v1/admin/']) {
      expect((await call(path, { method: 'GET' })).status, path).toBe(401);
    }
    const t = { token: env.ADMIN_TOKEN };
    expect((await call('/api/v1/admin/publish', { ...t, method: 'GET' })).status).toBe(405);
    expect((await call('/api/v1/admin/nope', { ...t, method: 'POST' })).status).toBe(404);
  });

  it('backfill and scan exist but are not implemented until M6', async () => {
    for (const op of ['backfill', 'scan']) {
      const res = await call(`/api/v1/admin/${op}`, { method: 'POST', token: env.ADMIN_TOKEN });
      expect(res.status, op).toBe(501);
      expect(await json(res)).toHaveProperty('error');
    }
  });
});

describe('everything else', () => {
  it('is a 404 that is never cached', async () => {
    for (const path of ['/', '/api/v1/', '/api/v2/status', '/api/v1/status/', '/favicon.ico']) {
      const res = await call(path);
      expect(res.status, path).toBe(404);
      expect(res.headers.get('cache-control'), path).toBe('no-store');
    }
  });

  it('fails closed with a bare 500 when access is misconfigured', async () => {
    const res = await call(`/log/${LOG}/checkpoint`, { env: envWith({ PUBLIC_LOG: 'maybe' }) });
    expect(res.status).toBe(500);
    expect(res.headers.get('cache-control')).toBe('no-store');
    expect(await res.text()).not.toContain('PUBLIC_LOG');
  });
});

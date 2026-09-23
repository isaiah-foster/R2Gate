// The public read path (PLAN §5.5, M4): /log/<name>/ serves the log bucket's resources with the
// headers C2SP tlog-tiles asks for, CORS for browser verifiers, HEAD, strict 404s, and bearer
// tokens when PUBLIC_LOG is "false".
import { CHECKPOINT_PATH, decodeBundle, entryBundlePath, tilePath } from '@r2notary/core';
import { env } from 'cloudflare:workers';
import { reset } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import worker from '../src/index.ts';
import { envWith, items, openTestCheckpoint, readBytes } from './helpers.ts';

const LOG = env.LOG_NAME;
const PUBLIC_ENV = envWith({ PUBLIC_LOG: 'true' });
const IMMUTABLE = 'public, max-age=31536000, immutable';

interface CallOptions {
  readonly method?: string;
  readonly token?: string;
  readonly headers?: Record<string, string>;
  readonly env?: Env;
}

function call(path: string, o: CallOptions = {}): Promise<Response> {
  const headers = new Headers(o.headers);
  if (o.token !== undefined) headers.set('authorization', `Bearer ${o.token}`);
  return worker.fetch(
    new Request(`https://r2notary.example.com${path}`, { method: o.method ?? 'GET', headers }),
    o.env ?? PUBLIC_ENV,
  );
}

async function bytes(res: Response): Promise<Uint8Array> {
  return new Uint8Array(await res.arrayBuffer());
}

/** Publishes 300 entries and then 10 more, so full, partial and superseded partial tiles exist. */
async function publishLog(): Promise<void> {
  const s = env.SEQUENCER.getByName(LOG);
  await s.append(items(300));
  await s.publish();
  await s.append(items(10, 300));
  await s.publish();
}

afterEach(() => reset());

describe('log resources', () => {
  beforeEach(publishLog);

  it('serves the live checkpoint: signed, with the configured origin, briefly cacheable (I9)', async () => {
    const res = await call(`/log/${LOG}/checkpoint`);
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toBe('text/plain; charset=utf-8');
    expect(res.headers.get('cache-control')).toBe('public, max-age=2');
    expect(res.headers.get('access-control-allow-origin')).toBe('*');
    expect(res.headers.get('x-content-type-options')).toBe('nosniff');
    const body = await bytes(res);
    expect(body).toEqual(await readBytes(`${LOG}/${CHECKPOINT_PATH}`));
    const cp = await openTestCheckpoint(body);
    expect(cp.origin).toBe(env.LOG_ORIGIN);
    expect(cp.size).toBe(310);
  });

  it.each([
    ['a full tile', tilePath(0, 0, 256)],
    ['a partial tile', tilePath(0, 1, 54)],
    ['a superseded partial tile (kept, immutable)', tilePath(0, 1, 44)],
    ['a level-1 partial tile', tilePath(1, 0, 1)],
    ['a full entry bundle', entryBundlePath(0, 256)],
    ['a partial entry bundle', entryBundlePath(1, 54)],
  ])('serves %s byte for byte with long-lived caching', async (_, path) => {
    const res = await call(`/log/${LOG}/${path}`);
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toBe('application/octet-stream');
    expect(res.headers.get('cache-control')).toBe(IMMUTABLE);
    expect(res.headers.get('access-control-allow-origin')).toBe('*');
    expect(await bytes(res)).toEqual(await readBytes(`${LOG}/${path}`));
  });

  it('serves archived checkpoints as immutable text', async () => {
    for (const size of [300, 310]) {
      const res = await call(`/log/${LOG}/x-checkpoints/${String(size)}`);
      expect(res.status).toBe(200);
      expect(res.headers.get('content-type')).toBe('text/plain; charset=utf-8');
      expect(res.headers.get('cache-control')).toBe(IMMUTABLE);
      expect((await openTestCheckpoint(await bytes(res))).size).toBe(size);
    }
  });

  it('answers HEAD with the GET headers, the length, and no body', async () => {
    for (const path of [CHECKPOINT_PATH, tilePath(0, 0, 256), entryBundlePath(1, 54)]) {
      const get = await call(`/log/${LOG}/${path}`);
      const head = await call(`/log/${LOG}/${path}`, { method: 'HEAD' });
      expect(head.status).toBe(200);
      expect(head.headers.get('content-length')).toBe(String((await bytes(get)).length));
      for (const h of ['content-type', 'cache-control', 'access-control-allow-origin']) {
        expect(head.headers.get(h), h).toBe(get.headers.get(h));
      }
      expect(await bytes(head)).toHaveLength(0);
    }
  });

  it('offers gzip for entry bundles, which compress well (tlog-tiles SHOULD)', async () => {
    const path = `/log/${LOG}/${entryBundlePath(0, 256)}`;
    const gz = await call(path, { headers: { 'accept-encoding': 'gzip, br' } });
    expect(gz.headers.get('content-encoding')).toBe('gzip');
    expect(gz.headers.get('vary')).toBe('Accept-Encoding');
    // fetch() decodes transparently, so the client sees the original bundle.
    expect(decodeBundle(await bytes(gz))).toHaveLength(256);

    for (const ae of [undefined, 'identity', 'gzip;q=0, br']) {
      const plain = await call(
        path,
        ae === undefined ? {} : { headers: { 'accept-encoding': ae } },
      );
      expect(plain.headers.get('content-encoding'), ae).toBeNull();
      expect(plain.headers.get('vary'), ae).toBe('Accept-Encoding');
      await plain.body?.cancel(); // an unread R2 stream would outlive the test
    }
    // Cloudflare rewrites Accept-Encoding to a canonical value and keeps the client's own in
    // request.cf.clientAcceptEncoding; negotiation must use the client's.
    const rewritten = await worker.fetch(
      new Request(`https://r2notary.example.com${path}`, {
        headers: { 'accept-encoding': 'gzip, br' },
        cf: { clientAcceptEncoding: 'identity' },
      }) as unknown as Request<unknown, IncomingRequestCfProperties>,
      PUBLIC_ENV,
    );
    expect(rewritten.headers.get('content-encoding')).toBeNull();
    await rewritten.body?.cancel();

    // Tiles are SHA-256 hashes: incompressible, so never encoded.
    const tile = await call(`/log/${LOG}/${tilePath(0, 0, 256)}`, {
      headers: { 'accept-encoding': 'gzip' },
    });
    expect(tile.headers.get('content-encoding')).toBeNull();
    await tile.body?.cancel();
  });

  it('answers CORS preflights without a token', async () => {
    const res = await call(`/log/${LOG}/checkpoint`, {
      method: 'OPTIONS',
      env,
      headers: {
        origin: 'https://verifier.example',
        'access-control-request-method': 'GET',
        'access-control-request-headers': 'authorization',
      },
    });
    expect(res.status).toBe(204);
    expect(res.headers.get('access-control-allow-origin')).toBe('*');
    expect(res.headers.get('access-control-allow-methods')).toBe('GET, HEAD, OPTIONS');
    expect(res.headers.get('access-control-allow-headers')).toBe('Authorization');
    expect(res.headers.get('access-control-max-age')).toBe('86400');
  });

  it('refuses other methods', async () => {
    for (const method of ['POST', 'PUT', 'DELETE', 'PATCH']) {
      const res = await call(`/log/${LOG}/checkpoint`, { method });
      expect(res.status, method).toBe(405);
      expect(res.headers.get('allow')).toBe('GET, HEAD, OPTIONS');
      expect(res.headers.get('cache-control')).toBe('no-store');
    }
  });
});

describe('404s', () => {
  beforeEach(publishLog);

  it.each([
    ['a tile beyond the tree', tilePath(0, 2, 256)],
    ['a partial width that was never published', tilePath(0, 1, 50)],
    ['a full tile that does not exist yet', tilePath(0, 1, 256)],
    ['an unpublished archive', 'x-checkpoints/305'],
    ['a non-canonical index', 'tile/0/0'],
    ['an x-prefixed last element', 'tile/0/x000/001'],
    ['width 0', 'tile/0/001.p/0'],
    ['width 256 as a partial', 'tile/0/000.p/256'],
    ['a leading-zero width', 'tile/0/001.p/054'],
    ['a trailing slash', 'checkpoint/'],
    ['an escaped slash', 'tile/0%2F000'],
    ['an unknown resource', 'x-reports/scan.json'],
    ['the log prefix itself', ''],
  ])('for %s', async (_, path) => {
    const res = await call(`/log/${LOG}/${path}`);
    expect(res.status).toBe(404);
    // A cached 404 would hide a tile once it is published.
    expect(res.headers.get('cache-control')).toBe('no-store');
    expect(res.headers.get('access-control-allow-origin')).toBe('*');
  });

  it('even when an object exists at a non-canonical or non-log key under the prefix', async () => {
    // Only parseLogPath's canonical names are served: reports (M6) and stray objects are not.
    for (const path of ['x-reports/scan.json', 'tile/0/0', 'tile/0/000.p/256', 'notes.txt']) {
      await env.LOG.put(`${LOG}/${path}`, 'secret');
      expect((await call(`/log/${LOG}/${path}`)).status, path).toBe(404);
    }
  });

  it('for another log name, and for paths outside /log/', async () => {
    for (const path of [
      '/log/other-log/checkpoint',
      '/log//checkpoint',
      '/log',
      '/',
      '/checkpoint',
      `/${LOG}/checkpoint`,
    ]) {
      const res = await call(path);
      expect(res.status, path).toBe(404);
      expect(res.headers.get('cache-control'), path).toBe('no-store');
    }
  });

  it('before anything has been published', async () => {
    await reset();
    expect((await call(`/log/${LOG}/checkpoint`)).status).toBe(404);
  });
});

describe('PUBLIC_LOG=false (the committed default)', () => {
  beforeEach(publishLog);
  const path = `/log/${LOG}/${tilePath(0, 0, 256)}`;

  it('rejects requests without a valid read token', async () => {
    for (const o of [
      {},
      { token: 'wrong' },
      { token: `${env.READ_TOKEN}x` },
      { token: env.READ_TOKEN.slice(0, -1) },
      { headers: { authorization: `Basic ${env.READ_TOKEN}` } },
    ] satisfies CallOptions[]) {
      const res = await call(path, { ...o, env });
      expect(res.status, JSON.stringify(o)).toBe(401);
      expect(res.headers.get('www-authenticate')).toBe('Bearer realm="r2notary"');
      expect(res.headers.get('cache-control')).toBe('no-store');
      expect(res.headers.get('access-control-allow-origin')).toBe('*');
      expect(await res.text()).not.toContain(env.READ_TOKEN);
    }
  });

  it('serves the log to the read token and the admin token, marked private', async () => {
    for (const token of [env.READ_TOKEN, env.ADMIN_TOKEN]) {
      const res = await call(path, { token, env });
      expect(res.status).toBe(200);
      expect(res.headers.get('cache-control')).toBe('private, max-age=31536000, immutable');
      expect(await bytes(res)).toEqual(await readBytes(`${LOG}/${tilePath(0, 0, 256)}`));
    }
    const cp = await call(`/log/${LOG}/checkpoint`, { token: env.READ_TOKEN, env });
    expect(cp.headers.get('cache-control')).toBe('private, max-age=2');
    await cp.body?.cancel();
  });

  it('does not reveal whether a resource exists without a token', async () => {
    expect((await call(`/log/${LOG}/${tilePath(0, 9, 256)}`, { env })).status).toBe(401);
  });
});

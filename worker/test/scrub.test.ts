// Deep scrub (sampling, conditional reads, DigestStream hashing) and the alert webhook.
import { sha256, toHex, utf8Encode } from '@r2notary/core';
import { env } from 'cloudflare:workers';
import { reset } from 'cloudflare:test';
import { afterEach, describe, expect, it } from 'vitest';
import { AlertError, parseWebhookUrl, sendAlert, type AlertSummary } from '../src/audit/alert.ts';
import { ConfigError } from '../src/config.ts';
import { putObject } from './helpers.ts';
import {
  MAX_SCRUB_PER_PAGE,
  ScrubError,
  sampled,
  scrubObject,
  selectForScrub,
} from '../src/audit/scrub.ts';

afterEach(() => reset());

const now = (): number => 1_000;

describe('sampling', () => {
  it('is deterministic per (scan, key), all-or-nothing at 1 and 0, and near the rate', async () => {
    expect(await sampled('s', 'k', 0)).toBe(false);
    expect(await sampled('s', 'k', 1)).toBe(true);
    const keys = Array.from({ length: 2000 }, (_, i) => `key-${String(i)}`);
    const picked = await Promise.all(keys.map((k) => sampled('scan-1', k, 0.1)));
    const again = await Promise.all(keys.map((k) => sampled('scan-1', k, 0.1)));
    expect(again).toEqual(picked);
    const n = picked.filter(Boolean).length;
    expect(n).toBeGreaterThan(140); // 200 expected; generous bounds, the hash is fixed
    expect(n).toBeLessThan(260);
    // A different scan samples a different subset.
    const other = await Promise.all(keys.map((k) => sampled('scan-2', k, 0.1)));
    expect(other).not.toEqual(picked);
  });

  it('skips objects over the size limit and caps a page', async () => {
    const objects = Array.from({ length: 50 }, (_, i) => ({
      key: `k${String(i)}`,
      etag: 'e',
      size: i,
      uploaded: 0,
    }));
    expect(await selectForScrub('s', objects, 1, 4)).toHaveLength(5);
    expect(await selectForScrub('s', objects, 1, 1000)).toHaveLength(MAX_SCRUB_PER_PAGE);
  });
});

describe('scrubObject', () => {
  it('hashes the body it read, conditional on the listed ETag', async () => {
    const body = 'hello, scrub';
    const o = await putObject(env.MONITORED, 'a', body);
    const obs = await scrubObject(env.MONITORED, { key: 'a', etag: o.etag, size: o.size }, now);
    expect(obs).toEqual({
      key: 'a',
      etag: o.etag,
      size: body.length,
      uploaded: o.uploaded.getTime(),
      sha256: toHex(await sha256(utf8Encode(body))),
      storedSha256: null,
      observedAt: 1_000,
    });
  });

  it('reports the SHA-256 R2 stored at upload', async () => {
    const digest = toHex(await sha256(utf8Encode('x')));
    const o = await putObject(env.MONITORED, 'a', 'x', { sha256: digest });
    const obs = await scrubObject(env.MONITORED, { key: 'a', etag: o.etag, size: 1 }, now);
    expect(obs?.storedSha256).toBe(digest);
  });

  it('skips an object that changed or vanished since it was listed', async () => {
    const o = await putObject(env.MONITORED, 'a', 'v1');
    await putObject(env.MONITORED, 'a', 'v2');
    expect(await scrubObject(env.MONITORED, { key: 'a', etag: o.etag, size: 2 }, now)).toBeNull();
    expect(
      await scrubObject(env.MONITORED, { key: 'nope', etag: o.etag, size: 2 }, now),
    ).toBeNull();
  });

  it('fails on a short read instead of recording a wrong hash', async () => {
    const o = await putObject(env.MONITORED, 'a', 'four');
    // An object whose body ends one byte early.
    const short = {
      key: 'a',
      etag: o.etag,
      size: 4,
      uploaded: o.uploaded,
      checksums: {},
      body: new Blob(['fou']).stream(),
    } as unknown as R2ObjectBody;
    const lying = { get: () => Promise.resolve(short) };
    await expect(scrubObject(lying, { key: 'a', etag: o.etag, size: 4 }, now)).rejects.toThrow(
      ScrubError,
    );
  });
});

describe('alert webhook', () => {
  const summary: AlertSummary = {
    type: 'r2notary.audit',
    origin: 'example.com/log/x',
    scanId: 'scan-1',
    objectsScanned: 10,
    findings: 2,
    startIndex: 4,
    endIndex: 9,
    reportKey: 'x/x-reports/scan-1.json',
  };

  it('parses only https URLs, and treats an unset secret as no webhook', () => {
    expect(parseWebhookUrl(undefined)).toBeNull();
    expect(parseWebhookUrl('')).toBeNull();
    expect(parseWebhookUrl('https://hooks.example.com/a?b=c')?.host).toBe('hooks.example.com');
    expect(() => parseWebhookUrl('http://hooks.example.com/')).toThrow(ConfigError);
    expect(() => parseWebhookUrl('not a url')).toThrow(ConfigError);
  });

  it('POSTs the summary as JSON and fails on a non-2xx answer', async () => {
    const seen: Request[] = [];
    const fetcher =
      (status: number): typeof fetch =>
      (input: RequestInfo | URL, init?: RequestInit) => {
        seen.push(new Request(input, init));
        return Promise.resolve(new Response(status === 204 ? null : 'ok', { status }));
      };
    const url = new URL('https://hooks.example.com/r2notary');
    await sendAlert(url, summary, fetcher(204));
    const req = seen[0];
    expect(req?.method).toBe('POST');
    expect(req?.headers.get('content-type')).toBe('application/json; charset=utf-8');
    expect(await req?.json()).toEqual(summary);
    await expect(sendAlert(url, summary, fetcher(500))).rejects.toThrow(AlertError);
  });
});

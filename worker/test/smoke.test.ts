import { env, exports } from 'cloudflare:workers';
import { describe, expect, it } from 'vitest';

describe('worker skeleton (runs inside workerd)', () => {
  it('serves the fetch handler', async () => {
    const res = await exports.default.fetch(new Request('https://example.com/'));
    expect(res.status).toBe(404);
  });

  it('reaches the SQLite-backed Sequencer DO over RPC', async () => {
    const stub = env.SEQUENCER.getByName('smoke');
    expect((await stub.status()).publishedSize).toBe(0);
  });

  it('has working R2 bindings for both buckets', async () => {
    await env.LOG.put('smoke', 'x');
    expect(await (await env.LOG.get('smoke'))?.text()).toBe('x');
    expect((await env.MONITORED.list()).objects).toEqual([]);
  });

  it('exposes config vars as strings', () => {
    expect(env.CHECKPOINT_INTERVAL_MS).toBe('5000');
    expect(env.MONITORED_BUCKET_NAME).not.toBe(env.LOG_BUCKET_NAME);
  });
});

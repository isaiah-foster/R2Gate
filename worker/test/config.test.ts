// Startup config validation (PLAN §5.4, §7): vars arrive as strings and are parsed once.
import { env } from 'cloudflare:workers';
import { describe, expect, it } from 'vitest';
import { ConfigError, parseConfig } from '../src/config.ts';

describe('parseConfig', () => {
  it('parses the committed wrangler.jsonc vars', () => {
    // The test pool overrides the audit vars (vitest.config.ts); these are the committed values.
    const committed = {
      ...env,
      AUDIT_GRACE_SECONDS: '300',
      DEEP_SCRUB_SAMPLE_RATE: '0',
      DEEP_SCRUB_MAX_BYTES: '104857600',
    };
    expect(parseConfig(committed)).toMatchObject({
      auditGraceSeconds: 300,
      deepScrubSampleRate: 0,
      deepScrubMaxBytes: 104_857_600,
      monitoredBucket: 'example-monitored-bucket',
      logBucket: 'example-log-bucket',
      checkpointIntervalMs: 5000,
      batchMaxEntries: 500,
      eventsDlqName: 'r2notary-events-dlq',
    });
  });

  it.each([
    ['monitoring the log bucket (I8)', { MONITORED_BUCKET_NAME: env.LOG_BUCKET_NAME }],
    ['an invalid bucket name', { LOG_BUCKET_NAME: 'Bad_Bucket' }],
    ['an origin with a scheme', { LOG_ORIGIN: 'https://example.com/log' }],
    ['a LOG_NAME with a slash', { LOG_NAME: 'a/b' }],
    ['a non-decimal interval', { CHECKPOINT_INTERVAL_MS: '5e3' }],
    ['a batch above 1,000', { BATCH_MAX_ENTRIES: '1001' }],
    ['an empty DLQ name', { EVENTS_DLQ_NAME: '' }],
    ['a DLQ name with spaces', { EVENTS_DLQ_NAME: 'my dlq' }],
    ['a grace window over a day', { AUDIT_GRACE_SECONDS: '86401' }],
    ['a negative grace window', { AUDIT_GRACE_SECONDS: '-1' }],
    ['a sample rate above 1', { DEEP_SCRUB_SAMPLE_RATE: '1.5' }],
    ['a sample rate in exponent form', { DEEP_SCRUB_SAMPLE_RATE: '1e-3' }],
    ['a sample rate with a leading dot', { DEEP_SCRUB_SAMPLE_RATE: '.5' }],
    ['a fractional byte limit', { DEEP_SCRUB_MAX_BYTES: '1.5' }],
  ])('rejects %s', (_, override) => {
    expect(() => parseConfig({ ...env, ...override })).toThrow(ConfigError);
  });
});

it('accepts sample rates written as decimals', () => {
  for (const [v, want] of [
    ['0', 0],
    ['0.01', 0.01],
    ['1', 1],
    ['1.000', 1],
  ] as const) {
    expect(parseConfig({ ...env, DEEP_SCRUB_SAMPLE_RATE: v }).deepScrubSampleRate).toBe(want);
  }
});

describe('WITNESSES and WITNESS_QUORUM (M8)', () => {
  // A cosigner key (type 0x04) and a log key (type 0x01), both fixed test data.
  const W = 'witness.example.com/vector+416f103d+BK/QmJFVP3SKJOqAMhFxBQPtylo3sjwWibyFDAlZKK8B';
  const LOGKEY = 'example.com/vector-log+4516a1da+ARGkVJ4QEa2MOOLGBO6i7NVSJ1FQ97tIX+w+Ku0RZ6Em';
  const one = (o: Record<string, unknown>) => JSON.stringify([o]);

  it('defaults to no witnesses', () => {
    expect(parseConfig(env)).toMatchObject({ witnesses: [], witnessQuorum: 0 });
  });

  it('parses witnesses and drops a trailing slash from the URL', () => {
    const c = parseConfig({
      ...env,
      WITNESSES: one({ vkey: W, url: 'https://witness.example.com/w1/' }),
      WITNESS_QUORUM: '1',
    });
    expect(c.witnesses).toEqual([{ vkey: W, url: 'https://witness.example.com/w1' }]);
    expect(c.witnessQuorum).toBe(1);
    // A witness running locally under wrangler dev.
    const local = parseConfig({
      ...env,
      WITNESSES: one({ vkey: W, url: 'http://127.0.0.1:8788' }),
    });
    expect(local.witnesses[0]?.url).toBe('http://127.0.0.1:8788');
  });

  it.each([
    ['not JSON', { WITNESSES: 'nope' }],
    ['an object', { WITNESSES: '{}' }],
    [
      'a log key instead of a cosigner key',
      { WITNESSES: one({ vkey: LOGKEY, url: 'https://w.example' }) },
    ],
    ['a malformed key', { WITNESSES: one({ vkey: 'w+123+abc', url: 'https://w.example' }) }],
    ['plain http to a remote host', { WITNESSES: one({ vkey: W, url: 'http://w.example' }) }],
    ['a URL with a query', { WITNESSES: one({ vkey: W, url: 'https://w.example/?a=1' }) }],
    ['an unknown field', { WITNESSES: one({ vkey: W, url: 'https://w.example', x: 1 }) }],
    [
      'the same witness twice',
      {
        WITNESSES: JSON.stringify([
          { vkey: W, url: 'https://a.example' },
          { vkey: W, url: 'https://b.example' },
        ]),
      },
    ],
    ['a quorum above the number of witnesses', { WITNESS_QUORUM: '1' }],
  ])('rejects %s', (_, override) => {
    expect(() => parseConfig({ ...env, ...override })).toThrow(ConfigError);
  });
});

// Startup config validation (PLAN §5.4, §7): vars arrive as strings and are parsed once.
import { env } from 'cloudflare:workers';
import { describe, expect, it } from 'vitest';
import { ConfigError, parseConfig } from '../src/config.ts';

describe('parseConfig', () => {
  it('parses the committed wrangler.jsonc vars', () => {
    expect(parseConfig(env)).toMatchObject({
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
  ])('rejects %s', (_, override) => {
    expect(() => parseConfig({ ...env, ...override })).toThrow(ConfigError);
  });
});

import { generateCosignerKey, generateKey } from '@r2notary/core';
import { cloudflareTest } from '@cloudflare/vitest-plugin';
import { defineProject } from 'vitest/config';

// Fresh keys per run, so nothing secret is committed: the witness's own key (a required secret,
// read from process.env), and a log key the witness is configured to trust. Tests sign
// checkpoints with TEST_LOG_KEY and verify cosignatures with TEST_WITNESS_VKEY.
const ORIGIN = 'r2notary.example.com/log/example-log';
const log = await generateKey(ORIGIN);
const witness = await generateCosignerKey('witness.example.com/test');
process.env.WITNESS_KEY = witness.skey;

export default defineProject({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: './wrangler.jsonc' },
      miniflare: {
        bindings: {
          WITNESS_LOGS: JSON.stringify([{ origin: ORIGIN, vkeys: [log.vkey] }]),
          TEST_ORIGIN: ORIGIN,
          TEST_LOG_KEY: log.skey,
          TEST_WITNESS_VKEY: witness.vkey,
        },
      },
    }),
  ],
  test: {
    name: 'witness',
    include: ['test/**/*.test.ts'],
  },
});

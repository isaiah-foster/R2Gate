import { generateKey } from '@r2notary/core';
import { cloudflareTest } from '@cloudflare/vitest-plugin';
import { defineProject } from 'vitest/config';

// Benchmarks that run inside workerd (bench/amplification.ts drives this). Not part of `npm test`:
// the root vitest config lists only the core and worker test projects. Secrets as in
// vitest.config.ts: generated per run, never committed.
process.env.SIGNING_KEY = (await generateKey('r2notary.example.com/log/example-log')).skey;
const token = (): string =>
  Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('base64url');
process.env.ADMIN_TOKEN = token();
process.env.READ_TOKEN = token();

export default defineProject({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: './wrangler.jsonc' },
      // Publication sizes to measure, as a binding (the Worker has no nodejs_compat, and the bench
      // should run with the same flags as production).
      miniflare: {
        bindings: { BENCH_SIZES: process.env.BENCH_SIZES ?? '1,2,5,10,20,50,100,200,500' },
      },
    }),
  ],
  test: {
    name: 'worker-bench',
    root: import.meta.dirname,
    include: ['bench/**/*.bench.ts'],
  },
});

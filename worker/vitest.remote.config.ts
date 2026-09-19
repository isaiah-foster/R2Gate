import { cloudflareTest } from '@cloudflare/vitest-plugin';
import { defineProject } from 'vitest/config';

// Opt-in project for the R2 contract test on real R2. Not part of `npm test` (the root config
// lists only the default worker project). R2_CONTRACT_LOCAL=1 disables remote bindings so the
// harness itself can be checked without touching Cloudflare.
export default defineProject({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: './test-remote/wrangler.remote.jsonc' },
      remoteBindings: process.env.R2_CONTRACT_LOCAL !== '1',
    }),
  ],
  test: {
    name: 'worker-remote-contract',
    root: import.meta.dirname,
    include: ['test-remote/**/*.remote.test.ts'],
  },
});

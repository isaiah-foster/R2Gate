import { generateKey } from '@r2notary/core';
import { cloudflareTest } from '@cloudflare/vitest-plugin';
import { defineProject } from 'vitest/config';

// A fresh signing key and fresh tokens per test run, so no secrets live in the repo. Wrangler reads
// required secrets from process.env when there is no .dev.vars. Tests get the verifier key from the
// signer (`newSigner(env.SIGNING_KEY).vkey`). The name must equal LOG_ORIGIN in wrangler.jsonc.
process.env.SIGNING_KEY = (await generateKey('r2notary.example.com/log/example-log')).skey;
const token = (): string =>
  Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('base64url');
process.env.ADMIN_TOKEN = token();
process.env.READ_TOKEN = token();

export default defineProject({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: './wrangler.jsonc' },
      // The auditor's end-to-end tests cannot wait out a real grace window (the clock only moves
      // with I/O), and should exercise deep scrub. Unit tests pass both values explicitly.
      miniflare: { bindings: { AUDIT_GRACE_SECONDS: '0', DEEP_SCRUB_SAMPLE_RATE: '1' } },
    }),
  ],
  test: {
    name: 'worker',
    include: ['test/**/*.test.ts'],
  },
});

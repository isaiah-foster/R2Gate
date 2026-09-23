// Generates r2notary's secrets (PLAN §5.5, M4): an Ed25519 note signing key named after the log's
// origin, plus ADMIN_TOKEN and READ_TOKEN, in `.dev.vars` format. The verifier key (public) is
// printed to stderr and kept as a comment in the output.
//
//   npm run keygen -- --origin r2notary.example.com/log/example-log --out worker/.dev.vars
//   npm run keygen -- --origin <origin>            # print to stdout instead
//
// Remotely, put each value with `wrangler secret put` (docs/OPERATIONS.md). The output is secret:
// `.dev.vars` is gitignored, and --out refuses to overwrite a file and creates it mode 0600.

import { writeFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { generateKey, validateOrigin } from '../packages/core/src/index.ts';

const { values } = parseArgs({
  options: {
    origin: { type: 'string' },
    out: { type: 'string' },
    help: { type: 'boolean', default: false },
  },
});

if (values.help || values.origin === undefined) {
  console.error('usage: keygen --origin <LOG_ORIGIN> [--out FILE]');
  process.exit(values.help ? 0 : 2);
}

function fail(message: string): never {
  console.error(`keygen: ${message}`);
  process.exit(1);
}

const origin = values.origin;
try {
  validateOrigin(origin); // the key name must equal LOG_ORIGIN (DECISIONS D1.10)
} catch (e) {
  fail(`--origin: ${e instanceof Error ? e.message : String(e)}`);
}

/** 32 random bytes, base64url: 43 characters, inside the RFC 6750 token alphabet. */
const token = (): string =>
  Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('base64url');

const key = await generateKey(origin);
const out = [
  `# r2notary secrets for ${origin}, generated ${new Date().toISOString()}. Keep secret.`,
  `# Verifier key (public: give it to clients and the Go CLI):`,
  `# ${key.vkey}`,
  `SIGNING_KEY=${key.skey}`,
  `ADMIN_TOKEN=${token()}`,
  `READ_TOKEN=${token()}`,
  '',
].join('\n');

if (values.out === undefined) {
  process.stdout.write(out);
} else {
  try {
    writeFileSync(values.out, out, { flag: 'wx', mode: 0o600 }); // wx: fail if it exists
  } catch (e) {
    fail(
      (e as { code?: unknown }).code === 'EEXIST'
        ? `${values.out} exists; not overwriting secrets`
        : String(e),
    );
  }
  console.error(`wrote ${values.out}`);
}
console.error(`vkey: ${key.vkey}`);

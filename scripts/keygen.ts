// Generates r2notary's secrets (PLAN §5.5, M4): an Ed25519 note signing key named after the log's
// origin, plus ADMIN_TOKEN and READ_TOKEN, in `.dev.vars` format. The verifier key (public) is
// printed to stderr and kept as a comment in the output.
//
//   npm run keygen -- --origin r2notary.example.com/log/example-log --out worker/.dev.vars
//   npm run keygen -- --origin <origin>            # print to stdout instead
//   npm run keygen -- --origin <origin> --blind    # also KEY_BLINDING_KEY (M8 key blinding)
//   npm run keygen -- --witness witness.example.com/w1 --out witness/.dev.vars
//                                                  # a witness's cosigner key (M8): WITNESS_KEY
//
// Remotely, put each value with `wrangler secret put` (docs/OPERATIONS.md). The output is secret:
// `.dev.vars` is gitignored, and --out refuses to overwrite a file and creates it mode 0600.

import { writeFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import {
  generateCosignerKey,
  generateKey,
  isValidKeyName,
  validateOrigin,
} from '../packages/core/src/index.ts';

const { values } = parseArgs({
  options: {
    origin: { type: 'string' },
    witness: { type: 'string' },
    blind: { type: 'boolean', default: false },
    out: { type: 'string' },
    help: { type: 'boolean', default: false },
  },
});

if (values.help || (values.origin === undefined) === (values.witness === undefined)) {
  console.error(
    'usage: keygen --origin <LOG_ORIGIN> [--blind] [--out FILE]\n' +
      '       keygen --witness <WITNESS_NAME> [--out FILE]',
  );
  process.exit(values.help ? 0 : 2);
}

function fail(message: string): never {
  console.error(`keygen: ${message}`);
  process.exit(1);
}

/** 32 random bytes, base64url: 43 characters, inside the RFC 6750 token alphabet. */
const token = (): string =>
  Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('base64url');

async function logSecrets(origin: string): Promise<{ out: string; vkey: string }> {
  try {
    validateOrigin(origin); // the key name must equal LOG_ORIGIN (DECISIONS D1.10)
  } catch (e) {
    fail(`--origin: ${e instanceof Error ? e.message : String(e)}`);
  }
  const key = await generateKey(origin);
  const lines = [
    `# r2notary secrets for ${origin}, generated ${new Date().toISOString()}. Keep secret.`,
    `# Verifier key (public: give it to clients and the Go CLI):`,
    `# ${key.vkey}`,
    `SIGNING_KEY=${key.skey}`,
    `ADMIN_TOKEN=${token()}`,
    `READ_TOKEN=${token()}`,
  ];
  if (values.blind) {
    // Whoever holds it can test guesses of key names against the log: share it like a read token.
    lines.push('# Key blinding (M8): give this to readers who may locate entries by key name.');
    lines.push(`KEY_BLINDING_KEY=${token()}`);
  }
  return { out: `${lines.join('\n')}\n`, vkey: key.vkey };
}

async function witnessSecrets(name: string): Promise<{ out: string; vkey: string }> {
  if (!isValidKeyName(name)) fail('--witness: not a valid key name (no spaces or "+")');
  const key = await generateCosignerKey(name);
  const lines = [
    `# r2notary-witness key ${name}, generated ${new Date().toISOString()}. Keep secret.`,
    `# Cosigner verifier key (public: the log's WITNESSES and the CLI's --witness take it):`,
    `# ${key.vkey}`,
    `WITNESS_KEY=${key.skey}`,
  ];
  return { out: `${lines.join('\n')}\n`, vkey: key.vkey };
}

const { out, vkey } =
  values.witness === undefined
    ? await logSecrets(values.origin ?? '')
    : await witnessSecrets(values.witness);

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
console.error(`vkey: ${vkey}`);

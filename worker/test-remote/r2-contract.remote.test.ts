// The R2 conditional-write contract against a real bucket (DECISIONS D2.1). Opt-in only:
//   npm run test:contract:remote            (real R2; needs `wrangler login`; see docs/OPERATIONS.md)
//   R2_CONTRACT_LOCAL=1 npm run test:contract:remote   (same harness against local R2, no network)
import { env } from 'cloudflare:workers';
import { afterAll, describe } from 'vitest';
import { conditionalWriteContract } from '../test/contract/r2-conditional.ts';

const bucket = (): R2Bucket => (env as unknown as { CONTRACT: R2Bucket }).CONTRACT;
const prefix = `r2notary-contract/${String(Date.now())}`;

describe('R2 conditional-write contract (remote R2)', () => {
  conditionalWriteContract(bucket, prefix);

  afterAll(async () => {
    const listed = await bucket().list({ prefix: `${prefix}/` });
    await bucket().delete(listed.objects.map((o) => o.key));
  });
});

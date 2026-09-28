// The R2 contracts against a real bucket: conditional writes (DECISIONS D2.1) and list order /
// startAfter (D6.2). Opt-in only:
//   npm run test:contract:remote            (real R2; needs `wrangler login`; see docs/OPERATIONS.md)
//   R2_CONTRACT_LOCAL=1 npm run test:contract:remote   (same harness against local R2, no network)
import { env } from 'cloudflare:workers';
import { afterAll, describe } from 'vitest';
import { conditionalWriteContract } from '../test/contract/r2-conditional.ts';
import { listOrderContract } from '../test/contract/r2-list-order.ts';

const bucket = (): R2Bucket => (env as unknown as { CONTRACT: R2Bucket }).CONTRACT;
const prefix = `r2notary-contract/${String(Date.now())}`;

describe('R2 conditional-write contract (remote R2)', () => {
  conditionalWriteContract(bucket, prefix);
});

describe('R2 list order contract (remote R2)', () => {
  listOrderContract(bucket, `${prefix}/order`);
});

// Everything both contracts wrote (well under list()'s 1,000-key page).
afterAll(async () => {
  const listed = await bucket().list({ prefix: `${prefix}/` });
  await bucket().delete(listed.objects.map((o) => o.key));
});

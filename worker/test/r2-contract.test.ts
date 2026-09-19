import { env } from 'cloudflare:workers';
import { describe } from 'vitest';
import { conditionalWriteContract } from './contract/r2-conditional.ts';

describe('R2 conditional-write contract (local R2)', () => {
  conditionalWriteContract(() => env.LOG, 'contract');
});

// PLAN §14.3: R2 and Durable Object operations per entry, by entries per publication. Drives the
// workerd benchmark in worker/bench/amplification.bench.ts (see there for what is counted and how)
// and saves its counts with the environment.
//
//   npm run bench:amplification [-- --sizes 1,2,5,10,20,50,100,200,500]
//
// Mapping a checkpoint interval to entries per publication needs an arrival rate; bench/cost.ts
// does that explicitly. The counts here are per publication size, which is what the code controls.

import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { ROOT, environment, intList, writeResult } from './lib.ts';

const { values } = parseArgs({
  options: { sizes: { type: 'string', default: '1,2,5,10,20,50,100,200,500' } },
});
const sizes = intList(values.sizes);
if (sizes.some((k) => k > 500))
  throw new Error('sizes above BATCH_MAX_ENTRIES (500) are not one publication');

const tmp = mkdtempSync(join(tmpdir(), 'r2notary-bench-amp-'));
const report = join(tmp, 'report.json');
try {
  const code = await new Promise<number>((done, fail) => {
    const child = spawn(
      join(ROOT, 'node_modules/.bin/vitest'),
      [
        'run',
        '--config',
        'worker/vitest.bench.config.ts',
        '--reporter=json',
        `--outputFile=${report}`,
      ],
      { cwd: ROOT, stdio: 'inherit', env: { ...process.env, BENCH_SIZES: sizes.join(',') } },
    );
    child.on('error', fail);
    child.on('close', (c) => {
      done(c ?? -1);
    });
  });
  if (code !== 0) throw new Error(`vitest exited with ${String(code)}`);
  interface Report {
    testResults: {
      assertionResults: { title: string; status: string; meta: Record<string, unknown> }[];
    }[];
  }
  const r = JSON.parse(readFileSync(report, 'utf8')) as Report;
  const results = r.testResults
    .flatMap((f) => f.assertionResults)
    .map((a) => {
      if (a.status !== 'passed' || a.meta.amplification === undefined) {
        throw new Error(`${a.title}: ${a.status}`);
      }
      return a.meta.amplification;
    });
  writeResult('amplification', {
    benchmark: 'PLAN §14.3 R2 and Durable Object operation amplification',
    environment: environment(
      'workerd via @cloudflare/vitest-plugin (local DO SQLite and local R2); counts, not timings',
    ),
    config: {
      checkpointIntervalMs: 'n/a (each publication is triggered by running the alarm)',
      batchMaxEntries: 500,
      queueMaxBatchSize: 100,
      messages: 'PutObject notifications for new keys data/2026/10/03/object-<7 digits>.bin',
      classes:
        'R2 pricing page (2026-10-01): put, list = Class A; get, head = Class B; delete free',
      rows: 'sum of SqlStorageCursor rowsRead/rowsWritten; setAlarm counted separately (billed as one row written)',
    },
    results,
  });
} finally {
  rmSync(tmp, { recursive: true, force: true });
}

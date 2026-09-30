// PLAN §14.6: auditor throughput. Objects per second for a full audit (list + merge-join) and for
// a backfill, and deep-scrub throughput in MB/s. Runs the real Workflow, Worker and Sequencer under
// `wrangler dev` (the local Workflows engine, local R2 and DO SQLite) and times them from here.
//
//   npm run bench:auditor [-- --objects 10000 --runs 5 --scrub-objects 20 --scrub-mib 8]
//
//   1. audit: `objects` small objects are written to the local monitored bucket through the dev
//      simulator, with their notifications, so the log matches the bucket. Each audit is timed
//      from POST /api/v1/admin/scan to the scan's state being `done` (polled every 100 ms) and
//      must report no findings. AUDIT_GRACE_SECONDS=0, so no grace sleep is included.
//   2. backfill: the same number of objects written with no notifications, then one backfill.
//   3. deep scrub: `scrub-objects` objects of `scrub-mib` MiB each (one listing page; at most 20
//      bodies are hashed per page), audited with DEEP_SCRUB_SAMPLE_RATE=0 and then, on the same
//      persisted state, =1. MB/s = bytes hashed / (time with scrub - time without).
//
// Local R2 reads files from local disk; on Cloudflare a list or a body read is a network call.
// These are local figures only.

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { generateKey } from '../packages/core/src/index.ts';
import { randomToken, sleep, startDev, type DevServer } from '../scripts/lib/dev.ts';
import { environment, nowMs, round, summarize, writeResult } from './lib.ts';

const { values } = parseArgs({
  options: {
    objects: { type: 'string', default: '10000' },
    runs: { type: 'string', default: '5' },
    'scrub-objects': { type: 'string', default: '20' },
    'scrub-mib': { type: 'string', default: '8' },
  },
});
const OBJECTS = Number(values.objects);
const RUNS = Number(values.runs);
const SCRUB_OBJECTS = Number(values['scrub-objects']);
const SCRUB_BYTES = Number(values['scrub-mib']) * 2 ** 20;

const tmp = mkdtempSync(join(tmpdir(), 'r2notary-bench-auditor-'));
const readToken = randomToken();
const adminToken = randomToken();
const skey = (await generateKey('r2notary.example.com/log/example-log')).skey;
// Typed through `as`: TypeScript would otherwise narrow it to null in the finally block.
let dev = null as DevServer | null;

async function start(state: string, extra: Record<string, string>): Promise<DevServer> {
  dev = await startDev({
    dir: tmp,
    persistTo: join(tmp, state),
    readToken,
    vars: {
      SIGNING_KEY: skey,
      ADMIN_TOKEN: adminToken,
      READ_TOKEN: readToken,
      AUDIT_GRACE_SECONDS: '0',
      ...extra,
    },
  });
  return dev;
}

interface ScanView {
  scanId: string;
  state: string;
  pages: number;
  objectsScanned: number;
  findings: number;
  observations: number;
  snapshots: number;
}
interface Status {
  size: number;
  durableSize: number;
  pending: number;
  audit: ScanView | null;
  backfill: ScanView | null;
}

async function status(d: DevServer): Promise<Status> {
  const res = await fetch(`${d.base}/api/v1/status`, {
    headers: { authorization: `Bearer ${readToken}` },
  });
  return (await res.json()) as Status;
}

/** Writes objects through the simulator, 100 per request, 4 requests at a time. */
async function populate(
  d: DevServer,
  count: number,
  o: { prefix: string; size: number; notify: boolean },
): Promise<void> {
  const before = (await status(d)).durableSize;
  const per = 100;
  const requests = Array.from({ length: Math.ceil(count / per) }, (_, r) => r);
  const send = async (r: number): Promise<void> => {
    const ops = Array.from({ length: Math.min(per, count - r * per) }, (_, j) => ({
      op: 'put',
      key: `${o.prefix}${String(r * per + j).padStart(7, '0')}`,
      size: o.size,
      notify: o.notify,
    }));
    const res = await fetch(`${d.base}/__simulate/objects`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(ops),
    });
    if (!res.ok) throw new Error(`objects: HTTP ${String(res.status)} ${await res.text()}`);
  };
  for (let i = 0; i < requests.length; i += 4)
    await Promise.all(requests.slice(i, i + 4).map(send));
  if (!o.notify) return;
  // Wait until every notification is durable and published.
  for (let i = 0; ; i++) {
    const s = await status(d);
    if (s.durableSize >= before + count && s.pending === 0) return;
    if (i > 1200) throw new Error(`notifications not ingested: ${JSON.stringify(s)}`);
    await sleep(250);
  }
}

/** Starts a scan and waits for it to finish. Returns the elapsed ms and the final summary. */
async function scan(
  d: DevServer,
  op: 'scan' | 'backfill',
): Promise<{ ms: number; scan: ScanView }> {
  const t = nowMs();
  const res = await fetch(`${d.base}/api/v1/admin/${op}`, {
    method: 'POST',
    headers: { authorization: `Bearer ${adminToken}` },
  });
  if (res.status !== 202) throw new Error(`${op}: HTTP ${String(res.status)} ${await res.text()}`);
  const { scanId } = (await res.json()) as { scanId: string };
  for (;;) {
    const s = await status(d);
    const view = op === 'scan' ? s.audit : s.backfill;
    if (view?.scanId === scanId && view.state === 'done') return { ms: nowMs() - t, scan: view };
    if (view?.scanId === scanId && view.state !== 'listing' && view.state !== 'confirming') {
      if (view.state !== 'reporting') throw new Error(`${op} ${scanId}: ${view.state}`);
    }
    if (nowMs() - t > 30 * 60_000) throw new Error(`${op} ${scanId} did not finish`);
    await sleep(100);
  }
}

try {
  // 1. Audits of a bucket the log matches.
  let d = await start('state-audit', {});
  let t = nowMs();
  await populate(d, OBJECTS, { prefix: 'audit/object-', size: 1024, notify: true });
  console.log(
    `populated ${String(OBJECTS)} objects in ${String(round((nowMs() - t) / 1000, 1))} s`,
  );
  const audits: { ms: number; scan: ScanView }[] = [];
  for (let i = 0; i < RUNS; i++) {
    const r = await scan(d, 'scan');
    if (r.scan.findings !== 0 || r.scan.objectsScanned !== OBJECTS) {
      throw new Error(`unexpected audit result ${JSON.stringify(r.scan)}`);
    }
    audits.push(r);
    console.log(
      `audit ${String(i)}: ${String(round(r.ms / 1000, 2))} s, ${String(r.scan.pages)} pages`,
    );
  }
  d.stop();

  // 2. A backfill of objects the log has never seen.
  d = await start('state-backfill', {});
  await populate(d, OBJECTS, { prefix: 'backfill/object-', size: 1024, notify: false });
  const backfill = await scan(d, 'backfill');
  if (backfill.scan.snapshots !== OBJECTS)
    throw new Error(`backfill ${JSON.stringify(backfill.scan)}`);
  console.log(`backfill: ${String(round(backfill.ms / 1000, 2))} s`);
  d.stop();

  // 3. Deep scrub: the same objects audited without and with hashing their bodies.
  d = await start('state-scrub', { DEEP_SCRUB_SAMPLE_RATE: '0' });
  t = nowMs();
  await populate(d, SCRUB_OBJECTS, { prefix: 'scrub/object-', size: SCRUB_BYTES, notify: true });
  const plain: number[] = [];
  for (let i = 0; i < RUNS; i++) plain.push((await scan(d, 'scan')).ms);
  d.stop();
  d = await start('state-scrub', { DEEP_SCRUB_SAMPLE_RATE: '1' });
  const scrubbed: number[] = [];
  for (let i = 0; i < RUNS; i++) {
    const r = await scan(d, 'scan');
    if (r.scan.observations !== SCRUB_OBJECTS || r.scan.findings !== 0) {
      throw new Error(`unexpected scrub result ${JSON.stringify(r.scan)}`);
    }
    scrubbed.push(r.ms);
  }
  d.stop();
  const plainS = summarize(plain);
  const scrubS = summarize(scrubbed);
  const mb = (SCRUB_OBJECTS * SCRUB_BYTES) / 1e6;

  const auditS = summarize(audits.map((a) => a.ms));
  writeResult('auditor', {
    benchmark: 'PLAN §14.6 auditor throughput',
    environment: environment(
      'wrangler dev (local Workflows engine, workerd, DO SQLite, R2), timed from Node over localhost HTTP',
    ),
    config: {
      objects: OBJECTS,
      objectBytes: 1024,
      runs: RUNS,
      pageSize: 1000,
      auditGraceSeconds: 0,
      timing:
        'POST /api/v1/admin/{scan,backfill} until the scan state is done, polled every 100 ms',
    },
    audit: {
      objects: OBJECTS,
      pages: audits[0]?.scan.pages,
      ms: auditS,
      objectsPerSecondAtMedian: Math.round((OBJECTS / auditS.median) * 1000),
    },
    backfill: {
      objects: OBJECTS,
      pages: backfill.scan.pages,
      ms: round(backfill.ms),
      objectsPerSecond: Math.round((OBJECTS / backfill.ms) * 1000),
    },
    deepScrub: {
      objects: SCRUB_OBJECTS,
      bytesPerObject: SCRUB_BYTES,
      auditWithoutScrubMs: plainS,
      auditWithScrubMs: scrubS,
      megabytesPerSecondAtMedians: round(mb / ((scrubS.median - plainS.median) / 1000), 1),
    },
  });
} finally {
  dev?.stop();
  rmSync(tmp, { recursive: true, force: true });
}

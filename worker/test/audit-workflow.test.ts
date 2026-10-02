// The real ScanWorkflow class under the local Workflows engine: started directly, from the admin
// API and from the cron trigger, with a step failure injected to exercise the engine's retry.
// The test pool sets AUDIT_GRACE_SECONDS=0 and DEEP_SCRUB_SAMPLE_RATE=1 (vitest.config.ts).
import { decodeEntry } from '@r2notary/core';
import { env } from 'cloudflare:workers';
import { introspectWorkflow, introspectWorkflowInstance, reset } from 'cloudflare:test';
import { afterEach, describe, expect, it } from 'vitest';
import worker from '../src/index.ts';
import { objectEvent, publishedEntries, putObject } from './helpers.ts';

afterEach(() => reset());

const LOG = env.LOG_NAME;
const OLD = '2026-01-01T00:00:00.000Z';

/** One object logged correctly, one never logged, one logged but gone. */
async function seed(): Promise<void> {
  const etag = (await putObject(env.MONITORED, 'kept', 'kept')).etag;
  await env.MONITORED.put('sneaky', 'sneaky');
  const s = env.SEQUENCER.getByName(LOG);
  await s.append([
    { eventId: 'a', entry: objectEvent(0, { key: 'kept', etag, size: 4, eventTime: OLD }) },
    {
      eventId: 'b',
      entry: objectEvent(1, { key: 'vanished', etag: 'v', size: 1, eventTime: OLD }),
    },
  ]);
  await s.publish();
}

function call(path: string, method = 'GET', token: string = env.ADMIN_TOKEN): Promise<Response> {
  return worker.fetch(
    new Request(`https://r2notary.example.com${path}`, {
      method,
      headers: { authorization: `Bearer ${token}` },
    }),
    env,
  );
}

describe('ScanWorkflow', () => {
  it('runs an audit to completion and survives a failed step (engine retry)', async () => {
    await seed();
    await using instance = await introspectWorkflowInstance(env.SCAN_WORKFLOW, 'wf-audit-1');
    await instance.modify(async (m) => {
      await m.disableSleeps();
      await m.disableRetryDelays();
      await m.mockStepError({ name: 'page-0' }, new Error('transient R2 failure'), 1);
    });
    await env.SCAN_WORKFLOW.create({
      id: 'wf-audit-1',
      params: { scanId: 'wf-audit-1', mode: 'audit', part: 0 },
    });
    await instance.waitForStatus('complete');
    expect(await instance.getOutput()).toEqual({
      scanId: 'wf-audit-1',
      part: 0,
      status: 'done',
      objectsScanned: 2,
      findings: 2,
      reportKey: `${LOG}/x-reports/wf-audit-1.json`,
    });
    const kinds = (await publishedEntries(LOG))
      .map((b) => decodeEntry(b))
      .flatMap((d) =>
        d.known && d.entry.type === 'audit.finding'
          ? [`${d.entry.kind} ${String(d.entry.key)}`]
          : [],
      );
    expect(kinds.sort()).toEqual(['MISSING_OBJECT vanished', 'UNLOGGED_OBJECT sneaky']);
  });

  it('fails without retrying on parameters it did not create', async () => {
    await using instance = await introspectWorkflowInstance(env.SCAN_WORKFLOW, 'wf-bad');
    await env.SCAN_WORKFLOW.create({
      id: 'wf-bad',
      params: { scanId: 'bad/id', mode: 'audit', part: 0 },
    });
    await instance.waitForStatus('errored');
    // The engine replaces the reason with a generic message; the reason goes to the logs.
    expect((await instance.getError()).message).toMatch(/NonRetryableError/);
  });
});

describe('starting scans', () => {
  it('POST /api/v1/admin/scan starts an audit; findings and status show it', async () => {
    await seed();
    await using wf = await introspectWorkflow(env.SCAN_WORKFLOW);
    await wf.modifyAll(async (m) => {
      await m.disableSleeps();
    });
    const res = await call('/api/v1/admin/scan', 'POST');
    expect(res.status).toBe(202);
    const { scanId } = await res.json<{ scanId: string }>();
    expect(scanId).toMatch(/^audit-\d+-[0-9a-f]{8}$/);
    const [instance] = await wf.get();
    await instance?.waitForStatus('complete');

    const findings = await (
      await call('/api/v1/findings', 'GET', env.READ_TOKEN)
    ).json<{
      scan: { scanId: string; state: string; findings: number; endIndex: number };
      size: number;
      findings: { index: number; published: boolean; entry: { kind: string; scanId: string } }[];
      next: number | null;
    }>();
    expect(findings.scan).toMatchObject({ scanId, state: 'done', findings: 2 });
    expect(findings.scan).not.toHaveProperty('cursor'); // a key name; not shown
    expect(findings.findings.map((f) => f.entry.kind).sort()).toEqual([
      'MISSING_OBJECT',
      'UNLOGGED_OBJECT',
    ]);
    expect(findings.findings.every((f) => f.published && f.entry.scanId === scanId)).toBe(true);
    expect(findings.next).toBeNull();

    // Paging: one at a time, with a cursor.
    const first = await (
      await call('/api/v1/findings?limit=1', 'GET', env.READ_TOKEN)
    ).json<{
      findings: { index: number }[];
      next: number | null;
    }>();
    expect(first.findings).toHaveLength(1);
    expect(first.next).toBe(first.findings[0]?.index);

    const status = await (
      await call('/api/v1/status', 'GET', env.READ_TOKEN)
    ).json<{
      audit: { scanId: string; state: string; objectsScanned: number };
    }>();
    expect(status.audit).toMatchObject({ scanId, state: 'done', objectsScanned: 2 });
  });

  it('POST /api/v1/admin/backfill starts a backfill', async () => {
    await seed();
    await using wf = await introspectWorkflow(env.SCAN_WORKFLOW);
    const res = await call('/api/v1/admin/backfill', 'POST');
    expect(res.status).toBe(202);
    const { scanId } = await res.json<{ scanId: string }>();
    const [instance] = await wf.get();
    await instance?.waitForStatus('complete');
    expect(await instance?.getOutput()).toMatchObject({ status: 'done', findings: 0 });
    // /status shows the latest backfill apart from the latest audit (M7).
    const status = await (
      await call('/api/v1/status', 'GET', env.READ_TOKEN)
    ).json<{ audit: unknown; backfill: { scanId: string; state: string; mode: string } }>();
    expect(status.backfill).toMatchObject({ scanId, state: 'done', mode: 'backfill' });
    expect(status.audit).toBeNull();
  });

  it('the cron trigger starts one audit per scheduled time', async () => {
    await seed();
    const scheduledTime = Date.parse('2026-10-02T18:00:00Z');
    await using instance = await introspectWorkflowInstance(
      env.SCAN_WORKFLOW,
      `audit-cron-${String(scheduledTime)}`,
    );
    await instance.modify(async (m) => {
      await m.disableSleeps();
    });
    const controller = { scheduledTime, cron: '0 */6 * * *', noRetry: () => undefined };
    for (let i = 0; i < 2; i++) {
      // Delivered twice: createBatch is idempotent per instance ID.
      await worker.scheduled(controller, env);
    }
    await instance.waitForStatus('complete');
    expect(await instance.getOutput()).toMatchObject({ status: 'done', findings: 2 });
  });
});

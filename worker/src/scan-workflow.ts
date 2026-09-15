import { WorkflowEntrypoint, type WorkflowEvent, type WorkflowStep } from 'cloudflare:workers';

/** Resumable bucket scan (M6). Skeleton only, so the `SCAN_WORKFLOW` binding resolves. */
export class ScanWorkflow extends WorkflowEntrypoint<Env> {
  override async run(_event: WorkflowEvent<unknown>, step: WorkflowStep): Promise<void> {
    await step.do('noop', () => Promise.resolve());
  }
}

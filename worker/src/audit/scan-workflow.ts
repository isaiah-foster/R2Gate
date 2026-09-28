// The auditor as a Cloudflare Workflow (PLAN §5.6): `runScan` with this instance's step API, the
// monitored bucket, and the Sequencer that holds the scan's state.

import { WorkflowEntrypoint, type WorkflowEvent, type WorkflowStep } from 'cloudflare:workers';
import { parseConfig } from '../config.ts';
import { parseWebhookUrl, sendAlert } from './alert.ts';
import {
  DEFAULT_BUDGET,
  instanceId,
  parseScanParams,
  runScan,
  type ScanOutcome,
  type ScanParams,
  type StepLike,
} from './scan.ts';
import { MAX_PAGE_OBJECTS } from './store.ts';

/** ALERT_WEBHOOK_URL is an optional secret, so `wrangler types` does not declare it. */
interface OptionalSecrets {
  readonly ALERT_WEBHOOK_URL?: string;
}

export class ScanWorkflow extends WorkflowEntrypoint<Env, ScanParams> {
  override async run(
    event: Readonly<WorkflowEvent<ScanParams>>,
    step: WorkflowStep,
  ): Promise<ScanOutcome> {
    const cfg = parseConfig(this.env);
    const params = parseScanParams(event.payload);
    const webhook = parseWebhookUrl((this.env as OptionalSecrets).ALERT_WEBHOOK_URL);
    // WorkflowStep.do constrains results to Rpc.Serializable, which the generic StepLike cannot
    // express; every step in runScan returns a plain object, string or boolean. `step` is an RPC
    // stub, so its methods are called on it directly (not bound or detached).
    const typed = step as unknown as { do: StepLike['do'] };
    const steps: StepLike = {
      do: (name, config, fn) => typed.do(name, config, fn),
      sleep: (name, ms) => step.sleep(name, ms),
    };
    return runScan(params, steps, {
      sequencer: this.env.SEQUENCER.getByName(cfg.logName),
      bucket: this.env.MONITORED,
      continueIn: async (next) => {
        // createBatch, unlike create, is idempotent for an ID already in use: this step may run twice.
        await this.env.SCAN_WORKFLOW.createBatch([{ id: instanceId(next), params: next }]);
      },
      alert: webhook === null ? null : (summary) => sendAlert(webhook, summary),
      origin: cfg.logOrigin,
      scrubRate: cfg.deepScrubSampleRate,
      scrubMaxBytes: cfg.deepScrubMaxBytes,
      pageSize: MAX_PAGE_OBJECTS,
      budget: DEFAULT_BUDGET,
      now: Date.now,
    });
  }
}

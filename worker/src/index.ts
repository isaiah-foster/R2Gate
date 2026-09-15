export { Sequencer } from './sequencer.ts';
export { ScanWorkflow } from './scan-workflow.ts';

export default {
  fetch(): Response {
    return new Response('r2notary: not implemented yet\n', {
      status: 501,
      headers: { 'content-type': 'text/plain; charset=utf-8' },
    });
  },

  // Real consumer lands in M3. Until then, retry so nothing is silently dropped.
  queue(batch): void {
    batch.retryAll();
  },
} satisfies ExportedHandler<Env>;

// Dev-only producer for local end-to-end runs (never deployed). Local R2 emits no event
// notifications, so `scripts/simulate-events.ts` POSTs synthetic ones here and this Worker puts
// them on the local `r2notary-events` queue, which the r2notary Worker consumes. Every other
// request is forwarded to r2notary, so its routes are reachable on the same port.
//
//   npm run dev:sim       # this Worker (primary, port 8787) + r2notary, one wrangler process

interface SimulatorEnv {
  readonly EVENTS: Queue;
  readonly R2NOTARY: Fetcher;
}

// Also in scripts/simulate-events.ts. Not exported: a Worker module may only export handlers.
const SEND_PATH = '/__simulate/send';
/** Queues accept at most 100 messages per sendBatch call. */
const MAX_BATCH = 100;

export default {
  async fetch(request: Request, env: SimulatorEnv): Promise<Response> {
    if (new URL(request.url).pathname !== SEND_PATH) return env.R2NOTARY.fetch(request);
    if (request.method !== 'POST') return new Response('POST a JSON array\n', { status: 405 });
    const bodies: unknown = await request.json();
    if (!Array.isArray(bodies) || bodies.length === 0 || bodies.length > MAX_BATCH) {
      return new Response(`expected a JSON array of 1-${String(MAX_BATCH)} messages\n`, {
        status: 400,
      });
    }
    await env.EVENTS.sendBatch(bodies.map((body: unknown) => ({ body, contentType: 'json' })));
    return Response.json({ sent: bodies.length });
  },
};

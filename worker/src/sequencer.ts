import { DurableObject } from 'cloudflare:workers';

/**
 * Single-writer sequencer, one instance per log (M2). Skeleton only: it exists so the
 * wrangler config and the Workers test pool have a real SQLite-backed class to bind.
 */
export class Sequencer extends DurableObject<Env> {
  /** Placeholder RPC used by the M0 smoke test; replaced by `status()` in M2. */
  ping(): string {
    return 'sequencer';
  }
}

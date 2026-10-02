// Constants shared with tests. Not in index.ts: a Worker's main module may export only handlers
// and classes (workerd refuses a plain constant, which tests do not notice).

/** Generous: a checkpoint, 63 proof lines and a hundred signature lines are a few tens of KB. */
export const MAX_BODY_BYTES = 256 * 1024;

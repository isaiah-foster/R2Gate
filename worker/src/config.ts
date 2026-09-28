// Configuration. Vars arrive from wrangler as strings; they are parsed and validated once, so a bad
// deployment fails at startup instead of on the first event.

import { validateOrigin } from '@r2notary/core';

export class ConfigError extends Error {
  override name = 'ConfigError';
}

export interface Config {
  /** Prefix of every log resource in the log bucket (`<logName>/checkpoint`, ...). */
  readonly logName: string;
  /** Checkpoint origin and signing key name: scheme-less, no trailing slash. */
  readonly logOrigin: string;
  readonly monitoredBucket: string;
  readonly logBucket: string;
  readonly checkpointIntervalMs: number;
  readonly batchMaxEntries: number;
  readonly dedupeTtlSeconds: number;
  /** Name of the dead-letter queue, so its batches can be counted (`batch.queue`). */
  readonly eventsDlqName: string;
  /** How long an observation must stay unexplained by an event before it is a finding (M6). */
  readonly auditGraceSeconds: number;
  /** Fraction of listed objects (0..1) whose bodies the auditor hashes (deep scrub). */
  readonly deepScrubSampleRate: number;
  /** Objects larger than this are never deep-scrubbed. */
  readonly deepScrubMaxBytes: number;
}

type ConfigVars = Record<
  | 'LOG_NAME'
  | 'LOG_ORIGIN'
  | 'MONITORED_BUCKET_NAME'
  | 'LOG_BUCKET_NAME'
  | 'CHECKPOINT_INTERVAL_MS'
  | 'BATCH_MAX_ENTRIES'
  | 'DEDUPE_TTL_SECONDS'
  | 'EVENTS_DLQ_NAME'
  | 'AUDIT_GRACE_SECONDS'
  | 'DEEP_SCRUB_SAMPLE_RATE'
  | 'DEEP_SCRUB_MAX_BYTES',
  string
>;

// Becomes an R2 key prefix and a URL path segment (/log/<name>/...), so keep it plain.
const LOG_NAME_RE = /^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/;
// R2 bucket naming rules (same as the entry schema).
const BUCKET_RE = /^[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])$/;
// Only compared with `batch.queue`, so this checks that it is a plausible name, not the full rules.
const QUEUE_RE = /^[A-Za-z0-9_-]{1,63}$/;

function int(name: string, value: string, min: number, max: number): number {
  if (!/^(?:0|[1-9]\d*)$/.test(value)) throw new ConfigError(`${name} must be a decimal integer`);
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < min || n > max) {
    throw new ConfigError(`${name} must be between ${String(min)} and ${String(max)}`);
  }
  return n;
}

/** A decimal fraction in [0, 1] with at most 6 decimals ("0", "0.01", "1"). */
function fraction(name: string, value: string): number {
  if (!/^(?:0(?:\.\d{1,6})?|1(?:\.0{1,6})?)$/.test(value)) {
    throw new ConfigError(`${name} must be a decimal between 0 and 1 (at most 6 decimals)`);
  }
  return Number(value);
}

export function parseConfig(vars: ConfigVars): Config {
  if (!LOG_NAME_RE.test(vars.LOG_NAME)) {
    throw new ConfigError('LOG_NAME must be 1-64 of [a-z0-9._-], starting and ending alphanumeric');
  }
  try {
    validateOrigin(vars.LOG_ORIGIN);
  } catch (e) {
    throw new ConfigError(`LOG_ORIGIN: ${e instanceof Error ? e.message : String(e)}`);
  }
  for (const k of ['MONITORED_BUCKET_NAME', 'LOG_BUCKET_NAME'] as const) {
    if (!BUCKET_RE.test(vars[k])) throw new ConfigError(`${k} is not a valid R2 bucket name`);
  }
  // Monitoring the log bucket would log the log's own writes forever (PLAN §11.10).
  if (vars.MONITORED_BUCKET_NAME === vars.LOG_BUCKET_NAME) {
    throw new ConfigError('MONITORED_BUCKET_NAME must differ from LOG_BUCKET_NAME');
  }
  if (!QUEUE_RE.test(vars.EVENTS_DLQ_NAME)) {
    throw new ConfigError('EVENTS_DLQ_NAME must be 1-63 of [A-Za-z0-9_-]');
  }
  return {
    logName: vars.LOG_NAME,
    logOrigin: vars.LOG_ORIGIN,
    monitoredBucket: vars.MONITORED_BUCKET_NAME,
    logBucket: vars.LOG_BUCKET_NAME,
    checkpointIntervalMs: int(
      'CHECKPOINT_INTERVAL_MS',
      vars.CHECKPOINT_INTERVAL_MS,
      100,
      3_600_000,
    ),
    // One publish holds its batch in memory; entries are at most 64 KiB.
    batchMaxEntries: int('BATCH_MAX_ENTRIES', vars.BATCH_MAX_ENTRIES, 1, 1000),
    dedupeTtlSeconds: int('DEDUPE_TTL_SECONDS', vars.DEDUPE_TTL_SECONDS, 60, 30 * 86_400),
    eventsDlqName: vars.EVENTS_DLQ_NAME,
    // 0 is allowed (tests use it); a day is far beyond any plausible notification delay.
    auditGraceSeconds: int('AUDIT_GRACE_SECONDS', vars.AUDIT_GRACE_SECONDS, 0, 86_400),
    deepScrubSampleRate: fraction('DEEP_SCRUB_SAMPLE_RATE', vars.DEEP_SCRUB_SAMPLE_RATE),
    deepScrubMaxBytes: int('DEEP_SCRUB_MAX_BYTES', vars.DEEP_SCRUB_MAX_BYTES, 0, 2 ** 40),
  };
}

// Configuration. Vars arrive from wrangler as strings; they are parsed and validated once, so a bad
// deployment fails at startup instead of on the first event.

import {
  SIG_TYPE_COSIGNATURE_V1,
  fromBase64,
  isValidKeyName,
  validateOrigin,
} from '@r2notary/core';

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
  /** Witnesses asked to cosign each checkpoint (C2SP tlog-witness, M8); empty: none. */
  readonly witnesses: readonly WitnessEndpoint[];
  /** Cosignatures a checkpoint needs before it is published (0: best effort). */
  readonly witnessQuorum: number;
  /**
   * Key blinding (M8): entries name objects by keyHmac, never by key. Fixed for the life of a log;
   * the secret (KEY_BLINDING_KEY) is read separately, by blinding.ts.
   */
  readonly keyBlinding: boolean;
}

export interface WitnessEndpoint {
  /** The witness's cosigner key (C2SP vkey, signature type 0x04). */
  readonly vkey: string;
  /** Its submission prefix: `<url>/add-checkpoint` is posted to. No trailing slash. */
  readonly url: string;
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
  | 'DEEP_SCRUB_MAX_BYTES'
  | 'WITNESSES'
  | 'WITNESS_QUORUM'
  | 'KEY_BLINDING',
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

function bool(name: string, value: string): boolean {
  if (value !== 'true' && value !== 'false')
    throw new ConfigError(`${name} must be "true" or "false"`);
  return value === 'true';
}

/** A decimal fraction in [0, 1] with at most 6 decimals ("0", "0.01", "1"). */
function fraction(name: string, value: string): number {
  if (!/^(?:0(?:\.\d{1,6})?|1(?:\.0{1,6})?)$/.test(value)) {
    throw new ConfigError(`${name} must be a decimal between 0 and 1 (at most 6 decimals)`);
  }
  return Number(value);
}

/** Hosts a witness may be reached on over plain http: a witness run locally (`wrangler dev`). */
const LOCAL_HOSTS = ['localhost', '127.0.0.1', '[::1]'];
const VKEY_RE = /^([^+\s]+)\+[0-9a-f]{8}\+([A-Za-z0-9+/]+=*)$/u;

/**
 * WITNESSES: a JSON array of {"vkey": "<cosigner vkey>", "url": "https://<submission prefix>"}.
 * The key's ID is checked when it is loaded (the Sequencer, asynchronously); here its shape, type
 * byte and length. Plain http is allowed only for a local witness.
 */
export function parseWitnesses(json: string): WitnessEndpoint[] {
  let value: unknown;
  try {
    value = JSON.parse(json);
  } catch {
    throw new ConfigError('WITNESSES is not JSON');
  }
  if (!Array.isArray(value)) throw new ConfigError('WITNESSES must be a JSON array');
  const out: WitnessEndpoint[] = [];
  for (const [i, item] of (value as unknown[]).entries()) {
    const where = `WITNESSES[${String(i)}]`;
    if (typeof item !== 'object' || item === null || Array.isArray(item)) {
      throw new ConfigError(`${where} must be an object`);
    }
    const o = item as Record<string, unknown>;
    for (const k of Object.keys(o)) {
      if (k !== 'vkey' && k !== 'url') throw new ConfigError(`${where}.${k} is not known`);
    }
    const m = typeof o.vkey === 'string' ? VKEY_RE.exec(o.vkey) : null;
    let typed: Uint8Array | null;
    try {
      typed = m?.[2] === undefined ? null : fromBase64(m[2]);
    } catch {
      typed = null;
    }
    if (
      m?.[1] === undefined ||
      !isValidKeyName(m[1]) ||
      typed?.length !== 33 ||
      typed[0] !== SIG_TYPE_COSIGNATURE_V1
    ) {
      throw new ConfigError(`${where}.vkey must be an Ed25519 cosigner key (type 0x04)`);
    }
    let url: URL;
    try {
      url = new URL(typeof o.url === 'string' ? o.url : '');
    } catch {
      throw new ConfigError(`${where}.url is not a URL`);
    }
    const local = url.protocol === 'http:' && LOCAL_HOSTS.includes(url.hostname);
    if ((url.protocol !== 'https:' && !local) || url.search !== '' || url.hash !== '') {
      throw new ConfigError(`${where}.url must be an https URL without a query`);
    }
    const vkey = m[0];
    if (out.some((w) => w.vkey === vkey)) throw new ConfigError(`${where}: witness listed twice`);
    out.push({ vkey, url: url.href.replace(/\/+$/, '') });
  }
  return out;
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
  const witnesses = parseWitnesses(vars.WITNESSES);
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
    witnesses,
    witnessQuorum: int('WITNESS_QUORUM', vars.WITNESS_QUORUM, 0, witnesses.length),
    keyBlinding: bool('KEY_BLINDING', vars.KEY_BLINDING),
  };
}

// Witness configuration. WITNESS_LOGS arrives as a string (a JSON array) and is parsed once per
// Durable Object; a bad value fails every request loudly rather than cosigning for the wrong keys.

import { newVerifier, utf8Encode, type NoteVerifier } from '@r2notary/core';

export class ConfigError extends Error {
  override name = 'ConfigError';
}

const MAX_ORIGIN_BYTES = 255;

/**
 * Parses WITNESS_LOGS: `[{"origin": "...", "vkeys": ["<log vkey>", ...]}, ...]`. Each origin is
 * listed once, with at least one key; the keys are log keys (signature type 0x01). Returns the
 * trusted verifiers per origin.
 */
export async function parseWitnessLogs(
  json: string,
): Promise<ReadonlyMap<string, readonly NoteVerifier[]>> {
  let value: unknown;
  try {
    value = JSON.parse(json);
  } catch {
    throw new ConfigError('WITNESS_LOGS is not JSON');
  }
  if (!Array.isArray(value)) throw new ConfigError('WITNESS_LOGS must be a JSON array');
  const out = new Map<string, readonly NoteVerifier[]>();
  for (const [i, item] of (value as unknown[]).entries()) {
    const where = `WITNESS_LOGS[${String(i)}]`;
    if (typeof item !== 'object' || item === null || Array.isArray(item)) {
      throw new ConfigError(`${where} must be an object`);
    }
    const o = item as Record<string, unknown>;
    for (const k of Object.keys(o)) {
      if (k !== 'origin' && k !== 'vkeys') throw new ConfigError(`${where}.${k} is not known`);
    }
    const { origin, vkeys } = o;
    if (
      typeof origin !== 'string' ||
      origin === '' ||
      origin.includes('\n') ||
      !origin.isWellFormed() ||
      utf8Encode(origin).length > MAX_ORIGIN_BYTES
    ) {
      throw new ConfigError(`${where}.origin must be a checkpoint origin line`);
    }
    if (out.has(origin)) throw new ConfigError(`${where}: origin listed twice`);
    if (!Array.isArray(vkeys) || vkeys.length === 0) {
      throw new ConfigError(`${where}.vkeys must be a non-empty array`);
    }
    const verifiers: NoteVerifier[] = [];
    for (const v of vkeys as unknown[]) {
      if (typeof v !== 'string') throw new ConfigError(`${where}.vkeys must hold strings`);
      try {
        verifiers.push(await newVerifier(v));
      } catch (e) {
        throw new ConfigError(`${where}.vkeys: ${e instanceof Error ? e.message : String(e)}`);
      }
    }
    out.set(origin, verifiers);
  }
  return out;
}

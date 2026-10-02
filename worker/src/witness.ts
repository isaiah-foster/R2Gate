// The log's side of C2SP tlog-witness (M8): before a checkpoint becomes the live checkpoint, it is
// submitted to every configured witness with a consistency proof from the size that witness last
// cosigned, and the cosignatures that come back are appended to it. A witness only cosigns a
// checkpoint consistent with everything it saw before, so a reader who requires cosignatures
// from witnesses it trusts cannot be shown a forked log, unless those witnesses collude.
//
// The proof is computed from the log's own published tiles (already in R2 when this runs, I2),
// with the same core code that checks I3. A witness's last size is a hint kept in SQLite; when it
// is wrong (state lost, a crash between cosigning and recording), the witness answers 409 with its
// real size and the request is repeated once. Cosignatures are verified before they are kept: a
// line from a witness's key that does not verify, or one with a zero timestamp, counts as that
// witness failing. Fewer than WITNESS_QUORUM cosignatures fails the publication, which is retried
// like any other failure; the entries stay durable meanwhile.

import {
  consistencyProof,
  cosignatureTimestamp,
  formatAddCheckpoint,
  fromBase64,
  newCosignatureVerifier,
  openNote,
  parseCosignatureLines,
  parseSizeBody,
  tileNodeReader,
  type NoteVerifier,
  type TileCoord,
} from '@r2notary/core';
import type { WitnessEndpoint } from './config.ts';

export const WITNESS_TIMEOUT_MS = 10_000;
/** A 409 is followed once with the witness's size; a second 409 means it is changing under us. */
const MAX_ATTEMPTS = 2;

export interface LoadedWitness extends WitnessEndpoint {
  readonly name: string;
  readonly verifier: NoteVerifier;
}

/** Where witness progress is remembered (the Sequencer's SQLite, `witnesses` table). */
export interface WitnessStateStore {
  witnessSize(vkey: string): number | null;
  recordWitnessSuccess(vkey: string, size: number, at: number): void;
  recordWitnessFailure(vkey: string, error: string, at: number): void;
}

export interface WitnessClientDeps {
  readonly witnesses: readonly LoadedWitness[];
  readonly quorum: number;
  readonly fetch: (url: string, init: RequestInit) => Promise<Response>;
  readonly state: WitnessStateStore;
  readonly now: () => number;
}

/** Collects cosignatures for a signed checkpoint note of `size` (the publish step's hook). */
export type Cosign = (
  note: string,
  size: number,
  readTile: (tile: TileCoord) => Promise<Uint8Array>,
) => Promise<readonly string[]>;

export class WitnessError extends Error {
  override name = 'WitnessError';
}

/** Fewer cosignatures than WITNESS_QUORUM: the checkpoint is not published. */
export class WitnessQuorumError extends Error {
  override name = 'WitnessQuorumError';
}

export async function loadWitnesses(
  endpoints: readonly WitnessEndpoint[],
): Promise<LoadedWitness[]> {
  return Promise.all(
    endpoints.map(async (e) => {
      const verifier = await newCosignatureVerifier(e.vkey);
      return { ...e, name: verifier.name, verifier };
    }),
  );
}

/** The key name and key ID a signature line claims, or null if it does not parse. */
function lineKey(line: string): { name: string; keyId: number } | null {
  const m = /^— (\S+) (\S+)\n$/u.exec(line);
  if (m?.[1] === undefined || m[2] === undefined) return null;
  try {
    const raw = fromBase64(m[2]);
    return raw.length < 4 ? null : { name: m[1], keyId: new DataView(raw.buffer).getUint32(0) };
  } catch {
    return null;
  }
}

/**
 * Of the returned lines, the ones that are this witness's valid cosignatures over `note`. Lines
 * from other keys are ignored (spec); a line from this witness's key that does not verify, or
 * that has a zero timestamp, is an error.
 */
async function ownCosignatures(
  note: string,
  lines: readonly string[],
  w: LoadedWitness,
): Promise<string[]> {
  const out: string[] = [];
  for (const line of lines) {
    const k = lineKey(line);
    if (k?.name !== w.verifier.name || k.keyId !== w.verifier.keyId) continue;
    let timestamp: number;
    try {
      const opened = await openNote(`${note}${line}`, [w.verifier]);
      timestamp = cosignatureTimestamp(opened.signatures.at(-1)?.signature ?? new Uint8Array());
    } catch (e) {
      throw new WitnessError(`invalid cosignature: ${e instanceof Error ? e.message : String(e)}`);
    }
    if (timestamp === 0) throw new WitnessError('cosignature without a timestamp');
    out.push(line);
  }
  if (out.length === 0) throw new WitnessError('no cosignature from the witness key');
  return out;
}

export function witnessCosigner(d: WitnessClientDeps): Cosign {
  return async (note, size, readTile) => {
    // One tile reader for all witnesses: proofs from different old sizes share most tiles.
    const reader = tileNodeReader(size, readTile);
    const proofs = new Map<number, Promise<Uint8Array[]>>();
    const proof = (old: number): Promise<Uint8Array[]> => {
      let p = proofs.get(old);
      if (p === undefined) {
        p = old === 0 || old === size ? Promise.resolve([]) : consistencyProof(old, size, reader);
        proofs.set(old, p);
      }
      return p;
    };

    const one = async (w: LoadedWitness): Promise<string[]> => {
      let old = d.state.witnessSize(w.vkey) ?? 0;
      for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
        if (old > size) {
          throw new WitnessError(
            `witness has cosigned size ${String(old)}, beyond ${String(size)}`,
          );
        }
        const res = await d.fetch(`${w.url}/add-checkpoint`, {
          method: 'POST',
          headers: { 'content-type': 'text/plain; charset=utf-8' },
          body: formatAddCheckpoint({ oldSize: old, proof: await proof(old), checkpoint: note }),
          signal: AbortSignal.timeout(WITNESS_TIMEOUT_MS),
        });
        const body = await res.text();
        if (res.status === 409) {
          old = parseSizeBody(body);
          continue;
        }
        if (res.status !== 200) {
          throw new WitnessError(`HTTP ${String(res.status)}: ${body.trim().slice(0, 200)}`);
        }
        const lines = await ownCosignatures(note, parseCosignatureLines(body), w);
        d.state.recordWitnessSuccess(w.vkey, size, d.now());
        return lines;
      }
      throw new WitnessError(`still 409 after ${String(MAX_ATTEMPTS)} attempts`);
    };

    const results = await Promise.allSettled(d.witnesses.map(one));
    const lines: string[] = [];
    const errors: string[] = [];
    results.forEach((r, i) => {
      const w = d.witnesses[i];
      if (w === undefined) return;
      if (r.status === 'fulfilled') {
        lines.push(...r.value);
        return;
      }
      const message = r.reason instanceof Error ? r.reason.message : String(r.reason);
      d.state.recordWitnessFailure(w.vkey, message.slice(0, 500), d.now());
      errors.push(`${w.name}: ${message}`);
      console.error(`r2notary witness ${w.name} (${w.url}): ${message}`);
    });
    const cosigned = results.filter((r) => r.status === 'fulfilled').length;
    if (cosigned < d.quorum) {
      throw new WitnessQuorumError(
        `${String(cosigned)} of ${String(d.quorum)} required cosignatures for size ` +
          `${String(size)}: ${errors.join('; ')}`,
      );
    }
    return lines;
  };
}

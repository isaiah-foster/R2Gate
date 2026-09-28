// Deep scrub (PLAN §5.6): hash the bodies of a sample of listed objects with the Workers
// `crypto.DigestStream` (a WritableStream that keeps no data), so content that changes without
// its ETag changing is caught. Events carry no content hash, so this is the only content check.

import { encodeCanonical, sha256, toHex } from '@r2notary/core';
import type { ScrubObservation } from './store.ts';
import type { ListedObject } from './reconcile.ts';

export interface ScrubTarget {
  readonly key: string;
  readonly etag: string;
  readonly size: number;
}

/** At most this many bodies are read per listed page, which bounds a page's subrequests. */
export const MAX_SCRUB_PER_PAGE = 20;

/**
 * Whether `key` is in this scan's sample: the first 32 bits of SHA-256([scanId, key]) as a
 * fraction, below `rate`. Deterministic, so a retried step picks the same objects; different per
 * scan, so repeated scans cover different objects.
 */
export async function sampled(scanId: string, key: string, rate: number): Promise<boolean> {
  if (rate <= 0) return false;
  if (rate >= 1) return true;
  const h = await sha256(encodeCanonical([scanId, key]));
  const x = (((h[0] ?? 0) << 24) | ((h[1] ?? 0) << 16) | ((h[2] ?? 0) << 8) | (h[3] ?? 0)) >>> 0;
  return x / 2 ** 32 < rate;
}

export async function selectForScrub(
  scanId: string,
  objects: readonly ListedObject[],
  rate: number,
  maxBytes: number,
): Promise<ScrubTarget[]> {
  const out: ScrubTarget[] = [];
  for (const o of objects) {
    if (out.length >= MAX_SCRUB_PER_PAGE) break;
    if (o.size > maxBytes || !(await sampled(scanId, o.key, rate))) continue;
    out.push({ key: o.key, etag: o.etag, size: o.size });
  }
  return out;
}

export class ScrubError extends Error {
  override name = 'ScrubError';
}

function hasBody(o: R2Object | R2ObjectBody): o is R2ObjectBody {
  return 'body' in o && (o as Partial<R2ObjectBody>).body !== undefined;
}

/**
 * Reads one object and hashes its body, or returns null if it changed or vanished since it was
 * listed: the read is conditional on the listed ETag, so the hash always belongs to that version.
 */
export async function scrubObject(
  bucket: { get(key: string, options: R2GetOptions): Promise<R2ObjectBody | R2Object | null> },
  t: ScrubTarget,
  now: () => number,
): Promise<ScrubObservation | null> {
  const obj = await bucket.get(t.key, { onlyIf: { etagMatches: t.etag } });
  if (obj === null || !hasBody(obj)) return null;
  const digest = new crypto.DigestStream('SHA-256');
  await obj.body.pipeTo(digest);
  const hash = toHex(new Uint8Array(await digest.digest));
  const read = Number(digest.bytesWritten);
  // A short read is a transport failure, not evidence about the object: fail the step (retried).
  if (read !== obj.size) {
    throw new ScrubError(`read ${String(read)} of ${String(obj.size)} bytes of a scrubbed object`);
  }
  const stored = obj.checksums.sha256;
  return {
    key: t.key,
    etag: obj.etag,
    size: obj.size,
    uploaded: obj.uploaded.getTime(),
    sha256: hash,
    storedSha256: stored === undefined ? null : toHex(new Uint8Array(stored)),
    observedAt: now(),
  };
}

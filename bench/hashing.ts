// PLAN §14.5: core hashing speed. How fast can a tree of N leaves be hashed (leaf hashes plus every
// interior node up to the root), and how does the WebCrypto batching strategy matter? Also the
// in-memory work of one publication (appendEntries + signing) at several batch sizes, which is
// the CPU part of the Sequencer's publish step.
//
//   npm run bench:hashing [-- --leaves 65536 --runs 15]
//
// Runs in Node, not workerd: workerd's clocks only advance on I/O, so CPU-bound work cannot be
// timed from inside it. Node and workerd share V8, but their WebCrypto implementations differ
// (Node: OpenSSL through libuv's thread pool; workerd: BoringSSL, synchronous under a promise), so
// these numbers show the relative cost of the strategies, not Workers throughput.

import { createHash } from 'node:crypto';
import { parseArgs } from 'node:util';
import {
  EMPTY_LOG,
  appendEntries,
  encodeEntry,
  generateKey,
  hashChildren,
  hashLeaf,
  hashLeaves,
  merkleRoot,
  newSigner,
  signCheckpoint,
  toHex,
  type LogState,
} from '../packages/core/src/index.ts';
import { environment, intList, nowMs, round, summarize, writeResult } from './lib.ts';

const { values } = parseArgs({
  options: {
    leaves: { type: 'string', default: '65536' },
    runs: { type: 'string', default: '15' },
    batches: { type: 'string', default: '1,10,100,500,1000' },
  },
});
const LEAVES = Number(values.leaves);
const RUNS = Number(values.runs);
const WARMUP = 2;

/** Synthetic object.event entries shaped like ingested PutObjects. */
function entries(n: number, offset = 0): Uint8Array[] {
  return Array.from({ length: n }, (_, j) => {
    const i = offset + j;
    return encodeEntry({
      v: 1,
      type: 'object.event',
      bucket: 'example-monitored-bucket',
      key: `bench/${String(i % 1000)}/object-${String(i)}.bin`,
      action: 'PutObject',
      size: 1024 + (i % 1024),
      etag: (i >>> 0).toString(16).padStart(32, '0'),
      eventTime: '2026-10-03T12:00:00.000Z',
      ingestedAt: '2026-10-03T12:00:01.000Z',
    });
  });
}

// ---- tree-hashing strategies: each returns the RFC 6962 root of `leaves` (a power of two) -----

/** One await per hash: every digest waits for the previous one. */
async function sequential(es: readonly Uint8Array[]): Promise<Uint8Array> {
  let row: Uint8Array[] = [];
  for (const e of es) row.push(await hashLeaf(e));
  while (row.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < row.length; i += 2) {
      next.push(await hashChildren(row[i] ?? new Uint8Array(), row[i + 1] ?? new Uint8Array()));
    }
    row = next;
  }
  return row[0] ?? new Uint8Array();
}

/** What packages/core does: every leaf of a call at once, then each level with one Promise.all. */
async function perLevel(es: readonly Uint8Array[]): Promise<Uint8Array> {
  return merkleRoot(await hashLeaves(es));
}

/** Per-level, but at most 256 digests in flight (bounded memory for the pending promises). */
async function chunked(es: readonly Uint8Array[]): Promise<Uint8Array> {
  const all = async (n: number, f: (i: number) => Promise<Uint8Array>): Promise<Uint8Array[]> => {
    const out: Uint8Array[] = [];
    for (let i = 0; i < n; i += 256) {
      const chunk = Array.from({ length: Math.min(256, n - i) }, (_, j) => f(i + j));
      out.push(...(await Promise.all(chunk)));
    }
    return out;
  };
  let row = await all(es.length, (i) => hashLeaf(es[i] ?? new Uint8Array()));
  while (row.length > 1) {
    const prev = row;
    row = await all(prev.length / 2, (i) =>
      hashChildren(prev[2 * i] ?? new Uint8Array(), prev[2 * i + 1] ?? new Uint8Array()),
    );
  }
  return row[0] ?? new Uint8Array();
}

/** Reference only: Node's synchronous createHash. Not available to packages/core (WebCrypto only). */
function nodeSync(es: readonly Uint8Array[]): Promise<Uint8Array> {
  const h = (...parts: Uint8Array[]): Uint8Array => {
    const c = createHash('sha256');
    for (const p of parts) c.update(p);
    return new Uint8Array(c.digest());
  };
  let row = es.map((e) => h(Uint8Array.of(0), e));
  while (row.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < row.length; i += 2) {
      next.push(h(Uint8Array.of(1), row[i] ?? new Uint8Array(), row[i + 1] ?? new Uint8Array()));
    }
    row = next;
  }
  return Promise.resolve(row[0] ?? new Uint8Array());
}

async function time(f: () => Promise<unknown>): Promise<number[]> {
  for (let i = 0; i < WARMUP; i++) await f();
  const out: number[] = [];
  for (let i = 0; i < RUNS; i++) {
    const t = nowMs();
    await f();
    out.push(nowMs() - t);
  }
  return out;
}

if ((LEAVES & (LEAVES - 1)) !== 0) throw new Error('--leaves must be a power of two');
const data = entries(LEAVES);
const meanEntryBytes = data.reduce((a, e) => a + e.length, 0) / data.length;

const strategies = { sequential, perLevel, chunked, nodeSync };
const roots = new Set<string>();
const treeResults: Record<string, unknown>[] = [];
for (const [name, f] of Object.entries(strategies)) {
  roots.add(toHex(await f(data)));
  const ms = await time(() => f(data));
  const s = summarize(ms);
  treeResults.push({
    strategy: name,
    ms: s,
    leavesPerSecondAtMedian: Math.round((LEAVES / s.median) * 1000),
    hashesPerTree: 2 * LEAVES - 1,
  });
  console.log(`${name}: median ${String(s.median)} ms for ${String(LEAVES)} leaves`);
}
if (roots.size !== 1) throw new Error('strategies disagree on the root');

// One publication's in-memory work: appendEntries (leaf hashes, tiles, bundles, root) and the
// checkpoint signature, starting from a log of 1,000 entries (mid-tile, like a running log).
const signer = await newSigner((await generateKey('r2notary.example.com/log/example-log')).skey);
const base: LogState = (await appendEntries(EMPTY_LOG, entries(1000))).state;
const publication: Record<string, unknown>[] = [];
for (const k of intList(values.batches)) {
  const batch = entries(k, 1000);
  const ms = await time(async () => {
    const u = await appendEntries(base, batch);
    await signCheckpoint(
      {
        origin: 'r2notary.example.com/log/example-log',
        size: u.state.tree.size,
        rootHash: u.root,
        extensions: [],
      },
      signer,
    );
  });
  const s = summarize(ms);
  publication.push({
    entries: k,
    ms: s,
    entriesPerSecondAtMedian: Math.round((k / s.median) * 1000),
  });
  console.log(`publication compute, ${String(k)} entries: median ${String(s.median)} ms`);
}

writeResult('hashing', {
  benchmark: 'PLAN §14.5 core hashing speed',
  environment: environment('Node.js (packages/core directly; not workerd)'),
  config: { leaves: LEAVES, runs: RUNS, warmup: WARMUP, meanEntryBytes: round(meanEntryBytes, 1) },
  tree: treeResults,
  publicationCompute: {
    description:
      'appendEntries (leaf hashes, tiles, bundles, root) + Ed25519 checkpoint signature, from a 1,000-entry log',
    results: publication,
  },
});

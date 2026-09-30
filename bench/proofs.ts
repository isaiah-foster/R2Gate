// PLAN §14.4: proof cost. For logs of 10^3, 10^5 and 10^6 entries, how many bytes does the Go
// verifier fetch, in how many requests, and how long does it take to verify an inclusion proof and
// a consistency proof? The log is generated in memory with packages/core (the writer's own code),
// served by a counting HTTP server on localhost, and verified by the real CLI binary.
//
//   npm run bench:proofs [-- --sizes 1000,100000,1000000 --runs 10]
//
// The CLI computes every proof from tiles and keeps no cache between runs, so each run fetches the
// checkpoint, the tiles the proof touches, and (inclusion) the entry bundle. Times are wall-clock
// for the whole process, including start-up and localhost HTTP; `checkpoint` alone is the
// baseline. Bytes and request counts are exact and do not depend on the machine.

import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { parseArgs } from 'node:util';
import {
  CHECKPOINT_PATH,
  EMPTY_LOG,
  HASH_SIZE,
  appendEntries,
  consistencyProof,
  encodeEntry,
  entryBundlePath,
  generateKey,
  newSigner,
  signCheckpoint,
  tileNodeReader,
  tilePath,
  type LogState,
  type LogUpdate,
} from '../packages/core/src/index.ts';
import { ROOT, environment, intList, nowMs, round, summarize, writeResult } from './lib.ts';

const { values } = parseArgs({
  options: {
    sizes: { type: 'string', default: '1000,100000,1000000' },
    runs: { type: 'string', default: '10' },
    // internal: generate one log into a directory and exit (run as a child process)
    generate: { type: 'string' },
    out: { type: 'string' },
    key: { type: 'string' },
  },
});
const SIZES = intList(values.sizes);
const RUNS = Number(values.runs);
const ORIGIN = 'bench.r2notary.example/log/proofs';
/** Entries appended per appendEntries call while generating. */
const CHUNK = 65_536;

const tmp = mkdtempSync(join(tmpdir(), 'r2notary-bench-proofs-'));
const cli = join(tmp, 'r2notary');

function run(
  cmd: string,
  args: readonly string[],
  cwd = ROOT,
): Promise<{ code: number; stderr: string }> {
  return new Promise((done, fail) => {
    const child = spawn(cmd, args, { cwd, stdio: ['ignore', 'ignore', 'pipe'] });
    const err: Buffer[] = [];
    child.stderr.on('data', (b: Buffer) => err.push(b));
    child.on('error', fail);
    child.on('close', (code) => {
      done({ code: code ?? -1, stderr: Buffer.concat(err).toString('utf8') });
    });
  });
}

function entry(i: number): Uint8Array {
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
}

/** RFC 6962 §2.1.1 audit path length for leaf m in a tree of n leaves. */
function inclusionPathLength(m: number, n: number): number {
  let len = 0;
  let lo = 0;
  let hi = n;
  while (hi - lo > 1) {
    let k = 1;
    while (k * 2 < hi - lo) k *= 2;
    if (m < lo + k) hi = lo + k;
    else lo += k;
    len++;
  }
  return len;
}

const oldSizeFor = (size: number): number => Math.floor(size / 2) + 7;

/**
 * Writes every resource a writer would publish with checkpoints at `oldSize` and `size` under
 * `dir` (partial resources exist only for published sizes), plus the two signed checkpoints.
 */
async function generate(size: number, dir: string, skey: string): Promise<void> {
  const signer = await newSigner(skey);
  const write = (path: string, data: Uint8Array | string): void => {
    mkdirSync(dirname(join(dir, path)), { recursive: true });
    writeFileSync(join(dir, path), data);
  };
  let state: LogState = EMPTY_LOG;
  for (const stop of [oldSizeFor(size), size]) {
    while (state.tree.size < stop) {
      const from = state.tree.size;
      const u: LogUpdate = await appendEntries(
        state,
        Array.from({ length: Math.min(CHUNK, stop - from) }, (_, j) => entry(from + j)),
      );
      for (const t of u.fullTiles) write(tilePath(t.level, t.index, t.width), t.data);
      for (const b of u.fullBundles) write(entryBundlePath(b.index, b.width), b.data);
      state = u.state;
      if (state.tree.size === stop) {
        for (const t of u.partialTiles) write(tilePath(t.level, t.index, t.width), t.data);
        const b = u.partialBundle;
        if (b !== null) write(entryBundlePath(b.index, b.width), b.data);
        const cp = { origin: ORIGIN, size: stop, rootHash: u.root, extensions: [] };
        write(`checkpoint-${String(stop)}`, await signCheckpoint(cp, signer));
      }
    }
  }
}

if (values.generate !== undefined) {
  if (values.out === undefined || values.key === undefined) throw new Error('--out, --key');
  await generate(Number(values.generate), values.out, readFileSync(values.key, 'utf8').trim());
  process.exit(0);
}

// ---- the counting server -------------------------------------------------------------------

// Files are read from disk per request, so this process stays small: spawning the CLI from a
// process holding a large heap measurably slows every run (seen in a first version).
let dir = '';
let live = new Uint8Array();
const readLog = (path: string): Uint8Array | undefined => {
  const f = join(dir, path);
  return path !== '' && !path.includes('..') && existsSync(f) ? readFileSync(f) : undefined;
};
const counts = { requests: 0, bytes: 0, tileBytes: 0, bundleBytes: 0, checkpointBytes: 0 };
const resetCounts = (): void => {
  counts.requests =
    counts.bytes =
    counts.tileBytes =
    counts.bundleBytes =
    counts.checkpointBytes =
      0;
};
const server = createServer((req, res) => {
  const prefix = '/log/proofs/';
  const path = req.url?.startsWith(prefix) === true ? req.url.slice(prefix.length) : '';
  const body = path === CHECKPOINT_PATH ? live : readLog(path);
  counts.requests++;
  if (body === undefined) {
    res.writeHead(404).end();
    return;
  }
  counts.bytes += body.length;
  if (path === CHECKPOINT_PATH) counts.checkpointBytes += body.length;
  else if (path.startsWith('tile/entries/')) counts.bundleBytes += body.length;
  else counts.tileBytes += body.length;
  res.writeHead(200, { 'content-length': String(body.length) }).end(body);
});
await new Promise<void>((done) => server.listen(0, '127.0.0.1', done));
const addr = server.address();
const logUrl = `http://127.0.0.1:${String(typeof addr === 'object' && addr !== null ? addr.port : 0)}/log/proofs`;

try {
  const build = await run('go', ['build', '-o', cli, './cmd/r2notary'], join(ROOT, 'cli'));
  if (build.code !== 0) throw new Error(`go build failed:\n${build.stderr}`);
  const key = await generateKey(ORIGIN);
  const keyFile = join(tmp, 'signing.key');
  writeFileSync(keyFile, key.skey, { mode: 0o600 });
  const flags = ['--log', logUrl, '--vkey', key.vkey];

  const results: Record<string, unknown>[] = [];
  for (const size of SIZES) {
    // An old checkpoint about half way, not on a tile boundary.
    const oldSize = oldSizeFor(size);
    dir = join(tmp, `log-${String(size)}`);
    const t0 = nowMs();
    const gen = await run(process.execPath, [
      import.meta.filename,
      '--generate',
      String(size),
      '--out',
      dir,
      '--key',
      keyFile,
    ]);
    if (gen.code !== 0) throw new Error(`generating ${String(size)}: ${gen.stderr}`);
    console.log(
      `generated ${String(size)} entries in ${String(round((nowMs() - t0) / 1000, 1))} s`,
    );
    live = readFileSync(join(dir, `checkpoint-${String(size)}`));
    const oldFile = join(dir, `checkpoint-${String(oldSize)}`);

    // Proof sizes from the writer's own code, for comparison with what is fetched.
    const readTile = (t: { level: number; index: number; width: number }): Promise<Uint8Array> =>
      Promise.resolve(readLog(tilePath(t.level, t.index, t.width)) ?? new Uint8Array());
    const consistencyHashes = (
      await consistencyProof(oldSize, size, tileNodeReader(size, readTile))
    ).length;

    const cases: { name: string; args: string[]; proofHashes: number | null }[] = [
      { name: 'checkpoint (baseline)', args: ['checkpoint', ...flags], proofHashes: null },
      ...[0, Math.floor(size / 2), size - 1].map((i) => ({
        name: `inclusion --index ${String(i)}`,
        args: ['inclusion', '--index', String(i), ...flags],
        proofHashes: inclusionPathLength(i, size),
      })),
      {
        name: `consistency ${String(oldSize)} -> ${String(size)}`,
        args: ['consistency', '--old', oldFile, ...flags],
        proofHashes: consistencyHashes,
      },
    ];
    for (const c of cases) {
      const ms: number[] = [];
      let fetched = { ...counts };
      for (let r = 0; r < RUNS + 1; r++) {
        resetCounts();
        const t = nowMs();
        const out = await run(cli, c.args);
        const elapsed = nowMs() - t;
        if (out.code !== 0) throw new Error(`${c.name}: exit ${String(out.code)}: ${out.stderr}`);
        if (r > 0) ms.push(elapsed); // the first run warms the page cache and the binary
        fetched = { ...counts };
      }
      results.push({
        logSize: size,
        case: c.name,
        proofHashes: c.proofHashes,
        proofBytes: c.proofHashes === null ? null : c.proofHashes * HASH_SIZE,
        fetched,
        wallMs: summarize(ms),
      });
      console.log(
        `${String(size)} ${c.name}: ${String(fetched.bytes)} B in ${String(fetched.requests)} requests, median ${String(summarize(ms).median)} ms`,
      );
    }
    rmSync(dir, { recursive: true, force: true });
  }

  writeResult('proofs', {
    benchmark: 'PLAN §14.4 proof cost',
    environment: environment(
      'Go CLI (cli/) against a Node HTTP server on 127.0.0.1; log generated by packages/core in Node',
    ),
    config: {
      sizes: SIZES,
      runsPerCase: RUNS,
      warmupRunsPerCase: 1,
      oldCheckpoint: 'floor(size / 2) + 7',
      generation: 'one child process per size; files served from disk',
      entries: 'synthetic object.event, keys bench/<i % 1000>/object-<i>.bin',
    },
    results,
  });
} finally {
  server.close();
  rmSync(tmp, { recursive: true, force: true });
}

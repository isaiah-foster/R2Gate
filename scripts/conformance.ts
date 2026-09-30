// Cross-language conformance (PLAN M5, I7, I9): the TypeScript writer produces a log, the Go
// verifier (cli/, no shared code) checks it, and then every published resource is corrupted in
// turn and the verifier must reject it.
//
//   npm run conformance              # needs Go and the npm dependencies; no network, no account
//   npm run conformance -- --keep    # keep the temporary directory (logs, mirror, state files)
//
// Steps:
//   1. Build the Go CLI. Generate the signing key with *Go's* keygen, so the writer signs with a key
//      in the format Go produced (DECISIONS D1.4, both directions).
//   2. Run the real Worker locally (`wrangler dev` with the event simulator, as `npm run dev:sim`),
//      private log, secrets from a temporary --env-file. Feed it synthetic R2 events and publish
//      through the admin API at sizes chosen around tile boundaries.
//   3. Verify against the live read path with the Go CLI: checkpoint, origin (I9), a full monitor
//      scan whose entries must equal what TypeScript decodes from the bundles, inclusion by index,
//      by key (scan and lookup API), --watch alerts, and consistency between every pair of
//      archived checkpoints (I3, Go side).
//   3b. Run an audit through the admin API (a local Workflow). The local monitored bucket is
//      empty, so every key the log shows as live must be reported MISSING_OBJECT. The Go CLI's
//      `findings` proves each finding and checks their number against the scan's signed end
//      entry; the log must stay consistent with the archived checkpoints after the audit.
//   4. Mirror every resource of every archived size, serve the mirror from a plain HTTP server, and
//      replay a monitor across the archived checkpoints in order. Uncorrupted, every step passes.
//      With one bit flipped in any tile, bundle or archived checkpoint, or a forged signature,
//      the replay must stop with exit code 1 (verification failed); a missing resource with 4.

import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import {
  CHECKPOINT_PATH,
  TILE_WIDTH,
  archivedCheckpointPath,
  decodeBundle,
  decodeEntry,
  entryBundlePath,
  fromBase64,
  generateKey,
  newSigner,
  parseCheckpoint,
  signCheckpoint,
  tilePath,
  toBase64,
  utf8Decode,
} from '../packages/core/src/index.ts';
import { ROOT, randomToken as token, sleep, startDev, type DevServer } from './lib/dev.ts';
import { simulate } from './simulate/events.ts';

const { values } = parseArgs({
  options: {
    keep: { type: 'boolean', default: false },
    help: { type: 'boolean', default: false },
  },
});
if (values.help) {
  console.log('usage: conformance [--keep]');
  process.exit(0);
}

const LOG_NAME = 'example-log'; // worker/wrangler.jsonc
const ORIGIN = 'r2notary.example.com/log/example-log';
const BUCKET = 'example-monitored-bucket';
/** Published sizes: around the 256 boundary of level-0 tiles and bundles, and of level-1 widths. */
const SIZES = [1, 255, 256, 257, 512, 513, 1000, 1300];
// Exit codes of the Go CLI (cli/cmd/r2notary/main.go).
const EXIT = { ok: 0, failure: 1, negative: 3, error: 4 } as const;

const tmp = mkdtempSync(join(tmpdir(), 'r2notary-conformance-'));
const cli = join(tmp, 'r2notary');
const failures: string[] = [];
let checks = 0;

function check(ok: boolean, what: string): void {
  checks++;
  if (!ok) {
    failures.push(what);
    console.error(`  FAIL ${what}`);
  }
}

function step(s: string): void {
  console.log(`conformance: ${s}`);
}

interface Run {
  readonly code: number;
  readonly stdout: string;
  readonly stderr: string;
}

function run(
  cmd: string,
  args: readonly string[],
  opts: { cwd?: string; env?: NodeJS.ProcessEnv } = {},
): Promise<Run> {
  return new Promise((done, fail) => {
    const child = spawn(cmd, args, { cwd: opts.cwd ?? ROOT, env: opts.env ?? process.env });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on('data', (b: Buffer) => out.push(b));
    child.stderr.on('data', (b: Buffer) => err.push(b));
    child.on('error', fail);
    child.on('close', (code) => {
      done({
        code: code ?? -1,
        stdout: Buffer.concat(out).toString('utf8'),
        stderr: Buffer.concat(err).toString('utf8'),
      });
    });
  });
}

/** Every resource of a tree of the given size: tiles and bundles at each level, and its archive. */
function resourcesAt(size: number): string[] {
  const out: string[] = [];
  for (let level = 0, count = size; count > 0; level++, count = Math.floor(count / TILE_WIDTH)) {
    const full = Math.floor(count / TILE_WIDTH);
    const rest = count % TILE_WIDTH;
    for (let n = 0; n <= full; n++) {
      const width = n < full ? TILE_WIDTH : rest;
      if (width === 0) continue;
      out.push(tilePath(level, n, width));
      if (level === 0) out.push(entryBundlePath(n, width));
    }
  }
  out.push(archivedCheckpointPath(size));
  return out;
}

/** Same semantics as the Go monitor's --watch (cli/internal/monitor), written independently. */
function expectedAlerts(entries: readonly Uint8Array[], prefix: string): number {
  const live = new Set<string>();
  let alerts = 0;
  for (const bytes of entries) {
    const d = decodeEntry(bytes);
    if (!d.known) continue;
    const e = d.entry;
    if (e.type === 'object.snapshot' && e.key.startsWith(prefix)) live.add(e.key);
    if (e.type !== 'object.event' || !e.key.startsWith(prefix)) continue;
    if (e.action === 'DeleteObject' || e.action === 'LifecycleDeletion') {
      alerts++;
      live.delete(e.key);
    } else {
      if (live.has(e.key)) alerts++;
      live.add(e.key);
    }
  }
  return alerts;
}

/** The entries printed by `monitor` / `inclusion`, as {index → exact entry text}. */
function printedEntries(stdout: string): Map<number, string> {
  const out = new Map<number, string>();
  for (const line of stdout.split('\n')) {
    const m = /^\{"index":(\d+),"entry":(.*)\}$/s.exec(line);
    if (m?.[1] !== undefined && m[2] !== undefined) out.set(Number(m[1]), m[2]);
  }
  return out;
}

let dev = null as DevServer | null;
// Typed through `as` so TypeScript does not narrow it to null for the finally block below.
let mirrorServer = null as Server | null;

function stopWrangler(): void {
  dev?.stop();
  dev = null;
}

async function main(): Promise<void> {
  step(`working directory ${tmp}`);

  // 1. Go CLI and a Go-generated signing key.
  const build = await run('go', ['build', '-o', cli, './cmd/r2notary'], { cwd: join(ROOT, 'cli') });
  if (build.code !== 0) throw new Error(`go build failed:\n${build.stderr}`);
  const keyFile = join(tmp, 'signing.key');
  const kg = await run(cli, ['keygen', '--name', ORIGIN, '--out', keyFile]);
  if (kg.code !== 0) throw new Error(`r2notary keygen failed:\n${kg.stderr}`);
  const vkey = kg.stdout.trim();
  const skey = readFileSync(keyFile, 'utf8').trim();
  const adminToken = token();
  const readToken = token();

  // 2. The Worker under wrangler dev. CHECKPOINT_INTERVAL_MS is an hour, so only the admin API
  // publishes and every checkpoint size is known.
  step('starting wrangler dev');
  dev = await startDev({
    dir: tmp,
    readToken,
    vars: {
      SIGNING_KEY: skey,
      ADMIN_TOKEN: adminToken,
      READ_TOKEN: readToken,
      CHECKPOINT_INTERVAL_MS: '3600000',
      BATCH_MAX_ENTRIES: '1000',
      // The simulated events are hours old, but the scan runs immediately after publication.
      AUDIT_GRACE_SECONDS: '0',
    },
  });
  const base = dev.base;
  const logUrl = `${base}/log/${LOG_NAME}`;
  const auth = (t: string): Record<string, string> => ({ authorization: `Bearer ${t}` });

  const status = async (): Promise<{ durableSize: number; size: number } | null> => {
    try {
      const res = await fetch(`${base}/api/v1/status`, { headers: auth(readToken) });
      return res.ok ? ((await res.json()) as { durableSize: number; size: number }) : null;
    } catch {
      return null;
    }
  };

  const { messages, manifest } = simulate({
    count: SIZES.at(-1) ?? 0,
    bucket: BUCKET,
    seed: 5,
    keys: 40,
  });
  let published = 0;
  for (const size of SIZES) {
    const batch = messages.slice(published, size);
    for (let i = 0; i < batch.length; i += 100) {
      const res = await fetch(`${base}/__simulate/send`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(batch.slice(i, i + 100)),
      });
      if (!res.ok) throw new Error(`simulator send: HTTP ${String(res.status)}`);
    }
    for (let i = 0; (await status())?.durableSize !== size; i++) {
      if (i > 120) throw new Error(`events for size ${String(size)} were not ingested`);
      await sleep(500);
    }
    const res = await fetch(`${base}/api/v1/admin/publish`, {
      method: 'POST',
      headers: auth(adminToken),
    });
    const result = (await res.json()) as { previousSize: number; size: number };
    if (result.previousSize !== published || result.size !== size) {
      throw new Error(
        `publish: ${JSON.stringify(result)}, expected ${String(published)} -> ${String(size)}`,
      );
    }
    published = size;
  }
  step(`published checkpoints at sizes ${SIZES.join(', ')}`);

  // Mirror every resource of every archived size through the read path.
  const mirror = new Map<string, Uint8Array>();
  for (const path of new Set([...SIZES.flatMap(resourcesAt), CHECKPOINT_PATH])) {
    const res = await fetch(`${logUrl}/${path}`, { headers: auth(readToken) });
    if (res.status !== 200) throw new Error(`GET ${path}: HTTP ${String(res.status)}`);
    mirror.set(path, new Uint8Array(await res.arrayBuffer()));
  }
  const archive = (size: number): Uint8Array => {
    const a = mirror.get(archivedCheckpointPath(size));
    if (a === undefined) throw new Error(`no archive ${String(size)}`);
    return a;
  };
  const final = SIZES.at(-1) ?? 0;
  check(
    Buffer.from(mirror.get(CHECKPOINT_PATH) ?? []).equals(archive(final)),
    'live checkpoint equals the archived checkpoint of the same size',
  );
  // What TypeScript reads from the final tree's bundles: the reference for the Go output.
  const entries: Uint8Array[] = [];
  for (let n = 0; n * TILE_WIDTH < final; n++) {
    const b = mirror.get(entryBundlePath(n, Math.min(TILE_WIDTH, final - n * TILE_WIDTH)));
    if (b === undefined) throw new Error(`bundle ${String(n)} missing`);
    entries.push(...decodeBundle(b));
  }
  check(entries.length === final, `TypeScript decodes ${String(final)} entries`);
  check(
    entries.every((e) => decodeEntry(e).known),
    'every entry is a known, schema-valid entry',
  );

  // 3. Go CLI against the live read path (private log: token from the environment).
  const cliEnv = { ...process.env, R2NOTARY_TOKEN: readToken };
  const go = (args: readonly string[], env: NodeJS.ProcessEnv = cliEnv): Promise<Run> =>
    run(cli, args, { env });
  const logFlags = ['--log', logUrl, '--vkey', vkey];

  step('verifying the live log with the Go CLI');
  const cp = await go(['checkpoint', ...logFlags]);
  check(
    cp.code === EXIT.ok && cp.stdout.includes(`size ${String(final)}\n`),
    `checkpoint: ${cp.stderr}`,
  );
  check(cp.stdout.startsWith(`origin ${ORIGIN}\n`), 'I9: origin line equals LOG_ORIGIN');
  const wrongOrigin = await go([
    'checkpoint',
    ...logFlags,
    '--origin',
    'r2notary.example.com/log/other',
  ]);
  check(
    wrongOrigin.code === EXIT.failure,
    `I9: another expected origin is rejected (exit ${String(wrongOrigin.code)})`,
  );
  const otherKey = await generateKey(ORIGIN);
  const foreign = await go(['checkpoint', '--log', logUrl, '--vkey', otherKey.vkey]);
  check(foreign.code === EXIT.failure, 'I9: a vkey with the same name but another key is rejected');
  const noToken = await go(['checkpoint', ...logFlags], { ...process.env, R2NOTARY_TOKEN: '' });
  check(
    noToken.code === EXIT.error && noToken.stderr.includes('401'),
    'private log without a token: exit 4 (401)',
  );

  const scan = await go([
    'monitor',
    '--once',
    '--state',
    join(tmp, 'live-monitor.json'),
    ...logFlags,
  ]);
  check(scan.code === EXIT.ok, `monitor scans the whole log: ${scan.stderr}`);
  const printed = printedEntries(scan.stdout);
  check(printed.size === final, `monitor printed ${String(printed.size)} entries`);
  let mismatched = 0;
  entries.forEach((e, i) => {
    if (printed.get(i) !== utf8Decode(e)) mismatched++;
  });
  check(
    mismatched === 0,
    `entries verified by Go equal the bytes TypeScript wrote (${String(mismatched)} differ)`,
  );

  for (const i of [0, 254, 255, 256, 511, 512, 999, final - 1]) {
    const r = await go(['inclusion', '--index', String(i), ...logFlags]);
    check(
      r.code === EXIT.ok &&
        printedEntries(r.stdout).get(i) === utf8Decode(entries[i] ?? new Uint8Array()),
      `inclusion --index ${String(i)}: ${r.stderr.trim()}`,
    );
  }
  const beyond = await go(['inclusion', '--index', String(final), ...logFlags]);
  check(beyond.code === EXIT.negative, 'inclusion beyond the tree: exit 3');

  // Keys with Unicode, spaces, quotes, `|` and emoji (the simulator's odd keys), and a plain one.
  const byKey = new Map<string, number[]>();
  entries.forEach((e, i) => {
    const d = decodeEntry(e);
    if (d.known && 'key' in d.entry) byKey.set(d.entry.key, [...(byKey.get(d.entry.key) ?? []), i]);
  });
  for (const key of [
    'sim/ünïcødé/ファイル',
    'sim/with space',
    'sim/a|b|c',
    'sim/"quoted"',
    'sim/😀',
    'sim/7',
  ]) {
    const want = (byKey.get(key) ?? []).join(',');
    check(want !== '', `simulator produced entries for ${key}`);
    for (const extra of [[], ['--api', base]]) {
      const r = await go(['inclusion', '--key', key, ...extra, ...logFlags]);
      const got = [...printedEntries(r.stdout).keys()].join(',');
      check(
        r.code === EXIT.ok && got === want,
        `inclusion --key ${key} ${extra.join(' ')}: [${got}] vs [${want}]`,
      );
    }
  }
  const absent = await go(['inclusion', '--key', 'sim/absent', ...logFlags]);
  check(absent.code === EXIT.negative, 'inclusion --key for an absent key: exit 3');

  const prefix = 'sim/1';
  const watch = await go([
    'monitor',
    '--once',
    '-q',
    '--watch',
    prefix,
    '--state',
    join(tmp, 'watch.json'),
    ...logFlags,
  ]);
  const alerts = watch.stdout.split('\n').filter((l) => l.includes('"alert":')).length;
  const wantAlerts = expectedAlerts(entries, prefix);
  check(
    wantAlerts > 0 && alerts === wantAlerts,
    `--watch ${prefix}: Go ${String(alerts)} alerts, TypeScript ${String(wantAlerts)}`,
  );
  check(watch.code === EXIT.negative, '--watch with alerts and --once: exit 3');

  const archiveFile = (size: number): string => join(tmp, `checkpoint-${String(size)}`);
  for (const size of SIZES) writeFileSync(archiveFile(size), archive(size));
  let pairs = 0;
  for (const [i, a] of SIZES.entries()) {
    for (const b of SIZES.slice(i)) {
      const r = await go([
        'consistency',
        '--old',
        archiveFile(a),
        '--new',
        archiveFile(b),
        ...logFlags,
      ]);
      check(r.code === EXIT.ok, `I3: consistency ${String(a)} -> ${String(b)}: ${r.stderr.trim()}`);
      pairs++;
    }
  }
  const back = await go([
    'consistency',
    '--old',
    archiveFile(1000),
    '--new',
    archiveFile(257),
    ...logFlags,
  ]);
  check(back.code === EXIT.failure, 'consistency 1000 -> 257 (a rollback) is rejected');
  step(`consistency verified for all ${String(pairs)} pairs of archived checkpoints`);

  // 3b. The auditor, end to end.
  step('running an audit (local Workflow) and verifying its findings with the Go CLI');
  const liveKeys = manifest.objects
    .filter((o) => !o.deleted)
    .map((o) => o.key)
    .sort();
  const started = await fetch(`${base}/api/v1/admin/scan`, {
    method: 'POST',
    headers: auth(adminToken),
  });
  check(started.status === 202, `admin scan: HTTP ${String(started.status)}`);
  const { scanId } = (await started.json()) as { scanId: string };
  interface AuditView {
    readonly scan: { scanId: string; state: string; findings: number } | null;
  }
  let audit: AuditView = { scan: null };
  for (let i = 0; audit.scan?.scanId !== scanId || audit.scan.state !== 'done'; i++) {
    if (i > 240) throw new Error(`audit ${scanId} did not finish: ${JSON.stringify(audit)}`);
    await sleep(500);
    const res = await fetch(`${base}/api/v1/findings?limit=1`, { headers: auth(readToken) });
    audit = (await res.json()) as AuditView;
  }
  check(
    audit.scan.findings === liveKeys.length,
    `audit reports ${String(audit.scan.findings)} findings for ${String(liveKeys.length)} live keys`,
  );
  const verified = await go(['findings', '--api', base, ...logFlags]);
  check(verified.code === EXIT.ok, `findings: ${verified.stderr.trim()}`);
  check(
    verified.stderr.includes('confirms the count'),
    'the number of findings matches the signed audit.scan end entry',
  );
  const found = [...printedEntries(verified.stdout).values()].map(
    (e) => JSON.parse(e) as { kind: string; key: string; scanId: string },
  );
  check(
    found.every((f) => f.kind === 'MISSING_OBJECT' && f.scanId === scanId) &&
      JSON.stringify(found.map((f) => f.key).sort()) === JSON.stringify(liveKeys),
    'every live key is a proven MISSING_OBJECT finding of this scan',
  );
  const extended = await go(['consistency', '--old', archiveFile(final), ...logFlags]);
  check(extended.code === EXIT.ok, `the audited log extends checkpoint ${String(final)}`);
  const tail = await go([
    'monitor',
    '--once',
    '-q',
    '--state',
    join(tmp, 'live-monitor.json'),
    ...logFlags,
  ]);
  check(tail.code === EXIT.ok, `monitor verifies the auditor's entries: ${tail.stderr.trim()}`);
  step(`audit ${scanId}: ${String(found.length)} findings proven by the Go CLI`);
  stopWrangler();

  // 4. Corruption, against a static mirror.
  let live: Uint8Array = archive(final);
  const files = new Map(mirror);
  mirrorServer = createServer((req, res) => {
    const prefix = `/log/${LOG_NAME}/`;
    const path = req.url?.startsWith(prefix) === true ? req.url.slice(prefix.length) : '';
    const body = path === CHECKPOINT_PATH ? live : files.get(path);
    if (body === undefined) {
      res.writeHead(404).end();
      return;
    }
    res.writeHead(200, { 'content-length': String(body.length) }).end(body);
  });
  const server = mirrorServer;
  await new Promise<void>((done) => server.listen(0, '127.0.0.1', done));
  const addr = server.address();
  const mirrorUrl = `http://127.0.0.1:${String(typeof addr === 'object' && addr !== null ? addr.port : 0)}/log/${LOG_NAME}`;
  const mirrorFlags = ['--log', mirrorUrl, '--vkey', vkey];

  /** A monitor that saw every checkpoint as it was published. Returns the first non-zero exit. */
  let replays = 0;
  const replay = async (): Promise<{ code: number; size: number; stderr: string }> => {
    const state = join(tmp, `replay-${String(replays++)}.json`);
    for (const size of SIZES) {
      live = files.get(archivedCheckpointPath(size)) ?? new Uint8Array();
      const r = await go(['monitor', '--once', '-q', '--state', state, ...mirrorFlags]);
      if (r.code !== EXIT.ok) return { code: r.code, size, stderr: r.stderr };
    }
    return { code: EXIT.ok, size: final, stderr: '' };
  };

  const baseline = await replay();
  check(baseline.code === EXIT.ok, `uncorrupted replay passes: ${baseline.stderr}`);

  step(`flipping bits in ${String(mirror.size - 1)} resources`);
  let flips = 0;
  for (const [path, orig] of mirror) {
    if (path === CHECKPOINT_PATH) continue; // the replay serves the archives as the live checkpoint
    for (const bit of [0, orig.length * 4 + 3, orig.length * 8 - 1]) {
      const bad = orig.slice();
      bad[bit >> 3] = (bad[bit >> 3] ?? 0) ^ (1 << (bit & 7));
      files.set(path, bad);
      const r = await replay();
      check(
        r.code === EXIT.failure,
        `I7: bit ${String(bit)} of ${path}: exit ${String(r.code)} ${r.stderr.trim()}`,
      );
      flips++;
    }
    files.set(path, orig);
  }

  // Well-formed notes with a bad signature: one signature bit flipped (after the 4-byte key ID,
  // re-encoded as valid base64), and a correctly signed note from another key with the same name.
  const forger = await newSigner(otherKey.skey);
  for (const size of SIZES) {
    const path = archivedCheckpointPath(size);
    const note = utf8Decode(archive(size));
    const [text = '', sigLine = ''] = note.split('\n\n');
    const sig = fromBase64(sigLine.trim().split(' ').at(-1) ?? '');
    sig[10] = (sig[10] ?? 0) ^ 0x01;
    const flipped = `${text}\n\n${sigLine.slice(0, sigLine.lastIndexOf(' ') + 1)}${toBase64(sig)}\n`;
    const forged = await signCheckpoint(parseCheckpoint(`${text}\n`), forger);
    for (const [what, bad] of [
      ['flipped signature bit', flipped],
      ['signature by another key', forged],
    ] as const) {
      files.set(path, new TextEncoder().encode(bad));
      const r = await replay();
      check(
        r.code === EXIT.failure && r.size === size,
        `I7: ${what} on checkpoint ${String(size)}: exit ${String(r.code)} at ${String(r.size)}`,
      );
    }
    files.set(path, archive(size));
  }

  // A missing resource cannot be verified, but it is not evidence of tampering: exit 4.
  for (const path of [tilePath(0, 1, TILE_WIDTH), entryBundlePath(3, TILE_WIDTH)]) {
    const orig = files.get(path);
    files.delete(path);
    const r = await replay();
    check(r.code === EXIT.error, `missing ${path}: exit ${String(r.code)}`);
    if (orig !== undefined) files.set(path, orig);
  }
  const restored = await replay();
  check(restored.code === EXIT.ok, 'replay passes again after restoring every resource');
  step(
    `${String(flips)} bit flips, ${String(SIZES.length * 2)} forged signatures, ${String(replays)} monitor replays`,
  );
}

try {
  await main();
} catch (e) {
  failures.push(e instanceof Error ? e.message : String(e));
  console.error(e);
} finally {
  stopWrangler();
  mirrorServer?.close();
  if (values.keep || failures.length > 0) console.log(`conformance: kept ${tmp}`);
  else rmSync(tmp, { recursive: true, force: true });
}

if (failures.length > 0) {
  console.error(`conformance: ${String(failures.length)} of ${String(checks)} checks failed`);
  process.exit(1);
}
console.log(`conformance: all ${String(checks)} checks passed`);

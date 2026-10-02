// Runs r2notary locally under `wrangler dev` (with the dev-only simulator, as `npm run dev:sim`)
// for the conformance harness and the benchmarks. Local only: no account, no network resources.
//
// Secrets and overrides go through a temporary --env-file. With several configs, wrangler applies
// --env-file to the first one only: any other reads the `.dev.vars` next to its config file if one
// exists (wrangler 4.147, checked in M8; D8.14). So each config is run from a copy in the
// temporary directory, with its relative paths made absolute, where no `.dev.vars` can be, and a
// developer's worker/.dev.vars is never read. Because worker/wrangler.jsonc declares `secrets`,
// wrangler also merges the process environment into them (DECISIONS D5.7), so every config key is
// removed from the child's environment. Ports and the --persist-to directory are chosen per run, and stop() kills the whole
// process group (wrangler and workerd).

import { spawn, type ChildProcess } from 'node:child_process';
import { openSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer as createNetServer } from 'node:net';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';

export const ROOT = resolve(import.meta.dirname, '../..');

/** Keys the Worker config reads from the environment; stripped from the child's environment. */
const CONFIG_KEYS = [
  'SIGNING_KEY',
  'ADMIN_TOKEN',
  'READ_TOKEN',
  'LOG_NAME',
  'LOG_ORIGIN',
  'MONITORED_BUCKET_NAME',
  'LOG_BUCKET_NAME',
  'CHECKPOINT_INTERVAL_MS',
  'BATCH_MAX_ENTRIES',
  'DEDUPE_TTL_SECONDS',
  'EVENTS_DLQ_NAME',
  'AUDIT_GRACE_SECONDS',
  'DEEP_SCRUB_SAMPLE_RATE',
  'DEEP_SCRUB_MAX_BYTES',
  'PUBLIC_LOG',
  'ALERT_WEBHOOK_URL',
  'WITNESSES',
  'WITNESS_QUORUM',
  'KEY_BLINDING_KEY',
  'WITNESS_KEY',
  'WITNESS_LOGS',
];

export const sleep = (ms: number): Promise<void> =>
  new Promise((done) => {
    setTimeout(done, ms);
  });

export const randomToken = (): string =>
  Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('base64url');

export async function freePort(): Promise<number> {
  return new Promise((done, fail) => {
    const srv = createNetServer();
    srv.on('error', fail);
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      const port = typeof addr === 'object' && addr !== null ? addr.port : 0;
      srv.close(() => {
        done(port);
      });
    });
  });
}

export interface DevOptions {
  /** Working directory for the env file, the log and (unless given) the persisted state. */
  readonly dir: string;
  /** Written to the --env-file: secrets and var overrides. */
  readonly vars: Readonly<Record<string, string>>;
  /** Token used to poll /api/v1/status until the Worker answers. */
  readonly readToken: string;
  readonly persistTo?: string;
}

export interface DevServer {
  readonly base: string;
  readonly logPath: string;
  stop(): void;
}

const running = new Set<ChildProcess>();

function kill(child: ChildProcess): void {
  if (child.pid !== undefined && child.exitCode === null) {
    try {
      process.kill(-child.pid, 'SIGTERM'); // the whole process group: wrangler and workerd
    } catch {
      // already gone
    }
  }
}

// A harness that throws or is interrupted must not leave workerd running.
process.on('exit', () => {
  for (const child of running) kill(child);
});

/** Starts wrangler dev and waits until /api/v1/status answers. */
export async function startDev(o: DevOptions): Promise<DevServer> {
  return start({
    ...o,
    name: 'dev',
    configs: ['worker/dev/wrangler.simulator.jsonc', 'worker/wrangler.jsonc'],
    ready: async (base) => {
      const res = await fetch(`${base}/api/v1/status`, {
        headers: { authorization: `Bearer ${o.readToken}` },
      });
      await res.body?.cancel();
      return res.ok;
    },
  });
}

export interface WitnessOptions {
  readonly dir: string;
  /** WITNESS_KEY, WITNESS_LOGS. */
  readonly vars: Readonly<Record<string, string>>;
}

/** Starts the witness Worker (witness/wrangler.jsonc) under its own wrangler dev, on its own port. */
export async function startWitness(o: WitnessOptions): Promise<DevServer> {
  return start({
    ...o,
    name: 'witness',
    configs: ['witness/wrangler.jsonc'],
    // The root path is a 404; any HTTP answer means the Worker is up.
    ready: async (base) => {
      const res = await fetch(`${base}/`);
      await res.body?.cancel();
      return res.status === 404;
    },
  });
}

interface StartOptions {
  readonly dir: string;
  readonly vars: Readonly<Record<string, string>>;
  readonly persistTo?: string;
  readonly name: string;
  readonly configs: readonly string[];
  readonly ready: (base: string) => Promise<boolean>;
}

/** Config keys that hold paths relative to the config file (in the configs this repo has). */
const PATH_KEYS = ['$schema', 'main', 'directory', 'watch_dir'];

/**
 * A copy of a wrangler config in `dir`, with its relative paths made absolute, so wrangler sees no
 * `.dev.vars` next to it (see the module comment). Fails if a path key is written in a form this
 * does not rewrite, rather than run with a broken config.
 */
export function isolatedConfig(dir: string, config: string, tag: string): string {
  const src = resolve(ROOT, config);
  const text = readFileSync(src, 'utf8').replace(
    /"([$\w]+)":\s*"([^"]*)"/g,
    (whole, key: string, value: string) =>
      PATH_KEYS.includes(key) && !isAbsolute(value)
        ? `"${key}": ${JSON.stringify(resolve(dirname(src), value))}`
        : whole,
  );
  for (const key of PATH_KEYS) {
    if (new RegExp(`"${key.replace('$', '\\$')}":\\s*"[.\\w]`).test(text)) {
      throw new Error(`${config}: ${key} was not made absolute`);
    }
  }
  const out = join(dir, `${tag}-${basename(config)}`);
  writeFileSync(out, text);
  return out;
}

async function start(o: StartOptions): Promise<DevServer> {
  const envFile = join(o.dir, `${o.name}.env`);
  writeFileSync(
    envFile,
    `${Object.entries(o.vars)
      .map(([k, v]) => `${k}=${v}`)
      .join('\n')}\n`,
    { mode: 0o600 },
  );
  const port = await freePort();
  const inspectorPort = await freePort();
  const childEnv: NodeJS.ProcessEnv = {
    ...Object.fromEntries(Object.entries(process.env).filter(([k]) => !CONFIG_KEYS.includes(k))),
    WRANGLER_SEND_METRICS: 'false',
  };
  const logPath = join(o.dir, `wrangler-${o.name}-${String(port)}.log`);
  const logFd = openSync(logPath, 'w');
  const child = spawn(
    join(ROOT, 'node_modules/.bin/wrangler'),
    [
      'dev',
      ...o.configs.flatMap((c, i) => ['-c', isolatedConfig(o.dir, c, `${o.name}-${String(i)}`)]),
      '--ip',
      '127.0.0.1',
      '--port',
      String(port),
      '--inspector-port',
      String(inspectorPort),
      '--persist-to',
      o.persistTo ?? join(o.dir, o.name === 'dev' ? 'state' : `${o.name}-state`),
      '--env-file',
      envFile,
      '--show-interactive-dev-session=false',
    ],
    { cwd: ROOT, env: childEnv, stdio: ['ignore', logFd, logFd], detached: true },
  );
  running.add(child);
  const base = `http://127.0.0.1:${String(port)}`;
  const stop = (): void => {
    kill(child);
    running.delete(child);
  };
  for (let i = 0; ; i++) {
    try {
      if (await o.ready(base)) break;
    } catch {
      // not listening yet
    }
    if (child.exitCode !== null || i > 240) {
      stop();
      throw new Error(`wrangler dev did not start:\n${readFileSync(logPath, 'utf8')}`);
    }
    await sleep(500);
  }
  return { base, logPath, stop };
}

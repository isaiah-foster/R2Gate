// Runs r2notary locally under `wrangler dev` (with the dev-only simulator, as `npm run dev:sim`)
// for the conformance harness and the benchmarks. Local only: no account, no network resources.
//
// Secrets and overrides go through a temporary --env-file, so a developer's .dev.vars is never
// read. Because worker/wrangler.jsonc declares `secrets`, wrangler also merges the process
// environment into them (DECISIONS D5.7), so every config key is removed from the child's
// environment. Ports and the --persist-to directory are chosen per run, and stop() kills the whole
// process group (wrangler and workerd).

import { spawn, type ChildProcess } from 'node:child_process';
import { openSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer as createNetServer } from 'node:net';
import { join, resolve } from 'node:path';

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

let running: ChildProcess | null = null;

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
  if (running !== null) kill(running);
});

/** Starts wrangler dev and waits until /api/v1/status answers. */
export async function startDev(o: DevOptions): Promise<DevServer> {
  const envFile = join(o.dir, 'dev.env');
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
  const logPath = join(o.dir, `wrangler-${String(port)}.log`);
  const logFd = openSync(logPath, 'w');
  const child = spawn(
    join(ROOT, 'node_modules/.bin/wrangler'),
    [
      'dev',
      '-c',
      'worker/dev/wrangler.simulator.jsonc',
      '-c',
      'worker/wrangler.jsonc',
      '--ip',
      '127.0.0.1',
      '--port',
      String(port),
      '--inspector-port',
      String(inspectorPort),
      '--persist-to',
      o.persistTo ?? join(o.dir, 'state'),
      '--env-file',
      envFile,
      '--show-interactive-dev-session=false',
    ],
    { cwd: ROOT, env: childEnv, stdio: ['ignore', logFd, logFd], detached: true },
  );
  running = child;
  const base = `http://127.0.0.1:${String(port)}`;
  const stop = (): void => {
    kill(child);
    if (running === child) running = null;
  };
  for (let i = 0; ; i++) {
    try {
      const res = await fetch(`${base}/api/v1/status`, {
        headers: { authorization: `Bearer ${o.readToken}` },
      });
      if (res.ok) break;
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

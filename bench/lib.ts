// Shared helpers for the benchmarks (PLAN §14): environment capture, summary statistics, and the
// result files under bench/results/. Every figure the docs quote comes from one of those files
// (CLAUDE.md working agreement 6); docs/BENCHMARKS.md describes how each is produced.

import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { cpus, platform, release, totalmem } from 'node:os';
import { join } from 'node:path';
import { ROOT } from '../scripts/lib/dev.ts';

export { ROOT };
export const RESULTS = join(ROOT, 'bench/results');

function tryRun(cmd: string, args: readonly string[]): string | null {
  try {
    return execFileSync(cmd, args, { cwd: ROOT, encoding: 'utf8' }).trim();
  } catch {
    return null;
  }
}

function packageVersion(name: string): string | null {
  try {
    const pkg = JSON.parse(
      readFileSync(join(ROOT, 'node_modules', name, 'package.json'), 'utf8'),
    ) as { version: string };
    return pkg.version;
  } catch {
    return null;
  }
}

export interface Environment {
  readonly date: string;
  readonly commit: string | null;
  /** True if the working tree had uncommitted changes when the benchmark ran. */
  readonly dirty: boolean;
  readonly os: string;
  readonly cpu: string;
  readonly cpus: number;
  readonly memoryGiB: number;
  readonly node: string;
  readonly go: string | null;
  readonly wrangler: string | null;
  readonly workerd: string | null;
  /** Where the measured code ran. Nothing here has run on Cloudflare's network yet. */
  readonly runtime: string;
}

export function environment(runtime: string): Environment {
  return {
    date: new Date().toISOString(),
    commit: tryRun('git', ['rev-parse', '--short', 'HEAD']),
    dirty: (tryRun('git', ['status', '--porcelain']) ?? '') !== '',
    os: `${platform()} ${release()}`,
    cpu: cpus()[0]?.model.trim() ?? 'unknown',
    cpus: cpus().length,
    memoryGiB: Math.round(totalmem() / 2 ** 30),
    node: process.version,
    go: tryRun('go', ['env', 'GOVERSION']),
    wrangler: packageVersion('wrangler'),
    workerd: packageVersion('workerd'),
    runtime,
  };
}

export interface Summary {
  readonly n: number;
  readonly min: number;
  readonly median: number;
  readonly p95: number;
  readonly p99: number;
  readonly max: number;
  readonly mean: number;
}

/** Nearest-rank percentile (no interpolation), so every reported value was actually observed. */
function percentile(sorted: readonly number[], p: number): number {
  const rank = Math.max(1, Math.ceil((p / 100) * sorted.length));
  return sorted[rank - 1] ?? Number.NaN;
}

const round = (x: number, digits = 3): number => Number(x.toFixed(digits));

export function summarize(samples: readonly number[], digits = 3): Summary {
  if (samples.length === 0) throw new Error('no samples');
  const s = [...samples].sort((a, b) => a - b);
  return {
    n: s.length,
    min: round(s[0] ?? Number.NaN, digits),
    median: round(percentile(s, 50), digits),
    p95: round(percentile(s, 95), digits),
    p99: round(percentile(s, 99), digits),
    max: round(s.at(-1) ?? Number.NaN, digits),
    mean: round(s.reduce((a, b) => a + b, 0) / s.length, digits),
  };
}

export { round };

/** Writes bench/results/<name>.json and prints where. */
export function writeResult(name: string, result: Record<string, unknown>): void {
  const path = join(RESULTS, `${name}.json`);
  writeFileSync(path, `${JSON.stringify(result, null, 2)}\n`);
  console.log(`bench: wrote ${path}`);
}

export const nowMs = (): number => performance.now();

/** Parses `--name value` style integer lists such as "1,10,100". */
export function intList(v: string): number[] {
  return v.split(',').map((x) => {
    const n = Number(x);
    if (!Number.isSafeInteger(n) || n < 1) throw new Error(`not a positive integer: ${x}`);
    return n;
  });
}

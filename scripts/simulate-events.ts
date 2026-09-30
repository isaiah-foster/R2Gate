// Sends synthetic R2 event notifications to a local r2notary (PLAN §5.4, M3). Local R2 does not
// emit notifications, so this stands in for R2 + the queue's producer side.
//
//   npm run dev:sim                          # terminal 1: wrangler dev with the simulator
//   npm run simulate -- --count 200 --duplicates 0.2 --shuffle 20 --malformed 5 --loop 3
//   curl -s localhost:8787/api/v1/status     # compare the counters with the printed manifest
//
// --dry-run prints the messages as JSON lines instead of sending them. Only talks to the URL
// given (default http://localhost:8787); it has no way to reach a real queue.
//
// --objects writes `count` real objects (<prefix>1 .. <prefix>N, a line of text each) to the
// local monitored bucket instead, each with the notification R2 would send, so the auditor sees a
// bucket that matches the log (worker/dev/simulator.ts /__simulate/objects):
//   npm run simulate -- --objects --count 300 --prefix demo/obj-

import { parseArgs } from 'node:util';
import { simulate } from './simulate/events.ts';

const SEND_PATH = '/__simulate/send'; // worker/dev/simulator.ts
const OBJECTS_PATH = '/__simulate/objects';
const CHUNK = 100; // sendBatch maximum

const { values } = parseArgs({
  options: {
    url: { type: 'string', default: 'http://localhost:8787' },
    count: { type: 'string', default: '100' },
    seed: { type: 'string', default: String(Date.now() % 2 ** 31) },
    keys: { type: 'string' },
    duplicates: { type: 'string', default: '0' },
    shuffle: { type: 'string', default: '0' },
    malformed: { type: 'string', default: '0' },
    loop: { type: 'string', default: '0' },
    foreign: { type: 'string', default: '0' },
    bucket: { type: 'string', default: 'example-monitored-bucket' },
    'log-bucket': { type: 'string', default: 'example-log-bucket' },
    'dry-run': { type: 'boolean', default: false },
    objects: { type: 'boolean', default: false },
    prefix: { type: 'string', default: 'demo/obj-' },
    help: { type: 'boolean', default: false },
  },
});

if (values.help) {
  console.log(
    'usage: simulate-events [--url U] [--count N] [--seed S] [--keys K] [--duplicates 0..1]\n' +
      '         [--shuffle W] [--malformed N] [--loop N] [--foreign N] [--bucket B]\n' +
      '         [--log-bucket B] [--dry-run]\n' +
      '       simulate-events --objects [--url U] [--count N] [--prefix P]',
  );
  process.exit(0);
}

function num(name: string, v: string, max = Number.MAX_SAFE_INTEGER): number {
  const n = Number(v);
  if (!Number.isFinite(n) || n < 0 || n > max)
    throw new Error(`--${name} must be 0..${String(max)}`);
  return n;
}
const whole = (name: string, v: string): number => {
  const n = num(name, v);
  if (!Number.isInteger(n)) throw new Error(`--${name} must be an integer`);
  return n;
};

async function post(path: string, body: unknown): Promise<void> {
  const res = await fetch(new URL(path, values.url), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${path} failed: ${String(res.status)} ${await res.text()}`);
}

if (values.objects) {
  const count = whole('count', values.count);
  const ops = Array.from({ length: count }, (_, i) => ({
    op: 'put',
    key: `${values.prefix}${String(i + 1)}`,
    text: `object ${String(i + 1)}\n`,
  }));
  for (let i = 0; i < ops.length; i += CHUNK) await post(OBJECTS_PATH, ops.slice(i, i + CHUNK));
  console.error(JSON.stringify({ objects: count, keys: `${values.prefix}1..${String(count)}` }));
  process.exit(0);
}

const seed = whole('seed', values.seed);
const { messages, manifest } = simulate({
  count: whole('count', values.count),
  bucket: values.bucket,
  seed,
  ...(values.keys === undefined ? {} : { keys: whole('keys', values.keys) }),
  duplicateRate: num('duplicates', values.duplicates, 1),
  shuffleWindow: whole('shuffle', values.shuffle),
  malformed: whole('malformed', values.malformed),
  loop: whole('loop', values.loop),
  logBucket: values['log-bucket'],
  foreign: whole('foreign', values.foreign),
});

if (values['dry-run']) {
  for (const m of messages) console.log(JSON.stringify(m));
} else {
  // undefined fields (one malformed variant) are dropped by JSON, as they would be on a real queue.
  for (let i = 0; i < messages.length; i += CHUNK) {
    await post(SEND_PATH, messages.slice(i, i + CHUNK));
  }
}

const { objects, ...counts } = manifest;
console.error(
  JSON.stringify(
    {
      seed,
      messages: messages.length,
      expected: { ...counts, keys: objects.length },
      note: 'counters are cumulative; compare with the change in /api/v1/status',
    },
    null,
    2,
  ),
);

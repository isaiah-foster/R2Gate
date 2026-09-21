// Sends synthetic R2 event notifications to a local r2notary (PLAN §5.4, M3). Local R2 does not
// emit notifications, so this stands in for R2 + the queue's producer side.
//
//   npm run dev:sim                          # terminal 1: wrangler dev with the simulator
//   npm run simulate -- --count 200 --duplicates 0.2 --shuffle 20 --malformed 5 --loop 3
//   curl -s localhost:8787/api/v1/status     # compare the counters with the printed manifest
//
// --dry-run prints the messages as JSON lines instead of sending them. Only talks to the URL
// given (default http://localhost:8787); it has no way to reach a real queue.

import { parseArgs } from 'node:util';
import { simulate } from './simulate/events.ts';

const SEND_PATH = '/__simulate/send'; // worker/dev/simulator.ts
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
    help: { type: 'boolean', default: false },
  },
});

if (values.help) {
  console.log(
    'usage: simulate-events [--url U] [--count N] [--seed S] [--keys K] [--duplicates 0..1]\n' +
      '         [--shuffle W] [--malformed N] [--loop N] [--foreign N] [--bucket B]\n' +
      '         [--log-bucket B] [--dry-run]',
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
    const res = await fetch(new URL(SEND_PATH, values.url), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(messages.slice(i, i + CHUNK)),
    });
    if (!res.ok) throw new Error(`send failed: ${String(res.status)} ${await res.text()}`);
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

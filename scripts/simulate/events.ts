// Synthetic R2 event notification messages (PLAN §5.4, M3). Local R2 does not emit notifications,
// so this generates what R2 would put on the queue, in the shape the event-notification docs give:
// {account, action, bucket, object{key, size?, eTag?}, eventTime, copySource?{bucket, object}}.
//
// Pure and deterministic for a given seed, so the worker tests and `scripts/simulate-events.ts`
// produce the same traffic. Alongside the messages it returns a manifest of what the consumer is
// expected to do with them (counters and final per-key state), which the tests compare against.

export interface R2EventMessage {
  account: string;
  action: string;
  bucket: string;
  object: { key: string; size?: number; eTag?: string };
  eventTime: string;
  copySource?: { bucket: string; object: string };
}

export interface SimulateOptions {
  /** Distinct valid events for the monitored bucket. */
  readonly count: number;
  readonly bucket: string;
  readonly seed?: number;
  /** Number of distinct keys the events touch (default: count / 4, at least 1). */
  readonly keys?: number;
  /** Fraction of valid events delivered a second time, as an at-least-once queue may (0..1). */
  readonly duplicateRate?: number;
  /** Maximum distance a message moves from its place in time order (0 = in order). */
  readonly shuffleWindow?: number;
  /** Messages that violate the documented shape. */
  readonly malformed?: number;
  /** Events from the log bucket (must never be logged, I8). Requires `logBucket`. */
  readonly loop?: number;
  readonly logBucket?: string;
  /** Events from some other bucket. */
  readonly foreign?: number;
  /** First event time (ms since the epoch); later events are 1-1,000 ms apart. */
  readonly startMs?: number;
}

export interface ExpectedObject {
  readonly key: string;
  readonly deleted: boolean;
  readonly etag: string | null;
  readonly size: number | null;
}

export interface Manifest {
  /** What the consumer's counters should show after every message is delivered once. */
  readonly accepted: number;
  readonly duplicates: number;
  readonly invalid: number;
  readonly loopDropped: number;
  readonly foreignDropped: number;
  readonly deletes: number;
  /** Final state per key (the latest event by eventTime), sorted by key. */
  readonly objects: readonly ExpectedObject[];
}

export interface Simulation {
  /** Message bodies in delivery order. Malformed ones are not R2EventMessages. */
  readonly messages: unknown[];
  readonly manifest: Manifest;
}

/** Placeholder account ID; the consumer must never log it. */
export const SIM_ACCOUNT = '0123456789abcdef0123456789abcdef';

// Keys beyond plain ASCII, so ordering and escaping are exercised end to end.
const ODD_KEYS = ['sim/ünïcødé/ファイル', 'sim/with space', 'sim/a|b|c', 'sim/"quoted"', 'sim/😀'];

/** mulberry32: small, seedable, good enough for test traffic. */
function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function malformedMessages(n: number, bucket: string, at: (i: number) => string): unknown[] {
  const ok = (i: number): R2EventMessage => ({
    account: SIM_ACCOUNT,
    action: 'PutObject',
    bucket,
    object: { key: `bad/${String(i)}`, size: 1, eTag: 'd41d8cd98f00b204e9800998ecf8427e' },
    eventTime: at(i),
  });
  const variants: ((i: number) => unknown)[] = [
    () => 'not an object',
    () => null,
    (i) => ({ ...ok(i), object: undefined }),
    (i) => ({ ...ok(i), action: 'PutObjectAcl' }),
    (i) => ({ ...ok(i), eventTime: '24 May 2024 19:36' }),
    (i) => ({ ...ok(i), action: 'DeleteObject' }), // deletes carry no size or eTag
    (i) => ({ ...ok(i), object: { key: `bad/${String(i)}`, size: 1, eTag: '"quoted"' } }),
    (i) => ({ ...ok(i), object: { key: '', size: 1, eTag: 'e' } }),
    (i) => ({ ...ok(i), object: { key: `bad/${String(i)}`, size: -1, eTag: 'e' } }),
    (i) => ({ ...ok(i), object: { key: `bad/${String(i)}`, size: 1.5, eTag: 'e' } }),
    (i) => ({ ...ok(i), copySource: { bucket, object: 'src' } }), // copySource on a PutObject
    (i) => ({ ...ok(i), bucket: 42 }),
  ];
  return Array.from({ length: n }, (_, i) => {
    const make = variants[i % variants.length];
    if (make === undefined) throw new Error('unreachable');
    return make(i);
  });
}

export function simulate(o: SimulateOptions): Simulation {
  const rand = rng(o.seed ?? 1);
  const int = (n: number): number => Math.floor(rand() * n);
  const hex = (len: number): string =>
    Array.from({ length: len }, () => int(16).toString(16)).join('');

  let ms = o.startMs ?? Date.UTC(2026, 9, 2, 12);
  // Strictly increasing times: no two generated events share an eventId by accident.
  const nextTime = (): string => {
    ms += 1 + int(1000);
    return new Date(ms).toISOString();
  };

  const keyCount = Math.max(1, o.keys ?? Math.floor(o.count / 4));
  const keys = Array.from({ length: keyCount }, (_, i) => ODD_KEYS[i] ?? `sim/${String(i)}`);
  const live = new Map<string, { etag: string; size: number }>();
  const final = new Map<string, ExpectedObject>();
  const valid: R2EventMessage[] = [];
  let deletes = 0;

  for (let i = 0; i < o.count; i++) {
    const key = keys[int(keys.length)] ?? 'sim/0';
    const existing = live.get(key);
    const choice = int(existing === undefined ? 3 : 5);
    const base = { account: SIM_ACCOUNT, bucket: o.bucket, eventTime: nextTime() };
    if (existing !== undefined && choice >= 3) {
      const action = choice === 3 ? 'DeleteObject' : 'LifecycleDeletion';
      valid.push({ ...base, action, object: { key } });
      live.delete(key);
      final.set(key, { key, deleted: true, etag: null, size: null });
      deletes++;
      continue;
    }
    const sources = [...live.keys()].filter((k) => k !== key);
    const source = choice === 1 ? sources[int(sources.length)] : undefined;
    const state =
      source !== undefined
        ? (live.get(source) ?? { etag: hex(32), size: int(1 << 20) })
        : { etag: choice === 2 ? `${hex(32)}-${String(2 + int(8))}` : hex(32), size: int(1 << 20) };
    const action =
      source !== undefined ? 'CopyObject' : choice === 2 ? 'CompleteMultipartUpload' : 'PutObject';
    valid.push({
      ...base,
      action,
      object: { key, size: state.size, eTag: state.etag },
      ...(source !== undefined ? { copySource: { bucket: o.bucket, object: source } } : {}),
    });
    live.set(key, state);
    final.set(key, { key, deleted: false, etag: state.etag, size: state.size });
  }

  const duplicates = valid.filter(() => rand() < (o.duplicateRate ?? 0));
  const loop = Array.from({ length: o.loop ?? 0 }, (_, i): R2EventMessage => {
    if (o.logBucket === undefined) throw new Error('loop events need logBucket');
    return {
      account: SIM_ACCOUNT,
      action: 'PutObject',
      bucket: o.logBucket,
      object: { key: `log/tile/0/${String(i).padStart(3, '0')}`, size: 8192, eTag: hex(32) },
      eventTime: nextTime(),
    };
  });
  const foreign = Array.from({ length: o.foreign ?? 0 }, (_, i): R2EventMessage => ({
    account: SIM_ACCOUNT,
    action: 'DeleteObject',
    bucket: 'some-other-bucket',
    object: { key: `elsewhere/${String(i)}` },
    eventTime: nextTime(),
  }));
  const malformed = malformedMessages(o.malformed ?? 0, o.bucket, () => nextTime());

  // Copies, not shared references: a redelivered message is a separate deserialized body.
  const messages: unknown[] = [...valid, ...duplicates, ...loop, ...foreign, ...malformed].map(
    (m) => structuredClone(m),
  );
  // Local reordering: each step swaps a message with one up to `shuffleWindow` places later.
  const w = o.shuffleWindow ?? 0;
  for (let i = 0; i < messages.length && w > 0; i++) {
    const j = Math.min(messages.length - 1, i + int(w + 1));
    [messages[i], messages[j]] = [messages[j], messages[i]];
  }

  return {
    messages,
    manifest: {
      accepted: valid.length,
      duplicates: duplicates.length,
      invalid: malformed.length,
      loopDropped: loop.length,
      foreignDropped: foreign.length,
      deletes,
      objects: [...final.values()].sort((a, b) => compareUtf8(a.key, b.key)),
    },
  };
}

/** Byte-wise UTF-8 order, which is how SQLite (BINARY) and R2 list() order keys. */
function compareUtf8(a: string, b: string): number {
  const ea = new TextEncoder().encode(a);
  const eb = new TextEncoder().encode(b);
  for (let i = 0; i < Math.min(ea.length, eb.length); i++) {
    const d = (ea[i] ?? 0) - (eb[i] ?? 0);
    if (d !== 0) return d;
  }
  return ea.length - eb.length;
}

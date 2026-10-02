import { describe, expect, it } from 'vitest';
import { MAX_ENTRY_SIZE } from '../src/bundle.ts';
import {
  EntryError,
  MAX_OBJECT_KEY_BYTES,
  decodeEntry,
  encodeEntry,
  type AuditFinding,
  type Entry,
  type ObjectEvent,
} from '../src/entry.ts';

const enc = new TextEncoder();
const SHA_A = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const SHA_B = 'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb';
const dec = new TextDecoder();

const put: ObjectEvent = {
  v: 1,
  type: 'object.event',
  bucket: 'my-bucket',
  key: 'photos/2026/cat.jpg',
  action: 'PutObject',
  size: 65536,
  etag: 'c846ff7a18f28c2e262116d6e8719ef0',
  eventTime: '2024-05-24T19:36:44.379Z',
  ingestedAt: '2024-05-24T19:36:45.001Z',
};

const valid: Entry[] = [
  put,
  { ...put, action: 'CompleteMultipartUpload', etag: 'd41d8cd98f00b204e9800998ecf8427e-3' },
  {
    ...put,
    action: 'CopyObject',
    copySource: { bucket: 'my-bucket', key: 'photos/original.jpg' },
  },
  {
    v: 1,
    type: 'object.event',
    bucket: 'my-bucket',
    key: 'gone',
    action: 'DeleteObject',
    eventTime: '2024-05-24T19:36:44Z',
    ingestedAt: '2024-05-24T19:36:45+00:00',
  },
  { ...put, action: 'PutObject', size: 0, key: 'ключ/🔑\u0001' },
  {
    v: 1,
    type: 'object.snapshot',
    bucket: 'my-bucket',
    key: 'a',
    size: 1,
    etag: 'abc',
    uploaded: '2026-01-01T00:00:00.000Z',
    snapshotId: 'snap-2026-01-01',
  },
  {
    v: 1,
    type: 'audit.finding',
    kind: 'UNLOGGED_OBJECT',
    bucket: 'my-bucket',
    key: 'a',
    observed: { etag: 'abc', size: 1, uploaded: '2026-01-01T00:00:00Z' },
    scanId: 'scan-1',
    observedAt: '2026-01-01T00:10:00Z',
    graceSeconds: 300,
  },
  {
    v: 1,
    type: 'audit.finding',
    kind: 'MISSING_OBJECT',
    bucket: 'my-bucket',
    key: 'a',
    expected: { etag: 'abc', size: 1, eventTime: '2026-01-01T00:00:00Z', seq: 41 },
    scanId: 'scan-1',
    observedAt: '2026-01-01T00:10:00Z',
    graceSeconds: 300,
  },
  {
    v: 1,
    type: 'audit.finding',
    kind: 'PHANTOM_DELETE',
    bucket: 'my-bucket',
    key: 'a',
    observed: { etag: 'abc', size: 1, uploaded: '2026-01-01T00:05:00Z' },
    expected: { eventTime: '2026-01-01T00:00:00Z', seq: 42 },
    scanId: 'scan-1',
    observedAt: '2026-01-01T00:10:00Z',
    graceSeconds: 300,
  },
  { v: 1, type: 'audit.scan', scanId: 'scan-1', phase: 'start', logSizeAtStart: 1000 },
  { v: 1, type: 'audit.scan', scanId: 'scan-1', phase: 'end', objectsScanned: 10, findings: 2 },
  {
    v: 1,
    type: 'audit.finding',
    kind: 'ETAG_MISMATCH',
    bucket: 'my-bucket',
    key: 'a',
    observed: { etag: 'def', size: 1, uploaded: '2026-01-01T00:05:00Z' },
    expected: { etag: 'abc', size: 1, eventTime: '2026-01-01T00:00:00Z', seq: 7 },
    scanId: 'scan-1',
    observedAt: '2026-01-01T00:10:00Z',
    graceSeconds: 0,
  },
  {
    v: 1,
    type: 'audit.observation',
    bucket: 'my-bucket',
    key: 'a',
    etag: 'abc',
    size: 1,
    sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    scanId: 'scan-1',
    observedAt: '2026-01-01T00:10:00Z',
  },
  // Deep scrub: the bytes changed but the ETag did not, against an earlier logged observation...
  {
    v: 1,
    type: 'audit.finding',
    kind: 'CONTENT_DRIFT',
    bucket: 'my-bucket',
    key: 'a',
    observed: { etag: 'abc', size: 1, uploaded: '2026-01-01T00:00:00Z', sha256: SHA_B },
    expected: { etag: 'abc', size: 1, eventTime: '2025-12-01T00:00:00Z', seq: 9, sha256: SHA_A },
    scanId: 'scan-1',
    observedAt: '2026-01-01T00:10:00Z',
    graceSeconds: 300,
  },
  // ... or against the SHA-256 R2 stored at upload, which has no log index.
  {
    v: 1,
    type: 'audit.finding',
    kind: 'CONTENT_DRIFT',
    bucket: 'my-bucket',
    key: 'a',
    observed: { etag: 'abc', size: 1, uploaded: '2026-01-01T00:00:00Z', sha256: SHA_B },
    expected: { etag: 'abc', eventTime: '2026-01-01T00:00:00Z', sha256: SHA_A },
    scanId: 'scan-1',
    observedAt: '2026-01-01T00:10:00Z',
    graceSeconds: 300,
  },
];
const drift = valid.find(
  (e): e is AuditFinding => e.type === 'audit.finding' && e.kind === 'CONTENT_DRIFT',
);
const observation = valid.find((e) => e.type === 'audit.observation');
const mismatch = valid.find((e) => e.type === 'audit.finding' && e.kind === 'ETAG_MISMATCH');

describe('entry encoding', () => {
  it.each(valid.map((e) => [`${e.type}${'action' in e ? ` ${e.action}` : ''}`, e] as const))(
    'round-trips %s',
    (_name, e) => {
      const b = encodeEntry(e);
      expect(decodeEntry(b)).toEqual({ known: true, entry: e });
    },
  );

  it('is canonical JSON with sorted keys', () => {
    expect(dec.decode(encodeEntry(put))).toBe(
      '{"action":"PutObject","bucket":"my-bucket","etag":"c846ff7a18f28c2e262116d6e8719ef0",' +
        '"eventTime":"2024-05-24T19:36:44.379Z","ingestedAt":"2024-05-24T19:36:45.001Z",' +
        '"key":"photos/2026/cat.jpg","size":65536,"type":"object.event","v":1}',
    );
  });

  // Sharp edge 6: R2 keys are up to 1,024 bytes; a worst-case entry must still fit in a bundle.
  it('a maximal object.event (two 1,024-byte keys of control characters) fits in 65,535 bytes', () => {
    const worstKey = '\u0001'.repeat(MAX_OBJECT_KEY_BYTES); // each escapes to 6 bytes
    const e: ObjectEvent = {
      ...put,
      action: 'CopyObject',
      key: worstKey,
      etag: 'x'.repeat(256),
      copySource: { bucket: 'b'.repeat(63), key: worstKey },
    };
    const size = encodeEntry(e).length;
    expect(size).toBeGreaterThan(12_000);
    expect(size).toBeLessThan(MAX_ENTRY_SIZE);
  });

  it('rejects keys longer than 1,024 UTF-8 bytes', () => {
    expect(() => encodeEntry({ ...put, key: 'é'.repeat(513) })).toThrow(/key/);
    expect(() => encodeEntry({ ...put, key: 'é'.repeat(512) })).not.toThrow();
  });

  it('refuses to encode any version other than 1', () => {
    expect(() => encodeEntry({ ...put, v: 2 } as unknown as Entry)).toThrow();
  });

  const bad: [string, unknown][] = [
    ['unknown action', { ...put, action: 'PutBucket' }],
    ['empty key', { ...put, key: '' }],
    ['lone surrogate in key', { ...put, key: 'a\ud800' }],
    ['uppercase bucket', { ...put, bucket: 'My-Bucket' }],
    ['short bucket', { ...put, bucket: 'ab' }],
    ['bucket with leading hyphen', { ...put, bucket: '-abc' }],
    ['negative size', { ...put, size: -1 }],
    ['float size', { ...put, size: 1.5 }],
    ['size as string', { ...put, size: '1' }],
    ['etag with space', { ...put, etag: 'a b' }],
    ['quoted etag', { ...put, etag: '"abc"' }],
    ['local time', { ...put, eventTime: '2024-05-24T19:36:44' }],
    ['date only', { ...put, eventTime: '2024-05-24' }],
    ['impossible date', { ...put, eventTime: '2024-13-45T99:99:99Z' }],
    ['February 30', { ...put, eventTime: '2023-02-30T00:00:00Z' }],
    ['lowercase t', { ...put, eventTime: '2024-05-24t19:36:44Z' }],
    ['extra field', { ...put, account: '3f4b7e3dcab231cbfdaa90a6a28bd548' }],
    ['missing eventTime', { ...put, eventTime: undefined }],
    ['delete with size', { ...valid[3], size: 1 }],
    ['delete with etag', { ...valid[3], etag: 'abc' }],
    ['copySource on PutObject', { ...put, copySource: { bucket: 'my-bucket', key: 'x' } }],
    ['copySource with extra field', { ...valid[2], copySource: { bucket: 'b-1', key: 'x', z: 1 } }],
    ['snapshot without etag', { ...valid[5], etag: undefined }],
    ['snapshot id with slash', { ...valid[5], snapshotId: 'a/b' }],
    ['snapshot id starting with dot', { ...valid[5], snapshotId: '..' }],
    ['finding with unknown kind', { ...valid[6], kind: 'WHATEVER' }],
    ['UNLOGGED_OBJECT without observed', { ...valid[6], observed: undefined }],
    [
      'MISSING_OBJECT with observed',
      { ...valid[7], observed: { etag: 'a', size: 1, uploaded: '2026-01-01T00:00:00Z' } },
    ],
    ['finding with negative grace', { ...valid[6], graceSeconds: -1 }],
    ['scan with unknown phase', { ...valid[9], phase: 'middle' }],
    ['scan start with end-only fields', { ...valid[9], findings: 1 }],
    [
      'CONTENT_DRIFT without observed sha256',
      { ...drift, observed: { ...drift?.observed, sha256: undefined } },
    ],
    [
      'CONTENT_DRIFT without expected sha256',
      { ...drift, expected: { ...drift?.expected, sha256: undefined } },
    ],
    [
      'sha256 on an ETAG_MISMATCH',
      {
        ...mismatch,
        observed: { etag: 'd', size: 1, uploaded: '2026-01-01T00:00:00Z', sha256: SHA_A },
      },
    ],
    [
      'ETAG_MISMATCH without expected seq',
      { ...mismatch, expected: { etag: 'abc', eventTime: '2026-01-01T00:00:00Z' } },
    ],
    [
      'MISSING_OBJECT without expected seq',
      { ...valid[7], expected: { eventTime: '2026-01-01T00:00:00Z' } },
    ],
    [
      'observation with uppercase sha256',
      {
        ...observation,
        sha256: 'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855',
      },
    ],
  ];

  it.each(bad)('refuses to encode: %s', (_name, e) => {
    expect(() => encodeEntry(e as Entry)).toThrow(EntryError);
  });

  it.each(bad)('refuses to decode: %s', (_name, e) => {
    // Bypass encodeEntry's validation to build the bytes a malicious writer could publish.
    const raw = JSON.stringify(
      Object.fromEntries(
        Object.entries(e as Record<string, unknown>)
          .filter(([, v]) => v !== undefined)
          .sort(([a], [b]) => (a < b ? -1 : 1)),
      ),
    );
    expect(() => decodeEntry(enc.encode(raw))).toThrow();
  });

  it('rejects non-canonical bytes even if the content is valid', () => {
    const pretty = JSON.stringify(JSON.parse(dec.decode(encodeEntry(put))), null, 1);
    expect(() => decodeEntry(enc.encode(pretty))).toThrow();
  });

  it('reports unknown types (and versions) as unknown instead of failing', () => {
    expect(decodeEntry(enc.encode('{"type":"future.thing","v":1,"x":1}'))).toEqual({
      known: false,
      type: 'future.thing',
      v: 1,
    });
    expect(decodeEntry(enc.encode('{"type":"object.event","v":2}'))).toEqual({
      known: false,
      type: 'object.event',
      v: 2,
    });
  });

  it('rejects entries that are not objects or lack v/type', () => {
    for (const s of ['[]', '1', '{"v":1}', '{"type":"object.event"}', '{"type":1,"v":1}']) {
      expect(() => decodeEntry(enc.encode(s)), s).toThrow();
    }
  });

  it('rejects an entry over 65,535 bytes', () => {
    const big = enc.encode(`{"type":"future.thing","v":1,"x":"${'a'.repeat(MAX_ENTRY_SIZE)}"}`);
    expect(() => decodeEntry(big)).toThrow(/65535/);
  });
});

describe('blinded keys (M8: keyHmac instead of key)', () => {
  const H = 'a'.repeat(64);
  const H2 = 'b'.repeat(64);
  const unnamed = {
    v: 1,
    type: 'object.event',
    bucket: 'my-bucket',
    action: 'PutObject',
    size: 65536,
    etag: 'c846ff7a18f28c2e262116d6e8719ef0',
    eventTime: '2024-05-24T19:36:44.379Z',
    ingestedAt: '2024-05-24T19:36:45.001Z',
  } as const;

  it('accepts keyHmac in place of key in every entry that names an object', () => {
    const entries: Entry[] = [
      { ...unnamed, keyHmac: H },
      {
        ...unnamed,
        keyHmac: H,
        action: 'CopyObject',
        copySource: { bucket: 'my-bucket', keyHmac: H2 },
      },
      {
        v: 1,
        type: 'object.snapshot',
        bucket: 'my-bucket',
        keyHmac: H,
        size: 1,
        etag: 'abc',
        uploaded: '2026-01-01T00:00:00.000Z',
        snapshotId: 'snap-1',
      },
      {
        v: 1,
        type: 'audit.finding',
        kind: 'MISSING_OBJECT',
        bucket: 'my-bucket',
        keyHmac: H,
        expected: { etag: 'abc', size: 1, eventTime: '2026-01-01T00:00:00Z', seq: 41 },
        scanId: 'scan-1',
        observedAt: '2026-01-01T00:10:00Z',
        graceSeconds: 300,
      },
      {
        v: 1,
        type: 'audit.observation',
        bucket: 'my-bucket',
        keyHmac: H,
        etag: 'abc',
        size: 1,
        sha256: SHA_A,
        scanId: 'scan-1',
        observedAt: '2026-01-01T00:10:00Z',
      },
    ];
    for (const e of entries) {
      const bytes = encodeEntry(e);
      expect(dec.decode(bytes)).not.toContain('"key"');
      expect(decodeEntry(bytes)).toEqual({ known: true, entry: e });
    }
  });

  it('requires exactly one of key and keyHmac, and never mixes them in one entry', () => {
    const bad: unknown[] = [
      unnamed,
      { ...put, keyHmac: H },
      { ...unnamed, keyHmac: H.toUpperCase() },
      { ...unnamed, keyHmac: H.slice(1) },
      { ...unnamed, keyHmac: 42 },
      // A blinded entry must not disclose its copy source's name, and the reverse is just as odd.
      {
        ...unnamed,
        keyHmac: H,
        action: 'CopyObject',
        copySource: { bucket: 'my-bucket', key: 'x' },
      },
      { ...put, action: 'CopyObject', copySource: { bucket: 'my-bucket', keyHmac: H2 } },
      {
        ...unnamed,
        keyHmac: H,
        action: 'CopyObject',
        copySource: { bucket: 'my-bucket', key: 'x', keyHmac: H2 },
      },
    ];
    for (const e of bad) {
      expect(() => encodeEntry(e as Entry), JSON.stringify(e)).toThrow(EntryError);
    }
  });
});

// The browser verifier's logic (M8), run in Node against logs built in memory with the core writer
// functions. Like the Go CLI's tests (I7), every published resource is corrupted in turn and the
// verifier must report the log as lying (VerifyError), never accept it; a missing resource is
// "unavailable" (UnavailableError), not evidence.
import {
  CHECKPOINT_PATH,
  EMPTY_LOG,
  appendEntries,
  archivedCheckpointPath,
  encodeEntry,
  entryBundlePath,
  generateCosignerKey,
  generateKey,
  newCosigner,
  newSigner,
  signCheckpoint,
  tilePath,
  tilesForTreeSize,
  utf8Encode,
  type LogState,
} from '@r2notary/core';
import { beforeAll, describe, expect, it } from 'vitest';
import {
  UnavailableError,
  VerifyError,
  openLog,
  proveConsistency,
  proveEntry,
  recentEntries,
  type LogSource,
} from '../src/verifier.ts';

const ORIGIN = 'r2notary.example.com/log/test';

function entry(i: number): Uint8Array {
  return encodeEntry({
    v: 1,
    type: 'object.event',
    bucket: 'example-monitored-bucket',
    key: `obj/${String(i)}`,
    action: 'PutObject',
    size: i,
    etag: `etag-${String(i)}`,
    eventTime: '2026-10-02T12:00:00.000Z',
    ingestedAt: '2026-10-02T12:00:01.000Z',
  });
}

/** A log published at each of `sizes`, every resource kept, as the Worker would leave it. */
async function buildLog(sizes: readonly number[], cosigners: string[] = []) {
  const { skey, vkey } = await generateKey(ORIGIN);
  const signer = await newSigner(skey);
  const witnesses = await Promise.all(cosigners.map((k) => newCosigner(k)));
  const files = new Map<string, Uint8Array>();
  let state: LogState = EMPTY_LOG;
  for (const size of sizes) {
    const u = await appendEntries(
      state,
      Array.from({ length: size - state.tree.size }, (_, j) => entry(state.tree.size + j)),
    );
    state = u.state;
    for (const t of [...u.fullTiles, ...u.partialTiles]) {
      files.set(tilePath(t.level, t.index, t.width), t.data);
    }
    for (const b of [...u.fullBundles, ...(u.partialBundle === null ? [] : [u.partialBundle])]) {
      files.set(entryBundlePath(b.index, b.width), b.data);
    }
    const note = await signCheckpoint(
      { origin: ORIGIN, size, rootHash: u.root, extensions: [] },
      signer,
    );
    files.set(archivedCheckpointPath(size), utf8Encode(note));
    const text = note.slice(0, note.indexOf('\n\n') + 1);
    let live = note;
    for (const w of witnesses) live += await w.cosign(text, 1_791_000_000);
    files.set(CHECKPOINT_PATH, utf8Encode(live));
  }
  const source: LogSource = {
    get: (path) => Promise.resolve(files.get(path)?.slice() ?? null),
  };
  return { vkey, files, source };
}

describe('openLog', () => {
  it('verifies the checkpoint signature and origin', async () => {
    const log = await buildLog([300]);
    const cp = await openLog(log.source, { vkey: log.vkey });
    expect(cp.checkpoint).toMatchObject({ origin: ORIGIN, size: 300 });
    await expect(openLog(log.source, { vkey: log.vkey, origin: 'other' })).rejects.toThrow(
      VerifyError,
    );
    const other = await generateKey(ORIGIN);
    await expect(openLog(log.source, { vkey: other.vkey })).rejects.toThrow(VerifyError);
  });

  it('applies a witness policy', async () => {
    const w1 = await generateCosignerKey('w1.example');
    const w2 = await generateCosignerKey('w2.example');
    const log = await buildLog([10], [w1.skey]);
    const ok = await openLog(log.source, { vkey: log.vkey, witnesses: [w1.vkey], quorum: 1 });
    expect(ok.cosignatures.map((c) => c.name)).toEqual(['w1.example']);
    // Not cosigned by w2: not evidence of anything, but not trusted under that policy.
    await expect(
      openLog(log.source, { vkey: log.vkey, witnesses: [w2.vkey], quorum: 1 }),
    ).rejects.toThrow(UnavailableError);
  });

  it('reports a missing checkpoint as unavailable', async () => {
    const log = await buildLog([10]);
    log.files.delete(CHECKPOINT_PATH);
    await expect(openLog(log.source, { vkey: log.vkey })).rejects.toThrow(UnavailableError);
  });
});

describe('proveEntry and recentEntries', () => {
  let log: Awaited<ReturnType<typeof buildLog>>;
  beforeAll(async () => {
    log = await buildLog([1, 255, 256, 257, 600]);
  });

  it('proves entries at tile boundaries and returns their exact bytes', async () => {
    const cp = await openLog(log.source, { vkey: log.vkey });
    for (const i of [0, 254, 255, 256, 511, 512, 599]) {
      const r = await proveEntry(log.source, cp, i);
      expect(r.entry).toEqual(entry(i));
    }
    await expect(proveEntry(log.source, cp, 600)).rejects.toThrow(RangeError);
  });

  it('returns the newest entries, verified', async () => {
    const cp = await openLog(log.source, { vkey: log.vkey });
    const recent = await recentEntries(log.source, cp, 5);
    expect(recent.map((r) => r.index)).toEqual([595, 596, 597, 598, 599]);
    expect(recent.map((r) => r.entry)).toEqual([595, 596, 597, 598, 599].map(entry));
  });

  it('proves consistency between published sizes, and rejects a rollback', async () => {
    const cp = await openLog(log.source, { vkey: log.vkey });
    for (const size of [1, 255, 256, 257, 600]) {
      const older = await openLog(
        { get: (p) => log.source.get(p === CHECKPOINT_PATH ? archivedCheckpointPath(size) : p) },
        { vkey: log.vkey },
      );
      await proveConsistency(log.source, older, cp);
      if (size < 600)
        await expect(proveConsistency(log.source, cp, older)).rejects.toThrow(VerifyError);
    }
  });
});

describe('I7 for the browser verifier: any flipped bit is caught', () => {
  it('rejects every corrupted tile, bundle and checkpoint', async () => {
    const log = await buildLog([300, 600]);
    const good = await openLog(log.source, { vkey: log.vkey });
    // Everything a reader of the size-600 checkpoint depends on (the size-300 partials are not).
    const paths = [
      CHECKPOINT_PATH,
      ...tilesForTreeSize(600).flatMap((t) => [
        tilePath(t.level, t.index, t.width),
        ...(t.level === 0 ? [entryBundlePath(t.index, t.width)] : []),
      ]),
    ];
    let flips = 0;
    for (const path of paths) {
      const orig = log.files.get(path) ?? new Uint8Array();
      for (const bit of [0, orig.length * 4 + 3, orig.length * 8 - 1]) {
        const bad = orig.slice();
        bad[bit >> 3] = (bad[bit >> 3] ?? 0) ^ (1 << (bit & 7));
        log.files.set(path, bad);
        // Everything a reader does: open the checkpoint, read every entry, check consistency.
        const attempt = async () => {
          const cp = await openLog(log.source, { vkey: log.vkey });
          for (let i = 0; i < cp.checkpoint.size; i += 1) {
            if (i % 256 === 0 || i % 256 === 255 || i === cp.checkpoint.size - 1) {
              await proveEntry(log.source, cp, i);
            }
          }
          await recentEntries(log.source, cp, 600);
          await proveConsistency(log.source, good, cp);
        };
        await expect(attempt(), `bit ${String(bit)} of ${path}`).rejects.toThrow(VerifyError);
        flips++;
      }
      log.files.set(path, orig);
    }
    expect(flips).toBe(paths.length * 3);
  });

  it('reports a missing tile or bundle as unavailable, not as tampering', async () => {
    const log = await buildLog([600]);
    const cp = await openLog(log.source, { vkey: log.vkey });
    log.files.delete(tilePath(0, 1, 256));
    await expect(proveEntry(log.source, cp, 300)).rejects.toThrow(UnavailableError);
    const log2 = await buildLog([600]);
    const cp2 = await openLog(log2.source, { vkey: log2.vkey });
    log2.files.delete(entryBundlePath(1, 256));
    await expect(proveEntry(log2.source, cp2, 300)).rejects.toThrow(UnavailableError);
  });
});

// C2SP tlog-cosignature, Ed25519 `cosignature/v1` (signature type 0x04), as used by witnesses
// (M8). The vector below was produced by a third-party implementation,
// github.com/transparency-dev/formats v0.1.1 (`note.NewSignerForCosignatureV1`), together with
// golang.org/x/mod/sumdb/note for the log signature, from fixed seeds (SHA-256 of "r2notary test
// vector: log key" and "... witness key"). It is used as data only.
import { describe, expect, it } from 'vitest';
import { fromBase64, toBase64, utf8Encode } from '../src/bytes.ts';
import {
  CheckpointError,
  formatCheckpoint,
  openCosignedCheckpoint,
  signCheckpoint,
} from '../src/checkpoint.ts';
import {
  NoteError,
  SIG_TYPE_COSIGNATURE_V1,
  computeKeyId,
  cosignatureTimestamp,
  generateCosignerKey,
  generateKey,
  newCosignatureVerifier,
  newCosigner,
  newSigner,
  newVerifier,
  openNote,
  parseVerifierKey,
} from '../src/note.ts';

const V = {
  logSkey:
    'PRIVATE+KEY+example.com/vector-log+4516a1da+ARnX7cNOLM36CVoVFnmyY1Yp3SE+vpow5cbV4Sw8rjRE',
  logVkey: 'example.com/vector-log+4516a1da+ARGkVJ4QEa2MOOLGBO6i7NVSJ1FQ97tIX+w+Ku0RZ6Em',
  witSkey:
    'PRIVATE+KEY+witness.example.com/vector+416f103d+BJEX3xv88eoQIKT4E+GkxZcXaJCYlQfi/GJ3NDFmZIW8',
  witVkey: 'witness.example.com/vector+416f103d+BK/QmJFVP3SKJOqAMhFxBQPtylo3sjwWibyFDAlZKK8B',
  text: 'example.com/vector-log\n1234\nSBNJTRN+FjG7owHVrKtue7eqdM4RhdRWVl71HXN2d7I=\n',
  logLine:
    '— example.com/vector-log RRah2qlLrSlk6J8DA1HmNewppUM15Quhs5cAIb1KjBsV3otVirJTW8AFVsQtJkTW1Zny7GuoAxZpI6bUPcpM68QOIgE=\n',
  witLine:
    '— witness.example.com/vector QW8QPQAAAABqwLUbDdj7sDNRIVjmjYgqFI6y4UJhPg/UAA8J8wAdqSd3q4PedRhkgXA4xFN/Jg5uWn7ZkBA+H/UHQs5d9hITdXmQAA==\n',
  /** 0x000000006ac0b51b, from bytes 4..12 of the witness signature. */
  time: 1_791_014_171,
};
const NOTE = `${V.text}\n${V.logLine}${V.witLine}`;

function flipByte(line: string, i: number): string {
  const [prefix, b64 = ''] = [
    line.slice(0, line.lastIndexOf(' ') + 1),
    line.trim().split(' ').at(-1),
  ];
  const raw = fromBase64(b64);
  raw[i] = (raw[i] ?? 0) ^ 0x01;
  return `${prefix}${toBase64(raw)}\n`;
}

describe('cosignature/v1: third-party vector', () => {
  it('verifies the log signature and the cosignature', async () => {
    const opened = await openNote(NOTE, [
      await newVerifier(V.logVkey),
      await newCosignatureVerifier(V.witVkey),
    ]);
    expect(opened.text).toBe(V.text);
    expect(opened.verified.map((s) => s.name)).toEqual([
      'example.com/vector-log',
      'witness.example.com/vector',
    ]);
    const wit = opened.signatures[1];
    expect(wit === undefined ? null : cosignatureTimestamp(wit.signature)).toBe(V.time);
  });

  it('reproduces the cosignature byte for byte from the same key and time', async () => {
    const c = await newCosigner(V.witSkey);
    expect(c.vkey).toBe(V.witVkey);
    expect(await c.cosign(V.text, V.time)).toBe(V.witLine);
  });

  it('computes the key ID over signature type 0x04', async () => {
    const k = await parseVerifierKey(V.witVkey, SIG_TYPE_COSIGNATURE_V1);
    const typed = new Uint8Array([SIG_TYPE_COSIGNATURE_V1, ...k.publicKey]);
    expect(await computeKeyId(k.name, typed)).toBe(0x416f103d);
    // The same public key under type 0x01 has another ID, so a cosignature is never mistaken for a
    // log signature (and vice versa).
    const asLog = new Uint8Array([0x01, ...k.publicKey]);
    expect(await computeKeyId(k.name, asLog)).not.toBe(0x416f103d);
  });

  it('rejects a cosignature with a changed timestamp, signature or text', async () => {
    const verifiers = [await newVerifier(V.logVkey), await newCosignatureVerifier(V.witVkey)];
    for (const i of [4, 11, 12, 75]) {
      await expect(
        openNote(`${V.text}\n${V.logLine}${flipByte(V.witLine, i)}`, verifiers),
      ).rejects.toThrow(NoteError);
    }
    const other = V.text.replace('1234', '1235');
    await expect(openNote(`${other}\n${V.logLine}${V.witLine}`, verifiers)).rejects.toThrow(
      NoteError,
    );
  });

  it('does not accept a cosignature as a log signature', async () => {
    // Only the witness line: the log verifier sees no known key.
    await expect(
      openNote(`${V.text}\n${V.witLine}`, [await newVerifier(V.logVkey)]),
    ).rejects.toThrow(/no signature from a known key/);
  });
});

describe('cosigner keys', () => {
  it('generates keys that cosign and verify, with the spec line format', async () => {
    const { skey, vkey } = await generateCosignerKey('witness.example/w1');
    expect(skey).toMatch(/^PRIVATE\+KEY\+witness\.example\/w1\+[0-9a-f]{8}\+/);
    const c = await newCosigner(skey);
    expect(c.vkey).toBe(vkey);
    const line = await c.cosign(V.text, 1_700_000_000);
    expect(line).toMatch(/^— witness\.example\/w1 [A-Za-z0-9+/]{102}==\n$/);
    const opened = await openNote(`${V.text}\n${V.logLine}${line}`, [
      await newCosignatureVerifier(vkey),
    ]);
    const sig = opened.signatures.find((s) => s.name === 'witness.example/w1');
    expect(sig === undefined ? null : cosignatureTimestamp(sig.signature)).toBe(1_700_000_000);
  });

  it('keeps log keys and cosigner keys apart', async () => {
    const log = await generateKey('example.com/log');
    const wit = await generateCosignerKey('witness.example/w1');
    await expect(newCosigner(log.skey)).rejects.toThrow(NoteError);
    await expect(newSigner(wit.skey)).rejects.toThrow(NoteError);
    await expect(newCosignatureVerifier(log.vkey)).rejects.toThrow(NoteError);
    await expect(newVerifier(wit.vkey)).rejects.toThrow(NoteError);
  });

  it('refuses timestamps that are not safe non-negative integers', async () => {
    const c = await newCosigner(V.witSkey);
    for (const t of [-1, 1.5, 2 ** 53, Number.NaN]) {
      await expect(c.cosign(V.text, t)).rejects.toThrow(NoteError);
    }
    expect(() => cosignatureTimestamp(new Uint8Array(71))).toThrow(NoteError);
    const huge = new Uint8Array(72);
    huge[1] = 0x20; // 2^53
    expect(() => cosignatureTimestamp(huge)).toThrow(NoteError);
  });
});

describe('openCosignedCheckpoint', () => {
  it('returns the checkpoint and each verified cosignature with its time', async () => {
    const r = await openCosignedCheckpoint(
      NOTE,
      await newVerifier(V.logVkey),
      'example.com/vector-log',
      [await newCosignatureVerifier(V.witVkey)],
    );
    expect(r.checkpoint.size).toBe(1234);
    expect(r.cosignatures).toEqual([
      { name: 'witness.example.com/vector', keyId: 0x416f103d, timestamp: V.time },
    ]);
  });

  it('ignores cosignatures from witnesses it was not given', async () => {
    const r = await openCosignedCheckpoint(
      NOTE,
      await newVerifier(V.logVkey),
      'example.com/vector-log',
      [],
    );
    expect(r.cosignatures).toEqual([]);
  });

  it('still requires the log signature and the origin', async () => {
    const wit = await newCosignatureVerifier(V.witVkey);
    await expect(
      openCosignedCheckpoint(
        `${V.text}\n${V.witLine}`,
        await newVerifier(V.logVkey),
        'example.com/vector-log',
        [wit],
      ),
    ).rejects.toThrow(/log signature/);
    await expect(
      openCosignedCheckpoint(NOTE, await newVerifier(V.logVkey), 'example.com/other', [wit]),
    ).rejects.toThrow(CheckpointError);
  });

  it('round-trips with the writer: a signed checkpoint plus a cosignature line', async () => {
    const log = await newSigner(V.logSkey);
    const cp = {
      origin: 'example.com/vector-log',
      size: 1234,
      rootHash: fromBase64('SBNJTRN+FjG7owHVrKtue7eqdM4RhdRWVl71HXN2d7I='),
      extensions: [],
    };
    expect(formatCheckpoint(cp)).toBe(V.text);
    const signed = await signCheckpoint(cp, log);
    expect(signed).toBe(`${V.text}\n${V.logLine}`);
    const cosigned = `${signed}${await (await newCosigner(V.witSkey)).cosign(V.text, V.time)}`;
    expect(utf8Encode(cosigned)).toEqual(utf8Encode(NOTE));
  });
});

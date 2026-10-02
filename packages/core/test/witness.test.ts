// C2SP tlog-witness `add-checkpoint`: the request/response formats and the witness's decision
// (M8). The witness Worker (witness/) wraps evaluateAddCheckpoint with storage and a cosigner; the
// log's witness client (worker/src/witness.ts) uses the formatters.
import { describe, expect, it } from 'vitest';
import { toBase64 } from '../src/bytes.ts';
import { signCheckpoint } from '../src/checkpoint.ts';
import { EMPTY_ROOT } from '../src/merkle.ts';
import { generateKey, newSigner, newVerifier, signNote, type NoteVerifier } from '../src/note.ts';
import {
  MAX_PROOF_LINES,
  WitnessProtocolError,
  evaluateAddCheckpoint,
  formatAddCheckpoint,
  formatSizeBody,
  parseAddCheckpoint,
  parseCosignatureLines,
  parseSizeBody,
  type WitnessedLogRecord,
} from '../src/witness.ts';
import { refConsistencyProof, refRootFromLeafHashes, syntheticLeafHashes } from './reference.ts';

const ORIGIN = 'example.com/witnessed-log';
const leaves = syntheticLeafHashes(40);
const root = (n: number): Uint8Array => refRootFromLeafHashes(leaves.slice(0, n));
const proof = (m: number, n: number): Uint8Array[] => refConsistencyProof(m, leaves.slice(0, n));

const keys = await generateKey(ORIGIN);
const signer = await newSigner(keys.skey);
const verifier = await newVerifier(keys.vkey);

async function checkpointNote(size: number, rootHash = root(size), s = signer): Promise<string> {
  return signCheckpoint({ origin: ORIGIN, size, rootHash, extensions: [] }, s);
}

/** A witness's view: trusted keys per origin, and the latest record per origin. */
function witness(records: Map<string, WitnessedLogRecord> = new Map()) {
  const trusted = new Map<string, readonly NoteVerifier[]>([[ORIGIN, [verifier]]]);
  return (body: string) =>
    evaluateAddCheckpoint(
      body,
      (o) => trusted.get(o),
      (o) => records.get(o) ?? null,
    );
}

describe('add-checkpoint request format', () => {
  it('round-trips, and matches the spec layout', async () => {
    const note = await checkpointNote(10);
    const body = formatAddCheckpoint({ oldSize: 4, proof: proof(4, 10), checkpoint: note });
    const lines = body.split('\n');
    expect(lines[0]).toBe('old 4');
    expect(lines.slice(1, 1 + proof(4, 10).length)).toEqual(proof(4, 10).map(toBase64));
    expect(body.endsWith(`\n\n${note}`)).toBe(true);
    const parsed = parseAddCheckpoint(body);
    expect(parsed.oldSize).toBe(4);
    expect(parsed.proof.map(toBase64)).toEqual(proof(4, 10).map(toBase64));
    expect(parsed.checkpoint).toBe(note);
  });

  it('parses the example request from the spec', () => {
    const body = [
      'old 20852014',
      'PlRNCrwHpqhGrupue0L7gxbjbMiKA9temvuZZDDpkaw=',
      'jrJZDmY8Y7SyJE0MWLpLozkIVMSMZcD5kvuKxPC3swk=',
      '5+pKlUdi2LeF/BcMHBn+Ku6yhPGNCswZZD1X/6QgPd8=',
      '/6WVhPs2CwSsb5rYBH5cjHV/wSmA79abXAwhXw3Kj/0=',
      '',
      'example.com/behind-the-sofa',
      '20852163',
      'CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=',
      '',
      '— example.com/behind-the-sofa Az3grlgtzPICa5OS8npVmf1Myq/5IZniMp+ZJurmRDeOoRDe4URYN7u5/Zhcyv2q1gGzGku9nTo+zyWE+xeMcTOAYQ8=',
      '',
    ].join('\n');
    const r = parseAddCheckpoint(body);
    expect(r.oldSize).toBe(20_852_014);
    expect(r.proof).toHaveLength(4);
    expect(r.checkpoint.startsWith('example.com/behind-the-sofa\n20852163\n')).toBe(true);
  });

  it('rejects malformed requests', () => {
    const cp = 'o\n1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\n— o AAAA\n';
    const h = toBase64(new Uint8Array(32));
    for (const body of [
      `old 01\n\n${cp}`, // leading zero
      `old -1\n\n${cp}`,
      `old 1.0\n\n${cp}`,
      `old  1\n\n${cp}`,
      `old 1\n${h.slice(0, -4)}\n\n${cp}`, // not 32 bytes
      `old 1\n${h} \n\n${cp}`, // trailing space
      `old 1\n${h.replace(/=$/, '')}\n\n${cp}`, // missing padding
      `new 1\n\n${cp}`,
      `old 1\n${h}\n`, // no blank line / checkpoint
      `old 1\n\n`, // empty checkpoint
      `old 9007199254740992\n\n${cp}`, // beyond 2^53 - 1
      `old 1\n${`${h}\n`.repeat(MAX_PROOF_LINES + 1)}\n${cp}`,
    ]) {
      expect(() => parseAddCheckpoint(body), JSON.stringify(body)).toThrow(WitnessProtocolError);
    }
    expect(() =>
      parseAddCheckpoint(`old 1\n${`${h}\n`.repeat(MAX_PROOF_LINES)}\n${cp}`),
    ).not.toThrow();
  });
});

describe('responses', () => {
  it('409 body is the size in decimal and a newline', () => {
    expect(formatSizeBody(0)).toBe('0\n');
    expect(parseSizeBody('20852014\n')).toBe(20_852_014);
    for (const b of ['', '1', '01\n', '-1\n', '1\n\n', ' 1\n']) {
      expect(() => parseSizeBody(b), JSON.stringify(b)).toThrow(WitnessProtocolError);
    }
  });

  it('200 body is one or more signature lines', () => {
    const lines = parseCosignatureLines('— w.example/a AAAA\n— w.example/b BBBB\n');
    expect(lines).toEqual(['— w.example/a AAAA\n', '— w.example/b BBBB\n']);
    for (const b of ['', '— w AAAA', 'w AAAA\n', '— w AAAA\n\n', '— w\n', '— w AA AA\n']) {
      expect(() => parseCosignatureLines(b), JSON.stringify(b)).toThrow(WitnessProtocolError);
    }
  });
});

describe('evaluateAddCheckpoint: status codes from the spec', () => {
  const add = (oldSize: number, p: Uint8Array[], note: string) =>
    formatAddCheckpoint({ oldSize, proof: p, checkpoint: note });

  it('accepts a first checkpoint from old size 0, then extensions with proofs', async () => {
    const records = new Map<string, WitnessedLogRecord>();
    const w = witness(records);
    const first = await w(add(0, [], await checkpointNote(5)));
    expect(first).toMatchObject({ ok: true, oldSize: 0 });
    if (!first.ok) throw new Error('unreachable');
    expect(first.checkpoint.size).toBe(5);
    expect(first.logSignatures).toHaveLength(1);
    expect(first.text).toBe(`${ORIGIN}\n5\n${toBase64(root(5))}\n`);
    records.set(ORIGIN, { size: 5, rootHash: root(5) });
    expect(await w(add(5, proof(5, 13), await checkpointNote(13)))).toMatchObject({ ok: true });
    records.set(ORIGIN, { size: 13, rootHash: root(13) });
    // The same checkpoint again (a client retrying): old size equals the size, roots equal.
    expect(await w(add(13, [], await checkpointNote(13)))).toMatchObject({ ok: true });
  });

  it('400 for a malformed body, a malformed note, or an old size above the checkpoint size', async () => {
    const w = witness();
    expect(await w('old 1\n')).toMatchObject({ ok: false, status: 400 });
    const note = await checkpointNote(5);
    const badLine = note.replace(/ [A-Za-z0-9+/=]+\n$/, ' !!!\n');
    expect(await w(add(0, [], badLine))).toMatchObject({ status: 400 });
    // Correctly signed by the trusted key, but not a checkpoint (size with a leading zero).
    const notCheckpoint = await signNote(`${ORIGIN}\n05\n${toBase64(root(5))}\n`, [signer]);
    expect(await w(add(0, [], notCheckpoint))).toMatchObject({ status: 400 });
    expect(await w(add(6, [], note))).toMatchObject({ status: 400 });
  });

  it('404 for an origin the witness does not know', async () => {
    const other = await generateKey('example.com/unknown-log');
    const note = await signCheckpoint(
      { origin: 'example.com/unknown-log', size: 1, rootHash: root(1), extensions: [] },
      await newSigner(other.skey),
    );
    expect(await witness()(add(0, [], note))).toMatchObject({ ok: false, status: 404 });
  });

  it('403 without a valid signature from a trusted key', async () => {
    const impostor = await newSigner((await generateKey(ORIGIN)).skey);
    expect(await witness()(add(0, [], await checkpointNote(5, root(5), impostor)))).toMatchObject({
      status: 403,
    });
    // A trusted key's signature that fails: the right key line over different text.
    const good = await checkpointNote(5);
    const tampered = good.replace(`\n5\n`, `\n6\n`);
    expect(await witness()(add(0, [], tampered))).toMatchObject({ status: 403 });
  });

  it('409 with the latest size when the old size does not match', async () => {
    const records = new Map([[ORIGIN, { size: 5, rootHash: root(5) }]]);
    const r = await witness(records)(add(0, [], await checkpointNote(13)));
    expect(r).toMatchObject({ ok: false, status: 409, size: 5 });
    const never = await witness()(add(5, proof(5, 13), await checkpointNote(13)));
    expect(never).toMatchObject({ ok: false, status: 409, size: 0 });
  });

  it('422 for a bad proof, a fork at the same size, or a proof from size 0', async () => {
    const records = new Map([[ORIGIN, { size: 5, rootHash: root(5) }]]);
    const w = witness(records);
    const bad = proof(5, 13).map((h, i) => (i === 0 ? h.map((b) => b ^ 1) : h));
    expect(await w(add(5, bad, await checkpointNote(13)))).toMatchObject({ status: 422 });
    expect(await w(add(5, proof(5, 13).slice(1), await checkpointNote(13)))).toMatchObject({
      status: 422,
    });
    // A checkpoint of size 5 with another root: a fork.
    expect(await w(add(5, [], await checkpointNote(5, root(6))))).toMatchObject({ status: 422 });
    // A tree that does not extend the recorded one.
    const forked = new Map([[ORIGIN, { size: 5, rootHash: root(6) }]]);
    expect(await witness(forked)(add(5, proof(5, 13), await checkpointNote(13)))).toMatchObject({
      status: 422,
    });
    expect(await witness()(add(0, [root(1)], await checkpointNote(5)))).toMatchObject({
      status: 422,
    });
  });

  it('422 for an empty tree whose root is not the hash of the empty string', async () => {
    expect(await witness()(add(0, [], await checkpointNote(0, EMPTY_ROOT)))).toMatchObject({
      ok: true,
    });
    expect(await witness()(add(0, [], await checkpointNote(0, root(1))))).toMatchObject({
      status: 422,
    });
  });

  it('ignores signatures from unknown keys alongside the trusted one', async () => {
    const other = await newSigner((await generateKey('example.com/someone-else')).skey);
    const note = await checkpointNote(5);
    const extra = (
      await signCheckpoint(
        { origin: 'example.com/someone-else', size: 5, rootHash: root(5), extensions: [] },
        other,
      )
    ).split('\n\n')[1];
    const r = await witness()(add(0, [], `${note}${extra ?? ''}`));
    expect(r).toMatchObject({ ok: true });
    if (r.ok) expect(r.logSignatures).toHaveLength(1);
  });
});

import { createPublicKey, verify as nodeVerify } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  MAX_NOTE_SIGNATURES,
  NoteError,
  generateKey,
  isValidKeyName,
  newSigner,
  newVerifier,
  openNote,
  parseVerifierKey,
  signNote,
} from '../src/note.ts';

// From the C2SP signed-note spec ("Verifier keys" → "Example").
const SPEC_VKEY = 'example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k';
const SPEC_NOTE =
  'This is an example message.\n\n' +
  '— example.com/foo Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXppzi2ONncAlTgK7Ztg1ERYNZXsYjOBH3mFXmRKuwHjG1Yu72IneyaQM=\n';

// From the documentation of golang.org/x/mod/sumdb/note (used as data only). Ed25519 is
// deterministic, so signing the same text with the same key must reproduce this signature exactly.
const GO_SKEY = 'PRIVATE+KEY+PeterNeumann+c74f20a3+AYEKFALVFGyNhPJEMzD1QIDr+Y7hfZx09iUvxdXHKDFz';
const GO_TEXT =
  'If you think cryptography is the answer to your problem,\n' +
  "then you don't know what your problem is.\n";
const GO_NOTE =
  GO_TEXT +
  '\n— PeterNeumann x08go/ZJkuBS9UG/SffcvIAQxVBtiFupLLr8pAcElZInNIuGUgYN1FFYC2pZSNXgKvqfqdngotpRZb6KE6RyyBwJnAM=\n';

async function expectNoteError(p: Promise<unknown>): Promise<void> {
  await expect(p).rejects.toBeInstanceOf(NoteError);
}

describe('verifier keys', () => {
  it('parses the spec example', async () => {
    const k = await parseVerifierKey(SPEC_VKEY);
    expect(k.name).toBe('example.com/foo');
    expect(k.keyId).toBe(0x530d903a);
    expect(k.publicKey).toHaveLength(32);
  });

  it.each([
    ['wrong key id', 'example.com/foo+530d903b+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k'],
    ['uppercase hex id', 'example.com/foo+530D903A+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k'],
    ['short hex id', 'example.com/foo+530d903+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k'],
    ['unknown algorithm', 'example.com/foo+530d903a+AkyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k'],
    ['truncated key', 'example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2'],
    ['missing part', 'example.com/foo+530d903a'],
    ['empty name', '+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k'],
  ])('rejects %s', async (_name, vkey) => {
    await expectNoteError(parseVerifierKey(vkey));
    await expectNoteError(newVerifier(vkey));
  });

  it('validates key names', () => {
    expect(isValidKeyName('example.com/log')).toBe(true);
    expect(isValidKeyName('ünïcode.example/ok')).toBe(true);
    for (const n of ['', 'a b', 'a+b', 'a b', 'a b', 'a\nb', 'a\u0001b', 'a\ud800']) {
      expect(isValidKeyName(n), JSON.stringify(n)).toBe(false);
    }
  });
});

describe('signed notes', () => {
  it('verifies the spec example note', async () => {
    const v = await newVerifier(SPEC_VKEY);
    const n = await openNote(SPEC_NOTE, [v]);
    expect(n.text).toBe('This is an example message.\n');
    expect(n.verified).toEqual([{ name: 'example.com/foo', keyId: 0x530d903a }]);
  });

  it('reproduces the Go note package example byte-for-byte', async () => {
    const s = await newSigner(GO_SKEY);
    expect(s.name).toBe('PeterNeumann');
    expect(s.keyId).toBe(0xc74f20a3);
    expect(s.vkey.startsWith('PeterNeumann+c74f20a3+')).toBe(true);
    expect(await signNote(GO_TEXT, [s])).toBe(GO_NOTE);
    const opened = await openNote(GO_NOTE, [await newVerifier(s.vkey)]);
    expect(opened.text).toBe(GO_TEXT);
  });

  it('generates Go-compatible key strings that round-trip', async () => {
    const { skey, vkey } = await generateKey('r2notary.example.com/log');
    expect(skey).toMatch(
      /^PRIVATE\+KEY\+r2notary\.example\.com\/log\+[0-9a-f]{8}\+A[A-Za-z0-9+/]{43}$/,
    );
    expect(vkey).toMatch(/^r2notary\.example\.com\/log\+[0-9a-f]{8}\+A[A-Za-z0-9+/]{43}$/);
    const s = await newSigner(skey);
    expect(s.vkey).toBe(vkey);
    const note = await signNote('hello\n', [s]);
    expect(note).toMatch(/^hello\n\n— r2notary\.example\.com\/log [A-Za-z0-9+/]{91}=\n$/);
    expect((await openNote(note, [await newVerifier(vkey)])).text).toBe('hello\n');
  });

  it('signatures are plain RFC 8032 Ed25519 over the note text (checked with node:crypto)', async () => {
    const { skey, vkey } = await generateKey('k');
    const note = await signNote('text\n', [await newSigner(skey)]);
    const sig = Buffer.from(note.split(' ')[2] ?? '', 'base64').subarray(4);
    const pub = (await parseVerifierKey(vkey)).publicKey;
    const spki = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), pub]);
    const key = createPublicKey({ key: spki, format: 'der', type: 'spki' });
    expect(nodeVerify(null, Buffer.from('text\n'), key, sig)).toBe(true);
  });

  it('supports multiple signers and ignores unknown keys', async () => {
    const a = await newSigner((await generateKey('a.example/log')).skey);
    const b = await newSigner((await generateKey('b.example/witness')).skey);
    const note = await signNote('multi\n', [a, b]);
    const opened = await openNote(note, [await newVerifier(a.vkey)]);
    expect(opened.verified).toEqual([{ name: a.name, keyId: a.keyId }]);
    expect(opened.signatures.map((s) => s.name)).toEqual([a.name, b.name]);
  });

  it('accepts text containing blank lines (split at the last blank line)', async () => {
    const s = await newSigner((await generateKey('k')).skey);
    const text = 'para one\n\npara two\n';
    const note = await signNote(text, [s]);
    expect((await openNote(note, [await newVerifier(s.vkey)])).text).toBe(text);
  });

  it('accepts bytes as well as strings', async () => {
    const v = await newVerifier(SPEC_VKEY);
    expect((await openNote(new TextEncoder().encode(SPEC_NOTE), [v])).text).toBe(
      'This is an example message.\n',
    );
  });

  describe('rejections', () => {
    const tamper = async (mutate: (note: string) => string): Promise<void> => {
      const v = await newVerifier(SPEC_VKEY);
      await expectNoteError(openNote(mutate(SPEC_NOTE), [v]));
    };

    it('altered text', () => tamper((n) => n.replace('example', 'exbmple')));
    it('altered signature byte', () => tamper((n) => n.replace('Uw2QOkn8', 'Uw2QOkn9')));
    it('altered key id (no known signature left)', () =>
      tamper((n) => n.replace('foo Uw2Q', 'foo Vw2Q')));
    it('non-canonical signature base64', () => tamper((n) => n.replace('yaQM=', 'yaQN=')));
    it('missing final newline', () => tamper((n) => n.slice(0, -1)));
    it('missing blank line', () => tamper((n) => n.replace('.\n\n', '.\n')));
    it('ASCII hyphen instead of em dash', () => tamper((n) => n.replace('—', '-')));
    it('control character', () => tamper((n) => n.replace('This', 'Th\u0007s')));
    it('carriage return', () => tamper((n) => n.replace('message.\n', 'message.\r\n')));
    it('trailing junk after signatures', () => tamper((n) => `${n}junk\n`));
    it('duplicate signature line', () => tamper((n) => n + n.slice(n.indexOf('—'))));

    it('a note with only unknown signatures', async () => {
      const other = await newVerifier((await generateKey('example.com/foo')).vkey);
      await expectNoteError(openNote(SPEC_NOTE, [other]));
    });

    it('a known key that fails, even when another known key verifies', async () => {
      const s = await newSigner((await generateKey('example.com/foo')).skey);
      const good = await signNote('This is an example message.\n', [s]);
      // Append the spec signature but with a corrupted body under the spec's (known) key.
      const badLine = SPEC_NOTE.slice(SPEC_NOTE.indexOf('—')).replace('Uw2QOkn8', 'Uw2QOkn9');
      await expectNoteError(
        openNote(good + badLine, [await newVerifier(s.vkey), await newVerifier(SPEC_VKEY)]),
      );
    });

    it('too many signatures', async () => {
      const s = await newSigner((await generateKey('k')).skey);
      const note = await signNote('x\n', [s]);
      const junk = '— junk AAAAAAAA\n';
      const many = note + junk.repeat(MAX_NOTE_SIGNATURES);
      await expectNoteError(openNote(many, [await newVerifier(s.vkey)]));
      // 16 signatures must be accepted (spec minimum); the extra ones are unknown keys.
      const sixteen =
        note + Array.from({ length: 15 }, (_, i) => `— junk${String(i)} AAAAAAAA\n`).join('');
      expect((await openNote(sixteen, [await newVerifier(s.vkey)])).verified).toHaveLength(1);
    });

    it('invalid UTF-8 bytes', async () => {
      const bytes = new TextEncoder().encode(SPEC_NOTE);
      bytes[2] = 0xff;
      await expectNoteError(openNote(bytes, [await newVerifier(SPEC_VKEY)]));
    });
  });

  describe('signing preconditions', () => {
    it('refuses text without a final newline, with control characters, or empty', async () => {
      const s = await newSigner((await generateKey('k')).skey);
      await expectNoteError(signNote('no newline', [s]));
      await expectNoteError(signNote('bell\u0007\n', [s]));
      await expectNoteError(signNote('', [s]));
      await expectNoteError(signNote('x\n', []));
    });

    it('rejects malformed signer keys', async () => {
      await expectNoteError(newSigner(GO_SKEY.replace('c74f20a3', 'c74f20a4')));
      await expectNoteError(newSigner(GO_SKEY.replace('PRIVATE+KEY+', '')));
      await expectNoteError(newSigner(GO_SKEY.slice(0, -4)));
      await expectNoteError(newSigner(GO_SKEY.replace('PeterNeumann', 'Peter Neumann')));
    });
  });
});

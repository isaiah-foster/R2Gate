import { describe, expect, it } from 'vitest';
import {
  CheckpointError,
  formatCheckpoint,
  openCheckpoint,
  parseCheckpoint,
  signCheckpoint,
  validateOrigin,
  type Checkpoint,
} from '../src/checkpoint.ts';
import { EMPTY_LOG, appendEntries } from '../src/log.ts';
import { NoteError, generateKey, newSigner, newVerifier } from '../src/note.ts';
import { hex, unhex } from './reference.ts';

const ORIGIN = 'r2notary.example.com/example-log';

// Note text from the C2SP tlog-checkpoint spec example.
const SPEC_TEXT =
  'example.com/behind-the-sofa\n20852163\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n';

describe('checkpoint text', () => {
  it('parses the spec example', () => {
    const cp = parseCheckpoint(SPEC_TEXT);
    expect(cp.origin).toBe('example.com/behind-the-sofa');
    expect(cp.size).toBe(20852163);
    expect(hex(cp.rootHash)).toBe(
      hex(new Uint8Array(Buffer.from('CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=', 'base64'))),
    );
    expect(cp.extensions).toEqual([]);
    expect(formatCheckpoint(cp)).toBe(SPEC_TEXT);
  });

  it('formats origin, decimal size and base64 root, each newline-terminated', () => {
    const root = unhex('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    expect(formatCheckpoint({ origin: ORIGIN, size: 0, rootHash: root, extensions: [] })).toBe(
      `${ORIGIN}\n0\n47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\n`,
    );
  });

  it('parses extension lines', () => {
    expect(parseCheckpoint(`${SPEC_TEXT}ext one\next two\n`).extensions).toEqual([
      'ext one',
      'ext two',
    ]);
  });

  it.each([
    ['leading zero size', SPEC_TEXT.replace('20852163', '020852163')],
    ['negative size', SPEC_TEXT.replace('20852163', '-1')],
    ['signed size', SPEC_TEXT.replace('20852163', '+1')],
    ['unsafe size', SPEC_TEXT.replace('20852163', '9007199254740993')],
    ['short root', SPEC_TEXT.replace('CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=', 'AAAA')],
    ['non-canonical root', SPEC_TEXT.replace('jxq2I=', 'jxq2J=')],
    ['empty origin', SPEC_TEXT.replace('example.com/behind-the-sofa', '')],
    ['origin over 255 bytes', SPEC_TEXT.replace('example.com', 'e'.repeat(250))],
    ['empty extension line', `${SPEC_TEXT}\n`],
    ['missing final newline', SPEC_TEXT.slice(0, -1)],
    ['two lines', 'example.com/x\n1\n'],
  ])('rejects %s', (_name, text) => {
    expect(() => parseCheckpoint(text)).toThrow(CheckpointError);
  });

  it('refuses to format invalid checkpoints', () => {
    const rootHash = new Uint8Array(32);
    const bad: Checkpoint[] = [
      { origin: ORIGIN, size: -1, rootHash, extensions: [] },
      { origin: ORIGIN, size: 1.5, rootHash, extensions: [] },
      { origin: ORIGIN, size: 1, rootHash: new Uint8Array(31), extensions: [] },
      { origin: 'has space', size: 1, rootHash, extensions: [] },
      { origin: ORIGIN, size: 1, rootHash, extensions: [''] },
    ];
    for (const cp of bad) expect(() => formatCheckpoint(cp)).toThrow(CheckpointError);
  });
});

describe('origin validation', () => {
  it.each(['r2notary.example.com/log', 'example.com', 'localhost:8787/log'])('accepts %s', (o) => {
    expect(() => {
      validateOrigin(o);
    }).not.toThrow();
  });

  it.each([
    '',
    'https://example.com/log',
    'example.com/log/',
    'example.com/ log',
    'example.com/a+b',
    'e'.repeat(256),
  ])('rejects %j', (o) => {
    expect(() => {
      validateOrigin(o);
    }).toThrow(CheckpointError);
  });
});

describe('signed checkpoints', () => {
  async function fixture(): Promise<{ vkey: string; note: string; root: Uint8Array }> {
    const { skey, vkey } = await generateKey(ORIGIN);
    const entries = Array.from({ length: 300 }, (_, i) => new TextEncoder().encode(String(i)));
    const { root } = await appendEntries(EMPTY_LOG, entries);
    const note = await signCheckpoint(
      { origin: ORIGIN, size: 300, rootHash: root, extensions: [] },
      await newSigner(skey),
    );
    return { vkey, note, root };
  }

  // I9: signatures verify against the published vkey and the origin line equals LOG_ORIGIN.
  it('I9: a signed checkpoint verifies against its vkey and expected origin', async () => {
    const { vkey, note, root } = await fixture();
    const cp = await openCheckpoint(note, await newVerifier(vkey), ORIGIN);
    expect(cp.size).toBe(300);
    expect(hex(cp.rootHash)).toBe(hex(root));
    expect(note.startsWith(`${ORIGIN}\n300\n`)).toBe(true);
  });

  it('I9: rejects a checkpoint whose origin differs from the expected origin', async () => {
    const { vkey, note } = await fixture();
    await expect(
      openCheckpoint(note, await newVerifier(vkey), 'r2notary.example.com/other-log'),
    ).rejects.toThrow(CheckpointError);
  });

  it('rejects a tampered size or root', async () => {
    const { vkey, note } = await fixture();
    const v = await newVerifier(vkey);
    await expect(openCheckpoint(note.replace('\n300\n', '\n301\n'), v, ORIGIN)).rejects.toThrow(
      NoteError,
    );
    const lines = note.split('\n');
    const root = lines[2] ?? '';
    const flipped = (root.startsWith('A') ? 'B' : 'A') + root.slice(1);
    await expect(openCheckpoint(note.replace(root, flipped), v, ORIGIN)).rejects.toThrow(NoteError);
  });

  it('refuses to sign with a key whose name is not the origin', async () => {
    const s = await newSigner((await generateKey('someone.else/log')).skey);
    await expect(
      signCheckpoint({ origin: ORIGIN, size: 0, rootHash: new Uint8Array(32), extensions: [] }, s),
    ).rejects.toThrow(CheckpointError);
  });
});

// packages/core is unit-tested under Node. These tests run the same code inside workerd to confirm
// that the WebCrypto operations it depends on (SHA-256, Ed25519 generate/sign/verify, PKCS#8
// import, JWK export) behave identically in the Workers runtime.
import {
  EMPTY_LOG,
  appendEntries,
  generateKey,
  newSigner,
  newVerifier,
  openCheckpoint,
  openNote,
  signCheckpoint,
  signNote,
  toHex,
} from '@r2notary/core';
import { describe, expect, it } from 'vitest';

// golang.org/x/mod/sumdb/note documentation example (data only); see packages/core/test/note.test.ts.
const GO_SKEY = 'PRIVATE+KEY+PeterNeumann+c74f20a3+AYEKFALVFGyNhPJEMzD1QIDr+Y7hfZx09iUvxdXHKDFz';
const GO_TEXT =
  'If you think cryptography is the answer to your problem,\n' +
  "then you don't know what your problem is.\n";
const GO_SIG =
  'x08go/ZJkuBS9UG/SffcvIAQxVBtiFupLLr8pAcElZInNIuGUgYN1FFYC2pZSNXgKvqfqdngotpRZb6KE6RyyBwJnAM=';

describe('core in workerd', () => {
  it('reproduces the Go note signature byte-for-byte', async () => {
    const note = await signNote(GO_TEXT, [await newSigner(GO_SKEY)]);
    expect(note).toBe(`${GO_TEXT}\n— PeterNeumann ${GO_SIG}\n`);
  });

  it('generates keys, signs and verifies a checkpoint', async () => {
    const origin = 'r2notary.example.com/example-log';
    const { skey, vkey } = await generateKey(origin);
    const leaves = ['', '00', '10', '2021', '3031', '40414243', '5051525354555657'];
    const entries = [...leaves, '606162636465666768696a6b6c6d6e6f'].map(
      (h) => new Uint8Array((h.match(/../g) ?? []).map((b) => parseInt(b, 16))),
    );
    const { root } = await appendEntries(EMPTY_LOG, entries);
    // RFC 6962 root for these 8 leaves (transparency-dev/merkle test vectors).
    expect(toHex(root)).toBe('5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328');

    const note = await signCheckpoint(
      { origin, size: 8, rootHash: root, extensions: [] },
      await newSigner(skey),
    );
    const cp = await openCheckpoint(note, await newVerifier(vkey), origin);
    expect(cp.size).toBe(8);
    await expect(
      openNote(note.replace('\n8\n', '\n9\n'), [await newVerifier(vkey)]),
    ).rejects.toThrow();
  });
});

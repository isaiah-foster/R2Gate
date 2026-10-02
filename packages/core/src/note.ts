// C2SP signed-note with Ed25519 signatures (signature type 0x01), and C2SP tlog-cosignature
// Ed25519 cosignatures (`cosignature/v1`, signature type 0x04) for witnesses, using WebCrypto only.
//
// Key strings use the same formats as golang.org/x/mod/sumdb/note, so keys interoperate with the
// Go verifier and with Go tooling:
//   verifier key  <name>+<hex key ID>+base64(type || 32-byte public key)       (C2SP "vkey")
//   signer key    PRIVATE+KEY+<name>+<hex key ID>+base64(type || 32-byte seed)  (Go convention)
// with type 0x01 for log keys and 0x04 for cosigner keys (as github.com/transparency-dev/formats
// writes them). The key ID covers the type, so the two kinds of key never match each other.
//
// WebCrypto cannot import a raw Ed25519 private key, so the seed is wrapped in a fixed PKCS#8
// envelope (RFC 8410) for import.

import {
  bytesEqual,
  concatBytes,
  fromBase64,
  fromHex,
  toBase64,
  utf8Decode,
  utf8Encode,
} from './bytes.ts';
import { sha256 } from './merkle.ts';

export const SIG_TYPE_ED25519 = 0x01;
/** C2SP tlog-cosignature, Ed25519 `cosignature/v1`. */
export const SIG_TYPE_COSIGNATURE_V1 = 0x04;
type SigType = typeof SIG_TYPE_ED25519 | typeof SIG_TYPE_COSIGNATURE_V1;
const ED25519_PUBLIC_KEY_SIZE = 32;
const ED25519_SIGNATURE_SIZE = 64;
/** A cosignature is a big-endian u64 timestamp followed by the Ed25519 signature. */
const TIMESTAMP_SIZE = 8;
/** RFC 8410 PKCS#8 prefix for an Ed25519 private key; the 32-byte seed follows. */
const PKCS8_ED25519_PREFIX = fromHex('302e020100300506032b657004220420');
const SIGNER_KEY_PREFIX = 'PRIVATE+KEY+';
const SIG_LINE_PREFIX = '— '; // em dash, space

/** Notes with more signature lines than this are rejected (the spec requires accepting ≥ 16). */
export const MAX_NOTE_SIGNATURES = 100;

// `CryptoKey` is a value-only global under @types/node, so name the key type structurally; this
// also keeps the module type-checking under both the Node and the Workers type definitions.
type Key = Awaited<ReturnType<typeof crypto.subtle.importKey>>;

function isKeyPair(k: unknown): k is { privateKey: Key; publicKey: Key } {
  return typeof k === 'object' && k !== null && 'privateKey' in k && 'publicKey' in k;
}

export class NoteError extends Error {
  override name = 'NoteError';
}

/**
 * A well-formed note without a valid signature from any supplied key, or with an invalid one from
 * a supplied key. Distinct from a malformed note: a witness answers 403 for this, 400 for that.
 */
export class SignatureError extends NoteError {
  override name = 'SignatureError';
}

export interface NoteSigner {
  readonly name: string;
  readonly keyId: number;
  /** The verifier key for this signer. */
  readonly vkey: string;
  sign(message: Uint8Array): Promise<Uint8Array>;
}

export interface NoteVerifier {
  readonly name: string;
  readonly keyId: number;
  verify(message: Uint8Array, signature: Uint8Array): Promise<boolean>;
}

export interface VerifierKey {
  readonly name: string;
  readonly keyId: number;
  readonly publicKey: Uint8Array;
}

export interface NoteSignature {
  readonly name: string;
  readonly keyId: number;
  /** Signature bytes without the 4-byte key ID. */
  readonly signature: Uint8Array;
}

export interface OpenedNote {
  /** The signed text, including its final newline. */
  readonly text: string;
  /** Every signature line, in order (known and unknown keys). */
  readonly signatures: readonly NoteSignature[];
  /** The signatures that were verified by one of the supplied verifiers. */
  readonly verified: readonly { readonly name: string; readonly keyId: number }[];
}

/** True if `s` has an ASCII control character (below U+0020) other than those in `allowed`. */
function hasControlChar(s: string, allowed = ''): boolean {
  for (const c of s) if (c < ' ' && !allowed.includes(c)) return true;
  return false;
}

/** Key names are non-empty and contain no Unicode spaces, `+`, or control characters. */
export function isValidKeyName(name: string): boolean {
  return (
    name.length > 0 && name.isWellFormed() && !/[\s\u0085+]/u.test(name) && !hasControlChar(name)
  );
}

function checkName(name: string): void {
  if (!isValidKeyName(name)) throw new NoteError(`invalid key name ${JSON.stringify(name)}`);
}

/** key ID = first 4 bytes, big-endian, of SHA-256(name || 0x0A || signature type || public key). */
export async function computeKeyId(name: string, typedPublicKey: Uint8Array): Promise<number> {
  const h = await sha256(concatBytes(utf8Encode(name), Uint8Array.of(0x0a), typedPublicKey));
  return new DataView(h.buffer, h.byteOffset, 4).getUint32(0);
}

function keyIdHex(id: number): string {
  return id.toString(16).padStart(8, '0');
}

/** Splits at the first `sep`, like Go's strings.Cut. */
function cut(s: string, sep: string): [string, string] | null {
  const i = s.indexOf(sep);
  return i < 0 ? null : [s.slice(0, i), s.slice(i + sep.length)];
}

function decodeKeyMaterial(b64: string, what: string, type: SigType): Uint8Array {
  let typed: Uint8Array;
  try {
    typed = fromBase64(b64);
  } catch {
    throw new NoteError(`${what}: invalid base64`);
  }
  if (typed[0] !== type) throw new NoteError(`${what}: unsupported signature type`);
  if (typed.length !== 1 + ED25519_PUBLIC_KEY_SIZE)
    throw new NoteError(`${what}: wrong key length`);
  return typed;
}

/** Parses `name+id+key` without verifying the key ID (see parseVerifierKey). */
function splitKey(
  s: string,
  what: string,
  type: SigType,
): { name: string; idHex: string; typed: Uint8Array } {
  const a = cut(s, '+');
  const b = a && cut(a[1], '+');
  if (!a || !b) throw new NoteError(`${what}: expected name+id+key`);
  const [name] = a;
  const [idHex, b64] = b;
  checkName(name);
  if (!/^[0-9a-f]{8}$/.test(idHex))
    throw new NoteError(`${what}: key ID must be 8 lowercase hex digits`);
  return { name, idHex, typed: decodeKeyMaterial(b64, what, type) };
}

/**
 * Parses a verifier key of the given signature type (a log key by default) and checks that its
 * key ID matches its name and public key.
 */
export async function parseVerifierKey(
  vkey: string,
  type: SigType = SIG_TYPE_ED25519,
): Promise<VerifierKey> {
  const { name, idHex, typed } = splitKey(vkey, 'verifier key', type);
  const keyId = Number.parseInt(idHex, 16);
  if ((await computeKeyId(name, typed)) !== keyId) {
    throw new NoteError('verifier key: key ID does not match name and key');
  }
  return { name, keyId, publicKey: typed.slice(1) };
}

export async function formatVerifierKey(
  name: string,
  publicKey: Uint8Array,
  type: SigType = SIG_TYPE_ED25519,
): Promise<string> {
  checkName(name);
  if (publicKey.length !== ED25519_PUBLIC_KEY_SIZE) throw new NoteError('wrong public key length');
  const typed = concatBytes(Uint8Array.of(type), publicKey);
  return `${name}+${keyIdHex(await computeKeyId(name, typed))}+${toBase64(typed)}`;
}

function arrayBufferCopy(b: Uint8Array): ArrayBuffer {
  return new Uint8Array(b).buffer;
}

async function importSeed(seed: Uint8Array, extractable: boolean): Promise<Key> {
  return crypto.subtle.importKey(
    'pkcs8',
    arrayBufferCopy(concatBytes(PKCS8_ED25519_PREFIX, seed)),
    { name: 'Ed25519' },
    extractable,
    ['sign'],
  );
}

// The Node and Workers type definitions disagree on exportKey's return type, so results are
// checked at runtime rather than trusted from either declaration.
async function exportBytes(format: 'pkcs8' | 'raw', key: Key): Promise<Uint8Array> {
  const out: unknown = await crypto.subtle.exportKey(format, key);
  if (!(out instanceof ArrayBuffer)) throw new NoteError(`${format} export returned no bytes`);
  return new Uint8Array(out);
}

/** Derives the public key from a seed via a JWK export (WebCrypto has no direct operation). */
async function publicKeyFromSeed(seed: Uint8Array): Promise<Uint8Array> {
  const jwk: unknown = await crypto.subtle.exportKey('jwk', await importSeed(seed, true));
  const x = typeof jwk === 'object' && jwk !== null && 'x' in jwk ? jwk.x : undefined;
  if (typeof x !== 'string') throw new NoteError('could not derive the public key');
  const b64 = x.replace(/-/g, '+').replace(/_/g, '/');
  return fromBase64(b64.padEnd(Math.ceil(b64.length / 4) * 4, '='));
}

/** A `PRIVATE+KEY+name+id+key` string of the given type, loaded and its key ID checked. */
async function loadSignerKey(
  skey: string,
  type: SigType,
): Promise<{ name: string; keyId: number; vkey: string; key: Key }> {
  if (!skey.startsWith(SIGNER_KEY_PREFIX))
    throw new NoteError('signer key: missing PRIVATE+KEY+ prefix');
  const { name, idHex, typed } = splitKey(skey.slice(SIGNER_KEY_PREFIX.length), 'signer key', type);
  const seed = typed.slice(1);
  let publicKey: Uint8Array;
  let key: Key;
  try {
    publicKey = await publicKeyFromSeed(seed);
    key = await importSeed(seed, false);
  } catch (e) {
    if (e instanceof NoteError) throw e;
    throw new NoteError(`signer key: ${String(e)}`);
  }
  const vkey = await formatVerifierKey(name, publicKey, type);
  const keyId = Number.parseInt(idHex, 16);
  if ((await computeKeyId(name, concatBytes(Uint8Array.of(type), publicKey))) !== keyId) {
    throw new NoteError('signer key: key ID does not match name and key');
  }
  return { name, keyId, vkey, key };
}

async function ed25519Sign(key: Key, message: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.sign('Ed25519', key, arrayBufferCopy(message)));
}

/** Creates a signer from a `PRIVATE+KEY+name+id+key` string, checking its key ID. */
export async function newSigner(skey: string): Promise<NoteSigner> {
  const { name, keyId, vkey, key } = await loadSignerKey(skey, SIG_TYPE_ED25519);
  return { name, keyId, vkey, sign: (message) => ed25519Sign(key, message) };
}

async function importPublicKey(vkey: string, type: SigType): Promise<VerifierKey & { key: Key }> {
  const k = await parseVerifierKey(vkey, type);
  let key: Key;
  try {
    key = await crypto.subtle.importKey(
      'raw',
      arrayBufferCopy(k.publicKey),
      { name: 'Ed25519' },
      false,
      ['verify'],
    );
  } catch (e) {
    throw new NoteError(`verifier key: ${String(e)}`);
  }
  return { ...k, key };
}

function ed25519Verify(key: Key, message: Uint8Array, signature: Uint8Array): Promise<boolean> {
  return crypto.subtle.verify('Ed25519', key, arrayBufferCopy(signature), arrayBufferCopy(message));
}

export async function newVerifier(vkey: string): Promise<NoteVerifier> {
  const k = await importPublicKey(vkey, SIG_TYPE_ED25519);
  return {
    name: k.name,
    keyId: k.keyId,
    verify: async (message, signature) =>
      signature.length === ED25519_SIGNATURE_SIZE && ed25519Verify(k.key, message, signature),
  };
}

// ---- cosignatures (C2SP tlog-cosignature, Ed25519 cosignature/v1) ---------------------------

/** A witness key: cosigns checkpoint text at a time the caller supplies. */
export interface Cosigner {
  readonly name: string;
  readonly keyId: number;
  readonly vkey: string;
  /** The note signature line (`— name base64(keyID || timestamp || signature)` and a newline). */
  cosign(text: string, timestamp: number): Promise<string>;
}

function checkTimestamp(t: number): void {
  if (!Number.isSafeInteger(t) || t < 0) {
    throw new NoteError(`cosignature timestamp ${String(t)} is not a safe non-negative integer`);
  }
}

/** `cosignature/v1\ntime <t>\n` followed by the cosigned note text. */
function cosignedMessage(message: Uint8Array, timestamp: number): Uint8Array {
  return concatBytes(utf8Encode(`cosignature/v1\ntime ${String(timestamp)}\n`), message);
}

/**
 * The timestamp of a cosignature (the signature bytes after the key ID). Rejects anything that is
 * not 72 bytes, or a time beyond 2^53 - 1 (the spec allows up to 2^63 - 1; no real time is that
 * large, and JavaScript numbers cannot hold it exactly).
 */
export function cosignatureTimestamp(signature: Uint8Array): number {
  if (signature.length !== TIMESTAMP_SIZE + ED25519_SIGNATURE_SIZE) {
    throw new NoteError('cosignature must be a timestamp and a 64-byte signature');
  }
  const t = new DataView(signature.buffer, signature.byteOffset, TIMESTAMP_SIZE).getBigUint64(0);
  if (t > BigInt(Number.MAX_SAFE_INTEGER)) throw new NoteError('cosignature timestamp too large');
  return Number(t);
}

export async function newCosigner(skey: string): Promise<Cosigner> {
  const { name, keyId, vkey, key } = await loadSignerKey(skey, SIG_TYPE_COSIGNATURE_V1);
  return {
    name,
    keyId,
    vkey,
    cosign: async (text, timestamp) => {
      checkText(text);
      checkTimestamp(timestamp);
      const sig = await ed25519Sign(key, cosignedMessage(utf8Encode(text), timestamp));
      const raw = new Uint8Array(4 + TIMESTAMP_SIZE + ED25519_SIGNATURE_SIZE);
      const view = new DataView(raw.buffer);
      view.setUint32(0, keyId);
      view.setBigUint64(4, BigInt(timestamp));
      raw.set(sig, 4 + TIMESTAMP_SIZE);
      return `${SIG_LINE_PREFIX}${name} ${toBase64(raw)}\n`;
    },
  };
}

/**
 * A verifier for cosignature/v1 lines. It plugs into openNote like a log verifier: the signature
 * it receives is the timestamp followed by the Ed25519 signature over the cosigned message.
 */
export async function newCosignatureVerifier(vkey: string): Promise<NoteVerifier> {
  const k = await importPublicKey(vkey, SIG_TYPE_COSIGNATURE_V1);
  return {
    name: k.name,
    keyId: k.keyId,
    verify: async (message, signature) => {
      let t: number;
      try {
        t = cosignatureTimestamp(signature);
      } catch {
        return false;
      }
      return ed25519Verify(k.key, cosignedMessage(message, t), signature.subarray(TIMESTAMP_SIZE));
    },
  };
}

/** Generates a witness (cosigner) key pair, signature type 0x04. */
export async function generateCosignerKey(name: string): Promise<{ skey: string; vkey: string }> {
  return generateTypedKey(name, SIG_TYPE_COSIGNATURE_V1);
}

/** Generates a new Ed25519 key pair as Go-compatible signer and verifier key strings. */
export async function generateKey(name: string): Promise<{ skey: string; vkey: string }> {
  return generateTypedKey(name, SIG_TYPE_ED25519);
}

async function generateTypedKey(
  name: string,
  type: SigType,
): Promise<{ skey: string; vkey: string }> {
  checkName(name);
  const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  if (!isKeyPair(pair)) throw new NoteError('Ed25519 key generation returned no key pair');
  const pkcs8 = await exportBytes('pkcs8', pair.privateKey);
  const prefix = pkcs8.slice(0, PKCS8_ED25519_PREFIX.length);
  if (
    pkcs8.length !== PKCS8_ED25519_PREFIX.length + 32 ||
    !bytesEqual(prefix, PKCS8_ED25519_PREFIX)
  ) {
    throw new NoteError('unexpected PKCS#8 encoding for Ed25519 private key');
  }
  const seed = pkcs8.slice(PKCS8_ED25519_PREFIX.length);
  const publicKey = await exportBytes('raw', pair.publicKey);
  const vkey = await formatVerifierKey(name, publicKey, type);
  const { idHex } = splitKey(vkey, 'verifier key', type);
  const skey = `${SIGNER_KEY_PREFIX}${name}+${idHex}+${toBase64(concatBytes(Uint8Array.of(type), seed))}`;
  return { skey, vkey };
}

function checkText(text: string): void {
  if (!text.isWellFormed()) throw new NoteError('note is not valid UTF-8');
  if (hasControlChar(text, '\n')) throw new NoteError('note contains a control character');
  if (!text.endsWith('\n')) throw new NoteError('note text must end with a newline');
}

/** Signs `text` (which must end in a newline) with each signer and returns the signed note. */
export async function signNote(text: string, signers: readonly NoteSigner[]): Promise<string> {
  checkText(text);
  if (signers.length === 0) throw new NoteError('no signers');
  const message = utf8Encode(text);
  const seen = new Set<string>();
  let lines = '';
  for (const s of signers) {
    checkName(s.name);
    const id = `${s.name}+${keyIdHex(s.keyId)}`;
    if (seen.has(id)) throw new NoteError(`duplicate signer ${id}`);
    seen.add(id);
    const sig = await s.sign(message);
    const idBytes = new Uint8Array(4);
    new DataView(idBytes.buffer).setUint32(0, s.keyId);
    lines += `${SIG_LINE_PREFIX}${s.name} ${toBase64(concatBytes(idBytes, sig))}\n`;
  }
  return `${text}\n${lines}`;
}

/**
 * Parses and verifies a signed note. Per the spec: signatures from unknown keys are ignored; a
 * signature from a known key (same name and key ID) that fails to verify rejects the whole note;
 * and at least one known key must verify.
 */
export async function openNote(
  note: string | Uint8Array,
  verifiers: readonly NoteVerifier[],
): Promise<OpenedNote> {
  let s: string;
  if (typeof note === 'string') {
    s = note;
  } else {
    try {
      s = utf8Decode(note);
    } catch {
      throw new NoteError('note is not valid UTF-8');
    }
  }
  checkText(s);
  const split = s.lastIndexOf('\n\n');
  if (split < 0) throw new NoteError('note has no signature block');
  const text = s.slice(0, split + 1);
  const lines = s
    .slice(split + 2)
    .split('\n')
    .slice(0, -1);
  if (lines.length === 0) throw new NoteError('note has no signatures');
  if (lines.length > MAX_NOTE_SIGNATURES) throw new NoteError('note has too many signatures');

  const message = utf8Encode(text);
  const signatures: NoteSignature[] = [];
  const verified: { name: string; keyId: number }[] = [];
  const seen = new Set<string>();
  for (const line of lines) {
    const parts = line.startsWith(SIG_LINE_PREFIX)
      ? cut(line.slice(SIG_LINE_PREFIX.length), ' ')
      : null;
    if (!parts) throw new NoteError('malformed signature line');
    const [name, b64] = parts;
    if (!isValidKeyName(name)) throw new NoteError('malformed signature line: bad key name');
    let raw: Uint8Array;
    try {
      raw = fromBase64(b64);
    } catch {
      throw new NoteError('malformed signature line: bad base64');
    }
    if (raw.length < 5) throw new NoteError('malformed signature line: signature too short');
    const keyId = new DataView(raw.buffer, raw.byteOffset, 4).getUint32(0);
    const id = `${name}+${keyIdHex(keyId)}`;
    if (seen.has(id)) throw new NoteError(`duplicate signature from ${id}`);
    seen.add(id);
    const signature = raw.slice(4);
    signatures.push({ name, keyId, signature });

    const v = verifiers.find((x) => x.name === name && x.keyId === keyId);
    if (v === undefined) continue;
    if (!(await v.verify(message, signature))) {
      throw new SignatureError(`invalid signature from ${id}`);
    }
    verified.push({ name, keyId });
  }
  if (verified.length === 0) throw new SignatureError('no signature from a known key');
  return { text, signatures, verified };
}

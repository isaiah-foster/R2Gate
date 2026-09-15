import { describe, expect, it } from 'vitest';
import { ENTRY_SCHEMA_VERSION } from '../src/index.ts';

describe('core skeleton', () => {
  it('exports the entry schema version', () => {
    expect(ENTRY_SCHEMA_VERSION).toBe(1);
  });

  it('has WebCrypto SHA-256 and Ed25519 available', async () => {
    const digest = await crypto.subtle.digest('SHA-256', new Uint8Array());
    expect(digest.byteLength).toBe(32);
    const kp = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
    expect('privateKey' in kp).toBe(true);
  });
});

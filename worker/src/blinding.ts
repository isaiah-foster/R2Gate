// Key blinding (M8) on the writer side: the KeyBlinder for this deployment, or null when the log is
// not blinded. KEY_BLINDING (a var) says whether; KEY_BLINDING_KEY (a secret) is the HMAC key.
// Parsed apart from Config because it is asynchronous (WebCrypto key import).

import { newKeyBlinder, type KeyBlinder } from '@r2notary/core';
import { ConfigError, type Config } from './config.ts';

export async function loadBlinder(
  config: Pick<Config, 'keyBlinding'>,
  secret: unknown,
): Promise<KeyBlinder | null> {
  if (!config.keyBlinding) return null;
  if (typeof secret !== 'string' || secret === '') {
    throw new ConfigError('KEY_BLINDING is "true" but KEY_BLINDING_KEY is not set');
  }
  try {
    return await newKeyBlinder(secret);
  } catch (e) {
    throw new ConfigError(`KEY_BLINDING_KEY: ${e instanceof Error ? e.message : String(e)}`);
  }
}

/** The value recorded in the Sequencer for a log's blinding: the secret's fingerprint, or "off". */
export function blindingState(blinder: KeyBlinder | null): string {
  return blinder === null ? 'off' : `hmac-sha256:${blinder.fingerprint}`;
}

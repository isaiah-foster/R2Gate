// Contract for the R2 behaviour publication depends on (DECISIONS D2.1). The same checks run
// against local R2 (r2-contract.test.ts) and, with human approval, real R2 (remote.test.ts; see
// docs/OPERATIONS.md). The Workers API reference documents `onlyIf.etagDoesNotMatch` but not
// what `'*'` means, and a Miniflare bug once inverted conditional puts, so this is tested, not assumed.

import { expect, it } from 'vitest';
import { CREATE_ONLY, LogDivergenceError, putImmutable } from '../../src/publish.ts';

async function text(bucket: R2Bucket, key: string): Promise<string | null> {
  const o = await bucket.get(key);
  return o === null ? null : o.text();
}

export function conditionalWriteContract(bucket: () => R2Bucket, prefix: string): void {
  const k = (name: string): string => `${prefix}/${name}`;

  it('etagDoesNotMatch "*" creates an absent object', async () => {
    const key = k('create-absent');
    await bucket().delete(key);
    const res = await bucket().put(key, 'first', { onlyIf: CREATE_ONLY });
    expect(res).not.toBeNull();
    expect(await text(bucket(), key)).toBe('first');
  });

  it('etagDoesNotMatch "*" refuses to overwrite: put returns null, object unchanged', async () => {
    const key = k('no-overwrite');
    await bucket().delete(key);
    await bucket().put(key, 'first');
    expect(await bucket().put(key, 'second', { onlyIf: CREATE_ONLY })).toBeNull();
    expect(await text(bucket(), key)).toBe('first');
  });

  it('If-None-Match: * as Headers behaves the same', async () => {
    const key = k('headers-form');
    await bucket().delete(key);
    const onlyIf = new Headers({ 'If-None-Match': '*' });
    expect(await bucket().put(key, 'first', { onlyIf })).not.toBeNull();
    expect(await bucket().put(key, 'second', { onlyIf })).toBeNull();
    expect(await text(bucket(), key)).toBe('first');
  });

  it('a concrete etagDoesNotMatch still compares etags', async () => {
    const key = k('concrete-etag');
    await bucket().delete(key);
    const first = await bucket().put(key, 'first');
    expect(first).not.toBeNull();
    const etag = first?.etag ?? '';
    expect(await bucket().put(key, 'second', { onlyIf: { etagDoesNotMatch: etag } })).toBeNull();
    expect(
      await bucket().put(key, 'third', { onlyIf: { etagDoesNotMatch: 'nope' } }),
    ).not.toBeNull();
    expect(await text(bucket(), key)).toBe('third');
  });

  it('a put with a wrong sha256 is rejected and stores nothing', async () => {
    const key = k('bad-sha256');
    await bucket().delete(key);
    await expect(bucket().put(key, 'data', { sha256: '00'.repeat(32) })).rejects.toThrow();
    expect(await bucket().head(key)).toBeNull();
  });

  it('putImmutable: created, then existed for identical bytes, then divergence', async () => {
    const key = k('put-immutable');
    await bucket().delete(key);
    const enc = (s: string) => new TextEncoder().encode(s);
    expect(await putImmutable(bucket(), key, enc('tile'))).toBe('created');
    expect(await putImmutable(bucket(), key, enc('tile'))).toBe('existed');
    await expect(putImmutable(bucket(), key, enc('tilf'))).rejects.toThrow(LogDivergenceError);
    expect(await text(bucket(), key)).toBe('tile');
  });
}

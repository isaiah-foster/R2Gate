// Contract for the R2 list() behaviour the auditor's merge-join depends on (DECISIONS D6.2):
//   - keys come back in UTF-8 byte order (the order SQLite's BINARY collation uses), which is not
//     JavaScript's UTF-16 order for astral characters;
//   - `startAfter` returns exactly the keys after it in that order, whether or not it exists.
// `startAfter` is in the Workers types and in R2's S3 API (ListObjectsV2 start-after) but not in
// the Workers API reference, so it is pinned here. Runs against local R2 (r2-list-order.test.ts)
// and, with approval, real R2 (test-remote/, docs/OPERATIONS.md).

import { compareUtf8 } from '@r2notary/core';
import { expect, it } from 'vitest';

/** Keys whose UTF-8 and UTF-16 orders differ, plus ASCII and 2- and 3-byte neighbours. */
export const ORDER_KEYS: readonly string[] = [
  'A',
  'Z',
  'a',
  'a b',
  'a/b',
  'a0',
  '~',
  'é',
  'ü',
  'ࠀ',
  '퟿',
  '',
  'x',
  '�',
  '\u{10000}',
  '\u{1F600}',
  '\u{1F600}x',
  '\u{20000}',
];

export function sortedUtf8(keys: readonly string[]): string[] {
  return [...keys].sort(compareUtf8);
}

export function listOrderContract(bucket: () => R2Bucket, prefix: string): void {
  const full = ORDER_KEYS.map((k) => `${prefix}/${k}`);
  const want = sortedUtf8(full);

  // Every loop is bounded: a listing that fails to advance must fail the test, not hang it.
  const MAX_PAGES = 50;

  /** Pages with the opaque cursor only. */
  async function listByCursor(): Promise<string[]> {
    const out: string[] = [];
    let cursor: string | undefined;
    for (let i = 0; i < MAX_PAGES; i++) {
      const page = await bucket().list({
        prefix: `${prefix}/`,
        limit: 4,
        ...(cursor === undefined ? {} : { cursor }),
      });
      out.push(...page.objects.map((o) => o.key));
      if (!page.truncated) return out;
      cursor = page.cursor;
    }
    throw new Error('listing did not finish');
  }

  /**
   * Pages with startAfter only, as the auditor does (each page starts after the previous page's
   * last key; a cursor is never combined with startAfter, see D6.2).
   */
  async function listFrom(after: string, limit: number): Promise<string[]> {
    const out: string[] = [];
    let from = after;
    for (let i = 0; i < MAX_PAGES; i++) {
      const page = await bucket().list({ prefix: `${prefix}/`, startAfter: from, limit });
      out.push(...page.objects.map((o) => o.key));
      const last = page.objects.at(-1);
      if (!page.truncated) return out;
      if (last === undefined) throw new Error('truncated page with no objects');
      from = last.key;
    }
    throw new Error('listing did not finish');
  }

  it('the key set really distinguishes UTF-8 from UTF-16 order', () => {
    expect([...full].sort()).not.toEqual(want);
  });

  it('list() returns keys in UTF-8 byte order', async () => {
    await Promise.all(full.map((k) => bucket().put(k, k)));
    expect(await listByCursor()).toEqual(want);
  });

  it('startAfter returns exactly the keys after it, present or not', async () => {
    await Promise.all(full.map((k) => bucket().put(k, k)));
    const probes = [...full, `${prefix}/\uE000\u0000`, `${prefix}/\u{1F5FF}`, `${prefix}/`];
    for (const after of probes) {
      const expected = want.filter((k) => compareUtf8(k, after) > 0);
      // One page holds everything: this checks the starting point alone.
      expect(await listFrom(after, 1000), JSON.stringify(after)).toEqual(expected);
    }
  });

  it('paging by startAfter (as the auditor does) visits every key once', async () => {
    await Promise.all(full.map((k) => bucket().put(k, k)));
    for (const limit of [1, 3, 4]) {
      expect(await listFrom(`${prefix}/`, limit), `limit ${String(limit)}`).toEqual(want);
    }
  });
}

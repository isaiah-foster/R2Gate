// PLAN M6: "Unicode-key ordering test". The merge-join needs R2 list() and the Sequencer's SQLite
// `ORDER BY key` to agree; both are checked against UTF-8 byte order (compareUtf8).
import { compareUtf8 } from '@r2notary/core';
import { env } from 'cloudflare:workers';
import { reset, runInDurableObject } from 'cloudflare:test';
import { afterEach, describe, expect, it } from 'vitest';
import { SequencerStore } from '../src/store.ts';
import { ORDER_KEYS, listOrderContract, sortedUtf8 } from './contract/r2-list-order.ts';

afterEach(() => reset());

describe('R2 list order contract (local R2)', () => {
  listOrderContract(() => env.MONITORED, 'order');
});

describe('SQLite key order in the Sequencer', () => {
  it('ORDER BY key and key > ? follow UTF-8 byte order', async () => {
    await runInDurableObject(env.SEQUENCER.getByName('order'), (_, state) => {
      const store = new SequencerStore(state.storage);
      store.migrate();
      for (const [i, key] of ORDER_KEYS.entries()) {
        state.storage.sql.exec(
          `INSERT INTO objects(key, etag, size, event_time, event_ms, seq, deleted)
           VALUES (?, 'e', 1, '2026-01-01T00:00:00Z', 0, ?, 0)`,
          key,
          i,
        );
      }
      const want = sortedUtf8(ORDER_KEYS);
      expect(store.objectStates({ limit: 100 }).map((o) => o.key)).toEqual(want);
      for (const after of [...ORDER_KEYS, '\u0000', '\u{1F5FF}']) {
        expect(
          store.objectStates({ after, limit: 100, liveOnly: true }).map((o) => o.key),
          JSON.stringify(after),
        ).toEqual(want.filter((k) => compareUtf8(k, after) > 0));
      }
    });
  });
});

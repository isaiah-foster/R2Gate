# Benchmarks

Methodology, environment and results for PLAN §14. Every figure below is copied from a file in
`bench/results/` (rounded for display; the files have full precision, sample counts and
percentiles). If a figure is not in those files, it is not claimed.

> **Everything here ran on one laptop.** Nothing has been measured on Cloudflare's network: the
> Worker, Durable Object, Queue, Workflow and R2 were local simulations (`wrangler dev` / workerd /
> Miniflare). Local SQLite and R2 are files on a local SSD; on Cloudflare every Durable Object write
> waits for replication and every R2 call crosses the network. Read the timings as the cost of the
> code, not as production capacity. Operation counts (§3, §4) do not depend on the machine.

## Environment

All runs on 2026-10-03, from commit `f35a560` plus the uncommitted M7 changes (each result file
records `dirty: true`).

|                    |                                                                  |
| ------------------ | ---------------------------------------------------------------- |
| CPU                | AMD Ryzen 5 3600 (6 cores, 12 threads)                           |
| Memory             | 16 GiB                                                           |
| OS                 | Linux 7.2.5                                                      |
| Node.js            | v26.10.0                                                         |
| Go                 | go1.27.1                                                         |
| wrangler / workerd | 4.147.0 / 1.20261001.1                                           |
| Worker config      | `worker/wrangler.jsonc` defaults unless a section says otherwise |

## Reproducing

```sh
npm ci
npm run bench               # all of the below, in order; or one at a time:
npm run bench:hashing       # §5, Node
npm run bench:proofs        # §4, Node + Go CLI (needs Go)
npm run bench:amplification # §3, workerd (vitest)
npm run bench:cost          # §7, arithmetic over §3's output
npm run bench:sequencer     # §2, wrangler dev
npm run bench:latency       # §1, wrangler dev
npm run bench:auditor       # §6, wrangler dev
```

No account, network or secrets are needed: each harness generates a throwaway signing key and
tokens, runs `wrangler dev` on random ports with its own state directory (`scripts/lib/dev.ts`),
and writes `bench/results/<name>.json` with the environment. Run nothing else heavy at the same
time.

**Conventions.** Times are wall-clock from the driving Node process (`performance.now()`), because
workerd's clocks only advance on I/O, so code cannot time itself inside it. Percentiles are
nearest-rank (every reported value was observed). `n` is the sample count. Where a harness drives
`wrangler dev`, each timing includes one localhost HTTP request and a Worker-to-DO call.

## 1. Event → visible latency (PLAN §14.1)

`bench/latency.ts` → `latency.json`. 1,000 `PutObject` notifications for distinct keys, sent at a
fixed rate through the dev simulator onto the **local queue**, consumed by the real Worker, published
by the Sequencer's alarm. Latency = from the send request until the first `/api/v1/status` poll
(every 50 ms) whose published size covers the event. It **excludes** R2's delay from object write
to notification, which a local run cannot observe.

| rate | `CHECKPOINT_INTERVAL_MS` | median    | p95       | p99       | max       | n     |
| ---- | ------------------------ | --------- | --------- | --------- | --------- | ----- |
| 25/s | 1,000                    | 3,059 ms  | 4,858 ms  | 4,994 ms  | 5,010 ms  | 1,000 |
| 25/s | 5,000                    | 5,030 ms  | 8,629 ms  | 8,906 ms  | 9,025 ms  | 1,000 |
| 25/s | 15,000                   | 12,373 ms | 18,374 ms | 18,876 ms | 19,027 ms | 1,000 |
| 50/s | 1,000                    | 1,961 ms  | 2,861 ms  | 2,944 ms  | 2,961 ms  | 1,000 |
| 50/s | 5,000                    | 4,350 ms  | 6,751 ms  | 6,950 ms  | 6,953 ms  | 1,000 |
| 50/s | 15,000                   | 4,978 ms  | 9,479 ms  | 9,879 ms  | 9,978 ms  | 1,000 |

Reading it:

- Two waits add up. The queue delivers a batch when it has 100 messages or 5 s after it started
  filling (`max_batch_size`, `max_batch_timeout`), which is 4 s at 25/s and 2 s at 50/s. Then
  publication is due one interval after the **oldest** pending entry arrived (D2.8), so an entry
  that arrives late in that window waits less than a full interval.
- That is why 25/s is slower than 50/s at a 1 s interval: the queue, not the Sequencer, dominates.
- At 50/s with a 15 s interval, 500 entries (`BATCH_MAX_ENTRIES`) pile up after 10 s and publication
  starts before the interval ends, so latency is capped by the batch limit rather than the interval.
- To lower latency, shorten `max_batch_timeout` as well as the interval; both cost more operations
  (§3).

## 2. Sequencer throughput (PLAN §14.2)

`bench/sequencer.ts` → `sequencer.json`. The real Sequencer under `wrangler dev`. Appends go
straight to it by RPC (`/__simulate/append`), bypassing the queue.

**One append call, alone** (no publication running), 30 samples each:

| entries per call | median  | p95     | entries/s at the median |
| ---------------- | ------- | ------- | ----------------------- |
| 1                | 4.4 ms  | 5.4 ms  | 227                     |
| 10               | 5.6 ms  | 7.5 ms  | 1,796                   |
| 100              | 19.4 ms | 20.9 ms | 5,163                   |

**One publication** (`POST /api/v1/admin/publish`), 15 samples each:

| entries | median   | p95      | entries/s at the median |
| ------- | -------- | -------- | ----------------------- |
| 1       | 10.9 ms  | 12.0 ms  | 92                      |
| 10      | 12.7 ms  | 14.4 ms  | 788                     |
| 100     | 25.8 ms  | 28.5 ms  | 3,873                   |
| 500     | 78.3 ms  | 86.6 ms  | 6,385                   |
| 1,000   | 148.7 ms | 156.8 ms | 6,723                   |

**Sustained load**: `c` clients append batches of 100 as fast as they can for about 20 s while the
alarm publishes (`CHECKPOINT_INTERVAL_MS=1000`, `BATCH_MAX_ENTRIES=500`):

| clients | accepted/s | published/s | backlog at the end | time to drain it | append call median / p95 |
| ------- | ---------- | ----------- | ------------------ | ---------------- | ------------------------ |
| 1       | 2,932      | 2,932       | 0                  | –                | 19.5 / 94.7 ms           |
| 2       | 3,102      | 3,087       | 300                | 0.8 s            | 43.2 / 129.1 ms          |
| 4       | 3,021      | 3,011       | 200                | 1.0 s            | 143.4 / 186.2 ms         |
| 8       | 3,071      | 2,940       | 2,700              | 0.6 s            | 245.6 / 324.4 ms         |
| 16      | 4,366      | 2,045       | 47,100             | 8.0 s            | 367.6 / 412.1 ms         |

**Saturation and bottleneck.** Locally, one Sequencer sustains about 3,000 entries/s whatever the
number of clients; extra clients only make each call wait longer. The ceiling matches doing both
jobs on one thread: appending 100 entries alone runs at 5,163/s and publishing 500 at 6,385/s, and
1 / (1/5,163 + 1/6,385) ≈ 2,850/s. The Durable Object is single-threaded, so appends and
publications take turns. At 16 clients appends won more of the turns: published/s fell to 2,045,
and the backlog grew by ~2,300 entries/s until the load stopped. Since an entry is durable when its
append returns, overload delays visibility; it does not lose entries.

What this does **not** say: the throughput on Cloudflare, where SQLite commits are replicated and R2
writes are remote. The queue in front also limits the RPC rate: one `ingest` call per batch of at
most 100 messages, and 5,000 messages/s per queue (D0.5).

## 3. Operation amplification (PLAN §14.3)

`worker/bench/amplification.bench.ts` (run by `bench/amplification.ts`) → `amplification.json`.
Inside workerd: PutObject notifications for new keys go through the real queue handler (batches of
min(k, 100)) and the real alarm publishes every k entries, for at least 2,560 entries per k. Counted
by wrapping the bindings: R2 calls by price class, SQLite `rowsRead`/`rowsWritten` from every cursor
(the values the DO docs say are billed), `setAlarm` calls (billed as a row written each), and bytes
written to R2. Exact counts, not timings.

| entries per publication (k) | R2 Class A per publication | Class A per entry | rows written per publication | rows written per entry (billed, all phases) | R2 bytes kept per entry |
| --------------------------- | -------------------------- | ----------------- | ---------------------------- | ------------------------------------------- | ----------------------- |
| 1                           | 4.0                        | 4.00              | 19.8                         | 28.8                                        | 38,258                  |
| 2                           | 4.0                        | 2.00              | 25.8                         | 19.9                                        | 19,203                  |
| 5                           | 4.1                        | 0.81              | 43.8                         | 14.6                                        | 7,889                   |
| 10                          | 4.1                        | 0.41              | 73.8                         | 12.8                                        | 4,078                   |
| 20                          | 4.2                        | 0.21              | 133.8                        | 11.9                                        | 2,173                   |
| 50                          | 4.6                        | 0.092             | 313.0                        | 11.4                                        | 1,058                   |
| 100                         | 5.2                        | 0.052             | 612.2                        | 11.2                                        | 676                     |
| 200                         | 6.3                        | 0.032             | 1,210.6                      | 11.1                                        | 471                     |
| 500                         | 8.7                        | 0.017             | 2,983.0                      | 11.0                                        | 405                     |

No Class B operations on the write path (a `get` happens only when a retried create-if-absent finds
the object already there).

Findings:

- **R2 Class A is per publication.** A checkpoint costs about 4 writes (partial bundle, partial
  tile, archived checkpoint, live checkpoint); a batch that completes full tiles also writes each
  full tile and bundle and the changed level-1 partial tile. Per entry, that is what larger batches
  amortize.
- **Durable Object rows written are per entry, and they dominate cost** (§7): about 4 per message at
  ingest, about 6 per entry at publication and 1 to prune the dedupe record, plus fixed rows per
  batch and per publication (`amplification.json` has the phases separately). Only totals were
  counted; by the schema, the per-entry rows are the entry, the dedupe row and its two indexes at
  ingest, and the expected-state row and its two indexes, the key-index row and its primary-key
  index, and deleting the published entry at publication. Follow-ups in D7.6.
- **R2 storage grows by far more than the entries at small k.** Every publication writes a new
  partial bundle (all entries since the last full bundle) and partial tile, and superseded partials
  are kept (D4.5). At one entry per publication that is about 38 KB kept per entry; at 500, about
  400 bytes. Follow-up in D7.7.

## 4. Proof cost (PLAN §14.4)

`bench/proofs.ts` → `proofs.json`. Logs of 10³, 10⁵ and 10⁶ synthetic entries generated by
`packages/core` (in a child process, written to disk), served by a counting HTTP server on
localhost, verified by the real Go CLI. Bytes and requests are exact; times are the whole CLI
process (start-up, localhost HTTP, verification), 10 runs after 1 warm-up. The old checkpoint for
consistency is at ⌊n/2⌋ + 7.

| log size | operation                       | RFC 6962 proof (hashes) | requests | bytes fetched (tiles + bundle + checkpoint) | median | p95    |
| -------- | ------------------------------- | ----------------------- | -------- | ------------------------------------------- | ------ | ------ |
| 10³      | checkpoint only                 | –                       | 1        | 216                                         | 6.1 ms | 7.4 ms |
| 10³      | inclusion, index 500            | 10                      | 5        | 80,952 (15,712 + 65,024 + 216)              | 6.5 ms | 6.9 ms |
| 10³      | consistency 507 → 1,000         | 11                      | 4        | 15,928                                      | 6.4 ms | 6.8 ms |
| 10⁵      | checkpoint only                 | –                       | 1        | 218                                         | 5.7 ms | 6.6 ms |
| 10⁵      | inclusion, index 50,000         | 17                      | 7        | 91,468 (25,824 + 65,426 + 218)              | 6.9 ms | 7.6 ms |
| 10⁵      | consistency 50,007 → 100,000    | 18                      | 6        | 26,042                                      | 6.7 ms | 7.3 ms |
| 10⁶      | checkpoint only                 | –                       | 1        | 219                                         | 5.6 ms | 7.2 ms |
| 10⁶      | inclusion, index 500,000        | 20                      | 7        | 86,925 (21,024 + 65,682 + 219)              | 6.7 ms | 7.0 ms |
| 10⁶      | consistency 500,007 → 1,000,000 | 21                      | 6        | 21,243                                      | 6.4 ms | 6.9 ms |

`proofs.json` also has indexes 0 and n − 1 (the last entry sits in a partial tile and bundle, so it
fetches less).

- Bytes fetched grow with the number of tile **levels**, not the log size: going from 10³ to 10⁶
  entries adds one level. A tile-based proof downloads whole tiles (up to 8 KB each) instead of the
  ~32-byte nodes of an RFC 6962 proof (at most 21 × 32 = 672 bytes here); that is the price of a
  server that only serves static, cacheable files.
- For inclusion, about three quarters of the bytes are the entry bundle, which the CLI fetches to
  print the entry and verifies in full (D5.4).
- Verification time is indistinguishable from the checkpoint-only baseline: process start-up and
  signature checking dominate. A first version timed the CLI from a process holding the whole
  10⁶-entry log in memory, and every run got slower with log size (16.7 ms for a checkpoint at 10⁵);
  spawning from a large process was the cost, not verification. Generation now runs in a child
  process (D7.5).

## 5. Core hashing speed (PLAN §14.5)

`bench/hashing.ts` → `hashing.json`. Node.js, not workerd (the clock problem above). Hashing a full
tree of 65,536 leaves (131,071 SHA-256 calls), 15 runs after 2 warm-ups:

| strategy                                            | median   | p95      | leaves/s at the median |
| --------------------------------------------------- | -------- | -------- | ---------------------- |
| one `await` per hash                                | 2,539 ms | 2,681 ms | 25,817                 |
| `Promise.all` per level (what `packages/core` does) | 1,086 ms | 1,295 ms | 60,343                 |
| `Promise.all` in chunks of 256                      | 942 ms   | 1,073 ms | 69,592                 |
| Node `createHash`, synchronous (reference only)     | 683 ms   | 1,095 ms | 95,961                 |

In-memory work of one publication (`appendEntries` + Ed25519 signature) from a 1,000-entry log:

| entries | median  | p95      |
| ------- | ------- | -------- |
| 1       | 2.2 ms  | 2.4 ms   |
| 10      | 3.8 ms  | 202.2 ms |
| 100     | 3.1 ms  | 6.1 ms   |
| 500     | 8.0 ms  | 14.2 ms  |
| 1,000   | 14.2 ms | 18.9 ms  |

- Batching matters: issuing a level's hashes together is 2.3× faster than awaiting each one.
  Bounding it to 256 in flight is slightly faster still in Node (less pending-promise overhead);
  the difference is small next to the run-to-run spread and was not adopted.
- Node's `createHash` is only a reference: `packages/core` must use WebCrypto. Node's WebCrypto
  runs digests on libuv's thread pool and workerd's does not, so the ratio in workerd is unknown.
- The 202 ms p95 at 10 entries is one outlier among 15 runs (likely garbage collection), kept as
  measured.
- Across runtimes, so only roughly: the computation of a 500-entry publication takes 8 ms in Node,
  while the whole local publication in §2 takes 78 ms. Most of a publication is R2 writes, SQLite
  and the RPC, not hashing.

## 6. Auditor (PLAN §14.6)

`bench/auditor.ts` → `auditor.json`. The real Workflow (local engine), Worker and Sequencer.
`AUDIT_GRACE_SECONDS=0`, so no grace sleep is included; on Cloudflare every audit also waits out
the grace window (300 s by default) after its last page.

| what                                      | objects | pages | time (median of 5 / single run) | objects/s |
| ----------------------------------------- | ------- | ----- | ------------------------------- | --------- |
| audit, bucket matches the log, 0 findings | 10,000  | 10    | 795 ms (p95 891 ms)             | 12,573    |
| backfill of unlogged objects              | 10,000  | 10    | 2,263 ms (one run)              | 4,418     |

A backfill appends and publishes one snapshot entry per object, which is why it is slower than an
audit that appends only its start and end entries.

**Deep scrub**: 20 objects of 8 MiB (one page; at most 20 bodies are hashed per page), audited
with `DEEP_SCRUB_SAMPLE_RATE=0` (median 41 ms) and then, on the same state, `=1` (median 987 ms):
**177 MB/s** at the medians (167.8 MB hashed with `crypto.DigestStream`, local disk reads). On the
Workers Free plan a step has 10 ms of CPU, which this rate suggests would not cover even one 8 MiB
body; not measured there.

## 7. Cost model (PLAN §14.7)

`bench/cost.ts` → `cost.json`. **Arithmetic, not a measurement**: §3's counts, the Workers Paid list
prices read on 2026-10-03 (R2 page updated 2026-10-01, Durable Objects 2026-09-30, Queues
2026-04-21, Workers 2026-10-02; URLs in the file), and an explicit arrival model: Poisson arrivals
at a constant rate over a 30-day month; a publication covers 1 + rate × interval entries (at most
500); a queue batch closes 5 s after its first message or at 100. Real traffic is burstier, which
means fewer, larger publications for the same total.

Monthly list price of the write path, before included allowances, in USD:

| events/month | interval | entries per publication | R2 Class A | DO rows written | Queues | total (list) | total on Paid, incl. 5 USD base, after allowances |
| ------------ | -------- | ----------------------- | ---------- | --------------- | ------ | ------------ | ------------------------------------------------- |
| 1M           | 1 s      | 1.4                     | 13.01      | 22.34           | 1.20   | 37.33        | 14.32                                             |
| 1M           | 5 s      | 2.9                     | 6.18       | 17.09           | 1.20   | 24.93        | 7.48                                              |
| 1M           | 15 s     | 6.8                     | 2.70       | 14.41           | 1.20   | 18.60        | 5.80                                              |
| 10M          | 1 s      | 4.9                     | 37.50      | 140.52          | 12.00  | 192.11       | 140.35                                            |
| 10M          | 5 s      | 20.3                    | 9.33       | 118.91          | 12.00  | 140.97       | 90.34                                             |
| 10M          | 15 s     | 58.9                    | 3.58       | 114.30          | 12.00  | 130.33       | 80.90                                             |
| 100M         | 1 s      | 39.6                    | 50.56      | 1,138.18        | 120.00 | 1,312.13     | 1,259.22                                          |
| 100M         | 5 s      | 193.9                   | 14.48      | 1,110.16        | 120.00 | 1,246.27     | 1,194.82                                          |
| 100M         | 15 s     | 500                     | 7.80       | 1,101.23        | 120.00 | 1,230.46     | 1,179.16                                          |

The "total" columns also include DO requests, DO rows read, Workers requests and the first month's
R2 storage, each under 2 USD in every scenario (see the file). R2 storage is cumulative: the 1M/1 s
scenario adds 27.6 GB a month, the 100M/15 s one 40.5 GB.

- **Durable Object rows written are 60-90 % of the bill** in every scenario. A longer interval saves
  R2 writes but barely moves the total; reducing rows per event is what would (D7.6).
- **Not included:** Durable Object duration (GB-s while the object is active), Workers CPU time,
  Workflow steps (the auditor), and reads by verifiers. None of them can be measured locally.
- To check against reality, compare with the R2 and Durable Object metrics of a real deployment
  (not done).

## Not measured

- Anything on Cloudflare's network: R2 → queue notification delay, replicated DO commits, remote R2
  latency, Workers Cache, the Free plan's 10 ms CPU limit per Workflow step.
- Durable Object duration and Workers CPU (cost model).
- Throughput with the real queue in front of the Sequencer at high rates.
- A real bill to validate §7.

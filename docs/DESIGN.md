# Design

How R2Notary works and why it is built this way. Scope and acceptance criteria are in `PLAN.md`;
every individual decision, with the alternatives considered, is in `docs/DECISIONS.md` (cited as
`Dn.m`). Measured figures quoted here come from `bench/results/` and are explained in
`docs/BENCHMARKS.md`; all of them are **local** measurements unless stated otherwise.

## 1. Architecture

```
                       ┌────────────────────┐
  writers ──PUT/DEL──▶ │ R2: monitored      │◀──────── list / get (auditor) ─────────┐
  (S3 API, Workers)    │ bucket             │                                        │
                       └─────────┬──────────┘                                        │
                                 │ event notifications (at least once, unordered)    │
                                 ▼                                                   │
                       ┌────────────────────┐  after max_retries  ┌───────────────┐   │
                       │ Queue              │────────────────────▶│ DLQ           │   │
                       └─────────┬──────────┘                     └──────┬────────┘   │
                                 ▼                                       ▼            │
┌─────────────────────────────────────────────────────────────────────────────────────┴──┐
│ Worker "r2notary"                                                                      │
│  queue()      validate → eventId → Sequencer.ingest(batch, counters) → ack / retry     │
│  fetch()      /log/<name>/…  tiles, bundles, checkpoints (read path)                   │
│               /api/v1/…      status, lookup, findings; admin publish / scan / backfill │
│  scheduled()  cron → start an audit                                                    │
│  ScanWorkflow resumable bucket scan: list page → Sequencer.scanPage → … → finish       │
└───────────────┬──────────────────────────────────────────────┬─────────────────────────┘
                ▼ RPC (one instance per log)                   │ get
       ┌──────────────────────────┐   tiles, bundles,   ┌──────▼───────────┐
       │ Sequencer Durable Object │──checkpoints───────▶│ R2: log bucket   │◀── Go CLI,
       │ SQLite: entries, dedupe, │   (create-if-absent;│ <name>/tile/…    │    browsers:
       │ tree state, objects view,│    live checkpoint  │ <name>/checkpoint│    verify
       │ audit state              │    last)            └──────────────────┘    locally
       └──────────────────────────┘
```

One deployment watches one monitored bucket and maintains one log (PLAN §7).

**Two durability points.**

1. **Durable**: the entry is committed to the Sequencer's SQLite. The queue message is acked only
   after the `ingest` RPC returns, and the DO's output gate holds that response until the write is
   flushed (D2.6). A crash after this point loses nothing.
2. **Visible**: the entry is covered by a signed checkpoint whose tiles and bundles are already in
   R2. Only then can anyone verify it.

The delay between the two is the publication cadence: `CHECKPOINT_INTERVAL_MS` after the oldest
pending entry arrived, or at once when `BATCH_MAX_ENTRIES` are waiting (D2.8).

## 2. The log format

The log is a standard C2SP **tlog-tiles** log, so third-party tooling can read it (PLAN G1).

- **Entries** are canonical JSON (sorted keys, no whitespace, integers only, one encoding per
  value; D1.5) with `"v":1` and a `type`: `object.event` (from a notification), `object.snapshot`
  (backfill), `audit.scan`, `audit.finding`, `audit.observation` (auditor). The account ID in R2
  notifications is never logged. Unknown types are skipped by verifiers, not rejected (D1.6, D6.9).
- **Merkle tree**: RFC 6962 hashing. Leaf = SHA-256(0x00 ‖ entry), node = SHA-256(0x01 ‖ l ‖ r).
- **Tiles**: height 8, so a full tile is 256 hashes (8,192 bytes). The writer persists only the
  partial tile of each level; the root is the right fold of the frontier read off those partial
  tiles (D1.2). Entry **bundles** are 256 entries, each prefixed with a big-endian uint16 length,
  which caps an entry at 65,535 bytes; the worst-case entry fits (D1.6).
- **Checkpoints**: `<origin>\n<size>\n<base64 root>\n`, signed as a C2SP signed note with Ed25519
  (WebCrypto in Workers; the key is a PKCS#8-wrapped seed in the Go `note` key format, D1.4). The
  origin is the log's URL prefix (D4.1).

Log bucket layout, under `<LOG_NAME>/`:

```
checkpoint                 live checkpoint (the only object ever overwritten)
tile/<L>/<N>[.p/<W>]       Merkle tiles (partial tiles at .p/<width>)
tile/entries/<N>[.p/<W>]   entry bundles
x-checkpoints/<size>       every published checkpoint (extension; immutable)
x-reports/<scanId>.json    audit reports (extension; convenience, not evidence)
```

Every object except `checkpoint` is written **create-if-absent** and is a pure function of the
log prefix it covers, partial tiles included (D2.3). That one property carries the whole crash-
safety argument below.

## 3. Ingest and the Sequencer

**Consumer.** Each queue batch (up to 100 messages) is classified message by message: events from
the log bucket are dropped first (loop protection, I8), events from other buckets are counted and
dropped, invalid messages are counted and acked (they can never become valid), and the rest become
`object.event` entries. Documented fields are validated strictly; unknown fields are ignored so a
new R2 field cannot make every event invalid (D3.2). The whole batch then goes to the Sequencer in
**one** `ingest` RPC, which commits the entries and the counters in one SQLite transaction (D3.3).
On success the batch is acked; on failure it is retried with backoff (10 s doubling to 300 s); after
5 retries it lands in the dead-letter queue, which this Worker also consumes once more (D3.5).

**Dedupe (I5).** `eventId` = SHA-256 of the canonical JSON array `[bucket, key, action, etag,
eventTime]` (D3.1; the plan's `|`-join could collide on keys containing `|`). An ID seen within
`DEDUPE_TTL_SECONDS` (default 24 h) is a duplicate. Redeliveries, replays and concurrent overlapping
batches are each recorded once.

**Ordering.** Queue delivery is unordered, so **log order is ingestion order**. Each entry carries
R2's `eventTime`; anyone who needs real-time order sorts by it. The Sequencer's materialized view
of expected object state (`objects`, read by the auditor) applies an event only if it is not older
than the stored state for that key, so late deliveries do not roll the view back (D2.7).

**State** (SQLite, schema v3, versioned migrations): `entries` (unpublished entries plus the
current partial bundle; a single-row bundle BLOB could exceed the 2 MB row limit, D2.2), `seen`
(dedupe), `tile_state`, `objects`, `key_index`, `counters`, `scrub_state`, and the auditor's `scans`
/ `scan_candidates` / `scan_findings`.

## 4. Publication, and why it is crash-safe

`publish()` (`worker/src/publish.ts`) runs from the alarm or the admin API, single-flight:

1. **Plan.** Target size = published size + min(pending, `BATCH_MAX_ENTRIES`), but at least any
   `publishing_size` recorded by an interrupted run. Record the target.
2. **Compute in memory**, from SQLite state only: leaf hashes, new full tiles and bundles, partial
   tiles and bundle, the root, and the signed checkpoint.
3. **Write to R2**, in this order: (a) full bundles and tiles, (b) partial bundle and partial tiles,
   (c) `x-checkpoints/<size>`, (d) the live `checkpoint`. (a)-(c) are create-if-absent
   (`onlyIf: { etagDoesNotMatch: '*' }`, with a SHA-256 the upload must match); an object that
   already exists must be byte-identical (archived checkpoints: same signed text), or publication
   fails with `TILE_DIVERGENCE` and keeps failing until a human looks (I4, D2.5).
4. **Commit** in one SQLite transaction: tree state, `objects` and `key_index`, published size,
   clear `publishing_size`, drop entries no longer needed.

Why a crash anywhere is safe:

- **Nothing is visible before it is durable (I2).** The live checkpoint is written last, after
  every object it references; R2 is strongly consistent, so a reader who sees it can fetch them.
- **Retries are idempotent (I6).** Everything in steps 2-3 is a deterministic function of durable
  state (pure core library, deterministic Ed25519). A retry recomputes the same bytes, and
  create-if-absent accepts "already there, identical".
- **No rollback (I3).** A crash after (d) but before (4) leaves R2 ahead of SQLite. If the retry
  chose a smaller batch, it would publish a smaller checkpoint over a larger one. The recorded
  `publishing_size` is a floor that prevents this (D2.4). A retry with a _larger_ batch leaves an
  orphaned archive of the interrupted size, which is still a valid prefix of the log.
- **Single writer.** `commitPublish` refuses to run unless the published size is still the one the
  run started from (D2.8).

Tests inject a crash before and after every step and before every R2 write, reload the state from
SQLite, recover, and compare every byte of the log with an uncrashed run (D2.9). Each guard was
also removed on purpose to confirm the tests catch it.

## 5. Reading and verifying

The Worker serves `/log/<name>/…` straight from R2 with tlog-tiles headers: immutable resources for
a year, the checkpoint for 2 s, errors and API answers never cached, CORS on log routes, gzip for
bundles when the client asks (D4.3-D4.6). Logs are **private by default**: every non-admin route
needs `READ_TOKEN` (D4.2).

The **Go CLI** (`cli/`) shares no code with the writer (PLAN G3). It verifies the checkpoint
signature and origin, then reads hashes only through `tlog.TileHashReader`, which authenticates
every tile against the signed root before use; inclusion and consistency proofs are computed
locally from tiles (D5.1). Bundles are checked whole against the leaf hashes (D5.4). `monitor`
keeps the last verified checkpoint and exits non-zero on a fork, rollback or bad signature, with
both signed notes as evidence (D5.6). Exit code 1 means "the log served something false", 4 means
"could not verify" (D5.2). The conformance harness runs the real Worker locally, verifies its output
with the CLI, and flips bits in every resource to check that each is rejected (I7, D5.7).

## 6. The auditor

Events can be lost (a rule deleted, retention expired, a DLQ exhausted), so a periodic audit
compares the bucket with the log's expected state.

- **Merge-join.** R2 `list()` and SQLite `ORDER BY key` both order keys by UTF-8 bytes;
  JavaScript's `<` does not (it compares UTF-16 code units), so the merge uses `compareUtf8` and
  rejects any input that is not strictly increasing (D6.2). Each page lists up to 1,000 objects with
  `startAfter` and reads the matching range of the `objects` view (D6.3).
- **Findings**: `UNLOGGED_OBJECT`, `MISSING_OBJECT`, `ETAG_MISMATCH`, `SIZE_MISMATCH`,
  `PHANTOM_DELETE`, and `CONTENT_DRIFT` from deep scrub (D6.4, D6.8).
- **Grace window and confirmation.** A divergence first becomes a _candidate_, recording the log
  row it was judged against. After `AUDIT_GRACE_SECONDS`, it becomes a finding only if that row is
  unchanged; an event that arrived in between explains it (D6.5, an addition to the plan: the grace
  window alone cannot protect `MISSING_OBJECT`, which has no "deleted at" time).
- **Exactly-once steps.** The scan's state lives in the Sequencer; each step is one SQLite
  transaction that is idempotent by page number or state. The Workflow only drives it, so a step
  replayed after a crash changes nothing twice, and a large bucket hands off to a fresh Workflow
  instance before the per-instance step and subrequest limits (D6.1, D6.6, D6.7).
- **Evidence.** Findings are log entries between signed `audit.scan` start and end entries; the CLI
  proves each finding and checks their number against the end entry (D6.11). A report goes to
  `x-reports/`, and an optional webhook gets counts only, never key names (D6.12).
- **Backfill** logs `object.snapshot` entries for objects the log has never named, so a bucket that
  predates the log does not produce one finding per object (D6.10).

## 7. Witnesses, key blinding and the browser verifier (M8)

**Witnesses** (C2SP tlog-witness, D8.4-D8.7). A signed checkpoint proves who signed it, not that
everyone was shown the same one: an operator holding the key can show different readers different
trees (a split view), and only a reader who compares notes with another notices. A witness is that
other party, made routine. Before a checkpoint becomes visible, publication submits it to each
configured witness with a consistency proof from the size the witness last cosigned; the witness
checks the proof against its own record, cosigns, and stores the new size atomically. Its
cosignature says "as of time t, this is the largest tree I have seen for this log, and it extends
everything before it". A reader that requires a quorum of cosignatures from witnesses it trusts
(`--witness`) therefore cannot be shown a fork unless those witnesses also misbehave. The archived
checkpoints stay log-signed only, so they remain a pure function of the prefix and the crash
argument above is unchanged; the live checkpoint carries the cosignatures. Missing the quorum fails
the publication before the checkpoint moves (entries stay durable), which is the price of requiring
witnesses. The included witness Worker (`witness/`) is useful only when someone other than the log
operator runs it.

**Key blinding** (D8.8). A public log names objects by `keyHmac` = HMAC-SHA256(secret, key). The
Merkle tree, tiles and verification are unchanged: a blinded entry is just different bytes. The
writer keeps working on real keys (the auditor needs them), which stay in the Sequencer's private
SQLite; the published log, reports and lookups use HMACs only. Readers with the secret compute the
HMAC themselves. It hides names, not how often an object changes, its sizes, times or ETags.

**Browser verifier** (D8.3). The page at `/` uses `packages/core` in the browser: it verifies the
checkpoint (and witness policy), proves each entry it displays and each audit finding, and keeps the
last verified checkpoint so the next visit proves the log only grew. It shares code with the
writer, so it is a demonstration rather than an independent check; and a page served by the log's
own Worker is only as trustworthy as that Worker, which is why the page can be saved and run from
elsewhere (the log and read API allow cross-origin reads).

## 8. Questions a reviewer will ask

**Isn't a single Durable Object a bottleneck?**
Yes, by design, and it is measured rather than hidden. One writer gives a total order and
create-if-absent publication without coordination; sharding the tree would need a coordinator or
several logs. Locally (`docs/BENCHMARKS.md` §2), one Sequencer sustained about 3,000 entries/s
however many clients appended, which is what doing appends and publications in turn on one thread
predicts; with 16 clients, appends crowded out publication (2,007 entries/s published) and the
backlog grew until the load stopped. Entries stay durable; only visibility is delayed. Those are
local workerd figures; on
Cloudflare every SQLite write waits for replication and every R2 write is a network call, so the
real ceiling has not been measured. The upstream ceiling is the queue (5,000 messages/s per queue,
D0.5). Past either, the answer is several logs (one per bucket or prefix), each with its own
Sequencer, which needs no change to the format.

**Why order in a Durable Object and not trust the Queue's order?**
Queues deliver at least once and do not promise order, and a batch can be retried as a whole. The
log needs exactly one position per event and the same position after any retry. The Sequencer
assigns positions in a SQLite transaction together with dedupe, so a redelivered message gets no
second position and a crash cannot produce two orders. It also owns the expected-state view and the
scan state, so each audit step reads and writes them atomically (D6.1).

**Why tiles in R2 instead of an API that returns proofs?**
A proof API makes the server part of the trusted computing base for every verification; with tiles
the server is a dumb file host and clients compute proofs themselves. Tiles are immutable, so they
cache for a year and can be served by R2 or the CDN with no Worker in the path; R2 has no egress
fees. A proof touches a handful of tiles regardless of log size (§4 of `docs/BENCHMARKS.md`: the Go
CLI fetched under 100 KB for an inclusion proof at every measured size up to 10^6 entries, most of
it the 256-entry bundle). And the format is a C2SP standard shared with Certificate Transparency
logs (Sunlight, Azul), so existing tools apply.

**What if an event is lost?**
Inside the system, nothing is lost once acked: entries are durable before the ack. Before the ack,
the queue retries with backoff, then the DLQ, which this Worker also consumes. Beyond that (rule
deleted, retention expired, R2 never sent it) the auditor finds the divergence after the grace
window, records it as a signed finding, and the next audit reports it again while it persists. What
it cannot see is a change that was undone before the next audit (`docs/THREAT_MODEL.md`).

**Doesn't a public log leak my object keys?**
By default, yes: key names are in every entry. That is why logs are private by default
(`PUBLIC_LOG=false`, a read token on every non-admin route), why webhooks carry counts and log
indexes only, and why `/status` error reasons name fields, never values (D3.4). With key blinding
(`KEY_BLINDING`, M8) a public log names objects by HMAC-SHA256 of the key under a secret, so it
proves history without disclosing names; readers given the secret locate a key's entries. What
blinding cannot hide is the pattern: how often each (unnamed) object changes, its sizes and times,
and its ETag, which for a single-part upload is the content's MD5 (D8.8).

**What do witnesses add, if the log is already signed?**
A signature shows who signed a checkpoint, not that everyone saw the same one. An operator with the
key could show an auditor one tree and everyone else another. Witnesses cosign a checkpoint only if
it extends what they saw before, so a reader requiring their cosignatures is shown the same history
as everyone else, unless the witnesses collude with the operator. That makes who runs them the
whole question: a witness deployed by the log's operator adds nothing against that operator. The
log uses the standard protocol so it can use independent witnesses (D8.5, D8.6).

**What does it cost?**
Measured per-operation counts (`bench/results/amplification.json`) priced at the Workers Paid list
prices of October 2026 (`bench/results/cost.json`, `docs/BENCHMARKS.md` §7), under a stated
Poisson-arrival model, at `CHECKPOINT_INTERVAL_MS=5000`: about 25 USD/month at 1M events, 141
USD/month at 10M and 1,247 USD/month at 100M, before included allowances and excluding Durable
Object duration and Workers CPU, which a local run cannot measure. The largest line by far is
**Durable Object SQLite rows written**: about 11 rows per event at large batches (dedupe record and
its index, the entry, the expected-state row and its indexes, the key index, pruning), against a few
hundredths of an R2 Class A operation per event. Two follow-ups would cut that: `WITHOUT ROWID`
tables and fewer secondary indexes, and pruning by sequence number instead of an expiry index (D7.6).
R2 storage also grows faster than the log itself at small batches, because every checkpoint writes
a new partial bundle and every superseded partial is kept (D4.5); deleting superseded partials,
which tlog-tiles allows, would fix that.

**Why a separate Go verifier?**
A verifier that shares code with the writer shares its bugs. The Go CLI uses Go's
`golang.org/x/mod/sumdb/tlog` and `note` (the code behind the Go checksum database) and its own tile
paths, and the conformance harness checks the two against each other, including corruption cases
(I7). It found real issues: Go's `note` accepted non-canonical base64 signatures (D5.3).

**How is this different from Azul?**
Same family of design, different problem. Azul is a Certificate Transparency log: clients submit
certificates and get signed timestamps. R2Notary's input is R2's own change feed, and what is new
here is that ingestion, the auditor that reconciles the log against live bucket state, deep
scrubbing, and the cross-language conformance harness. The log design itself (tiles in R2, one
sequencer DO) is not claimed as novel.

**What happens if the Durable Object's storage is lost?**
The log in R2 survives, but the writer cannot continue it: the partial tiles and unpublished entries
are gone, and starting from scratch would sign a new tree of size 1 under the same origin, which
every monitor reports as a rollback. The honest recovery is a new log (a new origin and key). DO
SQLite is replicated by Cloudflare; this is a disaster case, not a routine one.

**Why not just use R2 bucket locks?**
Locks prevent deletion and overwrite for a retention period; they do not give a third party a
verifiable history of what happened, they do not cover writes, and they cannot show that an object
present today was never changed. R2Notary records and proves history and detects drift. Using both
(locks on the log bucket) is the intended setup.

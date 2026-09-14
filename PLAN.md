# R2Notary: Implementation Plan

> **For Claude Code.** Read this entire file before writing any code. It is the source of truth for scope, architecture, ordering, and acceptance criteria. Where it conflicts with current Cloudflare docs, the docs win (see §0.1).

**One-line pitch:** *A verifiable, tamper-evident history for Cloudflare R2 buckets: every object change is recorded in a signed Merkle-tree transparency log that is stored in R2 itself, served as static tiles, and independently verifiable by a Go CLI.*

---

## 0. Instructions for Claude Code

### Context
The human (Isaiah) is a CS student applying for a 2027 internship on Cloudflare's **R2 (object storage) team**. This repo will be public and reviewed by R2 engineers. The quality bar is **correctness, honest documentation, and reproducible measurements, not feature count.** He must be able to explain every design decision in an interview, so record your reasoning as you go.

### Working agreements
1. **Verify before using.** This plan was written in Oct 2026 from docs. Before using any Cloudflare API, config key, or limit, check the current docs (§12). If docs and this plan disagree, follow the docs and log the discrepancy in `docs/DECISIONS.md`.
2. **Milestone discipline.** Work through §9 in order. Every milestone ends with: build passes, tests pass, lint passes, committed. Do not start the next milestone until the acceptance criteria are met.
3. **Test-first for `packages/core`.** Write the property/vector tests before the implementation.
4. **No remote side effects without asking.** Do **not** run `wrangler deploy`, create remote R2 buckets/queues/workflows, set remote secrets, or do anything that costs money without explicit confirmation from the human. Develop against local simulation. Put remote setup commands in `docs/OPERATIONS.md` and ask the human to run or approve them.
5. **No secrets in the repo.** `.dev.vars`, key files, and `.wrangler/` go in `.gitignore`. Use placeholder account IDs and bucket names in committed config.
6. **Never invent numbers.** Any performance or cost figure in the README or docs must come from benchmark output committed under `bench/results/`, with methodology in `docs/BENCHMARKS.md`. If a benchmark has not been run, the doc says so.
7. **Be honest about limits.** The README must state what the system does *not* protect against (§11).
8. **Original implementation.** Study Cloudflare's open-source Azul CT log and the Sunlight/Tessera designs for architecture, but write original code. Credit them as inspiration in the README. Do not copy source.
9. **After M0, create `CLAUDE.md`** at the repo root containing these working agreements plus the build/test commands, so future sessions inherit them.
10. **Ask only when blocked.** Otherwise make the best decision, write it in `docs/DECISIONS.md` (decision, alternatives, why), and continue.

### Defaults (change only with reason)
- Repo name `r2notary`, license MIT (ask the human to confirm before first public push).
- TypeScript (strict) for the Worker and core library; **Go ≥ 1.22** for the verifier CLI; npm workspaces; Vitest + `@cloudflare/vitest-pool-workers`; `fast-check` for property tests; `wrangler.jsonc` for config.

---

## 1. What we are building

R2Notary watches one R2 bucket (the **monitored bucket**) and maintains an append-only, publicly verifiable log of everything that happens to it, stored in a second R2 bucket (the **log bucket**).

- **Ingest:** R2 event notifications → Cloudflare Queue → Worker consumer → a single-writer **Sequencer Durable Object**.
- **Log:** the Sequencer builds an RFC 6962 Merkle tree, publishes it as static **tiles** and **entry bundles** in the log bucket per the C2SP `tlog-tiles` spec, and signs **checkpoints** (C2SP `tlog-checkpoint` + `signed-note`, Ed25519).
- **Verify:** a Go CLI fetches a checkpoint, checks the signature, and verifies **inclusion proofs** ("this object event is in the log") and **consistency proofs** ("the log only ever grew; history was not rewritten"), computing every proof locally from tiles. The server is never trusted for proofs.
- **Audit:** a scheduled, resumable job reconciles the bucket's real contents against the log's expected state and flags **unlogged writes, missing objects, and silent drift**. Findings are themselves written into the log.

### Why this is a good R2-team project
- Exercises R2's real semantics: strong consistency, conditional writes, checksums, event notifications, S3-compatible access, Class A/B operation cost.
- Treats R2 as the **storage substrate for an integrity system** (immutable tiles, cache-friendly static serving with zero egress cost).
- Security + distributed-systems substance: single-writer sequencing, crash-safe publication, idempotency, at-least-once delivery, offline verification.
- Complementary to **R2 bucket locks** (which give immutability) by adding **verifiable history** (provable who/what/when).

### Honest positioning (use in README)
Cloudflare already open-sourced **Azul**, a tiled Certificate Transparency log on Workers + Durable Objects + R2 (Rust). R2Notary applies the same *family* of design (tiled logs, single-threaded sequencer DO, R2 as tile store) to a **different problem**: integrity and audit history of an R2 bucket. What is specific to R2Notary: ingestion from R2 event notifications, the reconciliation auditor against live bucket state, deep checksum scrubbing, and a cross-language (TS writer / Go verifier) conformance harness. Do not claim novelty in the log design itself.

---

## 2. Goals and non-goals

**Goals**
- G1. Spec-compliant tiled log (C2SP tlog-tiles / tlog-checkpoint / signed-note) so third-party tooling can read it.
- G2. Crash-safe, idempotent publication; at-least-once ingestion tolerated.
- G3. Independent verification in a different language (Go) that shares **no code** with the writer.
- G4. Auditor that detects divergence between log and bucket, with controlled false-positive handling.
- G5. Measured, reproducible numbers: latency, throughput, R2 operation amplification, proof sizes.

**Non-goals (say so in README)**
- Not an S3 proxy or gateway; nothing sits on the data path of the monitored bucket.
- Not a replacement for R2 bucket locks / object lifecycle; it is complementary.
- Does not *prevent* tampering; it makes it **detectable**.
- Does not defend against R2 itself being malicious (R2 is the trusted storage substrate); see §11.
- Not horizontally sharded in the MVP (single sequencer per log; limits documented).

---

## 3. Architecture

```
                     ┌────────────────────┐
 writers ──PUT/DEL──▶│ R2: monitored      │
 (S3 API / Workers)  │ bucket             │
                     └─────────┬──────────┘
                               │ event notifications (at-least-once, unordered)
                               ▼
                     ┌────────────────────┐
                     │ Queue  (+ DLQ)     │
                     └─────────┬──────────┘
                               ▼
┌────────────────────────────────────────────────────────────────────┐
│ Worker "r2notary"                                                  │
│  queue():     validate → event_id → Sequencer.append()  → ack      │
│  fetch():     /log/<name>/…  public read path (tiles, checkpoint)  │
│               /api/v1/…      status, lookup, findings, admin       │
│  scheduled / Workflow: auditor (list ⇄ log state, merge-join)      │
└───────────┬──────────────────────────────────┬─────────────────────┘
            ▼                                  ▼
   ┌──────────────────┐   tiles, bundles,   ┌──────────────────┐
   │ Sequencer DO     │──checkpoints───────▶│ R2: log bucket   │◀── Go CLI / browser
   │ (SQLite, 1 / log)│                     └──────────────────┘    verify locally
   └──────────────────┘
```

**Two durability points (document both):**
1. **Durable** = entry committed to the Sequencer DO's SQLite. Queue messages are acked after this.
2. **Visible** = covered by a signed checkpoint whose tiles/bundles are already durable in R2.

| Cloudflare service | Role |
|---|---|
| R2 (monitored) | The thing being watched; also read by the auditor |
| R2 (log) | Immutable tiles/bundles, checkpoints, reports |
| R2 event notifications + Queues | Change feed (at-least-once) + DLQ |
| Durable Objects (SQLite) | Single-writer sequencer; dedupe; tree state; object-state view |
| Workers | Consumer, public read path, admin API, cron |
| Workflows (preferred) | Resumable bucket scan with retries; fallback is cron + DO alarm |
| Workers Static Assets | Optional dashboard (stretch) |

---

## 4. Repo layout

```
r2notary/
├─ README.md  CLAUDE.md  LICENSE  package.json (workspaces)  .gitignore
├─ packages/core/          # pure TS, no Workers APIs except WebCrypto
│  └─ src/ merkle.ts tiles.ts note.ts checkpoint.ts entry.ts canonical.ts paths.ts
├─ worker/                 # Cloudflare Worker (wrangler.jsonc)
│  └─ src/ index.ts ingest.ts sequencer.ts publish.ts api.ts readpath.ts
│          audit/ scan-workflow.ts reconcile.ts scrub.ts
├─ cli/                    # Go module: r2notary
│  └─ cmd/r2notary/  internal/{tilefetch,verify,monitor,keys}/
├─ dashboard/              # (stretch) static assets
├─ bench/                  # harnesses + results/
├─ scripts/                # keygen, simulate-events, e2e-remote, conformance
├─ docs/                   # DESIGN.md THREAT_MODEL.md DECISIONS.md BENCHMARKS.md DEMO.md OPERATIONS.md
└─ .github/workflows/ci.yml
```

---

## 5. Component specifications

### 5.1 `packages/core`
Pure functions, heavily tested. No I/O.

- **Hashing:** RFC 6962: leaf = `SHA256(0x00 ‖ entry)`, node = `SHA256(0x01 ‖ left ‖ right)`. Use WebCrypto; provide sync-friendly batching to avoid per-hash async overhead (benchmark).
- **Tile math (C2SP tlog-tiles):** height 8 (256 hashes, 8,192 bytes per full tile). Tile at level `L`, index `N`, optional width `W` (1..255 for partial). Partial tile at level `l` for tree size `s` has `floor(s / 256^l) mod 256` hashes; empty tiles never served.
- **Path encoding:** `N` as zero-padded 3-digit path elements, all but the last prefixed with `x` (e.g. 1234067 → `x001/x234/067`). Partial suffix `.p/<W>`. Entry bundles at `tile/entries/<N>[.p/<W>]`.
- **Entry bundles:** concatenation of big-endian **uint16 length-prefixed** entries (so max entry size 65,535 bytes; enforce).
- **Root hash:** right-fold over the *frontier* (maximal complete subtrees, left to right) of the current tree. Do not confuse with hashing each partial tile independently; the frontier is the binary decomposition of the count at each level. Cross-check against a naive recursive RFC 6962 `MTH` in tests.
- **Signed note + checkpoint:**
  - Checkpoint body (tlog-checkpoint): `<origin>\n<size>\n<base64 root hash>\n` (+ optional extension lines, unused).
  - Signed note (C2SP signed-note): body, blank line, then `— <key name> <base64(4-byte key hash ‖ signature)>\n` (em-dash U+2014). Key hash = first 4 bytes of `SHA256(name ‖ 0x0A ‖ 0x01 ‖ pubkey)` for Ed25519.
  - Ed25519 via WebCrypto in Workers if supported (**verify** current Workers WebCrypto docs); fall back to `@noble/ed25519` if not.
  - Key format helpers: generate keypair, emit `vkey` string (`name+hash+base64(0x01‖pubkey)`).
- **Canonical entry encoding:** UTF-8 JSON, sorted keys, no insignificant whitespace, integers only (no floats). Provide `encode()` and `decode()` with strict schema validation.

### 5.2 Entry schema (v1)
Every log entry is canonical JSON with `"v":1` and a `"type"`.

| type | Produced by | Fields (besides `v`, `type`) |
|---|---|---|
| `object.event` | ingest | `bucket`, `key`, `action` (`PutObject` \| `CopyObject` \| `CompleteMultipartUpload` \| `DeleteObject` \| `LifecycleDeletion`), `size?`, `etag?`, `eventTime`, `ingestedAt`, `copySource?{bucket,key}` |
| `object.snapshot` | backfill | `bucket`, `key`, `size`, `etag`, `uploaded`, `snapshotId` |
| `audit.finding` | auditor | `kind`, `key`, `observed?{etag,size,uploaded}`, `expected?{etag,size,eventTime,seq}`, `scanId`, `observedAt` |
| `audit.scan` | auditor | `scanId`, `phase` (`start` \| `end`), `objectsScanned?`, `findings?`, `logSizeAtStart?` |
| `audit.observation` | deep scrub | `key`, `etag`, `size`, `sha256`, `scanId`, `observedAt` |

Notes:
- R2 event messages carry `account`, `action`, `bucket`, `object{key,size,eTag}`, `eventTime`, `copySource?`. **`size` and `eTag` are absent on delete events. There is no content hash in events.** Single-part ETags are MD5; multipart ETags are not content hashes.
- `account` is intentionally **not** logged (avoid leaking account IDs in a public log).
- Keep schema evolvable: unknown `type` must not break verifiers; CLI prints and skips.

### 5.3 Sequencer Durable Object (the core)
SQLite-backed DO (`new_sqlite_classes`), **one instance per log** (`getByName(LOG_NAME)`; check current DO API naming).

**RPC methods:** `append(items: {eventId, entry: Uint8Array}[]) → {accepted, duplicates, firstSeq}`, `publish()`, `status()`, `getObjectStates(range)`, `lookup(key)`.

**SQLite schema (create in `blockConcurrencyWhile` on construct; versioned migrations):**
```sql
CREATE TABLE meta(k TEXT PRIMARY KEY, v);   -- published_size, next_seq, schema_version
CREATE TABLE staging(seq INTEGER PRIMARY KEY, event_id TEXT UNIQUE, entry BLOB NOT NULL, received_at INTEGER NOT NULL);
CREATE TABLE seen(event_id TEXT PRIMARY KEY, seq INTEGER NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE tile_state(level INTEGER PRIMARY KEY, hashes BLOB NOT NULL);  -- current partial tile per level
CREATE TABLE bundle_state(id INTEGER PRIMARY KEY CHECK (id = 0), entries BLOB NOT NULL); -- current partial entry bundle
CREATE TABLE objects(key TEXT PRIMARY KEY, etag TEXT, size INTEGER, event_time TEXT, seq INTEGER, deleted INTEGER NOT NULL DEFAULT 0);
CREATE TABLE key_index(key TEXT NOT NULL, seq INTEGER NOT NULL, PRIMARY KEY(key, seq));
```
(`objects` is the materialized "expected state" view that the auditor reads. Note SQLite bound-parameter limits in DO; prefer **range scans** over big `IN (...)` lists.)

**`append`:** in one `transactionSync`: skip items whose `event_id` is in `seen` (within TTL); assign monotonically increasing `seq`; insert into `staging` and `seen`. Return after commit (this is the *durable* point). Then ensure an alarm is set for publication.

**Publication algorithm (`publish`, single-flight, runs from alarm or when `staging` ≥ `BATCH_MAX_ENTRIES`):**
1. Load state; read up to N staged entries with `seq ≥ published_size`, in order.
2. **In memory**, compute leaf hashes; extend `tile_state` per level; whenever a level-`L` tile reaches 256 hashes, finalize it, compute its subtree root, and push that as a leaf into level `L+1` (recursive). Extend the current entry bundle; finalize at 256 entries.
3. Compute the new root; build the checkpoint note; sign.
4. **Write to R2 (log bucket) in this order:** (a) full entry bundles and full tiles, **create-if-absent** (`onlyIf: { etagDoesNotMatch: '*' }`); if it already exists, **verify byte-identical** (compare hash) and raise a loud `TILE_DIVERGENCE` error if not. (b) the partial entry bundle and partial tiles at their `.p/<W>` paths. (c) archived checkpoint `x-checkpoints/<size>` (create-if-absent). (d) the live `checkpoint` (overwrite).
5. In **one `transactionSync`**: persist new `tile_state`, `bundle_state`, update `objects` / `key_index` (apply events in `seq` order; for an event whose `eventTime` is older than the stored `event_time` for that key, keep the stored state: tolerates out-of-order delivery), set `published_size`, delete published `staging` rows.
6. Prune expired `seen` rows on alarm.

**Why this ordering is safe:** the checkpoint is written only after every tile/bundle it depends on is durable (R2 writes are strongly consistent). If the DO dies at any point before step 5 commits, the next `publish()` recomputes the *same* bytes from the same staged entries; step 4(a) tolerates "already exists, identical". Publication is therefore idempotent. (Invariants I2, I6.)

**Cadence:** `CHECKPOINT_INTERVAL_MS` (default 5000) or `BATCH_MAX_ENTRIES` (default 500), whichever first, only when staging is non-empty. Each checkpoint costs a handful of R2 Class A operations; benchmark and document the amplification (§14).

**Never regress:** refuse to publish a checkpoint with `size < published_size`.

### 5.4 Ingest (Queue consumer)
- `queue(batch, env)`: parse each message against a strict schema. Invalid → ack and increment an `invalid_messages` counter (do not retry poison forever).
- **Loop protection:** drop (and count) any event whose `bucket` equals the log bucket or is not `MONITORED_BUCKET_NAME`. Startup config validation must reject `MONITORED == LOG`.
- `eventId = hex(SHA256(bucket|key|action|etag|eventTime))`. Build the `object.event` entry (set `ingestedAt` from the Worker clock).
- Call `append` with the batch; on success `ackAll()`; on failure `retryAll({ delaySeconds })`.
- Queue config: `max_batch_size`, `max_batch_timeout`, `max_retries`, **dead-letter queue**. Free-plan queue retention is short (verify); document it.
- Ordering: delivery is unordered. **Log order = ingestion order.** Each entry carries `eventTime`; consumers needing real-time order sort by it. Document this.

### 5.5 Public read path and API
Routes served by the Worker (origin = `LOG_ORIGIN`, scheme-less, no trailing slash, per tlog-tiles):

| Route | Behavior |
|---|---|
| `GET /log/<name>/checkpoint` | `text/plain; charset=utf-8`; `Cache-Control: max-age=2` (spec: ≤ a few seconds) |
| `GET /log/<name>/tile/<L>/<N>[.p/<W>]` | `application/octet-stream`; `Cache-Control: public, max-age=31536000, immutable` |
| `GET /log/<name>/tile/entries/<N>[.p/<W>]` | same as tiles |
| `GET /api/v1/status` | log size, last checkpoint time, staging depth, DLQ/invalid counters, last audit summary |
| `GET /api/v1/lookup?key=` | **Unverified convenience**: list of `{index, entry}` for a key; clients must verify via proofs |
| `GET /api/v1/findings` | latest audit findings |
| `POST /api/v1/admin/{backfill,scan,publish}` | `Authorization: Bearer ADMIN_TOKEN`, constant-time compare |

- Map routes to R2 keys in the log bucket (see §6). Stream bodies; handle `HEAD`; return 404 for absent resources; CORS `Access-Control-Allow-Origin: *` on log routes (browser verifier).
- The Cache API may not function on `workers.dev` hostnames (**verify**); document that custom-domain deployment is needed for CDN caching, and optionally support serving the log bucket via an R2 custom domain instead.
- `PUBLIC_LOG=false` mode: require a bearer token on log routes too.

### 5.6 Auditor
Detects divergence between the **log's expected state** (`objects` table) and the **bucket's actual state**.

**Scan = merge-join.** R2 `list()` returns keys in lexicographic order, as does `ORDER BY key` in SQLite (BINARY collation = UTF-8 byte order; **add a Unicode-key test to confirm these orderings agree**). For each page of ≤1,000 listed objects, fetch the DO's `objects` rows for the same key range and merge-join:

| Finding kind | Condition (after grace window) |
|---|---|
| `UNLOGGED_OBJECT` | in bucket; no live entry in log; `uploaded` older than `AUDIT_GRACE_SECONDS` |
| `MISSING_OBJECT` | live in log; absent from bucket |
| `ETAG_MISMATCH` / `SIZE_MISMATCH` | both present; latest logged etag/size ≠ actual; `uploaded` newer than logged `eventTime` beyond grace |
| `PHANTOM_DELETE` | log says deleted; object present with `uploaded` after the delete event |

- **Grace window** (`AUDIT_GRACE_SECONDS`, default 300) suppresses false positives from in-flight events. Record the window in each finding.
- **Resumable:** implement as a **Cloudflare Workflow** (`step.do` per page, cursor persisted by the workflow) with retries. Fallback if Workflows prove troublesome: Cron Trigger + DO alarm with a persisted cursor. **Check subrequest, CPU, and wall-time limits** and chunk accordingly.
- Write `audit.scan` start/end and each `audit.finding` into the log (tamper-evident audit trail). Also write `x-reports/<scanId>.json` to the log bucket and optionally POST a webhook (`ALERT_WEBHOOK_URL`).
- **Backfill** (`/admin/backfill`): enumerate the bucket and append `object.snapshot` entries to establish a baseline for pre-existing objects.
- **Deep scrub:** for a sampled subset (`DEEP_SCRUB_SAMPLE_RATE`, objects ≤ `DEEP_SCRUB_MAX_BYTES`), stream `bucket.get(key).body` through `crypto.DigestStream('SHA-256')` (Workers API; **verify**), compare against any stored `checksums.sha256`, and record `audit.observation`. Flag a change in SHA-256 for an unchanged ETag as `CONTENT_DRIFT`.

### 5.7 Go CLI `r2notary`
Independent implementation. **Must not share code with the TS writer.** Prefer:
- `golang.org/x/mod/sumdb/tlog` for tile-tree proofs (RFC 6962 hashing). Implement a `tlog.TileReader` that maps `tlog.Tile{H:8, L, N, W}` onto **tlog-tiles URLs** (note `tlog.Tile.Path()` is *not* the tlog-tiles path format; do the mapping yourself). **Verify the package APIs on pkg.go.dev.**
- `golang.org/x/mod/sumdb/note` for signed-note verification (Ed25519).

Commands:
```
r2notary keygen --name <origin>                       # signing key + vkey
r2notary checkpoint  --log URL --vkey V               # fetch + verify signature, print size/root/time
r2notary inclusion   --log URL --vkey V (--index N | --key K)   # verify entry in latest checkpoint; print entry
r2notary consistency --log URL --vkey V --old FILE    # prove current checkpoint extends a saved one
r2notary monitor     --log URL --vkey V --state FILE [--watch PREFIX] [--interval 10s]
r2notary findings    --api URL --token T
```
`monitor` persists the last verified checkpoint, on each poll verifies consistency from it, tails new entries, and **exits non-zero on any inconsistency, signature failure, or size regression** (fork/rollback detection). `--watch PREFIX` alerts on any delete/overwrite under a protected prefix.

### 5.8 Dashboard and extras (stretch, M8)
Static page via Workers Static Assets: log size/rate, recent entries, findings, and a **"verify in your browser"** button that fetches tiles and checks an inclusion proof client-side using `packages/core` (demonstrates "don't trust the server"). Other stretch items in §9/M8.

---

## 6. Storage layout

**Log bucket (R2), under prefix `<LOG_NAME>/`:**
```
checkpoint                           # live signed checkpoint (mutable)
tile/<L>/<N>[.p/<W>]                 # Merkle tiles
tile/entries/<N>[.p/<W>]             # entry bundles
x-checkpoints/<size>                 # archived checkpoints (extension; immutable)
x-reports/<scanId>.json              # audit reports (extension)
```

## 7. Configuration

| Name | Kind | Purpose |
|---|---|---|
| `MONITORED` | R2 binding | monitored bucket (auditor reads) |
| `LOG` | R2 binding | log bucket (writes/reads) |
| `SEQUENCER` | DO binding | sequencer (SQLite class) |
| `EVENTS` + DLQ | Queue consumer | event feed |
| `SCAN_WORKFLOW` | Workflow binding | auditor |
| `LOG_NAME`, `LOG_ORIGIN`, `MONITORED_BUCKET_NAME`, `LOG_BUCKET_NAME` | vars | identity; origin is scheme-less, no trailing slash |
| `CHECKPOINT_INTERVAL_MS`, `BATCH_MAX_ENTRIES`, `DEDUPE_TTL_SECONDS` | vars | cadence; dedupe window |
| `AUDIT_GRACE_SECONDS`, `DEEP_SCRUB_SAMPLE_RATE`, `DEEP_SCRUB_MAX_BYTES` | vars | auditor |
| `PUBLIC_LOG` | var | public vs token-gated log reads |
| `SIGNING_KEY` | **secret** | Ed25519 private key |
| `ADMIN_TOKEN` | **secret** | admin API |
| `ALERT_WEBHOOK_URL` | secret (optional) | alerts |

MVP supports **one monitored bucket per deployment** (bindings are static). Multi-bucket is stretch.

---

## 8. Correctness invariants (each needs an automated test)

- **I1.** For every tree size 1..N tested, the published root equals a naive recursive RFC 6962 `MTH` over the same entries (property tests; include sizes around 255/256/257, 65,535/65,536/65,537).
- **I2.** A checkpoint is never visible before all tiles/bundles it depends on are durable in R2.
- **I3.** Published sizes are monotonic. A consistency proof between **any two** archived checkpoints verifies.
- **I4.** Immutable resources (full tiles, full bundles, archived checkpoints, partial tiles by path) never change; a conflicting write is detected and fails loudly.
- **I5.** Each `eventId` is recorded at most once within the dedupe window, even under duplicate/redelivered queue messages.
- **I6.** Crash injected between any two steps of `publish()` → recovery produces byte-identical resources and a valid checkpoint.
- **I7.** The Go verifier accepts logs produced by the TS writer and **rejects** logs with a flipped bit in any tile, bundle, or checkpoint signature.
- **I8.** Events from the log bucket are never ingested.
- **I9.** Checkpoint signatures verify against the published `vkey`; origin line equals `LOG_ORIGIN`.

---

## 9. Milestones

**Tier 1 = MVP, must ship. Tier 2 = what makes it impressive. Tier 3 = stretch.** Each milestone: tests green, committed, short entry in `docs/DECISIONS.md`.

### M0: Scaffold (Tier 1)
npm workspaces, strict TS, Vitest (+ Workers pool), ESLint/Prettier, Go module, `wrangler.jsonc` with placeholder bindings, CI workflow (TS tests + Go tests), `.gitignore`, LICENSE, README skeleton, `CLAUDE.md`, `docs/DECISIONS.md`.
**Accept:** `npm test` and `go test ./...` pass on the skeleton; CI green.

### M1: Core library (Tier 1)
Merkle hashing, frontier/root, tile math, path encoding, entry bundles, canonical JSON, signed note, checkpoint, keygen/vkey.
**Accept:** I1 property tests; the tlog-tiles worked example passes (tree size 70,000 → 273 full L0 tiles, one partial L0 tile of width 112, one full L1 tile, one partial L1 tile of width 17, one partial L2 tile of width 1); path example `1234067 → x001/x234/067`; signed-note round-trip; entry size limit enforced.

### M2: Sequencer + publisher (Tier 1)
DO class, SQLite schema/migrations, `append`/dedupe, `publish`, alarm scheduling, create-if-absent with identical-bytes verification, objects/key_index maintenance.
**Accept:** I2, I3, I4, I5, I6 via Miniflare tests with **fault-injection hooks** (throw between publish steps) and duplicate/out-of-order inputs. **Verify R2 conditional-write semantics against the docs, and add a contract test that is also runnable against real R2 in M6** (older bug reports exist around `etagMatches`/`etagDoesNotMatch`).

### M3: Ingest (Tier 1)
Queue consumer, strict message validation, loop protection, `scripts/simulate-events.ts` (synthetic R2 event messages; **local R2 does not emit notifications**).
**Accept:** I5, I8; replayed duplicates, out-of-order, malformed messages, and delete events (no `size`/`eTag`) all handled; counters visible in `/status`.

### M4: Public read path + admin API (Tier 1)
Routes in §5.5, headers, CORS, HEAD, 404s, bearer auth, `scripts/keygen`, `status`/`lookup`/`findings`.
**Accept:** `curl` against `wrangler dev` returns correct headers and bytes; admin routes reject bad tokens in constant time.

### M5: Go verifier + conformance (Tier 1) ← **MVP complete**
`checkpoint`, `inclusion`, `consistency`, `monitor`; `scripts/conformance`: generate a log with the TS writer into a temp dir, serve it locally, run the Go CLI against it, then **corrupt** tiles/bundles/signatures and assert rejection.
**Accept:** I7, I9; CI runs conformance on every push.

### M6: Auditor, backfill, deep scrub (Tier 2)
Workflow-based scan, merge-join reconcile, grace window, findings into the log, reports, webhook, backfill, deep scrub with `DigestStream`.
**Accept:** reconcile unit tests for every finding kind; Unicode-key ordering test; resumability test (kill and resume mid-scan). **With human approval,** run `docs/DEMO.md` against real R2: disable the notification rule, write/overwrite/delete objects, re-enable, run a scan, confirm `UNLOGGED_OBJECT` / `ETAG_MISMATCH` / `MISSING_OBJECT` findings.

### M7: Benchmarks and documentation (Tier 2)
Run §14 benchmarks; write `docs/DESIGN.md`, `THREAT_MODEL.md`, `BENCHMARKS.md`, `DEMO.md`, `OPERATIONS.md`; polish README (diagram, quickstart, honest limitations, Azul/Sunlight/Tessera/Go sumdb credits). `DESIGN.md` must include a **"Questions a reviewer will ask"** section with answers (single-writer bottleneck, why DO not Queue ordering, why tiles, event loss, key leakage, cost).
**Accept:** every number in the README appears in `bench/results/`; a new reader can reproduce the local demo from the README alone.

### M8: Stretch (Tier 3), in this order of value
1. **In-browser verifier** dashboard (`packages/core` bundled; fetch tiles; verify inclusion client-side).
2. **Witness cosigning** per C2SP `tlog-witness`: a second Worker verifies consistency and cosigns checkpoints; CLI requires ≥1 witness cosignature (defends against split-view).
3. **Key blinding** (`keyHmac` instead of `key` in public logs, HMAC-SHA256 with a secret) so object names are not disclosed; CLI accepts the HMAC key to locate entries.
4. **Gateway mode:** optional synchronous write-through that records a SHA-256 for uploads that supply `x-amz-checksum-sha256`.
5. **Multi-bucket** and **sharded state DOs** for the `objects` view.

---

## 10. Testing strategy

- **Unit/property (core):** `fast-check` against a naive reference; spec examples; edge sizes; signed-note vectors.
- **DO/R2/Queue integration:** `@cloudflare/vitest-pool-workers`; fault injection; duplicate and out-of-order messages.
- **Cross-language conformance (the key test):** TS writes, Go verifies, plus corruption cases. Optionally also verify with a third-party tlog-tiles client if one is easy to run.
- **Local end-to-end:** `wrangler dev` + `simulate-events`.
- **Remote end-to-end (human-approved):** real bucket, queue, event rules, real notifications; contract tests for conditional writes and event shapes; the tamper demo.
- **Lint/format/typecheck** in CI; Go `vet` and `staticcheck` if available.

---

## 11. Threat model, limits, and known sharp edges

**What R2Notary gives you:** a tamper-evident, third-party-verifiable record of bucket changes; detection of log/bucket divergence; evidence suitable for audits.

**It detects:** history rewritten by someone without the signing key; log truncation/rollback (via monitors holding earlier checkpoints); objects written/changed/deleted while notifications were disabled or lost; content drift on scrubbed objects.

**It does not protect against:** compromise of the signing key; R2 itself returning false data; an attacker who controls **both** the log bucket and the signing key; split-view attacks unless witnesses are used (M8); anything between an event occurring and its notification (the auditor closes this gap only after the grace window).

**Sharp edges to handle and document**
1. Events lack content hashes; deletes lack `size`/`eTag`.
2. Queues are at-least-once and unordered; free-plan retention is short; configure a DLQ.
3. Local dev does not emit R2 events; use the simulator, then verify remotely.
4. Verify conditional-put behavior on real R2 (contract test).
5. DO can be evicted anywhere: persist before publishing; never rely on in-memory state.
6. Entry limit is 65,535 bytes (uint16 prefix); object keys can be up to 1,024 bytes; check headroom.
7. Scan limits (subrequests, CPU, wall time): chunk and resume.
8. **Public logs leak object key names**; default docs/examples to `PUBLIC_LOG=false` or warn loudly; key blinding is M8.
9. Single sequencer per log is a throughput ceiling; measure and report it (§14), don't hide it.
10. Never monitor the log bucket (infinite loop); config validation prevents it.
11. `uint16` bundle prefix and 8,192-byte tiles are spec-fixed; do not "optimize" them.
12. Queues per-queue throughput is finite (see event-notification docs); document the ceiling.

---

## 12. Reference reading (read before designing; verify current versions)

**Specs:** C2SP `tlog-tiles`, `tlog-checkpoint`, `signed-note`, `tlog-witness` (c2sp.org); RFC 6962 §2.1 and RFC 9162 §2.1 (Merkle hashing, inclusion/consistency proofs); Russ Cox, "Transparent Logs for Skeptical Clients" (tile design).
**Cloudflare docs:** R2 event notifications; R2 Workers API reference (conditional operations, checksums); R2 limits and pricing; Durable Objects (SQLite storage, alarms, RPC, `blockConcurrencyWhile`); Queues (consumers, batching, DLQ, limits); Workflows; Workers limits (subrequests/CPU); wrangler configuration; Workers WebCrypto (Ed25519) and `DigestStream`; Vitest pool for Workers.
**Prior art (architecture only; do not copy code):** Cloudflare blog "A next-generation Certificate Transparency log built on Cloudflare Workers" and the open-source `cloudflare/azul`; Sunlight; Trillian-Tessera; Go checksum database (`sum.golang.org`); Sigstore Rekor; AWS CloudTrail log-file integrity validation (comparison point).
**Go:** `golang.org/x/mod/sumdb/tlog`, `golang.org/x/mod/sumdb/note` (verify APIs on pkg.go.dev).

---

## 13. Documentation deliverables

- **README.md:** pitch, honest positioning (§1), diagram, quickstart (local simulate → verify), limitations, credits.
- **docs/DESIGN.md:** architecture, publication algorithm and why it is crash-safe, dedupe/ordering semantics, auditor design, "Questions a reviewer will ask".
- **docs/THREAT_MODEL.md:** §11 expanded.
- **docs/DECISIONS.md:** ADR-style log, kept current throughout.
- **docs/BENCHMARKS.md:** methodology, environment, raw results, caveats.
- **docs/DEMO.md:** reproducible walkthrough: ingest 100 objects → verify inclusion → run `monitor` → disable notifications and make changes → audit flags them → flip a bit in a tile → CLI rejects → consistency proof between old and new checkpoints.
- **docs/OPERATIONS.md:** exact `wrangler` commands to create buckets/queue/DLQ/rules/secrets, deploy, rotate keys, and tear everything down; cost notes (free-tier limits; Workers Paid may be needed for heavier benchmarks; verify current pricing).

---

## 14. Benchmark specification (M7)

All results saved as CSV/JSON in `bench/results/` with environment details (date, region, plan, config values). Report medians and p95/p99, and state sample sizes.

1. **Event → visible latency:** time from object PUT to the entry being covered by a published checkpoint, for 1,000 objects, at `CHECKPOINT_INTERVAL_MS` ∈ {1000, 5000, 15000}.
2. **Sequencer throughput:** sustained entries/sec accepted and published vs batch size; identify the saturation point and bottleneck.
3. **R2 operation amplification:** Class A and Class B operations per 1,000 entries at each checkpoint interval (count from R2 metrics or instrumented binding calls).
4. **Proof cost:** bytes fetched and verification time for an inclusion proof and a consistency proof at log sizes 10³, 10⁵, 10⁶ (generate synthetic tiles locally with `packages/core`).
5. **Core hashing speed:** leaves/sec for tile building (WebCrypto batching strategies compared).
6. **Auditor:** objects/sec scanned (list + merge-join) and deep-scrub MB/s.
7. **Cost model:** a short table estimating monthly R2 + DO + Queue cost for 1M, 10M, and 100M object events/month from measured per-entry amplification and current published prices (cite price page date).

**Rule:** no figure appears in README, docs, or commit messages unless it is in `bench/results/`.

---

## 15. Definition of done (project)

- M0–M5 complete, CI green, conformance test passing (**MVP**).
- M6 demo executed on real R2 with the human's approval, with recorded output in `docs/DEMO.md`.
- M7 docs and benchmarks complete; README claims all traceable to committed results.
- Repository is public-ready: no secrets, placeholders only, LICENSE present, README quickstart verified from a clean clone.
- Human has read `docs/DESIGN.md` and `docs/DECISIONS.md` and can explain: why a single-writer DO, why tiles in R2, how crash recovery works, what the auditor can and cannot detect, and how this relates to Azul.

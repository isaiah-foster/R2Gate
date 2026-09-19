# Decisions

ADR-style log: decision, alternatives, why. Newest milestone last. Where current Cloudflare docs
disagreed with `PLAN.md`, the docs won (PLAN §0.1) and the discrepancy is recorded here.

## M0: Scaffold (2026-10-02)

### D0.1 Test runner is `@cloudflare/vitest-plugin`, not `@cloudflare/vitest-pool-workers`

- **Plan said:** `@cloudflare/vitest-pool-workers`.
- **Docs say:** the pool package is superseded by `@cloudflare/vitest-plugin` (same `cloudflareTest`
  API; types path is `@cloudflare/vitest-plugin/types`).
- **Decision:** use the plugin (1.3.6).
- **Consequence:** the plugin needs vitest `^4.1`. The latest vitest on npm is 5.x, so vitest is pinned to 4.1.11.

### D0.2 TypeScript pinned to 6.0.x

- **Why:** latest TypeScript is 7.0.2, but `typescript-eslint` 8.71 declares `typescript <6.1.0`.
  Strict type-aware linting matters more here than the newest compiler.
- **Revisit:** when typescript-eslint supports 7.

### D0.3 Durable Object class declared with `exports`, not `migrations`

- **Plan said:** `new_sqlite_classes` migration (PLAN §5.3).
- **Docs say:** `exports: { Sequencer: { type: "durable-object", storage: "sqlite" } }` is the preferred
  declarative form for new Workers; `migrations` is legacy.
- **Decision:** use `exports`. Verified locally: the Workers test pool resolves the class and a
  SQLite-backed DO answers RPC. Not yet verified on a real deployment (no remote actions in M0).
- **Fallback:** `migrations` with `new_sqlite_classes` if a deploy rejects `exports`.

### D0.4 Stub `ScanWorkflow` class exists in M0

The `SCAN_WORKFLOW` binding in `wrangler.jsonc` needs an exported class to resolve, so a no-op
`ScanWorkflow` lives in `worker/src/scan-workflow.ts` until M6.

### D0.5 Findings that do not change M0 but constrain later milestones

These are from the docs check; each needs action in the named milestone.

- **M1: Ed25519 keys.** Workers WebCrypto supports `"Ed25519"` but imports private keys as **PKCS8 only**
  (no raw import). Key helpers must wrap the 32-byte seed in a PKCS8 envelope. `@noble/ed25519` is not
  needed. `crypto.DigestStream` is confirmed available (M6).
- **M2: `bundle_state` row size.** DO SQLite limits a row/BLOB to **2 MB** and a statement to **100 bound
  parameters**. PLAN §5.3's single-row `bundle_state.entries` (up to 255 entries × 65,535 B) can exceed
  2 MB in the worst case. Needs a redesign in M2 (e.g. one row per entry, or rebuild from `staging`/R2).
- **M2: create-if-absent.** The Workers API reference documents `onlyIf.etagDoesNotMatch` but does not
  state that `'*'` means "object does not exist". The S3 API docs list `If-None-Match` as supported on
  PutObject. Treat `'*'` as **unverified** until the M2 contract test passes (locally and, in M6, on real R2).
- **M6: Workflows free plan.** 10 ms CPU per step and 50 subrequests per invocation; scan page sizes
  must be chosen against these (paid: 30 s CPU, 10,000 subrequests).
- **M3/M7: Queues.** Free-plan message retention is 24 h (not configurable); per-queue throughput is
  5,000 msgs/s; R2 allows at most 100 notification rules per bucket and rejects overlapping rules.
- **Confirmed unchanged:** `DurableObjectNamespace.getByName()` exists; R2 `list()` is lexicographic and
  returns at most 1,000 keys (use `truncated`, not the count); tlog-tiles path encoding, partial-tile
  suffix and the 70,000-entry worked example match PLAN §5.1; Go's `tlog.Tile.Path()` is not the
  tlog-tiles format, as PLAN §5.7 warned.

### D0.6 Go version and module path

- **Plan said:** Go ≥ 1.22. **Decision:** `go 1.26.0` in `cli/go.mod`, because current
  `golang.org/x/mod` (v0.41.0, needed in M5 for `sumdb/tlog` and `sumdb/note`) requires Go 1.26.
  This still satisfies "≥ 1.22". CI reads the version from `go.mod`.
- **Module path** `github.com/isaiahfoster/r2notary/cli` is a placeholder; rename when the real
  GitHub location is known.

### D0.7 Tooling defaults

- ESLint 10 flat config with `typescript-eslint` `strictTypeChecked`; Prettier (single quotes, width 100).
- TS strictness beyond `strict`: `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`,
  `verbatimModuleSyntax`. `allowImportingTsExtensions` is on (type-check only, `noEmit`; wrangler/vitest bundle).
- `packages/core` tests run in plain Node (fast, and WebCrypto Ed25519 works there); `worker` tests
  run in workerd. Both are vitest projects under one root `vitest.config.ts`.
- `staticcheck` is run in CI through `go run honnef.co/go/tools/cmd/staticcheck@2026.2.1` (pinned),
  since it is not assumed to be installed.
- MIT license, holder Isaiah Foster; to be confirmed with the human before the first public push.
- Actions pinned to major tags (`checkout@v7`, `setup-node@v7`, `setup-go@v7`).

### D0.8 CI not yet observed running

CI has not run on GitHub (pushing is a remote side effect; not done in M0). Every CI step was run
locally instead. `actionlint` was not available, so the workflow YAML was not linted.

## M1: Core library (2026-10-02)

Specs read for this milestone (C2SP editor's copies fetched 2026-10-02): `tlog-tiles`,
`tlog-checkpoint`, `signed-note`; RFC 6962 §2.1. Test vectors used as data only: RFC 6962 roots
from `transparency-dev/merkle` (`testonly/constants.go`), the signed-note spec's vkey/note example,
and the `golang.org/x/mod/sumdb/note` documentation example (a full signer key, text and signature).

### D1.1 Module layout

PLAN §4 lists `merkle canonical entry note checkpoint tiles paths`. Three small modules were added so
each file has one job: `bytes.ts` (strict hex/base64/UTF-8), `bundle.ts` (entry bundle codec and the
65,535-byte limit) and `log.ts` (`appendEntries`: tiles + bundles + root in one pure step, which is
what the M2 publisher calls).

### D1.2 Tree state is the partial tile at every level

- **Decision:** `TreeState = { size, partials[level] }`, exactly the PLAN §5.3 `tile_state` table.
  `extendTree` appends leaf hashes and returns the tiles that became full; the root is computed from
  the partial tiles alone (each level's partial tile, decomposed into powers of two, top level
  first, is the RFC 6962 frontier; then a right fold). Full tiles are never read back by the writer.
- **Alternatives:** keeping a separate compact-range frontier (redundant with `tile_state`, and two
  structures could disagree); recomputing from all leaves (unbounded).
- **Why:** one source of truth, O(levels × 256) state, and every function is pure and deterministic,
  which is what makes re-publication after a crash produce byte-identical resources (I6 in M2).
  `checkTreeState` rejects any state whose widths do not match its size, guarding state loaded from
  SQLite.

### D1.3 Hashing uses WebCrypto with per-level batching

- **Decision:** SHA-256 via `crypto.subtle.digest` only. Independent hashes are issued together
  (`Promise.all` per tree level; completed tiles are rooted in parallel).
- **Alternatives:** a pure-JS synchronous SHA-256 (fewer awaits, but a new dependency or hand-written
  crypto); `node:crypto` (not available to `packages/core`, which must stay WebCrypto-only).
- **Why:** no dependencies, and the same code runs in Node and workerd. Whether batching is fast
  enough is a PLAN §14.5 benchmark question; no speed claim is made here.

### D1.4 Ed25519 keys: Go-compatible strings, PKCS#8 wrapping, verified in workerd

- **Key formats:** verifier keys are C2SP vkeys (`name+hex(keyID)+base64(0x01‖pubkey)`). Signer keys
  use the `golang.org/x/mod/sumdb/note` convention, `PRIVATE+KEY+name+hex(keyID)+base64(0x01‖seed)`,
  so `SIGNING_KEY` can be produced or read by Go tooling. The signed-note spec does not define a
  private key format, so this is a convention, not a spec requirement.
- **Import:** the 32-byte seed is wrapped in the fixed RFC 8410 PKCS#8 prefix and imported as
  standard `Ed25519` (not the legacy `NODE-ED25519`). The public key is derived by exporting the
  imported key as JWK (`x`), and the signer key's key ID is checked against it, so a corrupted
  `SIGNING_KEY` fails at load time rather than producing unverifiable checkpoints.
- **Correction to D0.5:** the Workers docs footnote "will not support raw import of private keys"
  is attached to `NODE-ED25519`. For standard `Ed25519`, WebCrypto (Secure Curves) defines private
  import as PKCS#8 or JWK, never raw; either way the PKCS#8 wrapper is needed. Confirmed in workerd by
  `worker/test/core-runtime.test.ts`, which also reproduces the Go example signature byte for byte.
- `@noble/ed25519` is not needed.

### D1.5 Canonical JSON

- **Decision:** keys sorted by UTF-16 code units (the RFC 8785 rule and JavaScript's default sort),
  no whitespace, strings escaped exactly as `JSON.stringify` (same rules as RFC 8785), numbers limited
  to safe integers (no floats, no `-0`). Strings with lone surrogates are rejected, because
  `TextEncoder` would silently turn two different keys into the same bytes. Decoding re-encodes the
  parsed value and requires a byte-for-byte match, which rejects whitespace, unsorted or duplicate
  keys, `1.0`, `a`, a BOM, and anything else non-canonical with a single rule.
- **Why it matters:** the log commits to entry bytes. A unique encoding means a given event has one
  possible entry, which keeps re-publication byte-identical and makes the verifier's decoding strict.

### D1.6 Entry schema v1: details and deviations from PLAN §5.2

- **Timestamps** (`eventTime`, `ingestedAt`, `uploaded`, `observedAt`) are RFC 3339 strings with an
  explicit offset (`Z` or `±hh:mm`) and a real calendar date. `eventTime` is stored verbatim from R2
  (docs example: `2024-05-24T19:36:44.379Z`). Any offset is accepted so that a harmless format change
  in R2 does not turn valid events into dropped messages.
- **`copySource`:** R2 sends `{bucket, object}` (verified in the event-notification docs); the entry
  logs it as `{bucket, key}` to match the rest of the schema. Allowed only on `CopyObject`.
- **Deletes:** `DeleteObject`/`LifecycleDeletion` entries must not carry `size` or `etag` (R2 omits
  them). Creates may omit them (the plan marks both optional).
- **Validation:** bucket names follow the R2 rules from the docs (3-63 of `[a-z0-9-]`, no leading or
  trailing hyphen); keys are non-empty, well-formed and ≤ 1,024 UTF-8 bytes; ETags are 1-256
  printable ASCII characters without spaces or quotes; `scanId`/`snapshotId` are restricted to
  `[A-Za-z0-9._-]` (no leading dot) because they become R2 keys (`x-reports/<scanId>.json`).
  Unknown fields are rejected.
- **Headroom (sharp edge 6):** a worst-case `CopyObject` entry (two 1,024-byte keys of control
  characters, each escaping to 6 bytes) is tested to stay under 65,535 bytes.
- **Added fields:** `audit.finding` gains `bucket` and `graceSeconds` (PLAN §5.6 says to record the
  grace window in each finding, but §5.2 had no field for it); `audit.observation` gains `bucket`.
  Without `bucket`, findings would become ambiguous if multi-bucket support (M8) arrives.
- **Per-kind rules:** `UNLOGGED_OBJECT` has `observed` only, `MISSING_OBJECT` has `expected` only,
  the other kinds have both. `audit.scan` `start` may carry `logSizeAtStart` only; `end` may carry
  `objectsScanned`/`findings` only.
- **Unknown types:** `decodeEntry` returns `{known: false, type, v}` for any unknown type or version
  (PLAN: "unknown type must not break verifiers"). A _known_ type that violates the schema throws.
- **Provisional:** the `audit.*` shapes are a first cut and may change in M6. Nothing has been
  published, so changing them then is free. `CONTENT_DRIFT` is not yet a finding kind; it is added
  with deep scrub in M6.

### D1.7 Sizes and indexes are JavaScript numbers, capped at 2^53 − 1

The specs allow uint64 tree sizes. Using `number` (not `bigint`) keeps the code simple and fast, and
a log cannot plausibly reach 2^53 entries. Every entry point rejects unsafe integers instead of
silently losing precision, including parsing a checkpoint whose size exceeds 2^53 − 1.

### D1.8 Paths parse strictly

`parseLogPath` accepts only the exact string the encoder would produce (no `x000/001`, no leading
zeros in level or width, no `.p/256`, no `.p/0`, level ≤ 63). Every resource therefore has a single
name, and M4's read path can map URLs to R2 keys without normalization. Archived checkpoints are
`x-checkpoints/<decimal size>`.

### D1.9 Signed-note verification policy

Following the spec: signatures from unknown keys are ignored; a known key (same name **and** key ID)
whose signature fails rejects the whole note; at least one known key must verify. Also rejected:
non-canonical base64, duplicate (name, key ID) lines, malformed signature lines, ASCII control
characters other than newline (including `\r`), invalid UTF-8, a missing final newline, and more
than 100 signature lines (the spec requires accepting at least 16). Key names reject Unicode
whitespace, `+` and control characters.

### D1.10 Checkpoints

- The writer refuses to sign unless the signer's key name equals the origin (tlog-checkpoint says it
  SHOULD).
- `validateOrigin` (for our own `LOG_ORIGIN`) requires a scheme-less origin with no trailing slash,
  ≤ 255 bytes, that is also a valid key name. `parseCheckpoint` (for any log) enforces only the
  spec's MUSTs, since clients must not assume the origin's format.
- `openCheckpoint(note, verifier, expectedOrigin)` checks the signature and then the origin (I9).
- Extension lines are parsed but never written.

### D1.11 Deferred from M1

- **Inclusion and consistency proofs in TypeScript.** Not in M1's list. I3 ("a consistency proof
  between any two archived checkpoints verifies") is an M2 acceptance criterion, so a TS proof
  implementation (or tile-based proof check) arrives with M2. The Go CLI computes its own in M5.
- **`eventId` derivation** (`hex(SHA256(bucket|key|action|etag|eventTime))`) belongs to ingest (M3).
- **Cross-language check against Go's `note`/`tlog` packages** happens in M5. Until then, Go
  compatibility rests on reproducing the Go documentation's signature exactly.
- **D0.5 `bundle_state` 2 MB row limit** is unchanged: `LogState.bundle` is an in-memory list of
  entries, and how M2 persists it is still open.

## M2: Sequencer + publisher (2026-10-02)

Docs checked for this milestone (2026-10-02): R2 Workers API reference (`onlyIf`, `R2Conditional`,
`sha256`, strong consistency); DO SQLite storage API (`exec`, `transactionSync`, alarms, output
gates); DO limits; DO alarms (retries); Vitest integration test APIs; wrangler `secrets` config and
remote bindings. Code: `worker/src/{config,store,publish,sequencer}.ts`, `packages/core/src/proof.ts`.

### D2.1 Create-if-absent is `onlyIf: { etagDoesNotMatch: '*' }`, pinned by a contract test

- **Docs say:** `put()` returns `null` when an `onlyIf` precondition fails and stores nothing.
  `etagDoesNotMatch` is documented, but what `'*'` means is still **not** documented (D0.5). A
  `Headers` object with `If-None-Match` is accepted as an alternative. workers-sdk issue #6411
  reported Miniflare inverting `'*'` conditionals (Miniflare 3.20240725; closed "not planned").
- **Decision:** use `etagDoesNotMatch: '*'`, and test it instead of trusting it.
  `worker/test/contract/r2-conditional.ts` checks: creates when absent; returns `null` and leaves
  the object unchanged when present; the `If-None-Match: *` Headers form behaves the same; a
  concrete etag still compares; a wrong `sha256` is rejected; `putImmutable` semantics.
- **Result:** passes against local R2 (wrangler 4.147.0 / workerd 1.20261001.1). The #6411
  inversion is not present. **Not yet run against real R2**: that needs a bucket and the owner's
  approval. The same contract runs remotely with `npm run test:contract:remote` (remote bindings,
  which the docs confirm `@cloudflare/vitest-plugin` supports); see `docs/OPERATIONS.md`. Planned
  for M6, as the plan says.
- **Defense in depth:** if R2 ever answers "precondition failed" for an absent object (an inverted
  implementation), `putImmutable` throws `ConditionalWriteError` instead of continuing. A silent
  overwrite cannot be detected by the writer alone; that is what the contract test is for.

### D2.2 No `bundle_state` row: the `entries` table keeps the partial bundle (resolves D0.5)

- **Problem:** PLAN §5.3 stores the partial bundle as one BLOB. DO SQLite caps a row at 2 MB, and
  255 worst-case valid entries (CopyObject with two 1,024-byte keys of control characters, ~12 KB
  each) is over 3 MB. A test builds exactly that bundle.
- **Decision:** PLAN's `staging` table is named `entries` and keeps, besides unpublished entries,
  the already-published entries of the current partial bundle (`seq ≥ 256·⌊published_size/256⌋`).
  Commit deletes rows below that bound. The partial bundle is read back from those rows. Each row
  holds one entry (≤ 65,535 bytes), far under the limit.
- **Alternatives:** chunking the BLOB over several rows (another structure that can disagree);
  reading the partial bundle back from R2 (a Class B read on every publish, and it trusts R2 for
  writer state).
- **Also:** `entries` has no `event_id` column. Dedupe lives only in `seen`. With rows now
  outliving publication, a `UNIQUE(event_id)` there would make an event re-delivered after its
  dedupe window expired fail with a constraint error instead of being logged again (D2.6).

### D2.3 Partial tiles and bundles are create-if-absent too

- **Plan said:** step 4(b) writes partials at their `.p/<W>` paths (implicitly, overwrite), while
  I4 says partial tiles by path never change.
- **Decision:** every resource except the live `checkpoint` goes through `putImmutable`. A partial
  tile at a given path is fixed by the prefix it covers, so a conflicting one is divergence, the
  same as for a full tile.
- **Optimization:** a partial tile whose (level, index, width) is unchanged since the last commit
  was written by that publication and is skipped. Upper levels change rarely, so most checkpoints
  write one partial tile, one partial bundle and two checkpoint objects. The write count per
  checkpoint is a §14 benchmark question; no figure is claimed here.

### D2.4 `publishing_size` makes recovery monotonic

- **Problem:** a crash after the live checkpoint is written but before commit leaves R2 ahead of
  SQLite. If the retry picks a smaller batch (say `BATCH_MAX_ENTRIES` was lowered in between), it
  would overwrite the live checkpoint with a smaller size: a visible rollback.
- **Decision:** before any R2 write, publication records its target size in `meta.publishing_size`.
  A retry publishes at least that size. Commit clears it. Tested: crash after `checkpoint-written`,
  shrink the batch to 10, recover at 550, not 260.
- **Why the rest is safe without more bookkeeping:** every resource is a pure function of the log
  prefix it covers, and the prefix is fixed once durable. A retry with a _larger_ batch (entries
  arrived in between) leaves an orphaned archive and partial tiles for the interrupted size. They
  are valid: the archive is a real prefix of the log and consistent with every later checkpoint
  (tested).

### D2.5 Archived checkpoints are compared by signed text

`x-checkpoints/<size>` is create-if-absent. If it already exists, the signed text (origin, size,
root) must match; the signature lines may differ. Ed25519 is deterministic, so with an unchanged key
the bytes are identical anyway. Comparing text keeps a key rotation between a crash and its retry
from being reported as divergence, and still catches any different tree. The live `checkpoint` is
the only unconditional write.

### D2.6 Dedupe semantics (I5)

- An `eventId` accepted at time `t` is a duplicate during `[t, t + DEDUPE_TTL_SECONDS)`. After
  that it is accepted again, even if its `seen` row has not been pruned yet. Rows are pruned on
  every alarm.
- Duplicates within one append call, across calls, after publication, and across concurrent
  calls are all covered by tests. Concurrent appends are safe because each append is one
  synchronous `transactionSync`.
- **Durable point:** `append` returns after its transaction commits. The DO output gate holds the
  RPC response until writes are flushed ("the system will pause outgoing network messages ... until
  all previous writes have been confirmed flushed to disk", SQLite storage API docs). Not testable
  locally.
- `append` is all-or-nothing on validation: every item must be a known, schema-valid entry, and any
  entry naming a bucket must name `MONITORED_BUCKET_NAME`. That keeps the `objects` view
  single-bucket. Rejecting events from the log bucket itself (I8) is M3's job in the consumer; this
  is a second line of defence.

### D2.7 The `objects` view

- Updated at commit (step 5), not at append, so the auditor's expected state only cites entries
  already covered by a published checkpoint.
- An event older (by `eventTime`) than the stored state for its key does not replace it; equal
  times go to the later `seq`. A single SQLite upsert with `WHERE excluded.event_ms >=
objects.event_ms`.
- **Added column `event_ms`:** RFC 3339 strings with different offsets do not sort as text, so
  times are converted to epoch milliseconds by a hand-written parser (`eventMillis`), not
  `Date.parse`, so ordering does not depend on the engine's date parser. Sub-millisecond digits
  are truncated.
- `object.snapshot` sets state with `uploaded` as its time. `audit.finding` and
  `audit.observation` go into `key_index` (so `lookup` shows them) but do not change state.
- `getObjectStates({after, through, limit})` and `lookup(key)` exist now so the view can be tested
  through RPC. Their shapes may change when M4/M6 use them.

### D2.8 Scheduling, single flight, and failure handling

- **Deadline:** publication is due `CHECKPOINT_INTERVAL_MS` after the _oldest pending_ entry was
  accepted (`entries.received_at`), or immediately once `BATCH_MAX_ENTRIES` are pending. The first
  version used "now + interval" at re-arm time, which made the leftovers of a drained backlog wait
  a full extra interval. The rule is a pure function (`publicationDue`) with its own test.
- **Single flight:** input gates only cover storage operations, so other requests run while a
  publication awaits R2. `publish()` shares one in-flight promise, and `commitPublish` refuses to
  run unless `published_size` still equals the size the run started from.
- **Failures:** the runtime retries a throwing alarm at most 6 times (docs), after which durable
  entries would sit unpublished until the next append. So `alarm()` catches a failed publication
  and sets its own retry 30 s later (`PUBLISH_RETRY_MS`). The error is logged and kept in
  `status().lastError`. A `TILE_DIVERGENCE` fails again on every retry, which is the intended
  "fail loudly": it needs a human.
- **Migrations** run synchronously in the constructor rather than in `blockConcurrencyWhile`
  (PLAN §5.3). Synchronous SQL completes before any event is delivered, so the wrapper adds nothing.
  Migrations are versioned (`meta.schema_version`), idempotent, and refuse a newer schema.

### D2.9 Testing approach

- `publish()` is a plain function over a `SequencerStore`, a `LogBucket` and hooks. Tests run it
  inside `runInDurableObject` against real DO SQLite and local R2. The DO class calls the same
  function with no hooks.
- **Fault injection:** `afterStep` (7 steps) and `beforeWrite` (every R2 write) hooks throw. Each
  crash point is followed by recovery with a fresh store (state reloaded from SQLite), and the
  whole log prefix is compared byte for byte with an uncrashed reference run. This simulates a
  crash as an exception plus loss of memory. It does not kill the isolate mid-`await`; there is no
  hook for that in the test pool.
- **I2:** a wrapping bucket checks, at every live-checkpoint write, that all tiles and bundles of
  that size already exist in R2.
- **I3:** a consistency proof between every pair of archived checkpoints is computed from the
  published tiles and verified (core `consistencyProof` / `verifyConsistency`, D2.10).
- **Mutation check:** each of these was broken on purpose and the named tests failed: checkpoint
  written first (I2, I3, I6), immutable writes unconditional (I4, contract), no
  `publishing_size` floor (I6 shrink test), no dedupe check (I5), `eventTime` ordering ignored
  (objects view), wrong partial-tile skip (I2, I3, I6).
- **Test-pool quirk:** a rejected RPC call on a DO stub is reported by
  `@cloudflare/vitest-plugin` 1.3.6 as an unhandled rejection even when the test awaits it.
  Error paths are therefore tested by calling the instance inside `runInDurableObject`.
- **Signing key:** `worker/vitest.config.ts` generates a fresh key each run and passes it as the
  `SIGNING_KEY` secret through `process.env`, so no key material is committed. `SIGNING_KEY` is
  declared in `secrets.required` (wrangler config docs), which also types it in `Env`.

### D2.10 Consistency proofs in `packages/core` (follow-up to D1.11)

- `consistencyProof(size1, size2, readNodes)` implements RFC 6962 §2.1.2 `PROOF` over any source of
  subtree hashes. `tileNodeReader(size, readTile)` provides them from tlog-tiles, reading each tile
  once, with the width it has at `size`. `verifyConsistency` is RFC 9162 §2.1.4.2, using
  arithmetic instead of 32-bit bit operations. Written test-first against an independent recursive
  reference (`test/reference.ts`) and three vectors derived from the `transparency-dev/merkle`
  node-hash table.
- **A wrong test, caught:** the first property test also expected verification to fail for a
  mutated `size2`. It does not always fail: `PROOF(1, D[5])` also verifies "1 → 6" against the
  size-5 root, because the proof has the same shape. That is not a forgery, since sizes are bound
  to roots by the checkpoint signature. The mutation was removed and the reason commented.
- **Inclusion proofs** are deferred. Nothing in M2 needs them. The Go CLI implements its own in M5.

### D2.11 Write details

- Every immutable put sends `sha256` (R2 rejects the upload if the bytes it received hash
  differently; covered by the contract test) and `httpMetadata` (content type; `immutable` cache
  control for tiles, bundles and archives; `max-age=2` for the live checkpoint), so the bucket can
  later be served directly through an R2 custom domain (PLAN §5.5).
- Writes within a phase run at most 6 at a time. The DO limits page lists 6 simultaneous outgoing
  connections per request. Whether R2 binding calls count against that is not stated, so this is
  conservative.

### D2.12 Configuration

`worker/src/config.ts` parses vars once (DO constructor) and rejects: an invalid `LOG_NAME` (it is
an R2 prefix and URL segment), an invalid `LOG_ORIGIN` (`validateOrigin`), invalid bucket names,
`MONITORED_BUCKET_NAME == LOG_BUCKET_NAME` (PLAN §5.4), and out-of-range integers.
`BATCH_MAX_ENTRIES` is capped at 1,000 because one publication holds its batch in memory.

### D2.13 Deferred from M2

- **Real-R2 contract run** (D2.1): needs approval; M6.
- **A DO-level test across the 65,536 (level-2 tile) boundary.** Core tests cover those sizes
  (I1). The DO tests cross level-1 boundaries only, to keep the suite fast.
- **Admin `publish` route, `/status` counters for invalid/DLQ messages**: M3/M4.
- **Unicode key-order agreement** between R2 `list()` and SQLite: M6, as planned.

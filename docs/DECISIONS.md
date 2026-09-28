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

## M3: Ingest (2026-10-02)

Docs checked for this milestone (2026-10-02): R2 event notifications (message format, event types,
limits); Queues JavaScript APIs, batching and retries (explicit ack/retry precedence), limits, and
local development; Vitest integration test APIs (`createMessageBatch`, `getQueueResult`); `wrangler
queues create` and `wrangler r2 bucket notification create` (`--help`, wrangler 4.147.0). Code:
`worker/src/ingest.ts`, `worker/src/index.ts`, `worker/dev/`, `scripts/simulate-events.ts`,
`scripts/simulate/events.ts`.

### D3.1 eventId hashes a canonical JSON array, not a `|`-joined string

- **Plan said:** `eventId = hex(SHA256(bucket|key|action|etag|eventTime))`.
- **Problem:** object keys may contain `|`, and so may the entry schema's ETags. Then
  `key="a", etag="b|PutObject|c"` and `key="a|PutObject|b", etag="c"` produce the same string. A
  colliding event would be dropped as a duplicate (I5 working against us). Anyone who can choose
  key names gets some control over this; R2's real ETags are hex, which makes it harder but does
  not rule it out.
- **Decision:** `hex(SHA-256(canonicalJson([bucket, key, action, etag ?? null, eventTime])))`. Each
  tuple has exactly one encoding. Deletes have no ETag, so it is `null`. That is different from the
  string `"null"`. A test pins the exact preimage and shows that the `|` collision no longer occurs.
- **Alternatives:** length-prefixed fields (equivalent, but needs its own codec); hashing the whole
  message (it would include `account`, and any field R2 adds later would change the ID).
- **Consequence:** two events with the same bucket, key, action, ETag and `eventTime` string are
  one event. Two identical PUTs to one key in the same millisecond are logged once. They leave the
  same state, and R2 gives the consumer nothing that tells them apart.

### D3.2 What "strict validation" means for fields R2 might add

- **Decision:** every documented field the consumer uses is checked strictly. Types are checked in
  `classifyMessage`, and formats by `encodeEntry`: bucket rules, keys at most 1,024 bytes, ETag
  charset, non-negative integer sizes, RFC 3339 times, no size/ETag on deletes, `copySource` only on
  `CopyObject`. **Unknown fields are ignored**, not rejected, and are never logged.
- **Why:** if a field R2 adds later (say a version ID) were a validation error, every event would
  be acked and dropped from then on. The log would go dark with only a counter to show it. Ignoring
  it loses nothing the log records today. A _documented_ field with the wrong type or format is
  still rejected: that is a real contract break and should be visible.
- **Deletes that carry `size`/`eTag`** contradict the docs and are rejected as invalid (the entry
  schema forbids them, D1.6). That is the strict choice. If real R2 sends them, the
  `invalid` counter and `lastInvalid` reason will show it quickly (D3.7).

### D3.3 Batch handling, retries and counters

- **One RPC per batch:** `Sequencer.ingest(items, report)` appends the batch's events (possibly
  none) and adds its counters in **one SQLite transaction**. The counters therefore move exactly
  when events become durable. `append` stays as it was for other writers (the auditor in M6).
- **Ack/retry:** on success the batch is acked, invalid messages included. They can never become
  valid, so retrying them is pointless (PLAN: "do not retry poison forever"). If the RPC fails, the
  **whole batch** is retried with `retryAll({delaySeconds})`. The delay is 10 s doubling per
  attempt, capped at 300 s, so the 5 configured retries span about 5 minutes before the dead-letter
  queue. The handler does not throw. A throw would also retry the batch, but with no delay.
- **Counter semantics:** counts are exact unless an RPC commits and its response is lost. The
  retried batch's events are then deduplicated, but its drop counts are added a second time. The
  counters are operational signals, not evidence. The evidence is the log.
- **Loop protection (I8), three layers:** config rejects `MONITORED == LOG` (D2.12). The consumer
  checks a message's `bucket` against the log bucket _before anything else_, so even a malformed
  log-bucket event is counted as a loop, not as invalid. The Sequencer rejects any entry not naming
  the monitored bucket (D2.6). Events from any other bucket are counted as `foreignDropped`.
- **Clock:** `ingestedAt` is the Worker clock when the batch is handled. A redelivered event gets
  a new `ingestedAt`, but dedupe is on `eventId`, which excludes it.

### D3.4 `/status` counters arrive in M3; the route is minimal

PLAN M3's acceptance criteria say "counters visible in `/status`", but the routes are M4. So M3 adds
only `GET`/`HEAD /api/v1/status` (`no-store`, JSON): log size, durable size, pending, last
checkpoint time, next publication, last error, and the ingest counters with the last rejection
reason. Rejection reasons name the field, never its value: they are served publicly, and keys can
be sensitive (tested). M4 adds the other routes and decides how `PUBLIC_LOG=false` applies here;
M6 adds the audit summary. The counters live in a new `counters` table (schema v2, with a tested
v1→v2 upgrade).

### D3.5 The Worker consumes its own dead-letter queue

- **Plan said:** configure a DLQ and show DLQ counters in `/status`. It did not say who reads the DLQ.
- **Decision:** a second consumer entry reads `r2notary-events-dlq` with the same handler.
  `batch.queue === EVENTS_DLQ_NAME` (a new var, validated at startup) marks those messages as
  `deadLettered`. They are then processed normally: one more chance to be logged (dedupe makes this
  safe if an earlier attempt did commit), and they are counted. The DLQ has no DLQ of its own.
  A message that fails there too is dropped after its retries, and the auditor (M6) is the backstop
  for anything lost.
- **Why:** a message only reaches the DLQ after about 5 minutes of failed Sequencer calls, which
  points to an outage. Consuming the DLQ later recovers those events. An unread DLQ silently
  expires after 24 h on the free plan, and the Worker cannot see its depth.

### D3.6 Local simulation runs through a real local queue

- **Problem:** local R2 emits no notifications, and Queues offer no way to inject messages from
  outside the runtime. The docs support one `wrangler dev` process with several configs (`-c a -c
b`, marked experimental), where the first config is primary and gets the port.
- **Decision:** a dev-only producer Worker (`worker/dev/simulator.ts`, never deployed) is primary.
  It accepts `POST /__simulate/send` (at most 100 messages, the `sendBatch` limit), sends them with
  `contentType: 'json'`, and forwards every other request to r2notary through a service binding.
  `scripts/simulate-events.ts` generates the traffic. The generator (`scripts/simulate/events.ts`)
  is pure and seeded, and the worker tests use it too. It returns a manifest of the expected
  counters and final per-key state.
- **Run once (2026-10-02, wrangler 4.147.0, local mode only):** 507 messages (400 distinct events,
  87 duplicates, 12 malformed, 5 from the log bucket, 3 from another bucket, shuffled with window
  30). `/api/v1/status` matched the manifest exactly. The alarm published one checkpoint at size
  400 (tiles `0/000`, `0/001.p/144`, `1/000.p/1`, matching bundles, `x-checkpoints/400`). This run
  also caught a bug no test could have caught: workerd refuses a Worker module that exports a plain
  constant. It is not a benchmark, so no timing is reported.
- **Not covered:** this exercises local Queues, not R2's real notification payloads (D3.7).

### D3.7 Open questions for the first real events (M6, needs approval)

The docs give one example message. They do not say:

- whether `object.key` is URL-encoded in notifications (S3's are). The consumer logs the key
  **verbatim**. If R2 encodes it, the log and the auditor's `list()` keys disagree for keys that
  need escaping. The auditor would then report false `UNLOGGED_OBJECT`/`MISSING_OBJECT` findings,
  so this must be checked before M6's demo;
- whether `eTag` is ever quoted (the docs example is not; a quoted one is rejected as invalid);
- the exact `eventTime` format across actions (any RFC 3339 offset is accepted, D1.6).
  The remote end-to-end run (PLAN §10) should print a few raw messages and confirm all three.

### D3.8 Testing notes

- `consumeBatch` takes an `IngestSink`, so its failure path is tested with a fake that rejects.
  That avoids the test pool reporting rejected DO RPCs as unhandled (D2.9).
- **Test-pool quirk:** `@cloudflare/vitest-plugin` 1.3.6's `createMessageBatch().retryAll()`
  ignores its options, so `getQueueResult` never shows `delaySeconds`. The test wraps the batch to
  record the options instead.
- **End to end in workerd:** 300 simulated events (20% duplicates, shuffle window 25, malformed,
  loop and foreign events) go through the real queue handler and the real Sequencer. The test then
  checks the counters, the published size, every published entry (decoded from the R2 bundles: only
  the monitored bucket, and no account ID anywhere), and the objects view against the generator's
  final state, which shows that out-of-order delivery does not corrupt it. Replaying the whole
  stream adds nothing. Overlapping batches delivered concurrently are each recorded once (I5).
- **Mutation check:** each of these was broken on purpose and tests failed: no log-bucket check
  (5 failures), neither bucket check (6), `|`-joined eventId (2), ack instead of retry on failure
  (1), DLQ messages not counted (2), invalid messages not counted (6).

### D3.9 Deferred from M3

- **Real notifications and queues:** need the owner's approval; commands are in
  `docs/OPERATIONS.md`. The questions in D3.7 stay open until then.
- **`scripts/keygen`** (M4). The local run above generated a key with `packages/core`'s
  `generateKey` inline.
- **`PUBLIC_LOG`/auth on `/api/v1/status`** and the other routes: M4.
- **Throughput of the consumer → Sequencer path:** a §14 benchmark (M7); no figure is claimed.

## M4: Public read path + admin API (2026-10-02)

Docs and specs checked for this milestone (2026-10-02): C2SP `tlog-tiles` (serving: origin,
content types, caching, partial tiles, compression); R2 Workers API (`get`, `head`, `R2Object`);
Workers Web Crypto (`timingSafeEqual`); Workers `Response` (`encodeBody`, Content-Length);
Workers `Request` (`cf.clientAcceptEncoding`); Cache API; Workers Cache (overview, limitations);
Cloudflare content compression; Workers limits (subrequests, memory); wrangler config schema
(`cache`, `secrets`). Code: `worker/src/{index,api,auth,http,readpath}.ts`, `scripts/keygen.ts`.

### D4.1 `LOG_ORIGIN` is the log's URL prefix (placeholder changed)

- **Spec says:** "The origin line SHOULD be the schema-less URL prefix of the log with no trailing
  slashes" (tlog-tiles).
- **Problem:** the M0 placeholder `r2notary.example.com/example-log` does not match the route
  layout in PLAN §5.5, which serves the log at `https://<host>/log/<name>/`.
- **Decision:** the placeholder is now `r2notary.example.com/log/example-log`, and the test signing
  key is named to match. It stays a SHOULD, not enforced: serving the bucket through an R2 custom
  domain would make the prefix `<domain>/<name>`. `LOG_ORIGIN` is still validated by
  `validateOrigin` (D1.10). Nothing has been published, so the change costs nothing now. After the
  first real checkpoint it could not change without starting a new log.

### D4.2 Two tokens: `ADMIN_TOKEN`, and a new `READ_TOKEN` for private logs

- **Plan said:** `PUBLIC_LOG=false` "requires a bearer token on log routes too". It names no read
  token, and §7 lists only `ADMIN_TOKEN`.
- **Decision:** a separate `READ_TOKEN` secret. Handing readers the admin token would let them
  publish and, after M6, start scans. With `PUBLIC_LOG=false` (the committed default, per sharp
  edge 8), **every non-admin route** needs the read token or the admin token: log routes, `status`,
  `lookup` and `findings`. Lookup and findings disclose key names, and one rule is easier to reason
  about than a per-route list. Admin routes accept only `ADMIN_TOKEN`, on public logs too.
- **Validation** (`parseAccess`): `PUBLIC_LOG` must be exactly `true` or `false`. Tokens must be at
  least 32 characters of the RFC 6750 alphabet. `READ_TOKEN` is required only for a private log and
  must differ from `ADMIN_TOKEN`.
- **Parsed apart from `Config`:** only the fetch handler needs tokens. A missing token returns 500
  from the HTTP routes but cannot stop ingest or publication. `secrets.required` lists
  `SIGNING_KEY`, `ADMIN_TOKEN`, `READ_TOKEN`. Per the schema, that drives type generation and local
  warnings only, so a public log can leave `READ_TOKEN` unset.
- **Order of checks:** read routes check route (404), then method (405), then token (401), then
  resource (404). Without a token, nobody learns which tiles exist. Admin routes check the token
  **first**, so nothing about them (including which ops exist) is visible without it. Every
  failure gives the same 401 (`WWW-Authenticate: Bearer realm="r2notary"`).

### D4.3 Caching: Workers Cache exists and works on workers.dev; not enabled by default

- **Plan said:** the Cache API may not work on `workers.dev`, so CDN caching needs a custom domain.
- **Docs now say:** the Cache API is a no-op only in the dashboard editor and Playground previews.
  Worker responses are **not** cached by the CDN automatically. A separate feature, **Workers
  Cache** (`"cache": { "enabled": true }`, present in the wrangler 4.147 schema), serves cached
  `GET`/`HEAD` responses without running the Worker. It works on `workers.dev`, follows
  `Cache-Control` (RFC 9111), and never caches requests that carry `Authorization`.
- **Decision:** do not enable it in the committed config, but make every response correct under it:
  - errors (401, 404, 405, 500) and all JSON API answers are `no-store`. A cached 404 for a tile
    requested just before publication would hide that tile for its lifetime;
  - checkpoint: `public, max-age=2`; tiles, bundles and archived checkpoints:
    `public, max-age=31536000, immutable`. Every resource except the live checkpoint is immutable
    by path (D2.3), so long caching is safe;
  - private logs send `private` instead of `public`. Their requests carry `Authorization`, which
    Workers Cache bypasses anyway.
- **Why not on:** the default log is private, where the cache never hits. For a public log it would
  save R2 reads, but it has one sharp edge: switching a cached public log to private keeps serving
  cached immutable resources without a token until they are purged. `docs/OPERATIONS.md` says how
  to enable it, with that warning. Not tested: the test pool and `wrangler dev` do not show whether
  Workers Cache is active.
- **Alternative still open:** serving the log bucket through an R2 custom domain. Objects carry the
  same content types and cache headers as stored metadata (D2.11).

### D4.4 Constant-time token comparison, by construction

- `tokensEqual` hashes both strings with SHA-256 and compares the two 32-byte digests with Workers'
  `crypto.subtle.timingSafeEqual`. The docs do not say how that function treats unequal lengths;
  comparing digests avoids the question. Neither the expected token's length nor where the first
  difference falls affects the comparison. Hashing the presented token is linear in its own length,
  which the client already knows. When several tokens are accepted, all are compared (no early
  exit).
- **Not measured.** PLAN M4 says "admin routes reject bad tokens in constant time". Timing cannot be
  measured meaningfully in the test pool: Workers clocks are coarse and only advance on I/O. The
  claim rests on the construction above. The tests check correctness: prefix, extension, case,
  first and last character, empty, and 10,000 characters. A mutation that let the read token act as
  the admin token was caught only after adding a private-log admin test.

### D4.5 Read path details

- **Strict names:** `/log/<name>/<path>` is served only if core's `parseLogPath` accepts `<path>`
  as a canonical log path (D1.8). Objects stored under the prefix at other keys (M6's
  `x-reports/`, stray files, non-canonical tile names) are not reachable, even when they exist
  (tested by planting them).
- **Archived checkpoints** (`x-checkpoints/<size>`) are served as immutable text. PLAN's route
  table omits them, but §6 defines them and the M5 monitor and consistency checks will want them.
- **Headers come from the resource kind**, not from the object's stored metadata: what is served
  does not depend on how an object was written. All log responses, errors included, send
  `Access-Control-Allow-Origin: *`, so a browser verifier can read 404s too. `OPTIONS` answers
  preflights without a token (browsers send no credentials on a preflight) and allows the
  `Authorization` header. `X-Content-Type-Options: nosniff` everywhere.
- **HEAD** uses R2 `head()` and states `Content-Length` from the object size. For GET, the
  runtime sets `Content-Length` itself from the R2 body (observed under `wrangler dev`).
- **Superseded partial tiles stay.** tlog-tiles allows deleting a partial tile once its full tile
  exists. Keeping them costs storage, but each stays valid and immutable.
- Not supported: Range requests and conditional GETs (no `ETag`). Neither is in the spec or the plan.

### D4.6 Entry bundles are gzip-encoded on request, negotiated on the client's real header

- **Spec says:** entry bundles SHOULD be compressed at the HTTP layer; tiles are hashes and
  incompressible.
- **Decision:** when the client accepts gzip, bundle responses declare `Content-Encoding: gzip`.
  The Workers runtime then compresses on the way out (`encodeBody: "automatic"`). Bundles always
  send `Vary: Accept-Encoding`. Tiles are never encoded.
- **Caught by the local run:** under `wrangler dev`, `curl -H 'Accept-Encoding: identity'` still
  got gzip. The Workers Request docs explain it: Cloudflare rewrites the `Accept-Encoding` a Worker
  sees to a canonical value and keeps the client's original in `request.cf.clientAcceptEncoding`.
  Negotiation now reads that first and falls back to the header. After the fix, `wrangler dev`
  returned identity bytes with an exact `Content-Length` for no header and for `identity`, and gzip
  for `gzip`. A test pins this with a request whose header says `gzip, br` and whose
  `cf.clientAcceptEncoding` says `identity`.
- Cloudflare's compression docs say its proxy can also convert between encodings for the visitor.
  The production behaviour is unverified until a deployment exists.

### D4.7 Lookup

- `GET /api/v1/lookup?key=K[&after=I][&limit=N]` returns
  `{key, size, entries: [{index, entry}], next}`. `entry` is the parsed canonical JSON. Encoding is
  canonical (D1.5), so it re-encodes to the exact leaf bytes, though a verifier should take bytes
  from the bundle anyway. `size` is the published size the indexes were read at. Both values come
  from one synchronous DO call, so every index is below it and its bundles exist. `next` is a cursor
  for `after`.
- Entries are read from the R2 bundles, since SQLite keeps only the current partial bundle (D2.2).
  Bundles are read **one at a time**: a bundle can approach 16 MB, and an isolate has 128 MB.
- **At most 32 bundles per page.** R2 calls count as subrequests, and the Free plan allows 50 per
  invocation (Workers limits docs). A page that would need more stops early and returns a cursor.
  The cap is injectable, so a test checks it with two bundles. Page size is at most 100.
- The DO's `lookup` now takes `{after, limit}` and returns `{size, indexes}` (D2.7 said the shape
  might change in M4).

### D4.8 Findings and the M6 admin ops

`GET /api/v1/findings` answers `{latestScan: null, findings: []}`. That is accurate, since no
auditor exists yet; M6 fills it in. `POST /api/v1/admin/{backfill,scan}` exist, check the admin
token, and return 501. `POST /api/v1/admin/publish` runs `Sequencer.publish()` (single-flight,
D2.8) and returns its result.

### D4.9 Errors

The fetch handler catches everything and returns a bare `500 internal error` (`no-store`). The
detail goes to the logs only: a config error names variables, and DO or R2 errors can name keys.
Unknown paths are 404 (`no-store`), replacing M0's 501 stub.

### D4.10 `scripts/keygen.ts`

`npm run keygen -- --origin <LOG_ORIGIN> [--out worker/.dev.vars]` writes `SIGNING_KEY` (note
signer key named after the origin), `ADMIN_TOKEN` and `READ_TOKEN` (32 random bytes, base64url),
with the vkey as a comment, in `.dev.vars` format. `--out` creates the file with mode 0600 and
refuses to overwrite one. Checked by hand: the written signer loads, its vkey matches the printed
one, and a re-run refuses. It is a thin wrapper over core's `generateKey`, which has its own tests.

### D4.11 Acceptance run and testing notes

- **`curl` against `wrangler dev`** (2026-10-02, wrangler 4.147.0, local mode, private log with
  keygen secrets passed as environment variables, not files). 300 simulated events, then
  `POST /admin/publish`. Every log route returned the headers above. Without a token, with a wrong
  token, and with the read token on an admin route: 401. A missing tile: 404 `no-store`. The
  preflight returned 204. **Bytes were verified independently** with `packages/core`: the
  checkpoint's signature and origin; tile `0/000` and `0/001.p/44` equal the leaf hashes of the
  served bundles; tile `1/000.p/1` equals the root of tile `0/000`; the checkpoint root equals the
  RFC 6962 root of all 300 served entries.
- **Test hygiene:** a test that reads only a 200's headers must cancel its R2-backed body. Otherwise
  `reset()` aborts the open stream and logs a `deleteAllDurableObjects()` exception.
- **Mutation check:** each was caught after this milestone's tests were complete: reads open on a
  private log (5 failures), the admin route accepting the read token (1, after adding a test),
  serving non-canonical paths (1), cacheable 404s (15), no CORS (22), private responses marked
  `public` (1), no gzip (1), negotiating on the rewritten header (1), no bundle cap (1), short
  tokens accepted (2), the same token for both roles (1).

### D4.12 Deferred from M4

- **Go CLI support for private logs** (`--token` for log reads) is needed in M5. PLAN §5.7 has
  no flag for it.
- **Workers Cache and gzip behaviour in production**: no deployment (D4.3, D4.6).
- **CORS on `/api/v1/`**: not in the plan. The M8 browser verifier may need it for `lookup`.
- **Audit summary in `/status`** and real findings: M6.

## M5: Go verifier + conformance (2026-10-02)

Docs and APIs checked for this milestone (2026-10-02): `golang.org/x/mod` v0.41.0 `sumdb/tlog` and
`sumdb/note` (pkg.go.dev, and the module source for `TileHashReader`, `ProveTree` and
`GenerateKey`); Workers secrets and environment-variables docs; wrangler 4.147 `dev --help` and its
source for `--env-file`. Code: `cli/` (`cmd/r2notary`, `internal/{verr,tilefetch,verify,entry,
monitor,testlog}`), `scripts/conformance.ts`, the `conformance` CI job.

### D5.1 Verifier structure: Go's `tlog` does the proofs, tlog-tiles paths are ours

- `tilefetch` maps `tlog.Tile{H: 8, L, N, W}` onto `tile/<L>/<N>[.p/<W>]` and fetches over HTTP.
  `tlog.Tile.Path()` is the checksum database's layout (`tile/8/<L>/...`), as PLAN §5.7 warned. The
  index encoding is tested against the spec examples and against Go's own encoding over many
  values.
- `verify` reads hashes only through `tlog.TileHashReader`, which authenticates every tile against
  the signed root before any hash is used (frontier tiles against the root, then full tiles
  against their parents). Inclusion is `ProveRecord`/`CheckRecord` and consistency is
  `ProveTree`/`CheckTree`. Both are computed locally from tiles; the server is never asked for a
  proof.
- Authenticated tiles are cached in memory for one process. They are re-authenticated on every
  use, so the cache only saves downloads. Full level-0 tiles are not cached: a scan reads each one
  once, and keeping them would grow with the log.
- **No code shared with TS** (PLAN G3). The Go tests use their own log writer (`internal/testlog`),
  built on `tlog.StoredHashes`/`NewTiles`/`ReadTileData`, so the Go side is tested against a
  second, independent writer as well as the TS one.

### D5.2 Exit codes: evidence versus outage

0 ok · 1 verification failed · 2 usage · 3 verified but negative (no entry for `--key`/`--index`,
or a `--watch` alert with `--once`) · 4 could not verify (network, HTTP status, local files).
Anything wrong that was _received_ (bad signature, a tile or bundle that does not match the signed
tree, wrong sizes, an inconsistent or smaller checkpoint) is a `verr.Failure`, exit 1. A 404 for a
needed resource is exit 4: it breaks I2, but nothing false was accepted, and a monitoring system
should be able to tell "the log lied" from "the log is unreachable". The conformance harness
checks both.

### D5.3 Signatures must be canonical base64 (Go's `note` is lenient)

The bit-flip test found that `note.Open` decodes signatures with lenient base64. It ignores the
unused low bits of the last character, so flipping one of them still verified. Nothing was
forged, since the decoded signature is identical, but one checkpoint then had several valid
encodings. The TS side already rejects that (D1.9). The CLI now re-encodes each verified signature
and rejects any that is not canonical.

### D5.4 Bundles are verified whole

Every scan (`monitor`, `inclusion --key` without `--api`) compares each entry of every bundle it
touches with the leaf hashes from the authenticated level-0 tile, and parses bundles strictly
(exact width, no trailing bytes). So a flipped bit anywhere in a bundle is caught, not only in the
requested entry. Go test: a flipped bit (first, middle, last) or a one-byte resize of every
resource of a 700-entry tree is a verification failure.

### D5.5 CLI surface beyond PLAN §5.7

- **Private logs:** the token comes from `$R2NOTARY_TOKEN` or `--token-file`, not a flag, to keep
  it out of shell history and process listings (D4.12). Go's HTTP client drops `Authorization` on
  redirects to another host.
- `--vkey @FILE`; `--origin` (default: the vkey's name, because R2Notary names its key after the
  origin, D1.10); `checkpoint --out` (saves the verified note for `consistency --old`);
  `consistency --new FILE` (prove one saved checkpoint extends another, used for pairwise I3);
  `monitor --once` and `-q`; `keygen --out` (created 0600, never overwritten).
  `note.GenerateKey` does not validate the name, so keygen loads both keys back to check it.
- **`inclusion --key`** scans and verifies the whole log by default: it cannot be lied to, but it
  reads everything. With `--api https://host` it takes only the _indexes_ from `/api/v1/lookup`
  and proves each one. An index beyond the checkpoint, or one whose entry names another key, is a
  failure. The API can still omit entries, and the CLI says so.
- **Output:** entries are printed as `{"index":N,"entry":<exact committed bytes>}`, built by hand
  because `json.Marshal` HTML-escapes `<`, `>` and `&`. The conformance harness compares these
  bytes with what TS wrote.
- **`checkpoint` prints no time.** The plan says "print size/root/time", but the checkpoint format
  has no timestamp and R2Notary writes no extension lines. Signed times come with witness
  cosignatures (M8).
- **Deferred:** `findings --api` (M6: there is no auditor yet, and the route returns an empty
  list, D4.8).

### D5.6 Monitor semantics

- State = the last verified checkpoint's signed note (kept as evidence) plus, with `--watch`, the
  live keys under the prefix. It is saved atomically (temporary file, fsync, rename), and only
  after every new entry has verified. A missing state file means a new monitor, which verifies the
  log from entry 0 (no trust on first use beyond the vkey). A saved checkpoint that no longer
  verifies is a local error (exit 4), not blamed on the log.
- Each poll: verify the checkpoint, prove consistency from the saved one (a smaller size or the
  same size with another root is a rollback or fork, exit 1, and both signed notes are printed as
  evidence), then verify and print the new entries. In loop mode, network errors are logged and
  retried; any failure exits.
- `--watch PREFIX`, in log order: a delete under the prefix alerts; a put, copy or multipart
  completion of a key the log shows as live alerts as an overwrite; a backfill snapshot marks a
  key live without alerting. The prefix must match the state that built the live set, and a watch
  cannot be added to a state that did not track one. Unknown types and versions are printed and
  otherwise ignored (PLAN §5.2).

### D5.7 Conformance harness (`npm run conformance`, CI job `conformance`)

- **Writer:** the real Worker and Sequencer under `wrangler dev` (simulator + r2notary, as
  `npm run dev:sim`), private log, local only. Synthetic events from the M3 generator (seed 5, 40
  keys, including the Unicode/space/quote/`|`/emoji keys) are published through the admin API at
  sizes 1, 255, 256, 257, 512, 513, 1000 and 1300. `CHECKPOINT_INTERVAL_MS` is an hour, so the
  alarm never publishes and every size is known. **The signing key comes from the Go CLI's
  `keygen`**: TS signs with a Go-generated key and Go verifies, which tests the key format in the
  direction D1.4 had only argued.
- **Against the live read path** (token, gzip-encoded bundles): checkpoint and origin (I9; a
  different expected origin and a same-name foreign vkey are rejected; no token gives 401 / exit 4);
  a full monitor scan whose 1,300 printed entries must equal the bytes TS decodes from the bundles;
  inclusion at tile-boundary indexes; `--key` for six keys by scan and by lookup API, matching
  TS-computed indexes; `--watch sim/1` alert count equal to an independent TS implementation of
  the same rule; consistency for all 36 ordered pairs of archived checkpoints (I3 in Go), and a
  rollback pair rejected.
- **Corruption (I7):** every resource of every archived size (34) is mirrored and served by a
  plain HTTP server. A replayed monitor steps through the archived checkpoints in order, as one
  would have seen the log grow. Uncorrupted, it passes. For each resource, three bits (first,
  middle, last) are flipped one at a time: all 102 replays end with exit 1. For each archived
  checkpoint, a flipped signature bit (re-encoded as valid base64) and a valid signature from
  another key with the same name both fail at that size. A missing tile and a missing bundle end
  with exit 4.
- **Mutation check:** with the Go bundle-hash comparison and the origin check disabled, the harness
  reported every bundle bit flip and the I9 origin case. With the code restored, all 200 checks
  pass (about 45 s locally).
- **`--env-file` (wrangler source, docs silent):** with `--env-file`, `.dev.vars` is not read, so
  a developer's local secrets cannot leak in. File values override `vars` keys and fill required
  secrets. Because the config declares `secrets`, wrangler also merges `process.env`, so the
  harness removes every config key from the child's environment. The harness also uses a random
  port, inspector port and `--persist-to` directory, and kills the whole process group when done.
- **Not covered cross-language:** a full level-1 tile (65,536 entries) and level-2 tiles. Feeding
  65k events through local queues would make CI slow. Those sizes are covered by core I1 tests (TS)
  and the Go inclusion tests up to 70,000 entries (`testlog`), and both implement the same
  tlog-tiles layout that the harness checks at levels 0-1.

### D5.8 Deferred from M5

- **CI not observed running** (D0.8 still holds: nothing has been pushed). Every CI step, the new
  conformance job included, was run locally.
- **Third-party tlog-tiles client** (PLAN §10, optional): not tried.
- **`findings` command:** M6.

## M6: Auditor, backfill, deep scrub (2026-10-03)

Docs checked for this milestone (2026-10-02): Workflows Workers API (`step.do` config, step result
limits, `create`/`createBatch`, instance IDs, `NonRetryableError`), Workflows limits, Workers
limits (subrequests), R2 Workers API reference (`list`, `R2ListOptions`, `get` with `onlyIf`,
checksums), R2 S3 API compatibility (ListObjectsV2), Workers Web Crypto (`DigestStream`), Vitest
integration test APIs (Workflows introspection), the wrangler config schema (`secrets`). Code:
`worker/src/audit/{reconcile,store,scan,scan-workflow,scrub,alert}.ts`, schema v3 in
`worker/src/store.ts`, `cli/cmd/r2notary/findings.go`.

### D6.1 Where the scan state lives: in the Sequencer, with the Workflow as a driver

- **Decision:** every step of a scan is one synchronous transaction in the Sequencer DO
  (`audit/store.ts`): the merge-join reads the `objects` view and records its result in the same
  transaction, and a step's log entries, counters and cursor commit together. The Workflow
  (`audit/scan.ts`) lists the bucket, hashes bodies, sleeps, and calls those steps. It holds nothing
  a replay cannot rebuild from step results.
- **Alternatives:** the cursor only in Workflow step results (PLAN §5.6). Then a step that commits
  findings and crashes before its result is persisted would append them again, and a scan could not
  continue in another instance. A separate auditor DO: it would have to read the `objects` view over
  RPC, so a publication could commit between reading the expected state and acting on it.
- **Why:** exactly-once effects per step without distributed bookkeeping. The Sequencer is already
  the single writer, and the auditor's appends go through the same dedupe and publication path as
  events.
- **One scan at a time.** `scanStart` refuses while another scan is active. A scan with no progress
  for 24 hours (`STALE_SCAN_MS`) is marked `abandoned` by the next start, so a dead instance cannot
  block audits forever. An abandoned scan's `audit.scan` start entry stays in the log without an end
  entry, which is an honest record.

### D6.2 Key order is UTF-8 byte order, checked rather than assumed

- **Docs say:** R2 `list()` returns keys "ordered lexicographically", without saying over what.
  SQLite's BINARY collation compares UTF-8 bytes (`memcmp`).
- **Problem:** JavaScript's `<` compares UTF-16 code units. It puts astral characters
  (U+10000 and up, surrogate pairs) before U+E000..U+FFFF, while UTF-8 order puts them after. A
  merge-join with the wrong comparison skips or double-counts keys silently.
- **Decision:** core gets `compareUtf8` (code-point comparison, property-tested against byte
  comparison of the encodings). The merge-join uses it everywhere and **rejects** a listing or a row
  stream that is not strictly increasing in that order, rather than merging it wrongly.
- **Tests (PLAN M6 "Unicode-key ordering test"):** `worker/test/contract/r2-list-order.ts` checks
  that `list()` returns 18 keys chosen so the two orders differ in UTF-8 order, and that `startAfter`
  returns exactly the keys after it (present or not). The same contract is in the opt-in remote
  harness (`npm run test:contract:remote`), **not yet run against real R2**. A DO test checks that
  SQLite's `ORDER BY key` and `key > ?` agree with `compareUtf8`.

### D6.3 `startAfter` is used, and pinned by the contract test

- **Docs say:** the Workers API reference lists `limit`, `prefix`, `cursor`, `delimiter` and
  `include` for `R2ListOptions`. `startAfter` is in `@cloudflare/workers-types` and R2's S3 API
  lists ListObjectsV2 `start-after` as supported, but the Workers reference does not mention it.
- **Decision:** each page lists with `startAfter: <previous page's end>`, never with a cursor. The
  merge-join's page end can fall inside a listing page (when the log side is truncated first), and
  only a key can express that. A key also never expires, unlike an opaque cursor.
- **Fallback** if real R2 ignores `startAfter`: re-list from the previous cursor and skip keys up
  to the page end (costs an extra Class A list per page).
- **Local quirk found:** Miniflare combines `cursor` with `startAfter` using a JavaScript string
  comparison. With astral keys a listing that passes both can loop forever (observed: a probe
  returned `x`, `😀`, `x`, `😀`, ...). The auditor never passes both, and the contract
  test pages by `startAfter` alone, as the auditor does, with every loop bounded.

### D6.4 Finding conditions (PLAN §5.6 table, made exact)

`reconcilePage` (pure) compares one page of the listing with the log's expected state. With `G`
the grace window, `now` the observation time, and `quiet(t)` meaning `t <= now - G`:

| Kind              | Condition                                                     |
| ----------------- | ------------------------------------------------------------- |
| `UNLOGGED_OBJECT` | listed, no row in the log, `quiet(uploaded)`                  |
| `MISSING_OBJECT`  | live row, not listed, `quiet(eventTime)`                      |
| `PHANTOM_DELETE`  | listed, row deleted, `quiet(max(uploaded, eventTime))`        |
| `ETAG_MISMATCH`   | listed, live row with an ETag that differs, `quiet(max(...))` |
| `SIZE_MISMATCH`   | same, ETag equal or not logged, size differs                  |

- **Deviation:** the plan reports a mismatch or phantom delete only when `uploaded` is newer than
  the logged event. An object _older_ than the logged event that contradicts it (a delete that did
  not happen, a PUT whose object is not there) is divergence too, so both orders are reported once
  both times are outside the grace window. The finding records both times.
- Only what the log recorded is compared: a create logged without an ETag or size is not a
  mismatch on that field. One finding per key per scan; `ETAG_MISMATCH` wins over `SIZE_MISMATCH`.
- A divergence that persists is reported again by every scan: each scan is a separate observation.
- **Pages:** each side is read with a limit, so a page covers keys up to the smaller last key of
  whichever side was truncated. A property test checks that any combination of page sizes produces
  exactly the findings of a per-key oracle.

### D6.5 Confirmation after the grace window (an addition to the plan)

- **Problem:** the plan's grace window cannot protect `MISSING_OBJECT`. Its only timestamp is the
  log's `eventTime`; when the object was deleted is unknown. An object deleted one second before the
  listing, whose notification is still in the queue, would be reported missing.
- **Decision:** a page records **candidates**, each with the `seq` of the `objects` row it was
  judged against (or none). After the listing, the scan sleeps until every candidate is at least
  `G` old, publishes everything durable, and confirms: a candidate becomes an `audit.finding` only
  if the row for its key is still the same. Any event for the key that arrived since explains it,
  and the candidate is dropped (counted as `dropped`; the next scan judges the key again). The
  Sequencer itself refuses to confirm a candidate younger than `G`, so this does not depend on the
  Workflow sleeping correctly.
- **What `G` now means:** notification delivery, queue retries and publication must all complete
  within `AUDIT_GRACE_SECONDS`. The page-time conditions above are kept as well (as the plan says);
  they avoid creating candidates that would almost always be dropped.
- **Cost:** a scan takes at least `G` after its last page. `step.sleep` costs nothing (not a step,
  no subrequests, the instance is not "running").
- `observedAt` in a finding is when the divergence was seen, not when it was confirmed.

### D6.6 Exactly-once steps and resumability

- Page `n` is applied only if `n` equals the scan's page count and `after` its cursor. Re-sending
  the last applied page returns its stored result and changes nothing. Scrub results are applied
  once per page (`observed_through`). A candidate is deleted in the transaction that appends its
  finding. Start, end and report steps are state transitions. So a step re-run after it committed
  (a crash before Workflows stored its result) has no effect.
- **Event IDs** of audit entries are derived from the scan and step (`find:<scanId>:<candidate>`,
  `obs:<scanId>:<page>:<i>`, ...), not hashed: the idempotency comes from the state machine, and
  synchronous IDs keep each step free of awaits inside its transaction.
- **Expected failures are values.** A wrong state or an out-of-sequence page is returned as
  `{ok: false, reason}`; the Workflow turns it into a `NonRetryableError`. Thrown errors would cross
  RPC without their class, and the test pool reports rejected DO RPCs as unhandled (D2.9). The
  engine reports such an instance with a generic message ("a step threw an NonRetryableError"), so
  the reason is also logged.
- **Tests:** `audit-scan.test.ts` runs the driver with a step runner that replays as Workflows do
  (stored results by step name, `run()` restarted after a crash), then crashes once at **every**
  step of a full scan, before and after the step body: each run ends with the same published log as
  the uncrashed one, no entry missing or doubled, and the same step sequence. The real `ScanWorkflow`
  class also runs under the local Workflows engine with an injected step failure
  (`mockStepError`), from the admin API, and from the cron handler.

### D6.7 Limits, budgets and hand-off

- **Docs say (Workflows limits):** Free: 1,024 steps per instance, 10 ms CPU per step, 1 MiB per
  step result; Paid: 10,000 steps (configurable to 25,000), 30 s CPU per step. Subrequests are
  listed per instance ("50/request" Free, "10,000/request" Paid), and the subrequest section adds
  that Free Workers are limited to 50 external subrequests and **1,000 to Cloudflare services** per
  invocation. R2 and DO calls are Cloudflare services.
- **Correction to D0.5**, which said 50 subrequests per invocation on Free for Workflows: that is
  the limit for _external_ fetches; R2 and Durable Object calls count against 1,000.
- **Decision:** each instance budgets 900 subrequests and 1,000 steps (`DEFAULT_BUDGET`, the Free
  limits less a margin, used on every plan). A page costs 2 (list, Sequencer), plus up to 21 with
  deep scrub. When the next page might not fit, the instance starts `<scanId>-p<n+1>` with
  `createBatch`, which is idempotent per ID (`create` throws if the ID exists, and the step may be
  retried), and ends. The new instance resumes from the Sequencer's cursor. A budget that cannot fit
  one page is rejected, so hand-offs always make progress.
- **Not measured:** whether a 1,000-object page fits in 10 ms of CPU on the Free plan (list
  parsing, RPC serialization, the merge in the DO is the DO's CPU, not the step's). Deep scrub is
  likely to exceed it. This is a §14 benchmark question (M7); the page size is a single constant.
- Steps retry 5 times with exponential backoff from 10 s, and time out after 15 minutes.

### D6.8 Deep scrub

- **Sampling:** an object is scrubbed if the first 32 bits of `SHA-256([scanId, key])` are below
  `DEEP_SCRUB_SAMPLE_RATE`, it is at most `DEEP_SCRUB_MAX_BYTES`, and the page has scrubbed fewer
  than 20. Deterministic per scan (a retried step picks the same objects), different across scans.
- **Read:** `get(key, {onlyIf: {etagMatches: <listed ETag>}})`. The docs say a failed precondition
  returns an `R2Object` without a body: the object changed since it was listed and is skipped, as
  is a deleted one. The body is piped into `crypto.DigestStream('SHA-256')`. A short read
  (`bytesWritten` differs from the object's size) fails the step instead of recording a wrong hash.
- **Records:** an `audit.observation` per object. `CONTENT_DRIFT` when the SHA-256 differs from the
  last _published_ observation of the same key **with the same ETag** (kept in a new `scrub_state`
  table, updated at commit like the `objects` view), or from the SHA-256 R2 stored at upload, if the
  uploader supplied one. R2 rejects an upload whose bytes do not match a supplied `sha256` (D2.11),
  so the second case can only be produced with a fake bucket; it is tested at the store level.
- **Default off** (`"0"`): it costs a Class B read and CPU per object. Throughput is an M7 question.

### D6.9 Entry schema changes (D1.6 said the `audit.*` shapes were provisional)

- `CONTENT_DRIFT` is a finding kind. `observed` and `expected` gain an optional `sha256`, which is
  required for `CONTENT_DRIFT` and forbidden for every other kind.
- `expected.seq` is required except for `CONTENT_DRIFT` against R2's stored checksum, which no log
  entry holds.
- Unchanged otherwise. Nothing has been published, so the change is free. The Go CLI does not
  validate the schema (it reads the few fields it acts on), so it needed no change for this.

### D6.10 Backfill

- `POST /api/v1/admin/backfill` runs the same Workflow in `backfill` mode: it lists the bucket and
  appends an `object.snapshot` (with `snapshotId` = the scan ID) for each object the log has
  **never named**. A key the log knows, even as deleted or with another ETag, is left to the
  auditor: snapshotting it would replace evidence of a divergence with a new baseline.
- A backfill writes no `audit.scan` entries and no report; the snapshots identify it.

### D6.11 Reports, the findings API, and `r2notary findings`

- **Report:** `x-reports/<scanId>.json` in the log bucket (counts, findings by kind, and the first
  10,000 findings as `{index, kind, key}`), written create-if-absent after the end entry is
  published, then the scan is marked done. Unlike tiles it is **not** a pure function of the log
  prefix (it has start and finish times and the number of dropped candidates), but it is built only
  from state that is fixed once the scan's end entry exists, so a retried write produces the same
  bytes. It is a convenience, not evidence, and the read path does not serve it (D4.5).
- **`GET /api/v1/findings[?after=&limit=]`** now returns the latest audit (`scan`, without its
  cursor, which is a key name), the published size, and its findings as `{index, published, entry}`.
  Findings of earlier scans are pruned from SQLite when a newer scan finishes; the log keeps them
  all. `/api/v1/status` gains `audit`, the latest audit's summary.
- **Go CLI `findings --log URL --vkey V --api URL`** (deferred in D5.5). Like `inclusion --api`, it
  takes only indexes from the API and proves each entry against the signed checkpoint, and it
  checks that each is an `audit.finding` of that scan. **It also compares the number of findings
  with the count in the scan's signed `audit.scan` end entry**, so the API cannot hide a finding of
  a finished scan. Plan deviation: the token comes from `$R2NOTARY_TOKEN` or `--token-file` (D5.5),
  not `--token`, and `--log`/`--vkey` are required, since a listing that is not proven is what
  `curl` already gives.

### D6.12 Starting scans; the webhook

- **Cron** (`0 */6 * * *`, already in `wrangler.jsonc`): the scan ID is `audit-cron-<scheduledTime>`,
  so a trigger delivered twice starts one instance. **Admin:** `POST /api/v1/admin/{scan,backfill}`
  answers 202 with the scan ID, or 409 with the active scan. Both check for an active scan first;
  the check is advisory and the Sequencer's start step is what enforces it.
- **Webhook** (`ALERT_WEBHOOK_URL`, optional secret): one POST per audit with findings, with counts,
  log indexes and the report key, **never key names** (the receiver may be a chat service). https
  only. Retried 3 times; a failure is logged and does not fail the scan (the findings are in the log
  either way). Delivery is at least once. wrangler's `secrets` config only has `required`, so the
  secret is undeclared and read defensively. Not verified: whether `wrangler dev` passes an
  undeclared secret from `.dev.vars` when `secrets.required` is set (the webhook is tested with an
  injected fetch).

### D6.13 Testing notes

- New suites: `reconcile` (pure, with the pagination property), `audit-store` (explicit clocks:
  lifecycle, page replay, grace, drops, drift, report, backfill), `audit-scan` (the driver: every
  finding kind with Unicode keys, crash at every step, hand-off, an event published during the grace
  window, deep scrub, alerts), `audit-workflow` (the real Workflow class), `scrub`,
  `r2-list-order`, and Go `findings`. The test pool sets `AUDIT_GRACE_SECONDS=0` and
  `DEEP_SCRUB_SAMPLE_RATE=1` (`worker/vitest.config.ts`), because the end-to-end tests cannot wait
  out a real window; unit tests pass both explicitly.
- **Conformance harness:** a new stage starts an audit through the admin API under `wrangler dev`
  (local Workflows). The local monitored bucket is empty, so every key the simulator left live must
  be a `MISSING_OBJECT`; the Go CLI proves each finding and matches the signed count, and the log
  must still extend the archived checkpoints. Run 2026-10-02: all 207 checks passed.
- **Mutation check:** each was broken on purpose and tests failed: UTF-16 comparison (9 failures
  across core and worker), confirmation ignoring the basis row (2), no page replay (3), scrub
  results applied twice (4), page end ignoring the log side (3), no grace on uploads (2), confirm
  without publishing first (1), backfill snapshotting known keys (2), listing without `startAfter`
  (9), drift ignoring the ETag (1), MISSING ignoring grace (2), PHANTOM only for re-created objects
  (2), and in Go, `findings` without the signed-count check (1).

### D6.14 Not done in M6

- **The real-R2 demo (PLAN M6, needs approval).** `docs/DEMO.md` has the runbook; nothing has been
  deployed or run remotely. Before it, D3.7's open questions must be answered with real events: in
  particular, if R2 URL-encodes keys in notifications, the auditor will report every such key as
  both `UNLOGGED_OBJECT` and `MISSING_OBJECT`.
- **Real-R2 contract runs:** conditional writes (D2.1) and list order / `startAfter` (D6.2, D6.3).
- **Measurements:** auditor objects/s, deep-scrub MB/s, CPU per page (M7, §14). No figure is
  claimed.
- Findings of scans before the latest are only in the log (and the reports), not in the API.

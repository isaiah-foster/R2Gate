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

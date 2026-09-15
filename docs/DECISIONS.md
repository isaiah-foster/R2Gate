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

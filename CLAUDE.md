# CLAUDE.md

R2Notary: a signed, tamper-evident Merkle-tree transparency log for Cloudflare R2 buckets (TS Worker +
core library, independent Go verifier). **`PLAN.md` is the source of truth** for scope, architecture,
milestones and acceptance criteria. Read it before writing code. Status and decisions: `docs/DECISIONS.md`.

The repo is public-facing and will be reviewed by R2 engineers. Quality bar: correctness, honest docs and
reproducible measurements, not feature count. The owner must be able to explain every design decision, so
record reasoning in `docs/DECISIONS.md`.

## Working agreements

1. **Verify before using.** Check current Cloudflare docs (PLAN §12) before using any API, config key or
   limit. If docs and PLAN.md disagree, follow the docs and log it in `docs/DECISIONS.md`.
2. **Milestone discipline.** Work through PLAN §9 in order. Every milestone ends with build, tests and lint
   passing, and a commit. Do not start the next milestone until acceptance criteria are met.
3. **Test-first for `packages/core`.** Write property/vector tests before the implementation.
4. **No remote side effects without asking.** Never run `wrangler deploy`, create remote R2 buckets/queues/
   workflows, set remote secrets, push, or do anything that costs money without explicit confirmation.
   Develop against local simulation. Put remote setup commands in `docs/OPERATIONS.md` and ask the human.
5. **No secrets in the repo.** `.dev.vars`, key files and `.wrangler/` stay gitignored. Committed config uses
   placeholder account IDs and bucket names.
6. **Never invent numbers.** Any performance or cost figure in README/docs/commits must come from
   `bench/results/`, with methodology in `docs/BENCHMARKS.md`. If a benchmark hasn't run, say so.
7. **Be honest about limits.** The README states what the system does _not_ protect against (PLAN §11).
8. **Original implementation.** Azul / Sunlight / Tessera are architecture inspiration only; write original
   code and credit them in the README. Do not copy source.
9. **Ask only when blocked.** Otherwise decide, record it in `docs/DECISIONS.md` (decision, alternatives,
   why), and continue.
10. The Go CLI must share **no code** with the TS writer.

## Commands

```sh
npm ci                       # install (Node >= 22)
npm test                     # vitest: packages/core (node) + worker (workerd, @cloudflare/vitest-plugin)
npm run lint                 # eslint, typescript-eslint strictTypeChecked
npm run typecheck            # tsc for root, packages/core, worker
npm run format:check         # prettier (npm run format to fix)
npx wrangler types           # run in worker/ after editing wrangler.jsonc
npm run dev:sim              # local wrangler dev: r2notary + dev-only event simulator (needs SIGNING_KEY)
npm run simulate -- --help   # send synthetic R2 notifications to dev:sim; compare /api/v1/status
npm run keygen -- --origin <LOG_ORIGIN> --out worker/.dev.vars   # local secrets (gitignored)
npm run conformance          # wrangler dev writer -> Go verifier, audit findings, corruption (~1 min)
npm run bench                # PLAN §14 benchmarks -> bench/results/*.json (local only; see docs/BENCHMARKS.md)
npm run bench:amplification  # one of: hashing proofs amplification cost sequencer latency auditor

cd cli && go vet ./... && go test ./...
cd cli && go run honnef.co/go/tools/cmd/staticcheck@2026.2.1 ./...   # what CI runs
```

## Layout

`packages/core` pure TS (no Workers APIs except WebCrypto) · `worker` Cloudflare Worker + Sequencer DO ·
`cli` Go verifier · `scripts` (`scripts/lib/dev.ts` runs wrangler dev for harnesses) · `bench` (Node
drivers; `worker/bench` runs inside workerd) · `bench/results` · `docs` (DESIGN, THREAT_MODEL,
DECISIONS, BENCHMARKS, OPERATIONS, DEMO). See PLAN §4 for the full target layout.

## Conventions and gotchas

- Tests import with explicit `.ts` extensions; TS is strict (`noUncheckedIndexedAccess`,
  `exactOptionalPropertyTypes`). Match surrounding style; run `npm run format` before committing.
- Test runner is `@cloudflare/vitest-plugin` (not the older `vitest-pool-workers`) and needs vitest 4.1.x;
  TypeScript is pinned to 6.0.x for typescript-eslint. Don't bump either without reading D0.1/D0.2.
- Config vars arrive as **strings** in `env`; parse them once at startup.
- After changing `worker/wrangler.jsonc`, re-run `npx wrangler types` in `worker/`.
- D0.5's constraints are resolved in M2: no `bundle_state` row (D2.2), and create-if-absent
  (`etagDoesNotMatch: '*'`) is pinned by a contract test that passes locally but has **not** run on
  real R2 yet (D2.1; `npm run test:contract:remote` is opt-in and billed). Ed25519 key handling is
  settled in D1.4 (PKCS#8-wrapped seed, Go `note`-compatible key strings).
- Test DO error paths by calling the instance inside `runInDurableObject`: a rejected RPC call on a
  stub is reported as an unhandled rejection by the test pool (D2.9). Worker tests get a fresh
  `SIGNING_KEY` per run from `worker/vitest.config.ts`.
- Every log resource except the live `checkpoint` is written create-if-absent and must stay a pure
  function of the log prefix; publication order and recovery rules are in `worker/src/publish.ts`.
- `packages/core` must type-check under both `@types/node` and the Workers types (the worker
  type-checks it through `@r2notary/core`). They disagree on some WebCrypto signatures (e.g.
  `exportKey`, `CryptoKey` as a type); check results at runtime instead of casting.
  `worker/test/core-runtime.test.ts` runs core's crypto inside workerd.
- Core is pure and deterministic: same state + same entries → byte-identical tiles, bundles and root.
  Crash-safe republication (M2) depends on this; don't add clocks or randomness to `packages/core`.
- Ingest (M3): one `Sequencer.ingest(items, report)` RPC per queue batch commits events and
  counters together; eventId is SHA-256 of a canonical JSON array, not a `|` join (D3.1). Unknown
  fields in R2 messages are ignored, documented ones are strict (D3.2). The test pool's
  `retryAll()` drops its options (D3.8). A Worker module may export only handlers/classes (workerd
  refuses plain constants), which tests don't catch; `npm run dev:sim` does.
- HTTP (M4): every response sets Cache-Control explicitly (errors/API `no-store`), so it stays
  correct if Workers Cache is enabled (D4.3). Private logs (default) need READ_TOKEN on all
  non-admin routes; admin checks its token before routing (D4.2). Negotiate encodings on
  `request.cf.clientAcceptEncoding`, not the rewritten header (D4.6). Tests that read only headers
  of an R2-backed 200 must `body.cancel()`, or `reset()` logs exceptions. Override typed vars in
  tests with `envWith()` (wrangler types vars as literals).
- Go CLI (M5): exit 1 = verification failure (`verr.Failure`, evidence), 4 = could not verify
  (`tilefetch.FetchError`, e.g. 404); keep that split when adding checks. Tiles are authenticated
  only through `tlog.TileHashReader`; `tlog.Tile.Path()` is not the tlog-tiles layout (use
  `tilefetch.TilePath`). Go tests build logs with `internal/testlog` (Go-only writer). The
  conformance harness passes secrets with `wrangler dev --env-file` (skips `.dev.vars`; process env
  is merged too, so it strips config keys from the child env, D5.7).
- Auditor (M6): scan state lives in the Sequencer (`worker/src/audit/store.ts`); each step is one
  synchronous transaction and is idempotent by page number / state, so a re-run step does nothing
  twice. The Workflow (`audit/scan.ts`) only drives it; keep control flow a function of step
  results (replay). Compare keys with core `compareUtf8`, never `<` (D6.2). List pages with
  `startAfter` only: Miniflare loops if `cursor` and `startAfter` are combined (D6.3). Findings are
  confirmed only if the key's `objects` row is unchanged after the grace window (D6.5). Worker
  tests run with `AUDIT_GRACE_SECONDS=0` and `DEEP_SCRUB_SAMPLE_RATE=1` (vitest.config.ts).
  `x-reports/` is create-if-absent but, unlike tiles, not a pure function of the log prefix (D6.11).
- Benchmarks (M7): every figure in README/docs must be copied from `bench/results/*.json`; if code
  on a measured path changes, re-run that benchmark rather than editing numbers. Time only from the
  driving Node process (workerd clocks move only on I/O). Operation counts come from wrapping
  binding prototypes inside the vitest isolate (`worker/bench/amplification.bench.ts`, D7.4). Never
  spawn timed child processes from a process holding a large heap (D7.5). All results are local;
  say so wherever they are quoted.
- Dev simulator (`worker/dev/simulator.ts`): `/__simulate/{send,objects,append}`, unauthenticated,
  never deployed. `objects` writes real local objects with or without a notification (the local
  stand-in for a disabled rule). `npm run dev:sim` persists to `.wrangler/state`.
- Commit trailer: end commits with the attribution line the harness specifies.

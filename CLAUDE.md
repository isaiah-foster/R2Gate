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

cd cli && go vet ./... && go test ./...
cd cli && go run honnef.co/go/tools/cmd/staticcheck@2026.2.1 ./...   # what CI runs
```

## Layout

`packages/core` pure TS (no Workers APIs except WebCrypto) · `worker` Cloudflare Worker + Sequencer DO ·
`cli` Go verifier · `scripts`, `bench/results`, `docs`. See PLAN §4 for the full target layout.

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
- Commit trailer: end commits with the attribution line the harness specifies.

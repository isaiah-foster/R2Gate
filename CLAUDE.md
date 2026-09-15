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
- Unresolved design constraints from the docs check are listed in `docs/DECISIONS.md` D0.5 (DO SQLite 2 MB
  row limit vs `bundle_state`; R2 `etagDoesNotMatch: '*'` unverified; Ed25519 keys import as PKCS8 only).
- Commit trailer: end commits with the attribution line the harness specifies.

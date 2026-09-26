# R2Notary

A verifiable, tamper-evident history for Cloudflare R2 buckets: every object change is recorded in a signed Merkle-tree transparency log that is stored in R2 itself, served as static tiles, and independently verifiable by a Go CLI.

> **Status: M5 (MVP: Go verifier and conformance).** `packages/core` implements RFC 6962 hashing and consistency proofs, C2SP `tlog-tiles` tile math, paths and entry bundles, canonical-JSON log entries, and `signed-note` / `tlog-checkpoint` signing with Ed25519 (WebCrypto). The `Sequencer` Durable Object durably appends entries with dedupe, and publishes tiles, bundles and signed checkpoints to R2 in a crash-safe order. A Queue consumer validates R2 event notifications, drops events from the log bucket itself, and appends the rest. The Worker serves the log at `/log/<name>/` with tlog-tiles headers, CORS and gzip for entry bundles, plus a JSON API (`status`, `lookup`, `findings`) and a bearer-protected admin API. With `PUBLIC_LOG=false` (the default), reads need a token. All of this is tested locally in workerd, and has run end to end under `wrangler dev` with synthetic events, with the served bytes verified independently. The Go CLI (`cli/`, no code shared with the writer) verifies checkpoints, inclusion and consistency from tiles, and monitors a log for rollbacks, forks and deletes under a protected prefix. A conformance harness runs the real Worker locally, verifies its log with the Go CLI, then flips bits in every published resource and requires the CLI to reject each one. Local only: nothing has run against real R2 or real event notifications yet, and the auditor arrives in M6 (see `PLAN.md` §9).

## What it will do

- **Ingest:** R2 event notifications → Cloudflare Queue → Worker → a single-writer Sequencer Durable Object.
- **Log:** an RFC 6962 Merkle tree published as C2SP `tlog-tiles` tiles and entry bundles in a second R2 bucket, with Ed25519 signed checkpoints (`tlog-checkpoint` + `signed-note`).
- **Verify:** a Go CLI checks checkpoint signatures and computes inclusion and consistency proofs locally from tiles. The server is never trusted for proofs.
- **Audit:** a resumable job reconciles real bucket contents against the log and records unlogged writes, missing objects and drift as findings in the log.

## Positioning

Cloudflare has already open-sourced **Azul**, a tiled Certificate Transparency log on Workers, Durable Objects and R2. R2Notary applies the same family of design (tiled logs, a single-threaded sequencer, R2 as the tile store) to a different problem: integrity and audit history of an R2 bucket. What is specific here is ingestion from R2 event notifications, a reconciliation auditor against live bucket state, and a cross-language (TypeScript writer / Go verifier) conformance harness. It makes no claim of novelty in the log design itself.

## Non-goals and limits

- Not an S3 proxy or gateway; nothing sits on the data path of the monitored bucket.
- Complements R2 bucket locks and lifecycle rules; it does not replace them.
- Does not prevent tampering; it makes it **detectable**.
- Does not defend against R2 itself being malicious, a compromised signing key, or split-view attacks (until witness cosigning exists).
- One sequencer per log: a throughput ceiling that will be measured and reported, not hidden.
- Public logs reveal object key names.

A full threat model will live in `docs/THREAT_MODEL.md`.

## Performance and cost

No benchmarks have been run yet. Every figure in this repo must come from `bench/results/`; until then, there are none.

## Development

Requires Node ≥ 22 and Go ≥ 1.26.

```sh
npm ci
npm test            # core (node) + worker (workerd via @cloudflare/vitest-plugin)
npm run lint
npm run typecheck
npm run format:check

npm run conformance # TS writer under wrangler dev -> Go verifier, plus corruption cases

cd cli && go vet ./... && go test ./...
```

### Local end to end

Local R2 does not emit event notifications, so a dev-only producer Worker
(`worker/dev/simulator.ts`) puts synthetic ones on the local queue:

```sh
npm run keygen -- --origin r2notary.example.com/log/example-log --out worker/.dev.vars
npm run dev:sim          # r2notary + the simulator in one wrangler dev process, port 8787
npm run simulate -- --count 400 --duplicates 0.2 --shuffle 30 --malformed 12 --loop 5
export READ_TOKEN=...    # from worker/.dev.vars (the log is private by default)
curl -s -H "Authorization: Bearer $READ_TOKEN" localhost:8787/api/v1/status
curl -s -H "Authorization: Bearer $READ_TOKEN" localhost:8787/log/example-log/checkpoint
```

The simulator prints the counters it expects (`accepted`, `duplicates`, `invalid`, ...); they
should match the change in `/api/v1/status`. Then verify the log with the Go CLI, using the vkey
that keygen printed (`cd cli && go build -o r2notary ./cmd/r2notary` first):

```sh
export R2NOTARY_TOKEN=$READ_TOKEN ADMIN_TOKEN=... VKEY='r2notary.example.com/log/example-log+...'
curl -s -X POST -H "Authorization: Bearer $ADMIN_TOKEN" localhost:8787/api/v1/admin/publish
./r2notary checkpoint --log http://localhost:8787/log/example-log --vkey "$VKEY" --out old.cp
./r2notary inclusion  --log http://localhost:8787/log/example-log --vkey "$VKEY" --index 0
./r2notary monitor    --log http://localhost:8787/log/example-log --vkey "$VKEY" --state mon.json --once
# after more events and a publish:
./r2notary consistency --log http://localhost:8787/log/example-log --vkey "$VKEY" --old old.cp
```

Exit codes: 0 ok, 1 verification failed (the log served data that does not verify), 2 usage,
3 negative answer (no such entry, or a `--watch` alert), 4 could not verify (network, HTTP). `npm run simulate` and `npm run keygen` run TypeScript directly, which needs
Node ≥ 22.18.

`npm run test:contract:remote` runs the R2 conditional-write contract against a real bucket. It is
opt-in and billed; see `docs/OPERATIONS.md`.

Design decisions, including where current Cloudflare docs differ from the plan, are recorded in `docs/DECISIONS.md`.

## Credits

Architecture inspired by Cloudflare's **Azul** CT log, **Sunlight**, **Trillian-Tessera**, and the Go checksum database (`sum.golang.org`), plus Russ Cox's "Transparent Logs for Skeptical Clients". This is an original implementation; no source was copied. Tests use published test vectors as data: RFC 6962 roots from `transparency-dev/merkle`, the C2SP `signed-note` and `tlog-checkpoint` examples, and the example key and signature from the `golang.org/x/mod/sumdb/note` documentation.

## License

MIT

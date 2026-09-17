# R2Notary

A verifiable, tamper-evident history for Cloudflare R2 buckets: every object change is recorded in a signed Merkle-tree transparency log that is stored in R2 itself, served as static tiles, and independently verifiable by a Go CLI.

> **Status: M1 (core library).** `packages/core` implements RFC 6962 hashing, C2SP `tlog-tiles` tile math, paths and entry bundles, canonical-JSON log entries, and `signed-note` / `tlog-checkpoint` signing and verification with Ed25519 (WebCrypto). It is tested against published RFC 6962 vectors, the tlog-tiles worked example, the signed-note spec example, and the Go `note` package's example signature. Nothing runs end to end yet: the sequencer, ingest, read path, verifier and auditor arrive in later milestones (see `PLAN.md` §9). This README will be updated as each lands.

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

cd cli && go vet ./... && go test ./...
```

Design decisions, including where current Cloudflare docs differ from the plan, are recorded in `docs/DECISIONS.md`.

## Credits

Architecture inspired by Cloudflare's **Azul** CT log, **Sunlight**, **Trillian-Tessera**, and the Go checksum database (`sum.golang.org`), plus Russ Cox's "Transparent Logs for Skeptical Clients". This is an original implementation; no source was copied. Tests use published test vectors as data: RFC 6962 roots from `transparency-dev/merkle`, the C2SP `signed-note` and `tlog-checkpoint` examples, and the example key and signature from the `golang.org/x/mod/sumdb/note` documentation.

## License

MIT

# R2Notary

A verifiable, tamper-evident history for Cloudflare R2 buckets: every object change is recorded in a
signed Merkle-tree transparency log that is stored in R2 itself, served as static tiles, and
independently verifiable by a Go CLI.

> **Status.** Milestones M0-M7 of `PLAN.md` are implemented and tested **locally**. Nothing has run
> on Cloudflare's network yet: no deployment, no real R2 event notifications, no real-R2 contract
> tests, and every benchmark figure is from a local simulation (see "Measured, locally" below). Those
> steps need a Cloudflare account and the owner's approval; they are written up in
> `docs/OPERATIONS.md` and `docs/DEMO.md`.

## How it works

```
 writers ──PUT/DEL──▶ R2 monitored bucket ──event notifications──▶ Queue (+ DLQ)
                              ▲                                       │
                              │ list / get (auditor)                  ▼
                     ┌────────┴──────────────────────────────────────────────────┐
                     │ Worker: queue consumer · read path · JSON/admin API ·     │
                     │         ScanWorkflow (auditor) · cron                     │
                     └────────┬─────────────────────────────────────┬────────────┘
                              ▼ RPC                                 │ get
                     Sequencer Durable Object ──tiles, bundles,──▶ R2 log bucket ◀── Go CLI /
                     (SQLite: order, dedupe,     checkpoints                          browsers
                      expected state)                                                 verify
```

- **Ingest:** R2 event notifications go through a Queue to a Worker, which validates them and
  appends them to a single-writer **Sequencer** Durable Object. Duplicates are dropped by event ID;
  events from the log bucket itself are never logged.
- **Log:** the Sequencer publishes an RFC 6962 Merkle tree as C2SP **tlog-tiles** (tiles and entry
  bundles) in a second R2 bucket and signs **checkpoints** (C2SP tlog-checkpoint / signed-note,
  Ed25519). Publication is crash-safe: every object except the live checkpoint is written
  create-if-absent and is a pure function of the log prefix, and the checkpoint is written last.
- **Verify:** the Go CLI (`cli/`, no code shared with the writer) checks the signature and computes
  inclusion and consistency proofs locally from tiles. The server is never trusted for a proof.
  `monitor` detects rollbacks and forks; `--watch PREFIX` alerts on deletes and overwrites.
- **Audit:** a resumable Workflow merge-joins the bucket listing with the log's expected state and
  records unlogged writes, missing objects and overwrites as signed findings, once a grace window
  shows no event explains them. Optional deep scrub hashes object bodies to catch content drift.

Details: `docs/DESIGN.md` (including "Questions a reviewer will ask"). Every decision and every
place where the current Cloudflare docs differed from the plan: `docs/DECISIONS.md`.

## What it does not do

- It does not **prevent** tampering; it makes it **detectable**. It is not a backup.
- It does not defend against a compromised signing key or Cloudflare account, beyond what monitors
  that saved earlier checkpoints can detect (rewritten history). It cannot see events such an
  attacker chooses not to log.
- It does not defend against R2 itself returning false data.
- No split-view protection until witness cosigning (planned, M8).
- Between an event and the next checkpoint, an entry is durable but not yet verifiable; a change
  whose notification is lost is found only by the next audit, after the grace window.
- Public logs reveal object key names, so logs are private by default.
- One sequencer per log is a throughput ceiling (measured locally, below; not on Cloudflare).
- Not an S3 proxy (nothing sits on the bucket's data path), and not a replacement for R2 bucket
  locks, which it complements.

The full threat model: `docs/THREAT_MODEL.md`.

## Quickstart: the whole story, locally

No Cloudflare account needed. Requires Node ≥ 22.18, Go ≥ 1.26 and git. Local R2 emits
no event notifications, so a dev-only simulator Worker writes objects to the local monitored bucket
and queues the notification R2 would send.

```sh
git clone https://github.com/isaiahfoster/r2notary.git && cd r2notary   # placeholder URL
npm ci
(cd cli && go build -o r2notary ./cmd/r2notary)

# Local secrets in worker/.dev.vars (gitignored), and a zero grace window so local audits do not
# wait five minutes.
npm run keygen -- --origin r2notary.example.com/log/example-log --out worker/.dev.vars
echo 'AUDIT_GRACE_SECONDS=0' >> worker/.dev.vars

npm run dev:sim     # terminal 1: Worker, Sequencer, queue, Workflow, simulator on :8787
```

In a second terminal, from the repository root:

```sh
export R2NOTARY_TOKEN=$(sed -n 's/^READ_TOKEN=//p' worker/.dev.vars)   # the log is private
export ADMIN_TOKEN=$(sed -n 's/^ADMIN_TOKEN=//p' worker/.dev.vars)
export VKEY=$(sed -n '/^# Verifier key/{n;s/^# //p;}' worker/.dev.vars)
export HOST=http://localhost:8787 LOG=http://localhost:8787/log/example-log
api() { curl -s -H "Authorization: Bearer $R2NOTARY_TOKEN" "$HOST/api/v1/$1"; echo; }
admin() { curl -s -X POST -H "Authorization: Bearer $ADMIN_TOKEN" "$HOST/api/v1/admin/$1"; echo; }

# 1. Write 300 objects; each notification is queued, ingested and published.
npm run simulate -- --objects --count 300
sleep 15 && api status              # "size": 300, "pending": 0

# 2. Verify, without trusting the server: signature, inclusion, a full monitor scan.
cli/r2notary checkpoint --log $LOG --vkey "$VKEY" --out before.cp
cli/r2notary inclusion  --log $LOG --vkey "$VKEY" --key demo/obj-1
cli/r2notary monitor    --log $LOG --vkey "$VKEY" --state mon.json --once -q

# 3. A clean audit: the bucket matches the log.
admin scan && sleep 5
cli/r2notary findings --log $LOG --vkey "$VKEY" --api $HOST      # 0 findings

# 4. Change the bucket behind the log's back (no notifications), then audit again.
curl -s $HOST/__simulate/objects -H 'content-type: application/json' -d '[
  {"op": "put", "key": "demo/unlogged", "text": "sneaky", "notify": false},
  {"op": "put", "key": "demo/obj-2", "text": "rewritten", "notify": false},
  {"op": "delete", "key": "demo/obj-3", "notify": false}]'; echo
admin scan && sleep 5
cli/r2notary findings --log $LOG --vkey "$VKEY" --api $HOST
# UNLOGGED_OBJECT demo/unlogged, ETAG_MISMATCH demo/obj-2, MISSING_OBJECT demo/obj-3, each proven
# against the signed log, and the count checked against the scan's signed end entry.

# 5. The log only grew: prove the new checkpoint extends the saved one.
cli/r2notary consistency --log $LOG --vkey "$VKEY" --old before.cp
cli/r2notary monitor     --log $LOG --vkey "$VKEY" --state mon.json --once -q

# 6. Tamper with the log itself: flip one bit of the first tile in local R2.
tile=example-log-bucket/example-log/tile/0/000
r2() { npx wrangler r2 object "$@" -c worker/wrangler.jsonc --local --persist-to .wrangler/state; }
r2 get $tile --file tile.orig
node -e "const f=require('fs'); const b=f.readFileSync('tile.orig'); b[100]^=1; f.writeFileSync('tile.bad', b)"
r2 put $tile --file tile.bad
cli/r2notary inclusion --log $LOG --vkey "$VKEY" --index 0; echo "exit $?"   # exit 1: verification failed
r2 put $tile --file tile.orig        # restore
cli/r2notary inclusion --log $LOG --vkey "$VKEY" --index 0 >/dev/null; echo "exit $?"   # exit 0
```

CLI exit codes: 0 ok, 1 verification failed (the log served something false), 2 usage, 3 negative
answer (no such entry, a `--watch` alert, no audit yet), 4 could not verify (network, HTTP). Stop
`npm run dev:sim` with Ctrl-C; its state is in `.wrangler/state` (delete it to start over).

Synthetic traffic with duplicates, reordering, malformed messages and loop events:
`npm run simulate -- --help`. The same demo against real R2 (with approval, billed):
`docs/DEMO.md`.

## Measured, locally

From `bench/results/` (methodology, environment and every caveat: `docs/BENCHMARKS.md`). One
laptop, local simulation of every Cloudflare service; operation counts are exact, timings are not
production figures.

|                                                                                             |                                                                               |
| ------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| Event → visible, 1,000 events at 25/s, `CHECKPOINT_INTERVAL_MS` = 1 s / 5 s / 15 s          | median 3.1 s / 5.0 s / 12.4 s (local queue; excludes R2's notification delay) |
| Sequencer, sustained appends + publication                                                  | about 3,000 entries/s (2,932-3,102 with 1-8 clients)                          |
| R2 Class A writes per published checkpoint                                                  | about 4 (1 entry) to 8.7 (500 entries)                                        |
| Durable Object rows written per event                                                       | about 11 at large batches, 28.8 at one entry per checkpoint                   |
| Bytes fetched by the Go CLI for an inclusion proof, 10⁶-entry log                           | 86,925 (7 requests), 75 % of it the entry bundle                              |
| Full audit, 10,000 objects (bucket matches the log)                                         | 795 ms median                                                                 |
| Deep scrub                                                                                  | 177 MB/s                                                                      |
| Modeled monthly cost of the write path at 5 s interval, list prices, 1M / 10M / 100M events | 24.93 / 140.97 / 1,246.27 USD, mostly Durable Object rows written             |

The cost figures are arithmetic over measured counts under a stated arrival model, and exclude
Durable Object duration and Workers CPU (`docs/BENCHMARKS.md` §7).

## Development

```sh
npm ci
npm test               # core (Node) + worker (workerd via @cloudflare/vitest-plugin)
npm run lint
npm run typecheck
npm run format:check
npm run conformance    # real Worker under wrangler dev -> Go verifier, plus corruption cases
npm run bench          # PLAN §14 benchmarks -> bench/results/ (docs/BENCHMARKS.md)

cd cli && go vet ./... && go test ./...
```

`npm run test:contract:remote` runs the R2 conditional-write and list-order contracts against a
real bucket; it is opt-in and billed (`docs/OPERATIONS.md`).

| Document               |                                                         |
| ---------------------- | ------------------------------------------------------- |
| `PLAN.md`              | Scope, milestones, acceptance criteria                  |
| `docs/DESIGN.md`       | Architecture, crash safety, auditor, reviewer questions |
| `docs/THREAT_MODEL.md` | What is and is not protected                            |
| `docs/DECISIONS.md`    | Every decision, alternative and docs discrepancy        |
| `docs/BENCHMARKS.md`   | Methodology and results                                 |
| `docs/OPERATIONS.md`   | Deploying, rotating keys, teardown, cost notes          |
| `docs/DEMO.md`         | The tamper demo on real R2                              |

## Positioning

Cloudflare has already open-sourced **Azul**, a tiled Certificate Transparency log on Workers,
Durable Objects and R2. R2Notary applies the same family of design (tiled logs, a single-threaded
sequencer, R2 as the tile store) to a different problem: integrity and audit history of an R2
bucket. What is specific here is ingestion from R2 event notifications, a reconciliation auditor
against live bucket state, deep scrubbing, and a cross-language (TypeScript writer / Go verifier)
conformance harness. It makes no claim of novelty in the log design itself.

## Credits

Architecture inspired by Cloudflare's **Azul** CT log, **Sunlight**, **Trillian-Tessera**, and the
Go checksum database (`sum.golang.org`), plus Russ Cox's "Transparent Logs for Skeptical Clients".
This is an original implementation; no source was copied. The Go verifier uses
`golang.org/x/mod/sumdb/tlog` and `note`. Tests use published test vectors as data: RFC 6962 roots
from `transparency-dev/merkle`, the C2SP `signed-note` and `tlog-checkpoint` examples, and the
example key and signature from the `golang.org/x/mod/sumdb/note` documentation.

## License

MIT

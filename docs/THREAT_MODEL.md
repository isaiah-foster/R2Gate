# Threat model

What R2Notary protects, against whom, and where it stops. This expands PLAN §11. Design details are
in `docs/DESIGN.md`; decisions referenced as `Dn.m` are in `docs/DECISIONS.md`.

## The short version

R2Notary makes changes to an R2 bucket **detectable after the fact** by anyone holding the log's
verifier key. It does not prevent changes, and it is not a backup. It is useful against people who
can write to the monitored bucket but cannot control the Cloudflare account that runs the log, and
against silent loss of notifications. Against someone who controls the whole account, it detects
rewritten history only if an independent monitor saved an earlier checkpoint, and it cannot see
what such an attacker chooses not to log from then on.

## Assets

| Asset                       | Where it lives                                | Why it matters                                   |
| --------------------------- | --------------------------------------------- | ------------------------------------------------ |
| Log entries and tiles       | Log bucket, `<LOG_NAME>/tile/...`             | The history itself                               |
| Signed checkpoints          | Log bucket, `checkpoint` and `x-checkpoints/` | Commit to a tree size and root                   |
| Signing key (`SIGNING_KEY`) | Worker secret                                 | Whoever holds it can sign any tree               |
| Key blinding secret         | Worker secret (`KEY_BLINDING_KEY`, M8)        | Turns blinded names back into key names by guess |
| Witness keys                | Each witness's secret (`WITNESS_KEY`)         | Cosigns that a checkpoint extends what it saw    |
| Sequencer state             | Durable Object SQLite                         | Dedupe window, expected object state, scan state |
| Admin and read tokens       | Worker secrets                                | Start scans and publications; read a private log |
| Object key names            | Every `object.*` and `audit.*` entry          | Can be sensitive (sharp edge 8)                  |

## Trust assumptions

1. **R2 stores and returns bytes faithfully, and is strongly consistent.** R2 is the substrate,
   not an adversary. A lying R2 could serve different tiles to different readers; signatures
   still bind every tile to a signed root, so it could not forge history, but it could withhold.
2. **R2 event notifications report what happened**, at least once, possibly late and out of
   order. They carry no content hash, and deletes carry no size or ETag (sharp edge 1).
3. **The Cloudflare account that runs the log is trusted at the time an entry is logged.** The
   Worker builds entries, the Sequencer assigns their order, and the signing key is a secret of the
   same account. Anyone who can deploy code or read secrets there can make the log say anything
   from that moment on.
4. **Verifiers obtain the vkey out of band** (documentation, a pinned file), not from the log.
5. **Verifiers trust no server output except signed checkpoints.** The Go CLI computes every
   proof from tiles and checks every tile and bundle against the signed root; `lookup` and
   `findings` results are indexes the CLI then proves (D5.1, D5.5, D6.11).

## Adversaries and what happens

| Adversary                                                                                      | Can                                             | Detected?                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| ---------------------------------------------------------------------------------------------- | ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Bucket writer** (S3 or binding credentials for the monitored bucket only)                    | Put, overwrite, copy, delete objects            | **Yes.** Every change produces a notification that becomes a signed, ordered log entry. The writer cannot reach the log bucket if their R2 token is scoped to the monitored bucket (recommended in `docs/OPERATIONS.md`).                                                                                                                                                                                                                                                                                                                                                                                                            |
| **Lost notifications** (rule deleted or misconfigured, queue retention expired, DLQ exhausted) | Changes happen with no event                    | **Yes, late.** The auditor reports `UNLOGGED_OBJECT`, `ETAG_MISMATCH`/`SIZE_MISMATCH`, `MISSING_OBJECT`, `PHANTOM_DELETE` once the change is older than the grace window and still unexplained (D6.4, D6.5). Not detected between scans, and not if the object was changed and changed back in between.                                                                                                                                                                                                                                                                                                                              |
| **Content changed under the same ETag** (storage-level corruption, or an R2 bug)               | Different bytes, same metadata                  | **Only for scrubbed objects.** Deep scrub hashes a sample of bodies and reports `CONTENT_DRIFT` (D6.8). Off by default; coverage equals the sample rate.                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| **Log-bucket writer without the signing key** (a leaked R2 token for the log bucket)           | Overwrite or delete tiles, bundles, checkpoints | **Yes.** Any flipped bit in a tile, bundle or checkpoint fails verification (I7, conformance harness). Deletion makes verification impossible (CLI exit 4), which is visible but not proof of tampering. The writer does not re-read what it published; it notices a changed object only if it writes that path again (a retried publication), and then fails loudly (`TILE_DIVERGENCE`, I4).                                                                                                                                                                                                                                        |
| **Account administrator / stolen signing key**                                                 | Sign any tree, deploy any code, delete the log  | **Partly.** Rewriting or truncating published history produces a checkpoint inconsistent with an earlier one: any monitor holding that earlier checkpoint detects it (`monitor` exits 1 on a fork or rollback, with both signed notes as evidence). Showing different logs to different readers (split view) is detected by readers that require cosignatures from witnesses not under the attacker's control (`--witness`, M8); a witness run by the same administrator does not help. Omitting future events, or stopping the log, is not detected by the log; a monitor sees only that it stops growing (no staleness alarm yet). |
| **Reader of a public log**                                                                     | Read every entry                                | Not an attack, but **key names leak** unless key blinding is on (M8, D8.8), and even then the change pattern, sizes, times and ETags (MD5 of single-part content) do not. Logs are private by default (`PUBLIC_LOG=false`, read token required on every non-admin route, D4.2).                                                                                                                                                                                                                                                                                                                                                      |
| **Holder of the read token**                                                                   | Read the log and the API                        | Cannot start scans or publications: admin routes accept only `ADMIN_TOKEN` (D4.2).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| **Network attacker** between verifier and log                                                  | Modify or drop responses                        | Modification fails verification; dropping is an outage (exit 4). The CLI drops `Authorization` on cross-host redirects (D5.5).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |

## What it detects

- History rewritten by anyone without the signing key (I7).
- History rewritten, truncated or forked by anyone **with** the key, provided a monitor kept an
  earlier checkpoint (I3, consistency proofs; `monitor` state, D5.6).
- Objects written, changed or deleted while notifications were disabled or lost, once the grace
  window has passed (auditor).
- Changed content of scrubbed objects whose ETag did not change.
- Deletes and overwrites under a protected prefix, for a `monitor --watch` user (D5.6).

## What it does not protect against

- **Compromise of the signing key** (or of the account): see the table. Detection then depends on
  external monitors, and only for history that was already published.
- **R2 itself returning false data** (assumption 1).
- **An attacker who controls both the log bucket and the signing key**: a special case of the
  above.
- **Split view** (different readers shown different, individually valid logs), unless readers
  require cosignatures from witnesses independent of the log's operator (M8). Without witnesses,
  monitors comparing checkpoints with each other would catch it; the CLI does not gossip. A witness
  stops cosigning a fork, but if the operator controls enough of the required witnesses, nothing
  stops it.
- **What blinding leaves visible** (M8): which entries concern the same object, their sizes, times
  and ETags. Anyone who can guess a file's exact content can confirm a single-part upload of it by
  its MD5 ETag, and anyone with the blinding secret can test guessed key names.
- **The window between an event and its publication.** An entry is durable when the queue
  message is acked and visible after the next checkpoint (`docs/BENCHMARKS.md` §1 has local
  measurements of that delay). Changes whose notification is lost are found only by the next audit,
  after `AUDIT_GRACE_SECONDS`.
- **Changes that are undone between two audits** while notifications are off. The auditor
  compares states, not histories.
- **Content changes without a scrub.** Events carry no content hash; single-part ETags are MD5 of
  the body, multipart ETags are not content hashes.
- **Availability.** Deleting the log bucket, the Worker or the Durable Object destroys or stops the
  log. That is visible, not prevented. Use R2 bucket locks on the log bucket for retention; R2Notary
  complements them (PLAN §2).

## Sharp edges (PLAN §11) and how each is handled

| #   | Sharp edge                                             | Handling                                                                                                                                                         |
| --- | ------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Events lack content hashes; deletes lack size and ETag | Entries log what R2 sends; the schema forbids size/ETag on deletes (D1.6, D3.2). Content is checked only by deep scrub.                                          |
| 2   | Queues are at-least-once, unordered; short retention   | Dedupe by `eventId` (I5, D3.1); log order is ingestion order, each entry keeps `eventTime`; the Worker consumes its own DLQ (D3.5); the auditor is the backstop. |
| 3   | Local dev emits no R2 events                           | Dev simulator (D3.6, extended in M7); real-event questions are open (D3.7).                                                                                      |
| 4   | Conditional puts must really be create-only            | Contract test, passing locally, **not yet run on real R2** (D2.1).                                                                                               |
| 5   | A DO can be evicted anywhere                           | Entries are durable before ack; publication is a pure function of durable state and is crash-tested at every step (I6, D2.9).                                    |
| 6   | Entry limit 65,535 bytes; keys up to 1,024 bytes       | Worst-case entry tested to fit (D1.6).                                                                                                                           |
| 7   | Scan limits                                            | Budgeted Workflow steps with hand-off to a new instance (D6.7).                                                                                                  |
| 8   | Public logs leak key names                             | Private by default; webhook payloads never contain key names (D6.12); optional key blinding (M8, D8.8).                                                          |
| 9   | Single sequencer is a throughput ceiling               | Measured locally (`docs/BENCHMARKS.md` §2); not measured on Cloudflare.                                                                                          |
| 10  | Never monitor the log bucket                           | Three layers: config validation, consumer drop, Sequencer check (I8, D3.3).                                                                                      |
| 11  | Tile and bundle formats are spec-fixed                 | Not changed.                                                                                                                                                     |
| 12  | Per-queue throughput is finite                         | 5,000 messages/s per queue (D0.5). One queue per deployment.                                                                                                     |

## Open questions that affect the model

- **Real notification payloads** (D3.7): whether keys are URL-encoded, whether ETags are ever
  quoted. If keys are encoded, the auditor would report every such key as both unlogged and missing.
  Must be answered on real R2 before relying on audits.
- **Create-only puts on real R2** (D2.1) and **list order / `startAfter` on real R2** (D6.2, D6.3).
  Both pass locally; both have opt-in remote contract tests that have not been run.
- **Key rotation** has no cross-key verification path in the CLI yet (`docs/OPERATIONS.md`, D7.9).
- **Witness freshness:** cosignature times could show a log that stopped growing, but the log asks
  witnesses only when it publishes, so an idle log's cosignatures age honestly (D8.7).

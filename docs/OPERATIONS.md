# Operations

Commands that touch real Cloudflare resources. **None of these have been run yet.** Each one
creates, modifies or bills for something in a Cloudflare account, so the repository owner runs or
approves them (PLAN §0, working agreement 4). Flags were checked against `wrangler` 4.147.0
`--help` and the Cloudflare docs on 2026-10-02/03. Bucket, queue and host names are the committed
placeholders; use your own and keep them out of commits.

Order for a first deployment: §1 resources → §2 contract tests → §3 secrets → §4 deploy → §5
backfill and first audit. §8 and §9 are for later.

## Which plan

Everything used exists on the Workers Free plan, with limits that matter here: Queues allow 10,000
operations a day (each message is 3: write, read, delete), so roughly 3,300 events a day; Workflows
give a step 10 ms of CPU, which a 1,000-object audit page may or may not fit (not measured on
Cloudflare, DECISIONS D6.7); Durable Objects allow 100,000 rows written a day, and each logged
event costs about 11 (`docs/BENCHMARKS.md` §3). Anything beyond a demo needs Workers Paid (5 USD a
month base; usage pricing in §10).

## 1. Resources: buckets, queues, notification rule (M3)

1. Log in (interactive, opens a browser): `npx wrangler login`
2. The two buckets, if the monitored one does not exist yet:
   `npx wrangler r2 bucket create example-monitored-bucket`
   `npx wrangler r2 bucket create example-log-bucket`
3. `npx wrangler queues create r2notary-events`
4. `npx wrangler queues create r2notary-events-dlq`
   (free plan: retention is fixed at 24 h, so a dead-lettered message not consumed within a day is
   lost. The Worker consumes the DLQ itself; see DECISIONS D3.5.)
5. One rule for both event types, on the **monitored** bucket only:
   `npx wrangler r2 bucket notification create example-monitored-bucket --event-type object-create --event-type object-delete --queue r2notary-events --description r2notary`
   Never create a rule on the log bucket: the consumer drops such events (I8), but each one still
   costs a queue message. R2 rejects overlapping rules and allows at most 100 per bucket.

Put the real bucket names in `worker/wrangler.jsonc` (`r2_buckets`, `MONITORED_BUCKET_NAME`,
`LOG_BUCKET_NAME`) and the real origin in `LOG_ORIGIN` (`<host>/log/<LOG_NAME>`, no scheme, no
trailing slash). The origin is signed into every checkpoint and cannot change later without starting
a new log (D4.1).

After the first real events arrive, check them against DECISIONS D3.7 (key encoding, ETag quoting,
field set) and record the result there. **If R2 URL-encodes keys in notifications, stop before
running audits** (see `docs/THREAT_MODEL.md`, open questions).

## 2. R2 contract tests (M2 and M6, not yet run remotely)

Two R2 behaviours are pinned by contract tests that pass against local R2 and must also pass
against real R2 before the log is trusted there:

- publication relies on `put(key, data, { onlyIf: { etagDoesNotMatch: '*' } })` meaning "create
  only if absent" (DECISIONS D2.1); the Workers API reference does not define `'*'`;
- the auditor relies on `list()` returning keys in UTF-8 byte order and on `startAfter`
  (DECISIONS D6.2, D6.3); `startAfter` is not in the Workers API reference.

Counted from the test code, the run issues 66 PUTs (some deliberately rejected), about 57 LISTs,
8 GET/HEADs and a handful of DELETEs on one bucket, and deletes what it wrote. Use a dedicated,
empty bucket.

1. Create a test bucket: `npx wrangler r2 bucket create r2notary-contract-test`
2. Put that name in `worker/test-remote/wrangler.remote.jsonc` (`bucket_name`). Do not commit it.
3. Run: `npm run test:contract:remote`
4. Record the result (date, wrangler version, pass/fail per case) in `docs/DECISIONS.md` D2.1
   and D6.2.
5. Remove the bucket when done: `npx wrangler r2 bucket delete r2notary-contract-test`

`R2_CONTRACT_LOCAL=1 npm run test:contract:remote` runs the same harness against local R2 with no
network access; use it to check the setup first.

If the conditional-write cases fail: switch `CREATE_ONLY` in `worker/src/publish.ts` to the
`If-None-Match: *` `Headers` form if that case passes, otherwise stop and redesign (a silent
overwrite would break I4). If the list-order cases fail, do not run the auditor against that
bucket: its merge-join would report false findings (see DECISIONS D6.3 for the fallback).

## 3. Secrets (M4)

Generate them locally, then put each one. The values never go in the repository.

1. `npm run keygen -- --origin r2notary.example.com/log/example-log --out r2notary.secrets`
   (use the real `LOG_ORIGIN`; the file is created mode 0600 and must not be committed)
2. For each of `SIGNING_KEY`, `ADMIN_TOKEN` and `READ_TOKEN`:
   `npx wrangler secret put <NAME> -c worker/wrangler.jsonc` and paste the value.
   `READ_TOKEN` is only used when `PUBLIC_LOG` is `"false"` (the committed default).
   Optional: `ALERT_WEBHOOK_URL` (https only; receives counts and log indexes, never key names).
3. Publish the vkey (the comment line in the file) wherever clients will find it, then delete the
   file or move it to a password manager.

`wrangler secret put` deploys a new version of the Worker immediately (Workers secrets docs). Before
the first deploy (§4) it creates the Worker with the secret; that is expected.

Locally, `--out worker/.dev.vars` does the same for `wrangler dev` (`.dev.vars` is gitignored).

## 4. Deploy

`npx wrangler deploy -c worker/wrangler.jsonc` creates or updates the Worker, the `Sequencer`
Durable Object class (declared through `exports`, D0.3: if the deploy rejects that form, fall back to
a `migrations` entry with `new_sqlite_classes`), the `r2notary-scan` Workflow, the queue consumers
and the cron trigger. Never deploy `worker/dev/wrangler.simulator.jsonc`: the simulator has no
authentication and can append to the log.

Check it: `curl -s -H "Authorization: Bearer $READ_TOKEN" https://<host>/api/v1/status` shows
`size: 0`, then grows as events arrive. With a custom domain, route `<host>/*` to the Worker so the
log is served at `https://<host>/log/<LOG_NAME>/`, matching `LOG_ORIGIN`.

A deploy restarts Durable Objects (DO lifecycle docs). The Sequencer keeps nothing in memory that is
not in SQLite, so a restart, including one in the middle of a publication, is the crash case
publication is designed for (I6).

## 5. Backfill and the auditor (M6)

The `r2notary-scan` Workflow is created by `wrangler deploy`; there is no separate create command.

- **Backfill first.** On a bucket that already has objects, run a backfill once before the first
  audit; otherwise every pre-existing object is an `UNLOGGED_OBJECT`:
  `curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" https://<host>/api/v1/admin/backfill`.
  `/api/v1/status` shows its progress under `backfill`.
- **Schedule:** the cron trigger (`0 */6 * * *`) starts an audit unless one is running.
- **By hand:** `curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" https://<host>/api/v1/admin/scan`.
  The answer is 202 with the scan ID, or 409 with the scan in progress.
- **Watch it:** `/api/v1/status` (`audit`), or `npx wrangler workflows instances list r2notary-scan`
  and `npx wrangler workflows instances describe r2notary-scan <scanId>` (a large bucket hands off
  to `<scanId>-p1`, `-p2`, ...).
- **Findings:** `r2notary findings --log https://<host>/log/<name> --vkey "$VKEY" --api https://<host>`
  proves each finding and checks the count against the scan's signed end entry.
- **Grace window:** `AUDIT_GRACE_SECONDS` (default 300) must exceed the time from a write to its
  notification being published in the log, including queue retries; otherwise in-flight changes
  become findings. Every audit takes at least this long after its last page.
- **Deep scrub** is off (`DEEP_SCRUB_SAMPLE_RATE="0"`). Each scrubbed object is a Class B read and
  CPU time; on the Free plan a Workflow step has 10 ms of CPU, which hashing will likely exceed.

Cost per audit: one Class A `list` per page of up to 1,000 objects, plus Durable Object requests
for each page and confirmation batch, plus Workflow steps. Local throughput is in
`docs/BENCHMARKS.md` §6; nothing has been measured on Cloudflare.

The tamper demo that exercises all of this against real R2 is `docs/DEMO.md`.

## 6. Access: scope the tokens

- Give writers of the monitored bucket **R2 API tokens scoped to that bucket only** (Object Read &
  Write on one bucket). They then cannot touch the log bucket, which is what makes R2Notary's
  record of their changes independent of them (`docs/THREAT_MODEL.md`).
- Nobody but this Worker needs write access to the log bucket. Readers use the read path.
- Consider R2 bucket locks on the log bucket: they "prevent the deletion and overwriting of
  objects" for a period or indefinitely (R2 docs), which R2Notary alone cannot do (it only detects
  it). Rules are per prefix. The live `<LOG_NAME>/checkpoint` is overwritten on every publication,
  so lock `<LOG_NAME>/tile/` and `<LOG_NAME>/x-checkpoints/`, never the whole prefix. Not tried on a
  real bucket.

## 7. Caching a public log (optional, not enabled)

For `PUBLIC_LOG="true"`, Workers Cache can serve tiles and bundles at the edge without running the
Worker or reading R2: add `"cache": { "enabled": true }` to `worker/wrangler.jsonc` (DECISIONS
D4.3). Every response already states its caching: immutable resources for a year, the checkpoint
for 2 s, errors and API answers never.

**Before switching a cached log from public to private, purge the Worker's cache.** Cached
immutable resources would otherwise keep being served without a token. Requests with an
`Authorization` header always bypass the cache, so a log that has always been private is
unaffected.

## 8. Rotating keys and tokens

**Tokens** (`ADMIN_TOKEN`, `READ_TOKEN`): generate a new value (`npm run keygen` prints fresh
ones, or 32 random bytes as base64url), `npx wrangler secret put <NAME> -c worker/wrangler.jsonc`,
then hand it to the clients. The old value stops working when the new version is live.

**The signing key** is a trust event for every verifier, so plan it:

1. Save the last checkpoint signed by the old key:
   `r2notary checkpoint --log $LOG --vkey "$OLD_VKEY" --out last-old-key.cp`
2. Generate a key **with the same name** (the origin), and keep only its `SIGNING_KEY` line:
   `npm run keygen -- --origin <LOG_ORIGIN> --out new.secrets`
3. `npx wrangler secret put SIGNING_KEY -c worker/wrangler.jsonc`. This deploys a new version and
   restarts the Sequencer, which loads the new key. The next checkpoint is signed with it. A
   publication interrupted across the switch is safe: archived checkpoints are compared by signed
   text, not signature bytes (D2.5).
4. Publish the new vkey, with the date and the size of `last-old-key.cp`.

**Known gap (D7.9):** the Go CLI takes one `--vkey`. After a rotation, a monitor's saved state is
signed by the old key and will not load with the new one, and `consistency --old last-old-key.cp`
cannot verify across the two keys. Monitors must start new state with the new key. Proving that the
new key's tree extends the old key's checkpoint needs a CLI that accepts both keys (Go's
`note.VerifierList` supports it); not done yet.

If the key **leaked**, rotation does not undo anything already signed: the old key can sign forks of
the past. Treat checkpoints published by the old key after the leak as untrusted, and rely on
monitors that saved earlier checkpoints (`docs/THREAT_MODEL.md`).

## 9. Teardown

Deleting the log destroys the history it exists to keep. Export what you need first (the log bucket
is a set of plain files; any tlog-tiles client can read a copy).

1. Stop new events: `npx wrangler r2 bucket notification delete example-monitored-bucket --queue r2notary-events`
2. Let the queue drain (`/api/v1/status`: `pending` 0), then publish anything left:
   `curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" https://<host>/api/v1/admin/publish`
3. The Sequencer's data: a Durable Object namespace declared through `exports` is deleted by
   deploying a tombstone (`"Sequencer": { "type": "durable-object", "state": "deleted" }`) after
   removing the class and its binding. The docs warn this is permanent with no trash. They do not
   say what `wrangler delete` alone does to DO storage, so do not rely on it.
4. `npx wrangler workflows delete r2notary-scan` (deletes its instances too)
5. `npx wrangler delete -c worker/wrangler.jsonc`
6. `npx wrangler queues delete r2notary-events` and `npx wrangler queues delete r2notary-events-dlq`
7. Buckets: R2 deletes only empty buckets ("To delete a bucket, you must first empty it", R2
   docs). Empty the log bucket (dashboard, or a lifecycle rule), then
   `npx wrangler r2 bucket delete example-log-bucket`. The monitored bucket is yours; R2Notary never
   writes to it.
8. Secrets go with the Worker. Revoke any R2 API tokens created for §6.

## 10. Cost notes

`docs/BENCHMARKS.md` §7 (`bench/results/cost.json`) estimates the write path's monthly cost from
measured operation counts and the list prices of October 2026, for 1M, 10M and 100M events a month.
Three things drive it:

- **Durable Object rows written** dominate: about 11 billed rows per event at large batches, more at
  small ones (`bench/results/amplification.json`).
- **R2 Class A** writes are per publication (about 4 at one entry per checkpoint), so a longer
  `CHECKPOINT_INTERVAL_MS` costs fewer of them at the price of later visibility.
- **R2 storage** grows by the partial bundle written with every checkpoint, which is kept (D4.5); at
  small batches that is far more than the entries themselves.

Not estimated: Durable Object duration, Workers CPU, Workflow steps, and reads by verifiers (Class
B, or nothing with Workers Cache on a public log). Check current prices before relying on any of it.

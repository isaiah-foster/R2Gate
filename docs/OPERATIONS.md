# Operations

Commands that touch real Cloudflare resources. **None of these have been run yet.** Each one
creates, modifies or bills for something in a Cloudflare account, so the repository owner runs or
approves them (PLAN §0, working agreement 4). This file grows with each milestone; deployment,
key rotation and teardown are written up in M7.

## R2 contract tests (M2 and M6, not yet run remotely)

Two R2 behaviours are pinned by contract tests that pass against local R2 and must also pass
against real R2 before the log is trusted there:

- publication relies on `put(key, data, { onlyIf: { etagDoesNotMatch: '*' } })` meaning "create
  only if absent" (DECISIONS D2.1); the Workers API reference does not define `'*'`;
- the auditor relies on `list()` returning keys in UTF-8 byte order and on `startAfter`
  (DECISIONS D6.2, D6.3); `startAfter` is not in the Workers API reference.

Counted from the test code, the run issues 66 PUTs (some deliberately rejected), about 57 LISTs,
8 GET/HEADs and a handful of DELETEs on one bucket, and deletes what it wrote. Use a dedicated,
empty bucket.

1. Log in (interactive, opens a browser): `npx wrangler login`
2. Create a test bucket (billed per R2 pricing; the name is a placeholder):
   `npx wrangler r2 bucket create r2notary-contract-test`
3. Put that name in `worker/test-remote/wrangler.remote.jsonc` (`bucket_name`). Do not commit it.
4. Run: `npm run test:contract:remote`
5. Record the result (date, wrangler version, pass/fail per case) in `docs/DECISIONS.md` D2.1
   and D6.2.
6. Remove the bucket when done: `npx wrangler r2 bucket delete r2notary-contract-test`

`R2_CONTRACT_LOCAL=1 npm run test:contract:remote` runs the same harness against local R2 with no
network access; use it to check the setup first.

If the conditional-write cases fail: switch `CREATE_ONLY` in `worker/src/publish.ts` to the
`If-None-Match: *` `Headers` form if that case passes, otherwise stop and redesign (a silent
overwrite would break I4). If the list-order cases fail, do not run the auditor against that
bucket: its merge-join would report false findings (see DECISIONS D6.3 for the fallback).

## Event ingestion: queues and notification rule (M3, not yet run)

The consumer in `worker/wrangler.jsonc` reads `r2notary-events` and its dead-letter queue
`r2notary-events-dlq`. Both queues, and the R2 rule that feeds the first one, must exist before a
deploy. Flags below were checked against `wrangler` 4.147.0 `--help` and the R2
event-notification docs (2026-10-02). Bucket names are the committed placeholders.

1. `npx wrangler queues create r2notary-events`
2. `npx wrangler queues create r2notary-events-dlq`
   (free plan: retention is fixed at 24 h, so a dead-lettered message that is not consumed within
   a day is lost. The Worker consumes the DLQ itself; see DECISIONS D3.5.)
3. One rule for both event types, on the **monitored** bucket only:
   `npx wrangler r2 bucket notification create example-monitored-bucket --event-type object-create --event-type object-delete --queue r2notary-events --description r2notary`
   Never create a rule on the log bucket: the consumer drops such events (I8), but each one still
   costs a queue message. R2 rejects overlapping rules and allows at most 100 per bucket.

Queues and notifications are billed per operation (check current Queues pricing). After the first
real events arrive, check them against DECISIONS D3.7 (key encoding, ETag quoting, field set) and
record the result there.

## Secrets (M4, not yet run)

Generate them locally, then put each one. The values never go in the repository.

1. `npm run keygen -- --origin r2notary.example.com/log/example-log --out r2notary.secrets`
   (use the real `LOG_ORIGIN`; the file is created mode 0600 and must not be committed)
2. For each of `SIGNING_KEY`, `ADMIN_TOKEN` and `READ_TOKEN`:
   `npx wrangler secret put <NAME> -c worker/wrangler.jsonc` and paste the value.
   `READ_TOKEN` is only used when `PUBLIC_LOG` is `"false"` (the committed default).
3. Publish the vkey (the comment line in the file) wherever clients will find it, then delete the
   file or move it to a password manager.

Locally, `--out worker/.dev.vars` does the same for `wrangler dev` (`.dev.vars` is gitignored).

## Caching a public log (optional, not enabled)

For `PUBLIC_LOG="true"`, Workers Cache can serve tiles and bundles at the edge without running the
Worker or reading R2: add `"cache": { "enabled": true }` to `worker/wrangler.jsonc` (DECISIONS
D4.3). Every response already states its caching: immutable resources for a year, the checkpoint
for 2 s, errors and API answers never.

**Before switching a cached log from public to private, purge the Worker's cache.** Cached
immutable resources would otherwise keep being served without a token. Requests with an
`Authorization` header always bypass the cache, so a log that has always been private is
unaffected.

## The auditor (M6, not yet run remotely)

The `r2notary-scan` Workflow is declared in `worker/wrangler.jsonc` and is created by
`wrangler deploy`; there is no separate create command. Once deployed:

- **Schedule:** the cron trigger (`0 */6 * * *`) starts an audit unless one is running.
- **By hand:** `curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" https://<host>/api/v1/admin/scan`
  (or `/backfill`). The answer is 202 with the scan ID, or 409 with the scan in progress.
- **Watch it:** `npx wrangler workflows instances list r2notary-scan` and
  `npx wrangler workflows instances describe r2notary-scan <scanId>` (a large bucket hands off to
  `<scanId>-p1`, `-p2`, ...). `/api/v1/status` shows the latest audit's progress.
- **Findings:** `r2notary findings --log https://<host>/log/<name> --vkey "$VKEY" --api https://<host>`
  proves each finding and checks the count against the scan's signed end entry.
- **Backfill first.** On a bucket that already has objects, run a backfill once before the first
  audit; otherwise every pre-existing object is an `UNLOGGED_OBJECT`.
- **Webhook (optional):** `npx wrangler secret put ALERT_WEBHOOK_URL -c worker/wrangler.jsonc`
  (https only). It receives counts and log indexes, never key names.
- **Grace window:** `AUDIT_GRACE_SECONDS` (default 300) must exceed the time from a write to its
  notification being published in the log, including queue retries; otherwise in-flight changes
  become findings. Every audit takes at least this long after its last page.
- **Deep scrub** is off (`DEEP_SCRUB_SAMPLE_RATE="0"`). Each scrubbed object is a Class B read and
  CPU time; on the Workers Free plan a step has 10 ms of CPU, which hashing will likely exceed.

Cost per audit: one Class A `list` per page of up to 1,000 objects, plus Durable Object requests
for each page and confirmation batch, plus Workflow steps. Not measured yet (PLAN §14, M7).

The tamper demo that exercises all of this against real R2 is `docs/DEMO.md`.

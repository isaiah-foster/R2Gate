# Demo

A walkthrough against **real R2**: log a bucket's changes, verify them with the Go CLI, then change
the bucket behind the log's back and let the auditor find it.

> **Status: not yet run.** Every step below creates, changes or bills for resources in a Cloudflare
> account, so the repository owner runs it or approves it (PLAN §0, working agreement 4). When it
> has run, the date, wrangler version and the output of each "Record" step go here.
>
> The same story runs locally with no account: the README quickstart (dev simulator instead of real
> notifications, local R2 instead of real R2). That version was run from a clean copy of the
> repository on 2026-10-03 and behaved as described there (DECISIONS D7.10).

Commands were checked against `wrangler` 4.147.0 `--help` on 2026-10-03. Bucket, queue and host
names are the committed placeholders; use your own.

## 0. Prerequisites

- Everything in `docs/OPERATIONS.md` up to and including the auditor section: both buckets, the
  queues and the notification rule, the secrets, and **both R2 contract tests passing against real
  R2** (conditional writes and list order). If the list-order contract fails, stop: the auditor
  would report false findings.
- The Worker deployed (`npx wrangler deploy -c worker/wrangler.jsonc`) and reachable at `$HOST`.
- The Go CLI built (`cd cli && go build -o r2notary ./cmd/r2notary`), and:

```sh
export HOST=https://r2notary.example.com LOG=$HOST/log/example-log
export VKEY='r2notary.example.com/log/example-log+...'    # printed by npm run keygen
export R2NOTARY_TOKEN=...  ADMIN_TOKEN=...                # READ_TOKEN and ADMIN_TOKEN
export B=example-monitored-bucket
auth=(-H "Authorization: Bearer $ADMIN_TOKEN")
```

## 1. Log ordinary writes

```sh
for i in $(seq 1 300); do   # 300, so that step 5 has a full tile to corrupt
  echo "object $i" > /tmp/obj.txt
  npx wrangler r2 object put "$B/demo/obj-$i" --file /tmp/obj.txt --remote
done
echo special > /tmp/special.txt
npx wrangler r2 object put "$B/demo/with space/é+%.txt" --file /tmp/special.txt --remote
```

Wait for the events to be published (`curl -s -H "Authorization: Bearer $R2NOTARY_TOKEN"
$HOST/api/v1/status` shows `size` of at least 301 and `pending` 0), then:

```sh
./r2notary checkpoint --log $LOG --vkey "$VKEY" --out before.cp
./r2notary inclusion  --log $LOG --vkey "$VKEY" --key demo/obj-1
./r2notary inclusion  --log $LOG --vkey "$VKEY" --key 'demo/with space/é+%.txt'
./r2notary monitor    --log $LOG --vkey "$VKEY" --state mon.json --once -q
```

**Record:** the `inclusion` output for the special key. This answers DECISIONS D3.7: if R2
URL-encodes keys in notifications, the key is logged as `demo/with%20space/...` and the second
`inclusion` finds nothing. In that case stop here; the auditor would report that key as both
unlogged and missing until ingest decodes keys.

## 2. A clean audit

```sh
curl -s -X POST "${auth[@]}" $HOST/api/v1/admin/scan        # 202 {"scanId": ...}
```

Wait until `/api/v1/status` shows `audit.state` = `done` (at least `AUDIT_GRACE_SECONDS` after the
listing finishes). Then:

```sh
./r2notary findings --log $LOG --vkey "$VKEY" --api $HOST
```

**Expected:** 0 findings, and "the signed end entry ... confirms the count".

## 3. Change the bucket behind the log's back

Disable the notification rule, make three changes, re-enable it:

```sh
npx wrangler r2 bucket notification delete $B --queue r2notary-events
echo sneaky > /tmp/sneaky.txt
npx wrangler r2 object put "$B/demo/unlogged" --file /tmp/sneaky.txt --remote   # new object
echo "rewritten 2" > /tmp/obj.txt
npx wrangler r2 object put "$B/demo/obj-2" --file /tmp/obj.txt --remote        # overwrite
npx wrangler r2 object delete "$B/demo/obj-3" --remote                          # delete
npx wrangler r2 bucket notification create $B --event-type object-create --event-type object-delete --queue r2notary-events --description r2notary
```

Wait longer than `AUDIT_GRACE_SECONDS` (300 s by default), so the changes are outside the grace
window, then run a scan as in step 2.

## 4. What the auditor found

```sh
./r2notary findings --log $LOG --vkey "$VKEY" --api $HOST
./r2notary consistency --log $LOG --vkey "$VKEY" --old before.cp
./r2notary monitor --log $LOG --vkey "$VKEY" --state mon.json --once
```

**Expected:** three proven findings of the new scan, `UNLOGGED_OBJECT demo/unlogged`,
`ETAG_MISMATCH demo/obj-2` and `MISSING_OBJECT demo/obj-3`, with the count confirmed by the
scan's signed end entry. The log is consistent with `before.cp`, and the monitor prints the
scan's entries. The report is in the log bucket at `example-log/x-reports/<scanId>.json`.

**Record:** the `findings` output, the scan ID, and the time from starting the scan to `done`.

## 5. Tamper with the log, and catch it

Someone with write access to the log bucket (but not the signing key) changes one bit of a
published tile. Keep the original to restore it:

```sh
tile=example-log-bucket/example-log/tile/0/000
npx wrangler r2 object get $tile --remote --file tile.orig
node -e "const f=require('fs'); const b=f.readFileSync('tile.orig'); b[100]^=1; f.writeFileSync('tile.bad', b)"
npx wrangler r2 object put $tile --remote --file tile.bad
./r2notary inclusion --log $LOG --vkey "$VKEY" --index 0; echo "exit $?"           # exit 1
./r2notary monitor --log $LOG --vkey "$VKEY" --state fresh.json --once -q; echo "exit $?"   # exit 1
npx wrangler r2 object put $tile --remote --file tile.orig                           # restore
./r2notary inclusion --log $LOG --vkey "$VKEY" --index 0 > /dev/null; echo "exit $?"  # exit 0
```

`tile/0/000` is the first full tile; it exists because step 1 wrote more than 256 objects. The
replacement does not keep the original's stored HTTP metadata, which does not matter here: the read
path sets headers by resource kind (D4.5). Do **not** do this on a log with Workers Cache enabled: the
corrupted tile could be cached for a year.

**Record:** the two `exit 1` lines and the CLI's error messages.

## 5b. Optional (M8): a witness and the browser verifier

If a witness was configured (`docs/OPERATIONS.md` §11), repeat step 1's `checkpoint` with
`--witness "$WITNESS_VKEY"`: it prints the cosignature and its time. Then serve a fork to the
witness, as the conformance harness does locally: a checkpoint of the same size with another root,
signed with the log's key, posted to `<witness>/add-checkpoint` must get `422` and be kept as
evidence. Open `https://<host>/` in a browser with the read token and vkey: the page verifies the
same log and proves the audit's findings. Not run yet; key blinding is a choice made before a log's
first entry, so it needs its own log (§12 there).

**Record:** the cosignature line, the witness's 422, and a screenshot of the verified page.

## 6. Clean up

Delete the demo objects (`npx wrangler r2 object delete "$B/demo/obj-$i" --remote` for each), or the
whole setup as described in `docs/OPERATIONS.md`. The log keeps its history: that is the point.

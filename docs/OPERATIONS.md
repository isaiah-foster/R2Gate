# Operations

Commands that touch real Cloudflare resources. **None of these have been run yet.** Each one
creates, modifies or bills for something in a Cloudflare account, so the repository owner runs or
approves them (PLAN §0, working agreement 4). This file grows with each milestone; deployment,
key rotation and teardown are written up in M7.

## R2 conditional-write contract test (M2, to run in M6)

Publication relies on `put(key, data, { onlyIf: { etagDoesNotMatch: '*' } })` meaning "create
only if absent" (DECISIONS D2.1). The Workers API reference does not define `'*'`, so the
behaviour is pinned by a contract test that passes against local R2 and must also pass against
real R2 before the log is trusted there.

Counted from the test code, it issues 12 PUTs (some deliberately rejected), 1 LIST, 8 GET/HEADs
and a handful of DELETEs on one bucket, and deletes what it wrote. Use a dedicated, empty bucket.

1. Log in (interactive, opens a browser): `npx wrangler login`
2. Create a test bucket (billed per R2 pricing; the name is a placeholder):
   `npx wrangler r2 bucket create r2notary-contract-test`
3. Put that name in `worker/test-remote/wrangler.remote.jsonc` (`bucket_name`). Do not commit it.
4. Run: `npm run test:contract:remote`
5. Record the result (date, wrangler version, pass/fail per case) in `docs/DECISIONS.md` D2.1.
6. Remove the bucket when done: `npx wrangler r2 bucket delete r2notary-contract-test`

`R2_CONTRACT_LOCAL=1 npm run test:contract:remote` runs the same harness against local R2 with no
network access; use it to check the setup first.

If the remote run fails: switch `CREATE_ONLY` in `worker/src/publish.ts` to the
`If-None-Match: *` `Headers` form if that case passes, otherwise stop and redesign (a silent
overwrite would break I4).

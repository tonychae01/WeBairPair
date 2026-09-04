# WeBairPair

Random monthly 1:1 chats connecting people across BAIR and EECS at the Gateway.

## Local development

Requirements: Node.js 20 or newer.

```sh
npm install
npm run db:migrate:local
npm run dev
```

Open `http://localhost:8787`. With no AWS credentials configured, verification emails are skipped and the page shows a local confirmation link so the full flow remains testable.

To send real email locally, copy `.dev.vars.example` to `.dev.vars` and add a scoped SES access key. The sender in `wrangler.jsonc` must be verified in SES, and the SES account must be out of the sandbox to email arbitrary `@berkeley.edu` addresses.

## Production

The Worker is deployed at `https://webairpair.com` with a production D1 database in WNAM. AWS credentials are stored as encrypted Worker secrets and are not committed.

For future releases:

```sh
npm run typecheck
npm test
npx wrangler d1 migrations apply webairpair --remote
npx wrangler deploy
```

If SES credentials change, update `.dev.vars` and upload them with `npx wrangler secret bulk .dev.vars` before deploying.

The monthly cron runs at 17:00 UTC on the first day of each month. The matcher reads the full `pairings` history and uses weighted maximum matching to avoid repeat pairs except where a repeat is mathematically necessary to match the group. With an odd participant count, it favors someone who has never sat out, then the person who sat out least recently, and emails them that they remain opted in. Pairing and unmatched notifications are resumable if sending fails halfway through.

## Checks

```sh
npm test
npm run typecheck
```

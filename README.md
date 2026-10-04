# Neighbourhood Watch

Two Cloudflare Pages frontends + one shared Worker backend + D1, following the
card-free stack pattern (no R2, no paid tiers).

```
neighbourhood-watch/
├── public/                  # Pages project — resident-facing PWA + admin console
│   ├── index.html           # map, pin-drop reporting, address search
│   ├── manifest.json        # PWA manifest (blue theme, ElysiumWatch)
│   ├── sw.js                # service worker stub (public PWA)
│   ├── icons/               # icon-192.png, icon-512.png (blue shield)
│   └── admin/               # Pages sub-path — moderation console
│       ├── index.html       # moderation queue, approve/reject, history, push subscribe UI
│       ├── manifest.json    # PWA manifest (amber theme, EW Admin)
│       ├── sw.js            # admin service worker — Web Push + alert beep + fetch handler
│       └── icons/           # icon-192.png, icon-512.png (amber shield with lock)
│
├── worker/                  # Cloudflare Worker — shared backend for both frontends
│   ├── index.js             # /api/reports routes + B2 image storage + push fan-out
│   └── wrangler.toml        # D1 binding, B2 vars/secrets
│
└── db/
    ├── schema.sql            # D1 table definitions (reports)
    └── schema-push.sql       # D1 migration — push_subscriptions table
```

## Why one Pages project (not two)

The admin console lives at `public/admin/` and deploys as a sub-path of the same
Cloudflare Pages project (`elysiumwatch`), available at
`https://elysiumwatch.pages.dev/admin/`. This keeps the deploy simple — one
`wrangler pages deploy` covers both frontends. Security is handled by the
`ADMIN_KEY` bearer token required by all `/api/admin/` routes; there is no
public link to `/admin/` from the resident-facing map.

## Deploy order (fresh setup)

1. **D1**: `npx wrangler d1 create neighbourhood-watch-db`, paste the
   `database_id` into `worker/wrangler.toml`, then
   `npx wrangler d1 execute neighbourhood-watch-db --remote --file=db/schema.sql`
   followed by
   `npx wrangler d1 execute neighbourhood-watch-db --remote --file=db/schema-push.sql`
2. **Worker secrets**: `B2_KEY_ID`, `B2_APPLICATION_KEY`, `B2_BUCKET_ID`,
   `ADMIN_KEY`, `VAPID_PUBLIC_KEY`, `VAPID_PRIVATE_KEY` via `wrangler secret put`
   (from `worker/` directory); set `B2_BUCKET_NAME` directly in `wrangler.toml`
3. **VAPID keys**: generate once with the Node one-liner below, set as secrets
4. **Admin HTML**: paste `VAPID_PUBLIC_KEY` value into the `const VAPID_PUBLIC_KEY`
   constant near the top of `public/admin/index.html`
5. **Icons**: already in repo at `public/icons/` (blue) and `public/admin/icons/` (amber).
   If regenerating: rename downloaded files to `icon-192.png` / `icon-512.png` before deploying —
   Cloudflare deduplicates by content hash so filenames must be correct before the first upload.
6. **Worker**: `cd worker && npx wrangler deploy`
7. **Pages**: `cd public && npx wrangler pages deploy . --project-name=elysiumwatch --branch=main`

### VAPID key generation (run once, in any directory)

```bash
node -e "
const { webcrypto } = require('crypto');
webcrypto.subtle.generateKey(
  { name: 'ECDH', namedCurve: 'P-256' },
  true, ['deriveKey']
).then(async k => {
  const pub  = Buffer.from(await webcrypto.subtle.exportKey('raw', k.publicKey)).toString('base64url');
  const priv = Buffer.from(await webcrypto.subtle.exportKey('pkcs8', k.privateKey)).toString('base64url');
  console.log('VAPID_PUBLIC_KEY=' + pub);
  console.log('VAPID_PRIVATE_KEY=' + priv);
});
"
```

Then:
```bash
cd worker
npx wrangler secret put VAPID_PUBLIC_KEY   # paste public key at prompt
npx wrangler secret put VAPID_PRIVATE_KEY  # paste private key at prompt
```

And paste the public key into `public/admin/index.html`:
```js
const VAPID_PUBLIC_KEY = 'your-public-key-here';
```

## Local dev (Git Bash)

Same pattern as PAS — edit locally, `wrangler dev` in `worker/` for the API,
open the HTML files directly or serve `public/` with any static server for
frontend work. No build step on either frontend.

## Deploy workflow (ongoing)

```bash
# Worker changes
cd worker
npx wrangler deploy

# Frontend changes (both public PWA and admin console)
cd public
npx wrangler pages deploy . --project-name=elysiumwatch --branch=main
```

Note: local git branch is `master`; Cloudflare Pages production branch is `main`.
Always pass `--branch=main` explicitly on Pages deploys, or change the dashboard
production-branch setting to `master`.

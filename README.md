# حصن | HISN Web

Arabic security workspace with light/dark themes, responsive navigation, local message/link/phone analysis, image-capable HISN AI, eight security tools, lessons, quiz, searchable history and JSON export.

## One backend, not a separate data silo

This repository serves both the website and the existing iOS API. Deploy it to the existing `hisn-secure-api` Render service, preserving its hostname and all secret environment variables. iOS continues using `/v1/ai/chat`, `/v1/tools/ip-lookup`, and `/v1/tools/dns-lookup`. Both clients use the same Supabase project and private scan-history table.

Web requests use same-origin `/api/*` routes, encrypted HttpOnly cookies, CSRF checks, and request budgets. No Gemini, Supabase service, or iOS API-access secret appears in public assets. AI content and images are not persisted in operation logs. History synchronization requires explicit user pairing/consent; anonymous sessions do not persist records.

Transient provider 5xx responses get one bounded retry using Gemini 3.8 Flash (configurable via `GEMINI_FALLBACK_MODEL`), shared by iOS and web. Invalid keys/permissions/requests are not retried. Provider diagnostics log only status enums, never prompts, keys or image bytes.

## Setup

Node 22–24, no third-party runtime packages. `npm ci`, `npm test`, `npm run build`, `npm start`. Copy `.env.example` to `.env` for your own environment; use Node `--env-file=.env` if desired. Keep secrets in Render environment settings, never Git.

Apply `supabase/migrations/202609150001_shared_scan_history.sql` once in the existing project before enabling pairing. The API hashes 256-bit pairing keys and scopes every history query to that owner. Direct database access is revoked for anonymous/authenticated roles. The user retains their key; losing it means losing access. A key grants access to that private vault, so it must not be shared publicly.

## Render

Use repository `https://github.com/abon3lh2030-ai/HISN.CYS`, branch `main`, empty Root Directory, build `npm ci && npm run build`, start `npm start`, health path `/health`, free plan. Preserve `GEMINI_API_KEY`, `GEMINI_MODEL`, `HISN_API_ACCESS_TOKEN`, `SUPABASE_URL`, and `SUPABASE_SECRET_KEY`; set `NODE_ENV=production`.

## iOS integration

`ios-integration/` contains the new Swift service and pairing screen plus a patch for the iOS app, also implemented in the local iOS workspace. Install a newly built iOS version to see Settings → ربط السجل مع موقع حصن. Paste the web pairing key, consent, and link. New manual/shortcut scans upload sanitized summaries. Old local history uploads only by an explicit button. Open/pull-to-refresh the iOS History tab to download new web records. Existing installed binaries cannot gain synchronization without an update.

## Deliberate platform limits

- Browsers cannot read SMS/iMessage inboxes, enable iOS message filters, use Face ID as an app lock, or run iOS personal automations.
- Image analysis is remote and explicit; web has no native Arabic on-device Vision OCR.
- IP location is approximate. Phone analysis checks formatting, not identity or real-world reports.
- File hashing is local (100 MiB limit), not malware detection; VirusTotal link sends only the hash when clicked.
- AES-GCM packages are byte-compatible with HISN iOS: version + salt + nonce + ciphertext + tag. Passwords, plaintext, hash input and file bytes stay local.
- Web AI requests are capped per IP; the existing iOS client-token API is maintained for backward compatibility. For a wide public launch, replace that legacy shared-client credential with authenticated per-user sessions, add distributed abuse controls, and review provider billing limits.
- History is limited to the latest 500 records per read. Shared history deletion is soft and synchronized; old uploads do not resurrect removed rows. The iOS Settings “clear history” action remains explicitly device-local, while deleting in the History tab removes shared rows when linked.

## Verification

Native Node tests cover API input validation, privacy-only operation metadata, iOS-aligned message weights, password groups, cryptography round trips, wrong-password rejection, record redaction, static serving, CSRF and cookie secrecy. Public content is escaped before rendering; provider outputs are displayed as plain text.

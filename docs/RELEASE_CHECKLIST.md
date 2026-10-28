# ChainShield — Release Verification Checklist

Status on 2026-10-28: automated tests and an isolated end-to-end run pass. **Browser and
live blockchain checks have not been performed.** ChainShield is not production-ready;
see "Open issues".

Use synthetic messages only. Never paste real personal messages into test runs.

## 1. Switch the backend to `app.server:app`

- [ ] `cp chainshield.db chainshield.db.bak-$(date +%Y%m%d)`
- [ ] `ss -ltnp | grep :8000` — note the PID of the old `uvicorn main:app` process.
- [ ] Stop it (Ctrl+C in its terminal, or `kill <pid>`).
- [ ] From the repository root: `.venv/bin/uvicorn app.server:app --host 127.0.0.1 --port 8000`
- [ ] `curl -s http://127.0.0.1:8000/` → `{"message":"ChainShield Backend is Running!"}`
- [ ] `sqlite3 chainshield.db ".tables"` → `message_scans scans`. Startup makes two additive
  changes: it creates `message_scans` and adds the nullable column `scans.blockchain_status`.
  Existing rows are untouched (rehearsed on a copy of the live database: 3 rows kept,
  legacy rows reported as `unavailable`).
- [ ] Rollback if needed: stop the server, restore the backup file, start `main:app` again.

## 2. URL API

- [ ] `curl -s -X POST localhost:8000/scan -H 'Content-Type: application/json' -d '{"url":"https://example.com"}'`
  returns all original fields plus `blockchain_status` and `ml_status`. Use
  `https://www.wikipedia.org` as a clean example: without an RPC it should be `UNKNOWN`
  (no SAFE without the registry). Note: `https://example.com` is a known URL-model false
  positive and returns MEDIUM.
- [ ] `{"url":"nope"}` → HTTP 422.
- [ ] `curl -s localhost:8000/scan/history` → a list including pre-existing rows, each with a
  `blockchain_status` (older rows: `not_recorded`/`unavailable`/`no_match`/`match_unclassified`).

## 3. SMS API

- [ ] `curl -s -X POST localhost:8000/message/scan -H 'Content-Type: application/json' -d '{"text":"See you at 6"}'`
  → `verdict` one of `likely_legitimate | generic_spam | likely_smishing | smishing_registry_match | unavailable`; `risk_level` never `SAFE`.
- [ ] `{"text":"Your account is locked, verify at http://bank.example"}` → typically `likely_smishing`, MEDIUM.
- [ ] `{"text":""}`, `{}` and 2,001 characters → HTTP 422.
- [ ] `curl -s localhost:8000/message/history` → metadata only (no message text).
- [ ] `sqlite3 chainshield.db "select * from message_scans limit 3"` shows no message text and no hash.
- [ ] The server log contains no message text.

## 4. Live read-only blockchain lookups

- [ ] Put `SEPOLIA_RPC_URL=<your Sepolia RPC URL>` in `.env` (do not share it), then restart the server.
- [ ] Scan a URL → `blockchain_available: true` and `blockchain_status` is `no_match` (or a match).
- [ ] Scan a message → `registry.status` is not `unavailable`.
- [ ] No transaction is sent: the API only makes view calls and has no signing key.
- [ ] Wrong RPC (another chain) → `blockchain_status: unavailable` with "does not match Sepolia".

## 5. Chrome extension (unpacked)

- [ ] `chrome://extensions` → Developer mode → Load unpacked → `frontend/extension/`.
- [ ] Permissions shown: access to `http://127.0.0.1:8000/*` only.
- [ ] URL mode: `https://example.com` → a result with a registry line; `not a url` → validation message, nothing sent.
- [ ] Message mode: "See you at 6" → "Likely legitimate (model)" with scores; the account-locked message → "Likely smishing".
- [ ] More than 2,000 characters → blocked before sending.
- [ ] Stop the backend and scan → error "Cannot reach the ChainShield backend…", spinner stops, no verdict.

## 6. Dashboard

- [ ] `cd frontend/dashboard && npm ci && npm run dev`, open http://localhost:5173.
- [ ] URL Scanner (`/scanner`): result, registry section, loading and error states.
- [ ] Message Scanner (`/messages`): each verdict wording; scores labelled as model scores; Limitations panel.
- [ ] Message history table updates after a scan and shows no text.
- [ ] History (`/history`): URL history still loads.
- [ ] With the backend stopped: an error box, never a result.

## Seeder (policy implemented 2026-10-28; not run)

- Only `smishing` is a message threat; generic spam is counted separately and never
  registered; `phishing`/`malicious`/`0`/`1` need an explicit `--threat-label`.
- Unrecognized or misspelled labels are counted as unrecognized and listed in the summary.
- [ ] Before any seeding: prepare data with `prepare_mishra_soni`, run a dry run with
  `--threat-label smishing`, review "Labels seen", then decide on `--submit` (owner key).

## Open issues

1. Resolved 2026-10-28: with the registry unavailable, a URL with no threat signal is UNKNOWN,
   not SAFE. SAFE still requires a completed registry check and is weak evidence (the URL
   model has a known template bias).
2. SMS model external recall is 0.70 on IMC 2025 and 0 on "hey mum/dad" scams.
3. Resolved 2026-10-28: seeder registers only smishing for messages (above).
4. Resolved 2026-10-28: `blockchain_status` is stored in URL history (additive column, applied at restart).
5. Browser and live blockchain checks above are not yet done.

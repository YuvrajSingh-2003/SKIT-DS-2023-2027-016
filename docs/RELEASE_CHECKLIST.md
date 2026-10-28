# ChainShield — Release Verification Checklist

Status on 2026-10-28: automated tests and isolated end-to-end runs pass. The dashboard and
extension passed automated browser runs, including the real toolbar popup in a visible
window, against the port-8001 test backend (`docs/submission/TEST_EVIDENCE.md`). **Not yet
done:** the manual browser checks below against the live port-8000 setup, and live blockchain
checks. ChainShield is not production-ready; see "Open issues".

Use synthetic messages only. Never paste real personal messages into test runs.

## 1. Switch the backend to `app.server:app` — done 2026-10-28

- [x] Online backup `sqlite3 chainshield.db ".backup '<file>'"`, then `PRAGMA integrity_check`
  → `ok`, and the SHA-256 recorded (`chainshield-pre-restart-20261028T172433Z.db`).
- [x] The old `uvicorn main:app` process was identified (`ss -ltnp | grep :8000`) and stopped.
- [x] From the repository root: `.venv/bin/uvicorn app.server:app --host 127.0.0.1 --port 8000`
- [x] `curl -s http://127.0.0.1:8000/openapi.json` lists the five routes; one URL and two
  message scans returned 200; invalid inputs returned 422.
- [x] `sqlite3 chainshield.db ".tables"` → `message_scans scans`. The original 3 rows are
  byte-identical to the backup.
- Rollback if ever needed: stop the server, copy the backup over `chainshield.db`, start again.

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

Equivalent checks passed in automated browser runs against the port-8001 test backend (temporary database, no RPC), using a test copy of the
extension; see TEST_EVIDENCE.md. The boxes stay open for the manual check against port 8000,
which includes a physical click on the toolbar icon.

- [ ] `chrome://extensions` → Developer mode → Load unpacked → `frontend/extension/`.
- [ ] Permissions shown: access to `http://127.0.0.1:8000/*` only.
- [ ] URL mode: `https://example.com` → a result with a registry line; `not a url` → validation message, nothing sent.
- [ ] Message mode: "See you at 6" → "Likely legitimate (model)" with scores; the account-locked message → "Likely smishing".
- [ ] More than 2,000 characters → blocked before sending.
- [ ] Stop the backend and scan → error "Cannot reach the ChainShield backend…", spinner stops, no verdict.

## 6. Dashboard

Equivalent checks passed in automated browser runs against the port-8001 test backend (temporary database, no RPC), using a production build;
see TEST_EVIDENCE.md. The boxes stay open for the manual check against port 8000.

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
5. Manual browser checks against port 8000 and live blockchain checks are not yet done.
   Automated browser runs against the port-8001 test backend passed. Registry behaviour is
   tested against a local fake Sepolia node (`tests/test_registry_rpc_e2e.py`), not live.
6. Dashboard display issues seen in screenshots (open): the Overview page text is outdated,
   and long risk badges are cut off in the URL history table
   (`docs/submission/SCREENSHOT_CHECKLIST.md`, notes A and B).
7. `npm audit`: 2 moderate advisories remain (react-router 6). The upgrade to react-router-dom
   7 is deferred.

## 7. Manual demonstration checklist

Use only these synthetic inputs. Expected results assume the backend runs `app.server:app`.
"Registry" means `SEPOLIA_RPC_URL` is configured and Sepolia is reachable.

| # | Where | Input / action | Expected (no registry) | Expected (registry) |
|---|---|---|---|---|
| 1 | Dashboard `/scanner` or extension URL mode | `https://www.wikipedia.org` | `? Inconclusive` (UNKNOWN) with the "registry unavailable … not safe" note | `✓ No issues detected` (SAFE) and "hash not found … does not guarantee safety" |
| 2 | Same | `http://192.168.1.1/login/verify/account` | `✕ High risk`, IP-address and other heuristic findings | Same |
| 3 | Same | `not a url`, `ftp://example.com`, empty | Validation message; nothing sent | Same |
| 4 | Dashboard `/messages` or extension message mode | `See you at the station at 6` | `Likely legitimate (model prediction)`, `· Low risk`, registry "unavailable" | Same, registry "not found" |
| 5 | Same | `Your bank account is suspended. Verify now at http://secure-bank-login.example` | `Likely smishing (model prediction)`, `! Suspicious` (MEDIUM), link finding | Same |
| 6 | Same | Whitespace only; more than 2,000 characters | Validation message; nothing sent | Same |
| 7 | Any | Stop the backend, then scan | "Cannot reach the ChainShield backend … No result is available." No verdict shown | Same |
| 8 | Dashboard `/history` | Open; expand a row | Rows newest first; registry status per row; older rows "not recorded" or "unavailable" | Same |
| 9 | Dashboard `/messages` | Scroll to history | Verdict, risk, score, registry and length only; **no message text** | Same |
| 10 | Registry hit (only with a registered test record) | `https://chainshield-test.invalid/registry-check`, if registered | n/a | `✕ High risk`, "found in the blockchain threat registry", model not run |

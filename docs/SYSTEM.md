# ChainShield — System Guide and Project Status

Last updated 2026-10-28. Covers architecture, the two detection flows, the API,
the SMS model, blockchain behavior, the extension, the dashboard, privacy, tests,
and what still needs a person. Dataset provenance and licensing are in
[datasets.md](datasets.md). Step-by-step manual verification is in
[RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md). Submission material (architecture diagrams, test
evidence, report, screenshot checklist) is in [submission/](submission/).

## Component status

| Component | Status | Evidence |
|---|---|---|
| SMS model inference (`app/services/sms_detector.py`) | Implemented and tested | Unit tests; real model loads with pinned SHA-256; end-to-end API run |
| `POST /message/scan`, `GET /message/history` | Implemented and tested (local) | Unit tests; end-to-end run on an isolated server |
| Message history (metadata only) | Implemented and tested (local) | In-memory SQLite tests; isolated end-to-end run |
| URL scanning `POST /scan`, `GET /scan/history` | Implemented and tested | Original fields unchanged; added `blockchain_status`, `ml_status`; advisory model policy (see below) |
| URL ML model | Implemented, advisory only; **not reliable** | Pinned SHA-256 checked before loading; can raise risk to MEDIUM, never HIGH (template artifact, see datasets.md) |
| Blockchain lookups (URL and message, read-only) | Implemented; tested through the real Web3 stack against a local fake Sepolia node (hit, non-threat, miss, wrong type, wrong chain, missing code, unreachable); **not verified against live Sepolia** | `tests/test_registry_rpc_e2e.py`; no RPC configured in this environment |
| Hashing/canonicalization (Keccak-256) | Implemented and tested | Existing hashing tests |
| Chrome extension (URL + message modes) | Implemented; logic unit-tested; passed automated browser runs (Brave/Chromium 156), including the real toolbar popup, against the port-8001 test backend; **no manual check against port 8000** | Node tests (`frontend/extension/tests/`); `docs/submission/TEST_EVIDENCE.md` |
| Dashboard (URL, Message, History pages) | Implemented; production build passes on Vite 6.4.5; helpers unit-tested; passed automated browser runs against the port-8001 test backend; **no manual check against port 8000** | `vite build`; `frontend/dashboard/tests/`, `frontend/shared/tests/` |
| Training/data pipeline guards | Implemented and tested | 349 Python tests (Stage 0–2) |
| Running server on port 8000 | Serves `app.server:app` (all five routes) since 2026-10-28 | Restarted with owner approval after a verified database backup; routes and scans checked |
| Seeder label policy | Implemented and unit-tested (not run against a chain) | Smishing-only; generic spam never registered; unrecognized labels reported |

## Architecture

```
Dashboard (React/Vite) ─┐                      ┌─ sms_detector ── models/sms_baseline/<run>/model.joblib (pinned SHA-256)
                        ├─ FastAPI app.server ─┤─ ml_detector  ── models/url_inference/model.joblib
Extension (MV3 popup) ──┘    (main.app +       ├─ blockchain_checker ── Sepolia ThreatRegistry (view calls only)
                              message router)  └─ SQLite chainshield.db: scans (URL), message_scans (metadata)
```

`app/server.py` imports the existing `main.app` unchanged and adds the message
router. `main.py` and the URL route are frozen (Stage 0) and were not modified.

## Detection flows

**Message** (`POST /message/scan`):
1. Validate: `text` required, 1–2,000 characters, not blank (else 422).
2. Registry: Keccak-256 of the canonicalized message (`message:` domain prefix), read-only `threatExists`/`getThreat`.
3. SMS model: TF-IDF char 2–5-grams + logistic regression; classes `legitimate`, `generic_spam`, `smishing`.
4. Decision: registry `match_threat` → `smishing_registry_match` / HIGH; else model
   `smishing` → `likely_smishing` / MEDIUM, `generic_spam` → `generic_spam` / LOW,
   `legitimate` → `likely_legitimate` / LOW; model unavailable → `unavailable` / UNKNOWN.
   No message result is ever `SAFE`.
5. Persist metadata only (no text, no hash of the text); report `persisted: false` on failure.

Links inside a message are flagged as a finding but **not** scanned; use the URL scanner.

**URL** (`POST /scan`): validate → heuristics → read-only registry lookup (`url:` prefix)
→ URL model if the registry has no threat match → persist → respond.
- Registry `match_threat` → HIGH, model not run (`ml_status: not_run`).
- Otherwise heuristics set the level (0 findings SAFE, 1–2 MEDIUM, 3+ HIGH); a model
  "phishing" prediction can raise SAFE to MEDIUM and adds an advisory finding, but never
  makes HIGH on its own (changed 2026-10-28; previously the model alone gave HIGH).
- A registered non-threat (`match_non_threat`) is not treated as a threat.
- Model unavailable → UNKNOWN (`ml_status: error`). A registry miss is not a safety verdict.
- **No SAFE without the registry (2026-10-28):** if the registry is unavailable, heuristics
  find nothing and the model says legitimate, the result is UNKNOWN with the finding
  "Threat registry unavailable and no threat signal found; result is inconclusive, not safe".
  This only withholds SAFE. Heuristic MEDIUM/HIGH and a model phishing signal are unchanged.

## API reference

### `POST /message/scan`
Request:
```json
{"text": "Your parcel is held. Pay the fee at http://example.test/pay"}
```
Response (synthetic example):
```json
{
  "status": "processed",
  "verdict": "likely_smishing",
  "risk_level": "MEDIUM",
  "decision_source": "ml",
  "message": "Model classifies this message as likely smishing; threat registry unavailable during this scan",
  "model": {"status": "ok", "label": "smishing",
            "probabilities": {"legitimate": 0.01, "generic_spam": 0.01, "smishing": 0.98},
            "model_version": "sms_baseline/run-20261028T122841Z-seed42", "model_name": "char25_C10", "error": null},
  "registry": {"status": "unavailable", "error": "RPC endpoint is not configured"},
  "findings": ["Contains a link (scan it separately with the URL scanner)"],
  "limitations": ["Model predictions can be wrong; ..."],
  "message_length": 58, "scan_id": 1, "persisted": true
}
```
Errors: 422 for missing, blank, non-string or over-length text, or invalid JSON.
Probabilities are model scores, not calibrated likelihoods.

### `GET /message/history`
Newest first, at most 200 rows: `id, created_at, verdict, risk_level, decision_source,
model_label, model_version, probability_legitimate, probability_generic_spam,
probability_smishing, registry_status, message_length, has_url`. No message text.

### `POST /scan`, `GET /scan/history`
All original response fields are unchanged. Two fields were added (additive; clients that
ignore unknown fields are unaffected):
- `blockchain_status`: `match_threat` | `match_non_threat` | `no_match` | `unavailable`.
  `blockchain_found` keeps its original meaning (hash registered, any verdict); use
  `blockchain_status` to tell a known threat from a registered non-threat.
- `ml_status`: `not_run` | `error` | `ok`.
`blockchain_status` is stored in `scans` (new nullable column, added automatically at
startup by `ensure_schema`) and returned by `/scan/history`. Rows saved before the column
existed report a conservative status: `not_recorded`, `unavailable`, `no_match`, or
`match_unclassified` (an entry existed but its verdict was not recorded; never shown as a
threat). `ml_status` is not stored. The dashboard and extension use `blockchain_status` when
present and fall back to `blockchain_found` for older servers.

## SMS model card (summary)

- Run: `models/sms_baseline/run-20261028T122841Z-seed42/` (full card in its README.md).
- Data: Mishra & Soni SMS Phishing Dataset (CC BY 4.0), 5,762 rows after conflict exclusion; group-aware 70/15/15 split.
- Locked test (once): macro-F1 0.893 [0.840, 0.932]; smishing precision 0.892, recall 0.857;
  generic spam → smishing 8/63; legitimate → smishing 0/725.
- External (IMC 2025, GPT-4o labels, recall only): smishing recall 0.697; misses all
  "hey mum/dad" scams (0/55) and over half of delivery and telecom smishing.
- Known behavior: prize/"win a prize" messages are usually classed as smishing, because
  the training data's smishing class includes prize scams.
- Not production-ready. English only. Use as an advisory signal.

### SMS improvement protocol (future work; not started)
The locked internal test and IMC 2025 have both been observed, so neither can confirm a
new model. A defensible next model needs:
1. New, licensed training data covering the missed styles (conversational "hey mum/dad",
   delivery, telecom, recent campaigns), verified with the same license and label checks
   as `docs/datasets.md`, and prepared with the same conflict and group rules.
2. Model selection on validation data only (group-aware, from the training sources).
3. A **new, untouched test set** collected after the model is frozen (for example a fresh,
   dated smishing collection plus legitimate messages), evaluated once.
4. IMC 2025 reported again only as a previously-seen benchmark, never as confirmation.
5. Reported per class with group-bootstrap intervals, including generic-spam → smishing
   and legitimate → smishing rates.

## Blockchain

- Contract `ThreatRegistry` on Sepolia (`contracts/configs/contract_addresses.json`), hash-only storage.
- The backend only makes view calls. It checks connectivity, chain ID (11155111) and
  deployed code first, and verifies the stored threat type (URL=1, MESSAGE=0).
- Statuses: `match_threat`, `match_non_threat`, `no_match`, `unavailable`.
- Nothing is ever written. Nothing is seeded automatically.
- **Live verification is pending**: set `SEPOLIA_RPC_URL` in `.env` and run a scan.
- When the registry cannot be checked, a registered threat is not recognised: the result
  falls back to heuristics and the model (e.g. a registered URL becomes MEDIUM, a
  registered message LOW). A URL is never `SAFE` while the registry is unavailable.

### Registry batch preparation (read-only; no writes)
- `python -m src.blockchain.prepare_batch --urls-only|--messages-only --out <new file>` hashes
  eligible records with the runtime hash functions and writes a hash-only manifest
  (provenance, exclusions, source checksums). Locked-test-split messages, duplicates,
  synthetic test records and unlicensed feeds are excluded.
- `python -m src.blockchain.registry_preflight --manifest <file> --out <new file>` checks each
  hash with view calls and gets `eth_estimateGas` from the owner address. It holds no key and
  sends nothing. Reviewed manifests and the approval gate: `data/threat_registry/REVIEW.md`.

### Seeder (policy updated 2026-10-28; never run against a chain here)
`src/blockchain/seed_registry.py` is dry-run by default and writes only with `--submit`.
- Message datasets: only `smishing` is a threat. `spam`/`generic_spam` are counted as
  generic spam and never registered. `phishing`, `malicious`, `0`, `1` are ambiguous for
  SMS and are not registered unless `--threat-label` names the threat value.
- URL datasets: unchanged (PhiUSIIL `0` = phishing).
- Labels are trimmed and lowercased (`Smishing` = `smishing`). Unknown or misspelled
  labels are counted as "unrecognized" (not "benign"), and the summary lists every label
  seen with its outcome. No message text is printed.
- Recommended procedure: prepare the data first (`prepare_mishra_soni`, which excludes
  conflicting labels), export the prepared rows to a CSV with `message,label`, run a dry
  run with `--threat-label smishing`, review the summary, and only then consider `--submit`
  with the owner key. The specification §443 was updated to this policy.

## Configuration (variable names only; never commit values)

| Variable | Used by | Purpose |
|---|---|---|
| `SEPOLIA_RPC_URL` (or `WEB3_PROVIDER_URI`) | `app/services/blockchain_checker.py` | Read-only registry lookups; unset → `unavailable` |
| `SIGNER_PRIVATE_KEY` | deploy/seed scripts only | Never needed by the API |
| `CHAINSHIELD_CORS_ORIGINS` | `main.py` | Comma-separated dashboard origins (default Vite dev origins) |
| `CHAINSHIELD_DATABASE_URL` | `app/database/database.py` | SQLAlchemy URL; default `sqlite:///<repository root>/chainshield.db`. Set it for isolated test databases |
| `VITE_API_BASE_URL` | dashboard | Backend URL (default `http://127.0.0.1:8000`) |

The extension's backend URL is `BACKEND_URL` in `frontend/extension/src/popup.js` and must
match `host_permissions` in `manifest.json`.

## Model integrity
- SMS model: `app/services/sms_detector.py` loads `models/sms_baseline/run-20261028T122841Z-seed42/model.joblib`
  only if its SHA-256 is `9f753dd5…5b85815` (`MODEL_SHA256`).
- URL model: `app/services/ml_detector.py` loads `models/url_inference/model.joblib` only if its
  SHA-256 is `2f2e1d49…f2adc` (`MODEL_SHA256`) and `metadata.json` names the same hash.
- A missing, altered or mismatched file gives an explicit unavailable result (`UNKNOWN`),
  never a prediction and never `SAFE`. `joblib` files are never loaded unverified.

## Running locally

```bash
# Backend (full API including /message/*), from the repository root
.venv/bin/uvicorn app.server:app --host 127.0.0.1 --port 8000
# Dashboard
cd frontend/dashboard && npm ci && npm run dev        # http://localhost:5173
```
Run `app.server:app`, not `main:app` (which has no `/message/*` routes).

**Database.** `chainshield.db` in the repository root, independent of the working directory
(override with `CHAINSHIELD_DATABASE_URL`). Schema setup (adding missing tables and
columns) runs at server startup only; importing the code never touches the database.

**Safe backup** (consistent even while the server runs):
```bash
sqlite3 chainshield.db ".backup '<backup dir>/chainshield-$(date -u +%Y%m%dT%H%M%SZ).db'"
sqlite3 '<backup file>' "PRAGMA integrity_check"      # must print: ok
sha256sum '<backup file>'                              # record the checksum
```
**Safe restart:** back up as above; stop the old process (check `ss -ltnp | grep :8000`
first); start the command above from the repository root; check `curl -s
http://127.0.0.1:8000/openapi.json` lists five routes and run one scan of each kind.

### Chrome extension
1. Open `chrome://extensions`, enable Developer mode.
2. Load unpacked → `frontend/extension/`.
3. Open the popup, choose URL or Message, paste, press Scan.
Manual checks against port 8000 (not yet performed; the same scenarios passed in automated
browser runs against the port-8001 test backend, see `submission/TEST_EVIDENCE.md`; full list
in `RELEASE_CHECKLIST.md` §7):
1. URL mode: `https://example.com` → a result with a registry line; `not a url` → validation message.
2. Message mode: a harmless synthetic message → "Likely legitimate (model)" with scores.
3. Message mode: a synthetic "account suspended, verify at http://…" message → "! Likely smishing" (amber, MEDIUM).
4. Stop the backend and scan → an error ("Cannot reach…"), never a result; the spinner stops.
5. Paste more than 2,000 characters → blocked before sending.
Permissions: none, plus host `http://127.0.0.1:8000/*` only (unchanged).

### Dashboard
`cd frontend/dashboard && npm ci && npm run dev`, open http://localhost:5173:
URL Scanner (`/scanner`), Message Scanner (`/messages`), History (`/history`). Check the same
cases as above, plus that message history shows no message text.

## Privacy and retention

- Message text is used only in memory for one request. It is not logged, stored, or
  returned. Only its Keccak-256 hash is used, in a read-only registry query.
- Message history stores verdict, scores, registry status, length and a has-link flag.
- URL scans keep the existing behavior: the full URL, including any query string, is stored
  in `scans` indefinitely and returned by `GET /scan/history` without authentication. The
  API is meant for local use (bound to 127.0.0.1); do not expose it on a network as is.
- The extension sends data only when the user presses Scan.

## Tests

```bash
export PYTHONDONTWRITEBYTECODE=1
.venv/bin/python -m pytest -q -p no:cacheprovider -k "not TestPreprocessText"
node --test frontend/extension/tests/ frontend/shared/tests/ frontend/dashboard/tests/
cd frontend/dashboard && npx vite build
.venv/bin/python -m src.evaluation.verify_production_models --out <new file>.json   # model check
```
`TestPreprocessText` is excluded because it downloads NLTK corpora. Tests use in-memory or
temporary databases and a local fake RPC; none touches `chainshield.db` or a real network.
Latest results: `docs/submission/TEST_EVIDENCE.md`.

### Local model prerequisites (fresh checkout)

The model artifacts under `models/` are not in Git: the `model.joblib` files are gitignored,
and the rest of `models/` is untracked. In a fresh checkout, some model tests therefore cannot
use the real models.

**SMS model tests fail (they do not skip) when the files are missing:**
- `tests/test_message_scan.py::TestSmsDetector::test_real_model_returns_known_class_and_probabilities`
  needs `models/sms_baseline/run-20261028T122841Z-seed42/model.joblib` and
  `models/sms_baseline/run-20261028T122841Z-seed42/selection_frozen.json`.
- `tests/test_message_scan.py::TestSmsDetector::test_altered_model_file_is_refused` needs
  `selection_frozen.json` from the same directory.

To regenerate, run `python -m src.training.train_sms_baseline train`. It needs the prepared
Mishra & Soni splits (`data/processed/train.csv`, `val.csv`, `test.csv` and
`sms_split_metadata.json`, all untracked), built from the downloaded dataset as described in
[datasets.md](datasets.md). It does not work without that data. The command writes a **new**
directory `models/sms_baseline/run-<UTC timestamp>-seed42/`, never the pinned one. The backend
and tests load only `run-20261028T122841Z-seed42/`, and accept `model.joblib` only if its SHA-256
is `9f753dd5…5b85815` (`MODEL_SHA256` in `app/services/sms_detector.py`). An earlier independent
retrain produced a byte-identical `model.joblib`. Its `selection_frozen.json` differed, but the
tests only need the file to exist with the selected model's name. The simplest route is to copy
the original run directory from a machine that has it.

**URL model tests skip when the local URL model is missing.** In the clean-checkout run, 5 tests
in `tests/test_url_inference.py` skipped (reasons: URL model artifact "not present" or "not
trained", or URL model metadata "not present"). They
need `models/url_inference/model.joblib` and `metadata.json`. The skip message names
`src.training.train_url_inference`, which reads the tracked splits in `data/processed/url_splits/`.
However, the backend accepts the URL model only if its SHA-256 matches `MODEL_SHA256` in
`app/services/ml_detector.py`, and `test_pinned_checksum_matches_the_real_artifact` fails (not
skips) for a model with a different checksum. Nobody has verified that retraining reproduces the
pinned URL model byte for byte, so copy the original `models/url_inference/` directory instead.

**Clean-checkout result (historical, 2026-10-28).** HEAD `29a8ca9` was exported with
`git archive` and the full suite run without `models/`: 564 passed, 2 failed, 5 skipped, 27
deselected (`TestPreprocessText`). Both failures were the two SMS tests above, caused by the
missing local SMS model files. With the local artifacts present, the same suite passes in full
(571 passed; see `docs/submission/TEST_EVIDENCE.md`).

## Troubleshooting

| Symptom | Meaning |
|---|---|
| `verdict: unavailable`, model error "artifact not found" / "pinned checksum" | Model file missing or altered; restore the run directory |
| `registry.status: unavailable` | No RPC configured, network unreachable, wrong chain, or contract missing |
| 404 on `/message/scan` | Server was started as `main:app`; start `app.server:app` |
| Empty history after a restart | Pre-2026-10-28 code used `./chainshield.db` relative to the working directory; the database is now always the one in the repository root |
| Extension shows "Cannot reach the backend" | Server not running on 127.0.0.1:8000 |

## Remaining manual steps and decisions

1. ~~Restart the backend as `app.server:app`~~ (done 2026-10-28 after a verified backup).
2. Configure `SEPOLIA_RPC_URL` and confirm read-only registry lookups live.
3. Load the extension in Chrome and run the manual checks above; open the dashboard Message Scanner.
4. Decide the seeder policy for `spam` (see Blockchain → Seeder); use `--threat-label smishing` meanwhile.
5. Improve the SMS model with more recent, licensed smishing data before any production use.
6. ~~Approve the additive `scans.blockchain_status` column~~ (kept; present in the live database).
7. npm advisories (dashboard): 2 open (moderate). Vite was upgraded to 6.4.5 (esbuild
   0.25.12) on 2026-10-28 with owner approval, which fixed the vite and esbuild advisories.
   - react-router 6.30.6: open redirect via user-controlled link targets (all targets here are
     fixed paths) and SSR hydration (not used). There is no 6.x fix; deferred.

## Frozen-file changes (authorized 2026-10-28)
| File | Change | Reason |
|---|---|---|
| `app/services/ml_detector.py` | `MODEL_SHA256` pin; hash checked before `joblib.load`; metadata hash must match | Unverified deserialization of the URL model |
| `app/routes/scan.py` | URL model advisory (MEDIUM max); `blockchain_status`, `ml_status` in response | Template-artifact model must not give HIGH alone; non-threat entries must not read as threats |
| `app/schemas/scan.py` | Two optional fields | Response schema for the above |
| `tests/test_blockchain_scan_integration.py` | One assertion HIGH → MEDIUM; new regression tests | Intentional policy change |

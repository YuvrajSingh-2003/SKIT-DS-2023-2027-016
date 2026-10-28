# ChainShield — Test Evidence

Executed 2026-10-28 (13:42 UTC) on the project virtual environment (Python 3.14.8),
Node v26.8.1, Linux. All Python runs used `PYTHONDONTWRITEBYTECODE=1` and
`-p no:cacheprovider`. Results below are copied from the actual command output.

## Automated tests

| # | Command | Result |
|---|---|---|
| 1 | `.venv/bin/python -m pytest -q -p no:cacheprovider tests/test_url_history.py tests/test_seeding.py tests/test_message_scan.py tests/test_sms_baseline.py tests/test_group_split.py tests/test_training_guard.py tests/test_prepare_sources.py tests/test_dedupe_and_merge.py tests/test_data_integrity.py tests/test_data_validation.py tests/test_label_handling.py tests/test_load_data.py tests/test_blockchain_scan_integration.py tests/test_url_inference.py tests/test_hashing.py tests/test_canonicalization.py tests/test_threat_registry.py tests/test_deploy.py` | **474 passed**, 0 failed, 1 warning* |
| 2 | `.venv/bin/python -m pytest -q -p no:cacheprovider tests/test_features.py -k "not TestPreprocessText"` | **35 passed, 27 deselected** |
| 3 | `.venv/bin/python -m pytest --collect-only -q -p no:cacheprovider` | 536 collected (474 + 35 run; 27 deselected) |
| 4 | `.venv/bin/python -m pytest -q -p no:cacheprovider tests/test_threat_registry.py` (separately) | **26 passed**, exit 0 (local solc 0.8.20, compile only, no chain) |
| 5 | `.venv/bin/python -m pytest -q -p no:cacheprovider tests/test_deploy.py` (separately) | **18 passed**, exit 0 (Web3 mocked; no network) |
| 6 | `node --check frontend/extension/src/logic.js && node --check frontend/extension/src/popup.js` | syntax OK |
| 7 | `node --test frontend/extension/tests/` | **8 passed**, 0 failed |
| 8 | `cd frontend/dashboard && npx vite build` | build succeeded |

\* The warning is Python's `runpy` notice in the test that runs `src.training.train_baseline`
as `__main__` to prove it calls the guarded wrapper; it is expected.

Deselected: `TestPreprocessText` (27) — it downloads NLTK corpora.

## Isolated end-to-end runs

`app.server:app` on port 8001 with a working directory in a scratch folder, so it used
its own SQLite file; the live server (port 8000) and live database were not touched.

- 2026-10-28, against a copy of the verified live-database backup: startup added
  `message_scans` and `scans.blockchain_status`; the 3 existing rows were kept and reported
  as `unavailable`; a new scan persisted its status; routes `/`, `/scan`, `/scan/history`,
  `/message/scan`, `/message/history`.
- Earlier the same day: URL and SMS scans; 10 malformed requests → 422; no message text in
  responses, history rows, raw database rows or server logs; no 64-hex hash stored.

## Model evaluation records (not re-run)

- SMS model, locked internal test (evaluated once): macro-F1 0.8929; smishing precision
  0.892, recall 0.857 — `models/sms_baseline/run-20261028T122841Z-seed42/test_evaluation.json`.
- SMS model, IMC 2025 external (GPT-4o labels, recall only): 0.697 —
  `.../imc_evaluation.json`.
- URL model (XGBoost) stratified test phishing F1 0.9633 — `models/url_inference/metadata.json`
  (inflated by a dataset template artifact; see docs/datasets.md).

## Not performed

| Check | Status | Reason |
|---|---|---|
| Dashboard in a browser | **NOT PERFORMED** | No browser or automation library in this environment |
| Extension loaded in Chrome | **NOT PERFORMED** | Same |
| Screenshots | **NOT CAPTURED** | Same; see SCREENSHOT_CHECKLIST.md |
| Live Sepolia read-only lookup | **NOT PERFORMED** | No `SEPOLIA_RPC_URL` configured (no `.env`) |
| Port-8000 server on new code | **NOT SWITCHED** | Needs owner approval (RELEASE_CHECKLIST.md §1) |

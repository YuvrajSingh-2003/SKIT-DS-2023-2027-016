# ChainShield — Test Evidence

Executed on 2026-10-28 (final run around 23:20 IST) with the project virtual environment
(Python 3.14.8), Node v26.8.1, on Linux. Python runs used `PYTHONDONTWRITEBYTECODE=1` and
`-p no:cacheprovider`. Results are copied from the command output. Tests use in-memory or
temporary SQLite databases and a local fake RPC; the live `chainshield.db` was checked to be
unmodified before and after the runs.

## Summary by kind of evidence

These are separate kinds of evidence; their counts are not additive.

| Kind | Latest result | What it does **not** show |
|---|---|---|
| Automated Python tests | 571 passed, 27 deselected | Browser behaviour |
| Automated JS tests | Dashboard 6, shared client 5, extension 11, all passed | Rendering in a real browser |
| Dashboard production build | Succeeds on Vite 6.4.5 | Runtime behaviour |
| Registry tests against a local **fake** Sepolia node | Hit, non-threat, miss, wrong type, wrong chain, missing code, unreachable: all correct | The live Sepolia contract |
| Headless browser run (port-8001 test backend) | 35 checks passed | The toolbar popup; registry hit |
| Visible-browser run (port-8001 test backend, real toolbar popup) | 6 checks passed | The live port-8000 setup; registry hit |
| Live port-8000 API checks after restart (curl) | Routes, scans and 422s as expected | Browser UI on port 8000 |
| **Live Sepolia** registry lookups | **Not performed** | — |

## Automated tests

| # | Command | Result |
|---|---|---|
| 1 | `.venv/bin/python -m pytest -q -p no:cacheprovider -k "not TestPreprocessText"` | **571 passed**, 0 failed, 27 deselected, 1 warning* |
| 2 | `.venv/bin/python -m pytest --collect-only -q -p no:cacheprovider` | 598 collected (571 run + 27 deselected) |
| 3 | `node --test frontend/extension/tests/` | **11 passed**, 0 failed (rerun after the Vite upgrade) |
| 4 | `node --test frontend/shared/tests/` | **5 passed**, 0 failed (rerun after the Vite upgrade) |
| 5 | `node --test frontend/dashboard/tests/` | **6 passed**, 0 failed (after the Vite upgrade; includes the proxy and failure-text tests added during the browser run) |
| 6 | `cd frontend/dashboard && npx vite build` | build succeeded with **Vite 6.4.5** |
| 7 | `.venv/bin/python -m compileall -q app src main.py tests` | OK |
| 8 | `.venv/bin/python -m pip check` | No broken requirements |
| 9 | `node --check` on the extension's `logic.js` and `popup.js` | OK |

Rows 1–2, 7 and 8 come from the run at the start of the browser-verification session. Only
frontend files, docs and the dashboard's dependency files changed after that; no Python file did.

\* Python's `runpy` notice from the test that runs `src.training.train_baseline` as `__main__`; expected.

**Deselected:** `TestPreprocessText` (27 tests) downloads NLTK corpora.

**Not available:** no Python or JS linters, and no React component-test framework, are
installed. Nothing was installed for this run.

Notable test groups:
- `tests/test_registry_rpc_e2e.py`: registry hit, registered non-threat, miss, wrong threat
  type, wrong chain, missing contract code and unreachable node, all through the real Web3
  HTTP stack against an in-process fake node.
- `tests/test_app_startup.py`: importing the app does not touch the database, all five routes
  are registered, the schema is created at startup, and the database path is anchored to the
  repository root.
- `tests/test_prepare_batch.py` and `tests/test_registry_preflight.py`: registry proposal and
  read-only preflight logic, with no transaction code.
- `frontend/dashboard/tests/labels.test.mjs`: the dashboard and extension use the same
  risk wording.

## End-to-end runs (isolated)

**Fake Sepolia node.** Backend `app.server:app` on port 8001 with a temporary database and a
local fake JSON-RPC node on port 8545. Synthetic `.invalid` test inputs only.

| Scenario | Observed |
|---|---|
| Registry hit (URL) | HIGH, decision `blockchain`, model `not_run` |
| Registered non-threat | MEDIUM via model, registry `match_non_threat` |
| Stored with the wrong threat type | registry `unavailable` (not a match) |
| Miss, no warning signs | SAFE, registry `no_match` |
| IP-address login URL | HIGH (heuristics) |
| Message registry hit / miss | HIGH `smishing_registry_match` / LOW `likely_legitimate` |
| RPC unreachable, wrong chain, or no RPC | URL with no warning signs: UNKNOWN; registry `unavailable` |

**Live server, after the approved restart** (PID 90415, `app.server:app`, 127.0.0.1:8000).
These were API-level checks with `curl`; no browser was pointed at port 8000.
- All five routes are registered.
- `POST /scan` returned 200 (UNKNOWN, registry `unavailable`).
- Two `POST /message/scan` calls returned 200 (LOW and MEDIUM).
- Invalid URL and blank message returned 422.
- Both history endpoints returned 200, with no message text in the responses or the log.
- The original 3 scan rows are byte-identical to the pre-restart backup.

## Browser run (headless Brave Origin 156 / Chromium 156, 2026-10-28)

Setup:
- Automated over the DevTools protocol with Node built-ins; nothing was installed. The
  driver scripts were temporary local tooling and are not in the repository; the results
  below are copied from their output.
- Isolated `app.server:app` on port 8001 with a temporary database and RPC unset.
- Dashboard production build served by `vite preview`.
- Unpacked extension loaded from a copy that differs only in the backend port.

Results (all checks passed, after fixing the test script's case-sensitive badge assertions):

| Scenario | Checks |
|---|---|
| Overview page renders | 1 passed |
| Dashboard and extension input validation (empty, invalid, `ftp:`, blank, over 2,000 characters) | 8 passed |
| URL: benign shows Inconclusive without a registry; IP login URL shows High risk | 4 passed |
| Message: harmless shows Likely legitimate / Low risk; smishing shows Likely smishing / Suspicious | 4 passed |
| URL history (newest first, expandable, registry status) and message history (no message text) | 2 passed |
| Backend down: errors, no verdict, hints, Try again | 4 passed (rerun after the text fix: 4 passed) |
| Hung backend: loading state, then a timeout error after 60 s (dashboard and extension) | 4 passed |
| Retakes: readable message explanation; one-line URL domain style restored | 3 passed |
| Console errors | none |

Bugs found and fixed during the run:
- The Vite proxy captured `/scanner` and `/messages`, so a direct load or reload of those
  pages returned the backend's JSON 404.
- The extension's message explanation was cut off to a single line.
- Error text could read "?. No result is available.".
- The header "registry" pill looked like a live status indicator.

Screenshots: `docs/submission/screenshots/` (items 1–11).

**Follow-up run (visible Brave window, Vite 6.4.5 build), 6 checks, all passed.**

Setup: a separate Brave Origin window with its own throwaway profile; the port-8001 test
backend with a fresh temporary database and no RPC configured; and the extension test copy
pointing at port 8001. This run does not verify the live port-8000 environment.
- The header label has no status dot and has an explanatory tooltip.
- The real toolbar popup opened. It was opened as an actual popup with
  `chrome.action.openPopup()`, not loaded as a tab: Chrome reported one popup view, 340×211.
  A URL scan through it showed Inconclusive with the registry unavailable. A registry-unavailable
  result is inconclusive; it is never evidence that a URL or message is safe.
- Backend down: the dashboard error appears once, with clean punctuation.
- Backend down: the toolbar popup showed an error, no verdict, and the button re-enabled.

## Dependency upgrade (dashboard, approved 2026-10-28)

- **Vite** 5.4.21 → **6.4.5**. The declared range in `frontend/dashboard/package.json` changed
  from `^5.4.10` to `^6.4.5`.
- **esbuild** 0.21.5 → **0.25.12**, Vite's own dependency. The lockfile changes are limited to
  Vite's tree: vite, esbuild and its per-platform optional binaries, plus Vite 6's new
  dependencies `fdir`, `picomatch` and `tinyglobby`.
- **React Router was not upgraded** (react-router-dom 6.30.6).
- Afterwards the production build succeeds, and the dashboard (6), shared-client (5) and
  extension (11) tests pass.
- **`npm audit`: 2 moderate advisories remain**, in `react-router` and `react-router-dom` 6.
  They are an open redirect through user-controlled link targets (all link targets in this app
  are fixed paths) and an SSR-hydration issue (the app does not use SSR). Fixing them needs
  react-router-dom 7, a major upgrade, which was deliberately deferred. Before the upgrade
  there were 4 advisories (3 moderate, 1 high). The dashboard is **not** advisory-free.

## Model verification (measured; validation splits only)

`.venv/bin/python -m src.evaluation.verify_production_models --out reports/model_verification_20261028.json`

- Both models reproduce their recorded validation metrics exactly.
- URL: precision 0.983, recall 0.942, F1 0.962.
- SMS: macro-F1 0.924.
- Details and historical test results: [ML_EVALUATION.md](ML_EVALUATION.md).

## Not performed

| Check | Status | Reason |
|---|---|---|
| Registry hit / "No issues detected" in the browser | **NOT PERFORMED** | Needs a configured RPC; the browser run kept RPC unset (covered by the fake-node API tests) |
| Clicking the toolbar icon by hand | **NOT PERFORMED** | The real toolbar popup was opened with `chrome.action.openPopup()` in a visible Brave window and driven over DevTools; a physical click was not automated |
| Live Sepolia read-only lookup and preflight | **NOT PERFORMED** | No `SEPOLIA_RPC_URL` on this machine |
| npm advisories | 2 open (moderate, react-router 6) | Fixing them needs react-router-dom 7 (major); deferred |
| Screenshot item 12 (registry `no_match`) | **NOT CAPTURED** | Needs a configured RPC |
| Browser UI against the live port-8000 backend | **NOT PERFORMED** | Browser runs used the port-8001 test backend so no test scans reached the live database |

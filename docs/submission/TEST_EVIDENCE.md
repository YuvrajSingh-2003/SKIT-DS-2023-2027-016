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
| Visible-browser run against **live Sepolia** (port-8001 test backend, read-only RPC) | Genuine registry hit (dashboard and real toolbar popup) and confirmed miss: all passed | The live port-8000 setup |
| Live port-8000 API checks after restart (curl) | Routes, scans and 422s as expected | Browser UI on port 8000 |
| **Live Sepolia** read-only checks | Contract verified; registry hit and miss confirmed (below) | The URL-manifest preflight (pending) |

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

## Live Sepolia registry verification (read-only, 2026-10-28 UTC)

**Contract checks** (view calls; RPC from the gitignored `.env`, never printed):
- Chain ID 11155111; contract code present at `0x62bFA47Fe851545365b152B746475925100CEc96`.
- `threatCount` is 7; owner is `0x74faB8279d61BEC35D9e95B72FAE96ee550B07cd`.
- The synthetic test URL `https://chainshield-test.invalid/registry-check` hashes (with the
  runtime functions) to `0xa8472757acafcc048ff051b4bd6e8e4b9cb903b39027d4ed8720fc5a2105c65e`.
  The contract holds that hash with threatType 1 (URL), verdict 1, confidence 100.
- The examples in `contracts/docs/BLOCKCHAIN_INTEGRATION_SPEC.md` are not registered. Five of its
  nine example hashes also differ from the runtime hashing, which is an open documentation defect.
- The other six entries were not identified. The RPC provider's free tier limits `eth_getLogs`
  to 10 blocks per request, so they could not be enumerated.

**Smishing manifest preflight:** reported by the owner from a run on another machine (Fedora):
433 of 433 proposed hashes were misses, and the contract reported 7 entries. The preflight output
was not reviewed here; the 7-entry count was confirmed independently above. The **URL manifest
preflight is pending**: `proposed_phishing_urls.json` (untracked) was not present on that machine.

**Browser run 3** (visible Brave window, throwaway profile):
- Setup:
  - test backend `app.server:app` on port 8001 with a fresh temporary database
    (`CHAINSHIELD_DATABASE_URL`) and the read-only RPC;
  - a production dashboard build pointing at 8001;
  - a scratch extension copy whose only change is the port (8001).
- For each scan, the actual `POST /scan` response was captured over DevTools and compared
  with the rendered UI.

| Scenario | API response (captured) | Rendered UI |
|---|---|---|
| Dashboard, registry hit | `risk_level` HIGH, `decision_source` blockchain, `blockchain_status` match_threat, `ml_status` not_run, registry available, no error | "✕ High risk"; "This URL's hash was found in the blockchain threat registry."; finding "Blockchain registry identifies this URL as a threat" (matches the response's findings exactly) |
| Real toolbar popup (one popup view, not a tab), registry hit | Same four fields | "✕ High risk"; "URL hash found in the threat registry."; same finding |
| Dashboard, `https://www.wikipedia.org` | `blockchain_status` no_match, registry available, no error (a confirmed miss, not an RPC failure); the model then ran: `risk_level` SAFE, `ml_status` ok | "✓ No issues detected"; "Registry checked — this URL's hash was not found. Note: absence from the registry does not guarantee the URL is safe." |

**Test-script correction:** the first dashboard-hit check failed. The script compared each
finding's rendered text, which includes the "⚠" icon, with the bare text. This was a fault in the
test harness, not in the application: the badge, registry message and API fields in the same
check were correct. The check was corrected to compare the finding text, without the icon,
against the captured response, and a fresh scan in a new tab passed. The screenshot from the
first scan was kept.

**State after the run:**
- The live backend (PID 90415, port 8000) kept running, untouched.
- The live database's checksum (`dfa3dbbf…`), modification time and counts (4 URL scans,
  2 message scans) were unchanged.
- `threatCount` was still 7. No transaction was signed or sent, and no key was loaded.
- All test processes were stopped.

Screenshots: `12-registry-no-match.png`, `13-dashboard-registry-hit.png`,
`14-extension-registry-hit.png`.

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
| Clicking the toolbar icon by hand | **NOT PERFORMED** | The real toolbar popup was opened with `chrome.action.openPopup()` in a visible Brave window and driven over DevTools; a physical click was not automated |
| URL-manifest registry preflight (`proposed_phishing_urls.json`) | **NOT PERFORMED** | The manifest is untracked and was not on the machine where the smishing preflight ran |
| npm advisories | 2 open (moderate, react-router 6) | Fixing them needs react-router-dom 7 (major); deferred |
| Browser UI against the live port-8000 backend | **NOT PERFORMED** | Browser runs used the port-8001 test backend so no test scans reached the live database |

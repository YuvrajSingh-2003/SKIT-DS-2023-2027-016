# ChainShield — Screenshot Checklist

All screenshots are real captures of the application, taken on 2026-10-28 (UTC; run 3 at
19:16 UTC), in `docs/submission/screenshots/`. No screenshot was edited.

**Test configuration** (not the live port-8000 setup):
- Every screenshot used a separate `app.server:app` test backend on **port 8001** with a fresh
  temporary SQLite database. The live backend and database were not used.
- Runs 1 and 2 had **no RPC configured**. Run 3 (items 12–14) used a read-only Sepolia RPC.
- The dashboard was a production build served by `vite preview`.
- The extension was a test copy of `frontend/extension/` whose only change was the backend port
  (8001). Screenshots that show an error hint therefore display `127.0.0.1:8001`.
- In runs 1 and 2 every result therefore shows the threat registry as unavailable. That is an
  inconclusive state, never evidence that a URL or message is safe.

**Two capture runs:**
- **Run 1, headless:** Brave Origin 156 (Chromium 156), driven over the DevTools protocol, Vite
  5.4.21 build. Extension screenshots in this run are of `popup.html` opened as a browser tab
  (same files and extension origin, but not the toolbar popup).
- **Run 2, visible window:** Brave Origin 156, Vite 6.4.5 build. The real toolbar popup was
  opened with `chrome.action.openPopup()`, and Chrome reported it as a popup view.
- **Run 3, visible window, live Sepolia (read-only):** the same setup as run 2, with the test
  backend reading a Sepolia RPC from the gitignored `.env`. The browser's actual `POST /scan`
  response was captured over DevTools and compared with the rendered UI.

## Evidence index

| File | Shows | Source | Visible limitations | SHA-256 (first 16) |
|---|---|---|---|---|
| `01-overview.png` | Overview page and navigation | Dashboard, run 1 | Header pill has the old status dot. The page text is outdated (see note A) | `5166d7158121898e` |
| `02-url-legitimate.png` | `https://www.wikipedia.org` → "? Inconclusive"; "registry … not reachable … does not indicate the URL is safe" | Dashboard, run 1 | Header dot | `94708367ead5e042` |
| `03-url-suspicious.png` | IP login URL → "✕ High risk", 7 findings including the advisory-model notes | Dashboard, run 1 | Header dot | `5d1ee3a8e0e0ccab` |
| `04-sms-harmless.png` | Harmless message → "Likely legitimate (model prediction)", "· Low risk", scores, registry unavailable | Dashboard, run 1 | Header dot | `5cda8116fbe6b0dc` |
| `05-sms-smishing.png` | Smishing example → "Likely smishing (model prediction)", "! Suspicious", link and urgency signs | Dashboard, run 1 | Header dot | `348d395a11691680` |
| `06-url-history.png` | URL history, newest first; row expanded with registry status | Dashboard, run 1 | Header dot. Row #1's badge is cut off as "? INCONCLU" (see note B) | `95e7473b7e47f793` |
| `07-message-history.png` | Message history table: metadata only, no message text | Dashboard, run 1 (viewport retake) | Header dot. Four rows, from the test database | `1059824ee1ec6a8c` |
| `08-unavailable.png` | Backend stopped → "Scan failed: … No result is available."; history error | Dashboard, run 1 (retake after the punctuation fix) | Header dot | `c5bd38a445a76be4` |
| `08-unavailable-v2.png` | Same scenario, current build | Dashboard, run 2 | Mouse hover highlight on "Overview" | `0806d59c7b9bc4ef` |
| `09-extension-url.png` | URL mode → "? Inconclusive", "registry unavailable … does not indicate safety" | Extension `popup.html` as a tab, run 1 | Not the toolbar popup | `d6b053d8402061b0` |
| `09-extension-url-toolbar-popup.png` | Same scan in the **real toolbar popup** | Extension toolbar popup, run 2 | None noted (high-DPI capture) | `c872c1ab6a934859` |
| `10-extension-message.png` | Message mode → "! Likely smishing" (amber), wrapped explanation, scores | Extension `popup.html` as a tab, run 1 (retake after the wrapping fix) | Not the toolbar popup | `a1cb99723a9a360b` |
| `11-extension-error.png` | Backend stopped → "Cannot reach the ChainShield backend. No result is available." | Extension `popup.html` as a tab, run 1 | Shows `127.0.0.1:8001`. Not the toolbar popup | `719c51de6b33decb` |
| `11-extension-error-v2.png` | Same error in the **real toolbar popup**; no verdict shown | Extension toolbar popup, run 2 | Shows `127.0.0.1:8001` | `62fb8e1082599376` |

| `12-registry-no-match.png` | `https://www.wikipedia.org` → confirmed registry miss (`no_match`, registry available, no error); the model then ran → "✓ No issues detected"; registry box "Registry checked — this URL's hash was not found. Note: absence from the registry does not guarantee the URL is safe." | Dashboard, run 3 (live Sepolia, read-only) | None noted | `d52fdb6a9377d745` |
| `13-dashboard-registry-hit.png` | `https://chainshield-test.invalid/registry-check` → **genuine Sepolia registry hit**: "✕ High risk"; "This URL's hash was found in the blockchain threat registry."; finding "Blockchain registry identifies this URL as a threat" | Dashboard, run 3 | None noted | `1961d0c63d0ffc6b` |
| `14-extension-registry-hit.png` | Same genuine hit in the **real toolbar popup**: "✕ High risk", "URL hash found in the threat registry.", same finding | Extension toolbar popup, run 3 | The URL input is scrolled, so it reads "…eld-test.invalid/registry-check"; the result line shows the full domain | `4347f09e116a132c` |

For items 8, 9 and 11, prefer the run-2 files (`-v2` / `-toolbar-popup`). The registry-hit
input is the project's synthetic test record (a `.invalid` domain); the browser never visits it.

**Note A.** The Overview page's descriptive text predates the current design. It describes risk
levels as "Safe · Medium · High" calculated from a count of findings, and it does not mention the
advisory URL model, message scanning or the Inconclusive result. Fixing it is an application
change and was outside the documentation cleanup. Open item.

**Note B.** In URL history, a long badge such as "Inconclusive" is cut off by the risk column's
width. This is a display issue in the dashboard; it is open.

## Pending

| # | File | Needs | Status |
|---|---|---|---|
| — | Toolbar popup opened by a manual click on the icon | A person at the browser | **Not performed** |
| — | Any browser check against the live port-8000 backend | A person, with test scans accepted in the live history | **Not performed** |

Completed in run 3: item 12 (`12-registry-no-match.png`) and the registry hit (13, 14).

None of the screenshots above shows the live port-8000 environment.

## How to capture (for retakes)

Rules: use only the synthetic inputs below. Never show real messages, personal data, API
keys, `.env` contents or private keys on screen; close terminals and other tabs. Expected
results for each scenario: `docs/RELEASE_CHECKLIST.md` §7.

| # | File | Page | Action | Expected |
|---|---|---|---|---|
| 1 | `01-overview.png` | `/overview` | Open | Overview page with navigation |
| 2 | `02-url-legitimate.png` | `/scanner` | Scan `https://www.wikipedia.org` | No RPC: "? Inconclusive" and "registry unavailable"; with RPC: "✓ No issues detected" |
| 3 | `03-url-suspicious.png` | `/scanner` | Scan `http://192.168.1.1/login/verify/account` | "✕ High risk" with heuristic findings |
| 4 | `04-sms-harmless.png` | `/messages` | Scan `See you at the station at 6` | "Likely legitimate (model prediction)", "· Low risk", model scores |
| 5 | `05-sms-smishing.png` | `/messages` | Scan `Your bank account is suspended. Verify now at http://secure-bank-login.example` | "Likely smishing (model prediction)", "! Suspicious", link finding |
| 6 | `06-url-history.png` | `/history` | Open, expand a row | URL rows with registry statuses |
| 7 | `07-message-history.png` | `/messages` | Scroll to history | Metadata only, no message text |
| 8 | `08-unavailable.png` | `/messages` | Stop the backend, then scan | "Scan failed: … No result is available." |
| 9 | `09-extension-url.png` | Extension toolbar popup, URL mode | Scan `https://www.wikipedia.org` | Result with a registry line |
| 10 | `10-extension-message.png` | Extension toolbar popup, Message mode | Scan the smishing example | "! Likely smishing" and scores |
| 11 | `11-extension-error.png` | Extension toolbar popup | Stop the backend, then scan | "Cannot reach the ChainShield backend" |
| 12 | `12-registry-no-match.png` | `/scanner`, with RPC configured | Scan a benign URL | Registry "not found … does not guarantee safety" |

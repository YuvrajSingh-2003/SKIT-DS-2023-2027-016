# ChainShield — Screenshot Checklist

No screenshots have been captured: this environment has no browser. Capture these
from the real running application after switching the backend to `app.server:app`
(see `docs/RELEASE_CHECKLIST.md` §1). Save them in `docs/submission/screenshots/`.

Rules: use only the synthetic inputs below; no real messages, personal data, API keys,
`.env` contents, or private keys anywhere on screen (close terminals and other tabs).

| # | File | Page | Action | Expected |
|---|---|---|---|---|
| 1 | `01-overview.png` | http://localhost:5173/overview | Open | Overview page with navigation |
| 2 | `02-url-legitimate.png` | `/scanner` | Scan `https://www.wikipedia.org` | Result card; with no RPC: UNKNOWN + "registry unavailable"; with RPC: SAFE or UNKNOWN per registry |
| 3 | `03-url-suspicious.png` | `/scanner` | Scan `http://192.168.1.1/login/verify/account` | HIGH with heuristic findings |
| 4 | `04-sms-harmless.png` | `/messages` | Scan `See you at the station at 6` | "Likely legitimate (model prediction)", LOW, model scores |
| 5 | `05-sms-smishing.png` | `/messages` | Scan `Your bank account is suspended. Verify now at http://secure-bank-login.example` | "Likely smishing (model prediction)", MEDIUM, link finding |
| 6 | `06-url-history.png` | `/history` | Open | URL rows with registry statuses |
| 7 | `07-message-history.png` | `/messages` (history table) | Scroll to history | Metadata only, no message text |
| 8 | `08-unavailable.png` | `/messages` | Stop the backend, then scan | Error box "Scan failed… No result is available" |
| 9 | `09-extension-url.png` | Extension popup, URL mode | Scan `https://www.wikipedia.org` | Result with registry line |
| 10 | `10-extension-message.png` | Extension popup, Message mode | Scan the smishing example | "Likely smishing" badge and scores |
| 11 | `11-extension-error.png` | Extension popup | Backend stopped, scan | "Cannot reach the ChainShield backend" |

Optional with a configured RPC: `12-registry-no-match.png` showing `no_match` for a URL.

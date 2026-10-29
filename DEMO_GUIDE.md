# ChainShield — 10-minute demo

> **Status of the URL false-positive bug (2026-10-29, commit `c0b5544` + this guide): UNRESOLVED at
> the model level, mitigated in the UI.**
> - Bare domains such as `https://example.com/` and `https://wikipedia.org` are still scored
>   phishing (p = 0.9998) by the production model (SHA-256 `2f2e1d49…`, threshold 0.5, both
>   unchanged).
> - **Cause: training-data bias, not a code defect.** Feature order, class index, trailing-slash
>   normalization and train/serve parity are verified by regression tests.
> - **Mitigation already in place** (since `bef33c1`): the model is advisory. Its flag alone gives
>   MEDIUM, never HIGH, and the scan shows a finding explaining that the flag is unvalidated for this
>   URL shape.
> - Do **not** present these results as correct detections.

All inputs are **synthetic**. No real phishing site or real victim message is used.
- **Phishing-pattern URL:** uses a private IP (192.168.1.1), which never reaches the internet.
- **Smishing SMS:** links to the reserved `.example` domain (RFC 2606).
- **Benign inputs:** an ordinary site and an invented message.

The outputs below were observed with the pinned models on 2026-10-29.

| Input | Kind | Model output |
|---|---|---|
| `https://www.wikipedia.org` | benign URL | legitimate, p(phishing) = 0.019 |
| `http://192.168.1.1/secure/login.php?acct=1` | synthetic phishing *pattern* (not a known live site) | phishing, p = 1.0 |
| `Hi, are we still meeting for lunch at 1pm tomorrow?` | benign SMS | legitimate (0.991) |
| `URGENT: your bank account has been suspended. Verify your details now at http://secure-bank-verify.example/login or it will be closed.` | synthetic smishing | smishing (0.988) |

Do not describe the phishing-pattern URL as a "known malicious site". It is a constructed example
with typical phishing traits:
- `http` instead of `https`;
- an IP address instead of a domain name;
- the words `login` and `secure`.

## 0. One-command offline proof (no RPC, no network, temporary database)

```bash
.venv/bin/python -m src.evaluation.offline_smoke
```

- It runs every scenario below through the real route functions with the registry **mocked**, and
  prints PASS/FAIL per check (13 checks).
- Use it to show the control flow without any blockchain access.

## 1. Control flow

### URL scan (`POST /scan`)

| Step | Condition | Result |
|---|---|---|
| 1 | Read-only registry lookup of the canonical URL hash | — |
| 2a | Registry **threat match** | **HIGH**, `decision_source: blockchain`; the model is not consulted |
| 2b | Registry **miss** | Model runs (ML fallback). Heuristic findings set the base level. A model "phishing" label is **advisory**: it can raise SAFE to MEDIUM, never make HIGH on its own |
| 2c | Registry **unavailable** | Same as 2b, but a would-be SAFE becomes **UNKNOWN** |
| — | Model unavailable | **UNKNOWN**, never SAFE |

### Message scan (`POST /message/scan`)

| Condition | Result |
|---|---|
| Registry threat match | `smishing_registry_match`, HIGH |
| Model smishing | `likely_smishing`, MEDIUM |
| Model generic_spam | `generic_spam`, LOW |
| Model legitimate | `likely_legitimate`, LOW (never SAFE) |
| Model unavailable | UNKNOWN |

Message text is never stored; only metadata goes to history.

## 2. Live demo (dashboard or extension)

Start the backend and the dashboard from the repository root:

```bash
.venv/bin/uvicorn app.server:app --host 127.0.0.1 --port 8000          # terminal 1 (not main:app)
curl -s http://127.0.0.1:8000/                                          # {"message":"ChainShield Backend is Running!"}
cd frontend/dashboard && npm ci && npm run dev                          # terminal 2 -> http://localhost:5173
```

Chrome extension: `chrome://extensions` → Developer mode → Load unpacked → `frontend/extension/`.

Without `SEPOLIA_RPC_URL`, every scan shows the
registry as **unavailable**. That is the safe way to demonstrate the ML fallback: nothing is sent to
any chain.

| Input | Expected without RPC | Expected with RPC, if not registered (miss) |
|---|---|---|
| `https://www.wikipedia.org` | UNKNOWN (model legitimate; registry unavailable, so no SAFE) | SAFE |
| `http://192.168.1.1/secure/login.php?acct=1` | HIGH (6 findings: no HTTPS, IP host, keywords, plus model advisory) | HIGH |
| Benign SMS | `likely_legitimate`, LOW | same |
| Synthetic smishing SMS | `likely_smishing`, MEDIUM | same |

**Registry *hit*:**
- Show it with the smoke test (mocked), not on-chain.
- Live hits only happen for URLs/messages already in the deployed registry. Do **not** submit
  transactions or run the seeder for a demo.
- Registry lookups during scans are read-only `view` calls. Only `src/blockchain/seed_registry.py`,
  `submit_reviewed_batch.py` and `deploy.py` send transactions, and they need a private key, which
  is not needed for the demo.

## 3. The URL-shape false positive: reproduce, explain, show the guardrails (3 minutes)

### 3a. Reproduce live (registry miss or unavailable)

| Input | Model p(phishing) | Model label | Risk shown | Correct? |
|---|---|---|---|---|
| `https://www.example.com/` | 0.0122 | legitimate | SAFE (UNKNOWN without RPC) | yes |
| `https://example.com/` | **0.9998** | phishing | **MEDIUM**, with an "unvalidated for this URL shape" finding | **no: known false positive** |
| `https://example.org/` | **0.9998** | phishing | **MEDIUM**, with the same finding | **no: known false positive** |
| `https://www.wikipedia.org` | 0.0190 | legitimate | SAFE (UNKNOWN without RPC) | yes |
| `https://wikipedia.org` | **0.9998** | phishing | **MEDIUM**, with the same finding | **no: known false positive** |
| `http://192.168.1.1/secure/login.php?acct=1` (synthetic) | 1.0 | phishing | HIGH (heuristics: no HTTPS, IP host, keywords) | yes: phishing *pattern* |

### 3b. Why URL formatting causes it

- In the PhiUSIIL training data, **all 134,850 legitimate URLs are `https://www.<host>`** with no
  path.
- The feature `NoOfSubDomain` counts `www` (`src/features/url_lexical.py:126`), so `example.com` → 0
  and `www.example.com` → 1.
- No legitimate training URL has 0, so the model learned "no `www` ⇒ phishing".
- Changing only that feature moves `example.com` from 0.9998 to 0.0106.
- On real held-out legitimate URLs without the template (Hannousse 2021), the model flags **98.2%**.
- Evidence: `docs/url_shape_guard.md`, `docs/url_feature_investigation.md`.

### 3c. What has and has not been fixed

| Item | Status |
|---|---|
| Code defect (parsing, feature order, class index, slash, parity) | **None found**; each is covered by a regression test |
| UI honesty: the model flag is advisory and explained for untrained shapes | **Done** (`bef33c1`) |
| Shape regression guard in CI | **Done.** The production model is exempt only by its exact checksum |
| Model fix | **Not done.** Eight retrained or alternative candidates (c4–c8, H1, L1, L2) all failed the predeclared acceptance gates. The binding limit is licensed, representative legitimate data (`docs/legitimate_url_collection_plan.md`) |

### 3d. Offline fallback (no UI, no network)

```bash
.venv/bin/python -m pytest -q tests/test_url_shape_false_positive.py    # 31 passed: reproduces + pins the behaviour
.venv/bin/python -m pytest -q -rsP tests/test_url_shape_guard.py | grep EVALUATED
#   URL-SHAPE-GUARD EVALUATED model_sha256=2f2e1d49… status=known_failing flag_rate={… drop_www 0.8445 …}
.venv/bin/python -m src.experiments.url_shape_false_positive_eval       # rows 1-5 of 3a (the IP row is checked by the smoke test)
.venv/bin/python src/evaluation/offline_smoke.py                        # 13/13; includes the known issue
```

The guard figures are controlled stress tests on transformed URLs, **not** real-world
false-positive rates.

## 4. Things not to claim

- That a candidate model is better in the real world. None was promoted.
- That the reputation pre-check reduces false positives. It is unmeasured and **disabled**.
- That the SMS model is production-grade. On the external IMC set it caught about 70% of smishing and
  none of the "hey mum/dad" scams (README).

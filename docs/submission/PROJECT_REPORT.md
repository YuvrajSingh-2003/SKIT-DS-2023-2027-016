# ChainShield — Project Report

Status as of 2026-10-28. Every number below comes from a saved artifact or a recorded
test run (see TEST_EVIDENCE.md and ML_EVALUATION.md). Nothing here has been verified in a
browser or against the live Sepolia network.

## 1. Objectives

Detect phishing URLs and smishing (SMS phishing) messages, explain the evidence behind
each result, and use a blockchain registry as a tamper-evident list of known threats,
without ever reporting a failed check as safe.

## 2. Contributions

1. A combined detector for URLs (heuristics + advisory XGBoost model + registry lookup)
   and messages (three-class SMS model + registry lookup).
2. A hash-only threat registry (`contracts/ThreatRegistry.sol`): only Keccak-256 hashes of
   canonicalized inputs are stored; the API makes read-only view calls.
3. Fail-closed behavior: model, registry and database failures surface as UNKNOWN or
   explicit errors; models load only after pinned SHA-256 checks.
4. A reproducible, leakage-aware ML workflow: dataset licence and label verification,
   label-conflict exclusion, near-duplicate-aware group splits, a training guard that
   rejects external-evaluation data, one-time locked test evaluation, and an external
   benchmark.
5. Privacy by design: message text is never stored, logged or sent anywhere (only its hash
   is used for a registry lookup).

## 3. System

Architecture diagrams: [ARCHITECTURE.md](ARCHITECTURE.md). Full guide, API reference
and configuration: [../SYSTEM.md](../SYSTEM.md).

- Backend: FastAPI, `app.server:app` (`/scan`, `/scan/history`, `/message/scan`,
  `/message/history`), SQLite.
- Clients: React/Vite dashboard; Chrome Manifest V3 extension (no permissions, one host).
- Blockchain: ThreatRegistry on Sepolia (`contracts/configs/contract_addresses.json`).

## 4. Data

| Dataset | Use | Licence |
|---|---|---|
| PhiUSIIL Phishing URL (UCI) | URL model | CC BY 4.0 |
| Mishra & Soni SMS Phishing (Mendeley) | SMS model | CC BY 4.0 |
| IMC 2025 "Fishing for Smishing" | external evaluation only | CC BY 4.0 |

Details, checksums and label mappings: [../datasets.md](../datasets.md). Excluded:
`vinit9638` (no licence) and SmishTank (terms unverified).

## 5. Method and evaluation

**SMS model.** 5,971 rows → 5,762 after excluding 34 exact and 19 near-duplicate label
conflicts and removing duplicates; group-aware 70/15/15 split (seed 42); TF-IDF character
2–5-grams + logistic regression; four candidates compared on validation only.

| Evaluation | Result |
|---|---|
| Locked internal test (865 messages, evaluated once) | macro-F1 0.893 [0.840, 0.932]; smishing precision 0.892, recall 0.857; legitimate→smishing 0/725; generic spam→smishing 8/63 |
| IMC 2025 external (GPT-4o labels, recall only) | smishing recall 0.697 [0.668, 0.725]; "hey mum/dad" 0/55; delivery 0.44 |

Intervals: group bootstrap over near-duplicate groups (2,000 replicates).

**URL model.** XGBoost on lexical features of PhiUSIIL; stratified test phishing F1 0.963.
This figure is inflated: every legitimate URL in the dataset is `https://www.<domain>`, and
a one-line rule based on that template outperformed the model on validation. The model is
therefore used only as an advisory signal.

**Re-verification (measured 2026-10-28, validation splits).** Both production models reproduce
their recorded validation metrics exactly. The API's per-request URL scores equal batch scores.
None of the 20,227 legitimate validation URLs has a path, against 4,214 of the 15,078
phishing URLs, which confirms the template bias. A small number of URLs (26 to 124 per split
pair) appear in two splits after canonicalization. Details: [ML_EVALUATION.md](ML_EVALUATION.md).

## 6. Privacy and security

- No message text in storage, logs, responses or registry calls (verified in isolated runs).
- Read-only blockchain access; no signing key in the API; chain ID and contract checked.
- Pinned SHA-256 for both models before deserialization.
- Input validation (422 on malformed input; 2,000-character message limit).
- CORS restricted to configured origins; extension requests no permissions.
- Not implemented: authentication and rate limiting (local use only).

## 7. Limitations

- The SMS model misses many current scam styles (see §5); it is a research baseline.
- The URL model reflects a dataset artifact and is not reliable on its own.
- English only.
- The locked test set and IMC 2025 have both been used; confirming any new model needs a
  new, untouched test set.

## 8. Verification status

| Item | Status |
|---|---|
| Automated tests (Python, extension, dashboard, shared client; counts in TEST_EVIDENCE.md) | passed |
| Contract compile and deployment-script tests (mocked) | passed |
| Isolated end-to-end API runs | passed |
| Dashboard and extension in a browser (automated; port-8001 test backend; real toolbar popup in a visible window) | passed (see TEST_EVIDENCE.md) |
| Manual browser check against the live port-8000 setup | **not yet performed** |
| Registry hit / "No issues detected" shown in a browser | **not yet performed** (needs RPC) |
| Dashboard dependencies | Vite 6.4.5; **2 moderate npm advisories remain** (react-router 6; upgrade deferred) |
| Registry hit / miss / unavailable through the real Web3 stack (local fake Sepolia node) | passed |
| Live Sepolia read-only lookups | **not yet performed** (no RPC configured) |
| Running server switched to the new backend | done 2026-10-28 (verified backup; five routes checked) |

## 9. Future work

1. New, licensed smishing data covering conversational and recent scams, with a fresh test set.
2. A URL dataset without the template bias.
3. Authentication, rate limiting and deployment hardening before any public use.
4. Pinned dependencies and frontend component tests.

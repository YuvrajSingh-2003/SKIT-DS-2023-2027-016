# URL safety engineering — log (2026-10-29, branch `feature/url-shape-guard`)

## Inspection

- **Serving path:** `app/routes/scan.py` → registry (decisive on threat) → `ml_detector.predict_phishing`.
  The model is advisory: it can raise SAFE to MEDIUM, never to HIGH.
- **Model:** pinned by SHA `2f2e1d49…`.
- **Gaps found:**
  - `*.joblib` is gitignored, so CI has no model.
  - The only workflow was the weekly report; no CI ran tests.
  - No PyYAML or tldextract is installed, so the config is JSON and there is no PSL.
  - No top-sites list exists locally.

## Phase 1 — URL-shape guard

**Added:**
- `src/evaluation/url_shape_guard.py`
- `configs/url_shape_guard.json`
- `tests/test_url_shape_guard.py` (13 tests after finalization)
- `.github/workflows/url_shape_guard.yml`
- `docs/url_shape_guard.md`

**Commands:**
```
python -m src.evaluation.url_shape_guard
python -m src.evaluation.url_shape_guard --candidate models/candidates/url/c1_xgb_neutral
python -m src.evaluation.url_shape_guard --candidate models/candidates/url/c2_xgb_host
python -m src.evaluation.url_shape_guard --candidate models/candidates/url/c2_xgb_host --threshold 0.7366147041320801
```

**Results:** in `docs/url_shape_guard.md`.
- Production is `known_failing`: drop_www 84.5%, others ~100%.
- c1 fails on path/query (100%).
- c2@0.5 fails the 5% ceiling (5.65%).
- c2@0.7366 passes (1.05%).

So the criterion separates shortcut models from shape-robust ones, and a shape-robust model can meet
it.

**Bug the tests caught:** a path suffix ("spring-update") contained a suspicious keyword. It was
replaced and all runs were repeated.

## Phase 2 — Reputation pre-check (disabled by default)

**Added:**
- `app/services/reputation_precheck.py`
- `tests/test_reputation_precheck.py` (38 tests)
- `src/experiments/reputation_precheck_bypass.py`

**Route change** (`app/routes/scan.py`, +17/−3):
- Applies only when the model says phishing **and** the pre-check applies.
- Effect: the model advisory is withheld, and a SAFE result becomes UNKNOWN.
- The registry is still decisive, and heuristic risk still counts.
- When disabled (the default), the route behaves exactly as before. A test covers this.

**Offline evaluation:**
- **False-positive reduction: BLOCKED.** No licensed popularity list is available locally, and
  downloading one needs permission.
- **Bypass bound** (`python -m src.experiments.reputation_precheck_bypass`): how often the pre-check
  would withhold the advisory for *known phishing*, if the list contained the phishing domains.

| Scenario | OpenPhish 2026-10-28 (300) | PhiUSIIL val phishing (15,078) |
|---|---|---|
| Every exact host listed (absolute worst case) | 64.7% | 71.9% |
| Every registrable domain (last 2 labels) listed | 14.7% | 31.3% |

- The path, subdomain and hosting-platform rules stop about 85% of current OpenPhish URLs, *even if*
  the parent domain is listed.
- The other ~15% are bare homepages on the attacker's own apex domain. Those bypass only if the list
  contains the attacker's domain.
- So the residual risk is set by **list quality**. It must be measured against a real list before
  enabling: count list entries that appear in phishing feeds.

## Phase 3 — Legitimate-URL pipeline

**Added:**
- `src/data/url_eval_pipeline.py`
- `tests/test_url_eval_pipeline.py` (10 tests)
- `docs/url_data_acquisition_plan.md`

**Status:**
- **No data acquired**; network retrieval needs permission.
- The pipeline enforces a provenance sidecar, verified licence and checksum. It canonicalizes with the
  existing canonicalizer, dedupes, drops label conflicts, and removes URL- and host-level overlap with
  the PhiUSIIL splits.
- Output is marked `evaluation_only` and is immutable.

## Phase 4 — Hygiene

- Branch `feature/url-shape-guard` was created from `feature/complete-detection-pipeline` with
  `git switch -c`.
- Unrelated untracked files under `data/threat_registry/proposed_*.json` were left alone and not
  committed.
- Model binaries are gitignored; candidate `config.json` files carry the checksums.
- **Tests:** `.venv/bin/python -m pytest -q` → **682 passed** (was 624; +58 new).
  `CHAINSHIELD_REQUIRE_MODELS=1 pytest tests/test_url_shape_guard.py -k deployed` → passed.
- **Production SHAs unchanged:** URL `2f2e1d49…`, SMS `9f753dd5…`.
- `src/blockchain`, `contracts` and `data/threat_registry` are untouched.

## Finalization (2026-10-29)

**Decisions recorded:**
- 5% / 3-point limits retained as **provisional engineering guardrails**, not validated real-world
  thresholds.
- Production exemption limited to SHA `2f2e1d49…` and documented as a known failure. It is never
  extended automatically.
- Pre-check stays disabled.
- No external downloads.

**Changes:**
- The guard fails if any transformation is unmeasured.
- CI reports evaluated / skipped / required-but-missing distinctly:
  - annotations and step summary;
  - `pytest -rsP` with an `EVALUATED model_sha256=…` line;
  - both missing-model paths unit-tested via a non-existent path.
- Pre-check docstring corrected. It does suppress the model warning, and SAFE becomes UNKNOWN.
- Pipeline test asserts that the manifest provenance and dedupe fields are present.

**Tests:**
- Full suite: **685 passed**. That is 624 before this branch plus 61 new: 13 guard + 38 pre-check +
  10 pipeline.
- The earlier "682 / 58 new" was accurate at `b69f4fd`, but the per-file split above it said 40
  pre-check tests; the actual count is 38.
- With `CHAINSHIELD_REQUIRE_MODELS=1`: 13/13 guard tests passed, with the deployed model evaluated.

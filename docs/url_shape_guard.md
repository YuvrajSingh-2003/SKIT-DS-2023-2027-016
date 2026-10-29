# URL-shape regression guard

**What it is:** a *controlled stress test*.
- It takes 2,000 legitimate validation URLs (PhiUSIIL `stratified_validation.csv`, sha `3d10e183…`,
  seed 42).
- It applies four transformations to each one and measures how often the URL model flags the result
  as phishing.
- The transformed URLs are synthetic, so the rates measure **shape dependence**. They are **not
  real-world false-positive rates**. A real FPR needs the time-stamped evaluation set described in
  `docs/url_data_acquisition_plan.md`.

## Transformations

All four non-control transformations must be measured. If any one is missing, including for the exempt
model, the check fails. Every run records the evaluated model's SHA-256:
- in `reports/url_shape_guard/*_summary.json` (`model_sha256`);
- in the CI log line `URL-SHAPE-GUARD EVALUATED model_sha256=…`.

All are deterministic. Each URL's suffix is chosen from its SHA-256. Every suffix is checked against
the feature code's suspicious keywords.

| Name | Change |
|---|---|
| `as_is` | none (control) |
| `drop_www` | `https://www.x.com` → `https://x.com` |
| `http_scheme` | `https://` → `http://` |
| `add_path` | `+ /about`, `/careers`, `/blog/2024/05/spring-recipes`, … |
| `add_query` | `+ /?q=news`, `/?utm_source=newsletter`, … |

The per-URL record is in `reports/url_shape_guard/<model>_cases.csv`: original URL, transformation,
transformed URL, probability and label.

## Criterion (`configs/url_shape_guard.json`)

**Status:** provisional engineering guardrails, retained by decision on 2026-10-29.
- They are **not** validated real-world performance thresholds.
- Revisit them once a representative, time-stamped evaluation set exists.

- Flag rate ≤ **5%** for every transformation.
- Rate minus the `as_is` rate ≤ **3 points**.

**Evidence** (validation, `reports/model_optimization/model_comparison.md`):

| Model | Rates |
|---|---|
| production | 1.24% in-template |
| c1 (scheme/www stripped) | 3.07% |
| c2 (host only) | 6.0% at threshold 0.5, 1.17% at threshold 0.737 |
| production shortcut | 85–100% off-template |

**Trade-off:** a tighter ceiling forces a higher threshold and loses recall. c3 meets 1.2% but catches
only 54% of test phishing. A looser ceiling lets partial shortcuts pass. Raise or lower the values in
the config; the tests read them.

## Measured (2026-10-29)

`python -m src.evaluation.url_shape_guard [--candidate DIR] [--threshold T]`

| Model | as_is | drop_www | http | path | query | Result |
|---|---|---|---|---|---|---|
| production `2f2e1d49` @0.5 | 1.3% | 84.5% | 100% | 100% | 99.95% | known_failing (exempt) |
| c1_xgb_neutral @0.5 | 3.1% | 3.1% | 3.1% | 100% | 100% | fail |
| c2_xgb_host @0.5 | 5.65% | 5.65% | 5.65% | 5.65% | 5.65% | fail (ceiling) |
| c2_xgb_host @0.7366 | 1.05% | 1.05% | 1.05% | 1.05% | 1.05% | pass |

## Production exemption

- The deployed model fails the target. The test would fail on every run unless that artifact is
  exempted.
- **Status: documented known failure.** The production model has the shape shortcut.
- The exemption is never extended automatically. A new checksum must meet the ceilings, or get a new,
  reviewed config entry.
- `known_failing_models` exempts **only SHA `2f2e1d49…`**, and only within a ratchet: recorded rates
  + 0.02.
- CI fails if:
  - its rates get worse;
  - any other (retrained) artifact misses the ceilings;
  - the exempt artifact starts passing. In that case, delete the stale entry.

## CI

- `.github/workflows/url_shape_guard.yml` runs the guard, the pre-check and the pipeline tests.
Three CI outcomes are reported distinctly:
- **evaluated:** the CI log shows `URL-SHAPE-GUARD EVALUATED model_sha256=…`, and the step summary
  says "evaluated".
- **intentional skip:** the artifact is absent and `CHAINSHIELD_REQUIRE_MODELS` is not 1. You get a
  `::warning::` annotation, a "SKIPPED — not evaluated" step summary, and a skip reason listed by
  `pytest -rs`.
- **required but missing:** `CHAINSHIELD_REQUIRE_MODELS=1` (repository variable) and no artifact. You
  get a `::error::` annotation, and the test fails. Both missing-model paths are unit-tested against a
  non-existent path.

- `*.joblib` is gitignored, so on CI the deployed-model test **skips**. The logic tests, including a
  synthetic shape-dependent model that must fail, still run.
- To enforce the model check, provision the artifact and set `CHAINSHIELD_REQUIRE_MODELS=1`. A
  missing model then fails instead of skipping. Locally the artifact exists, so the test runs.

## Related: reputation pre-check (`app/services/reputation_precheck.py`)

- **Disabled by default.** It is enabled only by `CHAINSHIELD_REPUTATION_PRECHECK=1` plus a local list
  file. It must not be enabled in production without representative evaluation data.
- **What it does when it applies:** it applies only to a bare homepage of an exactly-listed,
  non-hosting domain, and only when the model says "phishing".
  - It **suppresses the model's phishing warning**: the advisory finding is replaced by a note, and the
    advisory no longer raises SAFE to MEDIUM.
  - A result that would otherwise be SAFE becomes **UNKNOWN**. Popularity never produces SAFE.
  - Heuristic findings still set MEDIUM/HIGH.
  - The registry is checked first; a threat match returns HIGH, and the model and pre-check are not
    consulted.
- **False-positive reduction:** unmeasured, because no licensed list is available.
- **Bypass risk:** depends on the list's contents; see `reports/model_optimization/url_safety_log.md`.

## Observed false positive: `https://example.com/` (investigated 2026-10-29)

### Report

The dashboard showed "Suspicious" for `https://example.com/` and `https://example.org/`, with the
finding "URL model predicts phishing". It showed no issues for `https://www.example.com/`. All three
use HTTPS with a root path and no IP address, and the registry reported no match.

### Reproduction

- **Model and pipeline evaluated:** pinned production model (SHA `2f2e1d49…`), with the same feature
  path as serving (`ScanRequest` → `extract_lexical_url_dataframe` → `predict_proba[:, 1]`) and the
  registry mocked as a miss.
- **Command:** `python -m src.experiments.url_shape_false_positive_eval`. The output is in
  `reports/model_optimization/results/url_shape_false_positive_eval.json`.

| Input | Served as | p(phishing) | Model | Heuristic findings | Risk | Shape note |
|---|---|---|---|---|---|---|
| `https://example.com` | `https://example.com/` | 0.9998 | phishing | none | MEDIUM | yes |
| `https://example.com/` | same | 0.9998 | phishing | none | MEDIUM | yes |
| `https://www.example.com` | `https://www.example.com/` | 0.0122 | legitimate | none | SAFE | no |
| `https://www.example.com/` | same | 0.0122 | legitimate | none | SAFE | no |
| `https://example.org/` | same | 0.9998 | phishing | none | MEDIUM | yes |
| `https://www.wikipedia.org` | `https://www.wikipedia.org/` | 0.0190 | legitimate | none | SAFE | no |
| `https://wikipedia.org` | `https://wikipedia.org/` | 0.9998 | phishing | none | MEDIUM | yes |

The scores and risk levels are identical before and after this change. The only difference is the
added note.

### Root cause (confirmed)

**It is the model's learned shortcut, not the application pipeline.** Ruled out:
- **Trailing slash / normalization:** `ScanRequest` turns `https://example.com` into
  `https://example.com/`, and the feature code strips a root slash, so the features are identical.
- **Feature order:** `metadata.feature_names` equals `LEXICAL_URL_FEATURES`. This is checked at load.
- **Class index:** `classes_ == [0, 1]`, and the training target is phishing = 1. The detector now
  also refuses a model whose classes are not exactly `[0, 1]`.
- **Thresholds and aggregation:** the threshold is 0.5. The heuristics report nothing for these URLs.
  MEDIUM comes only from the advisory model label.
- **The guard:** `url_shape_guard` runs in tests and CI only. It does not, and never did, affect
  inference.

**Demonstrated cause:**
- `www.` makes `NoOfSubDomain` 1 instead of 0. Changing only that feature moves `example.com` from
  0.9998 to 0.0106.
- In `stratified_train.csv`, **0 of 94,395** legitimate URLs have `NoOfSubDomain = 0`, compared with
  9,702 phishing URLs. A bare apex domain is therefore phishing by construction of the PhiUSIIL data.

### Candidate fix evaluated and rejected

**Candidate:** "if the URL shape is outside the trained legitimate shape and only the model says
phishing, report UNKNOWN instead of MEDIUM".

**Effect** (same command):

| Set | MEDIUM → UNKNOWN |
|---|---|
| validation phishing | 5,799 / 15,078 (38.5%) |
| OpenPhish 2026-10-28 snapshot (local-only, licence review pending) | 135 / 300 (45.0%) |
| validation legitimate | 0 (all are in-template) |

The model cannot tell `example.com` from a phishing apex domain. No legitimate off-template training
data exists, so any verdict-level suppression weakens real detections just as much. Allowlisting the
example domains or `www.` was also ruled out. Retraining is not possible without representative
legitimate URLs (`docs/url_data_acquisition_plan.md`).

### Change made (verdict-neutral)

- **`app/routes/scan.py`:** when the model says phishing and the host has no `www.` prefix and/or the
  scheme is not HTTPS, a finding now names those reasons and states that the flag is unvalidated for
  this shape.
  - The risk level, `ml_label` and `ml_probability` are unchanged.
  - Registry hits, heuristic HIGH, model-unavailable and registry-unavailable behaviour are
    unchanged.
  - Path and query keep their existing note.
- **`app/services/ml_detector.py`:** the model is refused (reported as unavailable, never SAFE) if its
  classes are not `[0, 1]`, so `predict_proba[:, 1]` is guaranteed to be the phishing probability.
- **Tests:** `tests/test_url_shape_false_positive.py` (19 tests), offline. It covers:
  - trailing slash, `www.`, root and non-root paths, `http`;
  - registry hit / miss / unavailable;
  - model unavailable;
  - HIGH preserved;
  - class and feature order.

  It also characterizes the pinned model's shortcut; it skips if the artifact is absent. Run it with
  `python -m pytest -q tests/test_url_shape_false_positive.py`.

### Still unresolved

- `https://example.com/` and similar bare-domain sites are still MEDIUM, with an explanation.
- Fixing the verdict needs a retrained model on licensed, representative legitimate URLs: bare apex,
  non-`www` subdomains, paths and `http`. It must then pass this guard's ceilings.

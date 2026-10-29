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

## Criterion (`configs/url_shape_guard.json`, proposed — review required)

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
- `known_failing_models` exempts **only SHA `2f2e1d49…`**, and only within a ratchet: recorded rates
  + 0.02.
- CI fails if:
  - its rates get worse;
  - any other (retrained) artifact misses the ceilings;
  - the exempt artifact starts passing. In that case, delete the stale entry.

## CI

- `.github/workflows/url_shape_guard.yml` runs the guard, the pre-check and the pipeline tests.
- `*.joblib` is gitignored, so on CI the deployed-model test **skips**. The logic tests, including a
  synthetic shape-dependent model that must fail, still run.
- To enforce the model check, provision the artifact and set `CHAINSHIELD_REQUIRE_MODELS=1`. A
  missing model then fails instead of skipping. Locally the artifact exists, so the test runs.

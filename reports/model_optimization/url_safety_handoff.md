# Handoff — URL safety work (2026-10-29)

## Done

1. **The URL-shape guard is in CI.**
   - The ceiling is 5% per transformation, plus a 3-point gap limit. This is a proposal, configurable
     in `configs/url_shape_guard.json`.
   - The production model is exempt by SHA, with a ratchet. Any retrained model must pass.
   - It is a stress test, not a real-world FPR.
2. **Reputation pre-check prototype:**
   - Off by default (`CHAINSHIELD_REPUTATION_PRECHECK=1` and `CHAINSHIELD_REPUTATION_LIST=<file>`).
   - It never yields SAFE and never overrides the registry.
   - Bare homepages of exactly-listed, non-hosting domains only.
3. **Offline evaluation-set pipeline** with enforced provenance and training-overlap removal. Plus an
   acquisition plan.

## Decisions needed from you

- Approve or adjust the 5% / 3-point guard thresholds.
- Whether CI should hold the model artifact, for example via LFS or a release asset with
  `CHAINSHIELD_REQUIRE_MODELS=1`. Today the deployed-model check runs locally only.
- Permission to retrieve Tranco, the Common Crawl index and phishing feeds, with a licence review.
  Without data:
  - the pre-check cannot be evaluated for FP reduction;
  - a real-world FPR cannot be measured.
- Whether to ever enable the pre-check. Precondition: measure the chosen list against phishing feeds
  (attacker domains on the list are the remaining bypass).

## Remaining risks

- Production still has the shape shortcut. Mitigations already in the route: the model is advisory,
  plus the path/query note.
- Compromised legitimate sites serving phishing at the homepage would get the advisory withheld if
  the pre-check is enabled. The registry and heuristics are the only remaining checks there.
- The PSL is approximated in the bypass study (last two labels).
- The guard sample is 2,000 URLs, one seed. That is fine for detecting 85–100% shortcuts; a ~1-point
  change is within sampling noise.

## Changed files

- **Modified:** `app/routes/scan.py`
- **New:**
  - `app/services/reputation_precheck.py`
  - `src/evaluation/url_shape_guard.py`
  - `src/data/url_eval_pipeline.py`
  - `src/experiments/reputation_precheck_bypass.py`
  - `configs/url_shape_guard.json`
  - `.github/workflows/url_shape_guard.yml`
  - `tests/test_url_shape_guard.py`
  - `tests/test_reputation_precheck.py`
  - `tests/test_url_eval_pipeline.py`
  - `docs/url_shape_guard.md`
  - `docs/url_data_acquisition_plan.md`
  - `reports/url_shape_guard/*`
  - `reports/model_optimization/url_safety_*`
- **Committed from earlier sessions:** `src/experiments/`, `reports/model_optimization/`,
  `models/candidates/**/config.json`

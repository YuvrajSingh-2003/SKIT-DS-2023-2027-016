# Handoff — URL model optimization (2026-10-29)

## Outcome

- **Keep the production URL model.** It is unchanged: sha `2f2e1d49…adc`.
- Three cycles ran. Every candidate is saved under `models/candidates/url/` with its `config.json`
  and checksum.
- Details: `experiment_log.md`, `model_comparison.md`, `best_candidates.json`, `results/*.json`.

## Key finding

PhiUSIIL's legitimate class is 100% `https://www.<host>` with no path. As a result, production flags:
- 85% of legitimate URLs when `www.` is dropped
- 100% of legitimate URLs with `http`, no scheme, or any path

Its 0.96 F1 / 1.1% FPR holds only for template-shaped input. Removing the shortcut drops AUC to
0.84–0.88. That is the honest lexical skill on this data.

## Why nothing was promoted

- The template-invariant c3 (host-only, threshold 0.7366) holds 1.2–1.3% FPR on any URL shape.
- But it catches only 54% of test phishing and 60% of OpenPhish, compared with production's 94% / 95%.
- Swapping it in would trade an unmeasured real-world FP problem for a measured recall loss.

## Recommended next steps (not done)

1. Get licensed legitimate URLs with paths, http and non-www hosts, for example internal links from a
   top-sites crawl. Retrain c1/raw features on that data. This is the only real fix.
2. Until then, consider an allowlist or reputation pre-check in the serving layer for well-known
   domains. A product decision is needed.
3. Add the template probes as a standing regression check (`score_model` in
   `src/experiments/url_optimization.py`).

## SMS

- Valid, licensed, three-class data exists (Mishra & Soni, grouped split, `sms_split_metadata.json`).
- A baseline already exists (`models/sms_baseline/run-20261028T122841Z-seed42`; val macro-F1 0.924,
  test 0.893).
- This round's three cycles went to URL, per the stated priority. SMS was not retrained.
- Next SMS lever: missed smishing is mostly predicted as `generic_spam` (6 of 8 on validation).

## Limitations

- Probes are synthetic transformations of real legitimate URLs. They measure template dependence,
  not true real-world FPR.
- OpenPhish has only 300 rows and is phishing only.
- Latency was measured on a 24-core dev machine.
- No legitimate external set was available.

## Files added

- `src/experiments/` (new package; production code untouched)
- `models/candidates/url/`
- `reports/model_optimization/`

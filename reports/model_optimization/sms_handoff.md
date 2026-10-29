# SMS optimization handoff (2026-10-29)

## Recommendation

**Retain the production model.** It is `run-20261028T122841Z-seed42`, sha `9f753dd5…5b85815`, and is
unchanged.

## Why

- **XGBoost (C, D, E):** never beat the char-TF-IDF LR on validation. Best was E at −0.017.
  - Word-level features are clearly worse: C is −0.069, and its CI excludes 0.
  - Numeric features help XGBoost but do not close the gap.
  - XGBoost was *feasible* (chi²-bounded features, ≤ 8 s train). It lost on accuracy, not runtime.
- **Linear SVM (B):** +0.016 on validation, but grouped 5-fold CV shows no gain (−0.003, better in only
  2 of 5 folds). On test, B differs from production on 1 message.
  - It is also 5× slower per message and 3× larger.
- The baseline reproduces exactly from its config.

## Data limitation

- Smishing vs generic spam comes from a single-source annotation, Mishra & Soni.
- The minority classes are small: val/test each hold 63 spam and 77 smishing.
- At this size, differences under about 0.02 macro-F1 are not distinguishable from noise, so any
  future candidate must be checked with grouped CV, not one validation pass.
- The dominant error is the spam↔smishing boundary: 6–12 smishing messages are predicted as spam in
  every model. This boundary is ambiguous in the labels themselves; prepare_sources already excluded
  105 conflicting or near-conflicting rows.

## If continuing

- More labelled smishing data (licensed) is the highest-value lever.
- E's 0% legitimate FPR suggests numeric features plus char n-grams could serve as a second-stage
  check. That idea is untested.

## Reproduce

```
.venv/bin/python -m src.experiments.sms_optimization --cycle 1 --candidates A_retrain B_svm_char
.venv/bin/python -m src.experiments.sms_optimization --cycle 2 --candidates C_xgb_word_k2000 D_xgb_word_k2000_numeric
.venv/bin/python -m src.experiments.sms_optimization --cycle 3 --candidates E_xgb_char_k5000_numeric
.venv/bin/python -m src.experiments.sms_group_cv
.venv/bin/python -m src.experiments.sms_optimization --cycle 3 --final B_svm_char
```

## Changes

New files only:
- `src/experiments/sms_*.py`
- `models/candidates/sms/`
- `reports/model_optimization/sms_*`
- `reports/model_optimization/results/sms_*`

No production code, URL artifacts, or registry files were touched.

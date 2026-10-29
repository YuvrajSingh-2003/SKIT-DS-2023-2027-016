# SMS model optimization — experiment log (2026-10-29)

Code:
- `src/experiments/sms_optimization.py` (sha `c3e9ba2b…0cda`)
- `src/experiments/sms_group_cv.py` (sha `260d238b…a0b`)

Raw results: `results/sms_cycle{1,2,3}.json`, `sms_cycle3_groupcv.json`, `sms_cycle3_final.json`.
Seed 42 throughout.

## Pipeline inspection

- **Production model:** `models/sms_baseline/run-20261028T122841Z-seed42/model.joblib`, sha
  `9f753dd5235537c77b046044a058592c9c64f791fc4608abce0d3eb0a5b85815`. It is pinned in
  `app/services/sms_detector.py`.
- **Model:** `TfidfVectorizer(char_wb, 2–5, min_df=2, sublinear_tf, preprocessor=normalize_text)` +
  `LogisticRegression(C=10, class_weight=balanced)`.
- **Task:** three-class *multiclass* (`legitimate`, `generic_spam`, `smishing`), argmax of
  `predict_proba`.
- **Interface:** `predict_proba([raw_text])` with string `classes_`. Every candidate keeps this
  interface.
- **Data:** Mishra & Soni SMS Phishing Dataset (CC BY 4.0, DOI 10.17632/f45bkkt8pr.1). The dataset
  labels smishing and spam *separately* at source; this project did not derive smishing from a generic
  spam label. Train smishing subcategories: prize_premium 229, other 60, free_offer 34, payment 33.
- **Splits** (`data/processed/sms_split_metadata.json`): near-duplicate groups (ratio ≥ 92) kept
  within one split, 70/15/15.

| Split | Rows | sha256 |
|---|---|---|
| train | 4,032 | `a8e48b56…6496` |
| val | 865 | `24d7e884…7930` |
| test (locked) | 865 | `dc153500…7699` |

- **Leakage check:** 0 `group_id`s are shared between train and val or between train and test.
  0 exact normalized-text overlaps for train–val or train–test.
- **Limitation:** smishing vs generic spam is a single-source annotation. Validation has only 63 spam
  and 77 smishing messages, so one message moves a class F1 by about 0.01.
- **Fitting:** vectorizers, chi² selection and scaling are all inside each Pipeline and fitted on train
  only.

## Cycle 1 — Baseline + Linear SVM

- **Hypothesis:** a margin-based linear SVM on the same char n-grams separates spam from smishing
  better than LR.
- **Command:** `python -m src.experiments.sms_optimization --cycle 1 --candidates A_retrain B_svm_char`
- **A (production config, refit):** reproduced production *exactly* (identical confusion matrix,
  macro-F1 0.9245). The baseline is reproducible.
- **B:** `LinearSVC(C=0.5, balanced)` wrapped in `CalibratedClassifierCV(sigmoid, cv=5)` on the same
  TF-IDF. The calibration wrapper keeps `predict_proba` available.
  - Val macro-F1 **0.9405** (+0.016).
  - Paired group-bootstrap CI: [+0.003, +0.035].
  - Legitimate FPR 0.14% vs 0.28%.
  - The gain comes from 3 spam messages and 1 legitimate message moving into the correct class.
- **Decision: PROVISIONAL PASS.** The gain is small (about 4 messages), so it needs a reproducibility
  check (Cycle 3). Next, test the requested XGBoost candidates.

## Cycle 2 — XGBoost on word TF-IDF (± numeric features)

- **Hypothesis:** trees on a bounded word vocabulary can capture keyword interactions that linear
  models miss.
- **Command:** `python -m src.experiments.sms_optimization --cycle 2 --candidates C_xgb_word_k2000 D_xgb_word_k2000_numeric`
- **Representation:** word 1–2 TF-IDF (min_df=2), chi² top-k=2000. The value of k bounds the dense
  work XGBoost has to do and avoids feeding it the full sparse matrix.
- **XGBoost settings:** 400 trees, depth 4, lr 0.1, `hist`, balanced sample weights.
- **D** adds 9 documented numeric features: chars, words, digit ratio, upper ratio, has_url, has_phone,
  has_money, has_urgent, "!" count.
- **C:** val macro-F1 **0.8570** (−0.069, CI [−0.124, −0.016]). Significantly worse; smishing recall
  0.779.
- **D:** val macro-F1 **0.8892** (−0.036, CI [−0.086, +0.014]). The numeric features help XGBoost by
  +0.032, but it is still below the baseline. Spam→smishing confusions rise from 3 to 7.
- **Runtime:** fine (≤ 2.7 s train). It did not need to be infeasible to reject.
- **Decision: FAIL.** Word features lose the sub-word cues (obfuscated words, URLs, numbers) that
  char n-grams capture. Next, give XGBoost char n-grams and verify B.

## Cycle 3 — XGBoost on char n-grams + numeric; reproducibility check of B

- **Hypothesis E:** char_wb 2–5 TF-IDF with chi² k=5000 + the 9 numeric features closes XGBoost's gap.
  - **Command:** `python -m src.experiments.sms_optimization --cycle 3 --candidates E_xgb_char_k5000_numeric`
  - Val macro-F1 **0.9081** (−0.017, CI [−0.067, +0.029]).
  - Legitimate FPR **0.00%** (best), but spam→smishing confusions are 7.
  - Latency 6.7 ms vs 0.7 ms.
  - **FAIL:** better than C/D, still not above the baseline.
- **Verification of B:** `python -m src.experiments.sms_group_cv`
  - `StratifiedGroupKFold(5, shuffle, seed 42)` over train+val, grouped by near-duplicate `group_id`.
    Test untouched.
  - Fold macro-F1, A vs B: 0.933/0.938, 0.919/0.908, 0.891/0.905, 0.925/0.912, 0.947/0.939.
  - B − A mean **−0.003**; B better in **2 of 5 folds**.
  - A 0.923 ± 0.019, B 0.920 ± 0.015.
  - **The Cycle 1 gain does not reproduce.** It was split noise.
- **Decision: retain the baseline.** It was frozen *before* the test split was scored.
- **Post-decision locked-test check (information only):**
  `python -m src.experiments.sms_optimization --cycle 3 --final B_svm_char`
  - Production 0.8929 vs B 0.8976. One smishing message differs.
  - Paired CI [0.000, +0.017].
  - Test legitimate FPR 0.0% for both.
- **Regression:** `pytest -q tests/test_sms_baseline.py tests/test_message_scan.py tests/test_training_guard.py tests/test_group_split.py`
  → 83 passed. The full suite was 624 passed earlier in this session. Only new files were added since
  then, and no production code changed. Production SMS sha is unchanged.

### Candidate artifacts (`models/candidates/sms/<name>/model.joblib`, each with `config.json`)

| Candidate | sha256 |
|---|---|
| A_retrain | `4de7b9b672623e18cbbd53560422dfcd0edb2ba3b4bbdca8c34594398a82a389` |
| B_svm_char | `da92b5d0f515df2307324007365d2195fcdba7f3c56c26857bdd3c1064c4ac96` |
| C_xgb_word_k2000 | `79015a0b56888b95d05f8d49a617149a88a77eeaa270355d81a10237bb106118` |
| D_xgb_word_k2000_numeric | `e60bfc3df51ea32740d803981b27cdb2a7c2621cdef9256d8fca6c72b87dcd26` |
| E_xgb_char_k5000_numeric | `6af0c777c1d302af87a8eebe5ddb5d8e69ef9b9cb9a6972616fee0d9573bee18` |

A_retrain's sha differs from production because of joblib pickling. Its predictions are identical.

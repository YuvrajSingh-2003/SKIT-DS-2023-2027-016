# ChainShield — ML Evaluation

Measured 2026-10-28 with `python -m src.evaluation.verify_production_models`. The raw output is
in `reports/model_verification_20261028.json`. The script:
- loads both production models through the backend's own checksum-verified loaders;
- re-measures them on their **validation** splits;
- checks for leakage between splits;
- copies the recorded test results.

**Measured** means computed in that run. **Historical** means read from files saved at training
time and not recomputed. The locked SMS test split was not used for predictions, and no model
was retrained or changed.

## Production models

| Task | Model | Artifact (SHA-256 pinned) | Role in the API |
|---|---|---|---|
| URL | XGBoost on lexical URL features, threshold 0.5 | `models/url_inference/model.joblib` | Advisory: can raise a result to MEDIUM, never to HIGH |
| SMS | TF-IDF char_wb 2–5-grams + logistic regression (`char25_C10`), 3 classes | `models/sms_baseline/run-20261028T122841Z-seed42/model.joblib` | Verdict for messages: MEDIUM (smishing) or LOW; never SAFE |

If either artifact is missing or altered, the API returns an explicit unavailable result
(URL: UNKNOWN), never a prediction.

## Data and splits

- **URL: PhiUSIIL** (UCI 967, CC BY 4.0). Label 0 = phishing. Stratified split; the
  validation set has 35,305 URLs, of which 15,078 are phishing.
- **SMS: Mishra & Soni** (Mendeley f45bkkt8pr v1, CC BY 4.0). Label conflicts were excluded,
  and the split is group-aware on near-duplicate groups (seed 42). Per split:
  - train: 3,384 legitimate / 292 generic spam / 356 smishing
  - validation: 725 / 63 / 77
  - test: 725 / 63 / 77 (locked)
- Details: [../datasets.md](../datasets.md).

## Reproducibility check (measured)

Both models reproduced their recorded validation metrics exactly.

| | Measured now | Recorded at training |
|---|---|---|
| URL phishing precision / recall / F1 | 0.9826 / 0.9421 / 0.9619 | identical |
| URL ROC AUC | 0.9873 | identical |
| SMS macro-F1 | 0.9245 | identical |

The API scores one URL per request. On 300 sampled validation URLs those scores matched batch
scoring exactly (maximum difference 0.0), so the feature order and preprocessing are
consistent between training and serving.

## URL model

| Validation (measured) | |
|---|---|
| Confusion matrix (phishing = positive) | TN 19,976 · FP 251 · FN 873 · TP 14,205 |
| Precision / Recall / F1 | 0.983 / 0.942 / 0.962 |

Test results (historical, 2026-10-28): precision 0.985, recall 0.943, F1 0.963
(TN 20,006 · FP 222 · FN 862 · TP 14,216).

**Why these numbers overstate real-world performance (measured):**
- None of the 20,227 legitimate validation URLs has a path or query string, while 4,214 of
  the 15,078 phishing URLs do.
- In this dataset a path alone almost identifies phishing. Every legitimate URL follows the
  `https://www.<domain>` template, so a page such as `https://example.com/login` from a real
  site lies outside anything the model saw.
- The API therefore treats the model as advisory and notes when a URL has a path or query.

**Leakage (measured):**
- No URL appears in two splits as the same string.
- After canonicalization, some URLs do appear in two splits: 124 train/validation, 113
  train/test and 26 validation/test. They differ only in case, default port or trailing slash.
- The effect on the metrics is negligible (under 0.4% of a split), but it is a real overlap.
  A future re-split should group URLs by canonical hash.

## SMS model

Validation (measured), per class:

| Class | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| legitimate | 0.988 | 0.997 | 0.993 | 725 |
| generic_spam | 0.869 | 0.841 | 0.855 | 63 |
| smishing | 0.958 | 0.896 | 0.926 | 77 |

Confusion matrix (rows = true, columns = predicted: legitimate, generic_spam, smishing):

```
[[723, 2, 0], [7, 53, 3], [2, 6, 69]]
```

- **Missed smishing:** 8 of 77 on validation. 6 were predicted as generic spam and 2 as
  legitimate; 4 of the 8 contain link-like text.
- **Main weakness:** the model mostly confuses smishing with generic spam, not with legitimate
  messages.

**Test results (historical, the single locked evaluation on 2026-10-28, 865 messages):**
- macro-F1 0.893
- smishing precision 0.892, recall 0.857
- confusion matrix `[[725,0,0],[6,49,8],[2,9,66]]`
- No legitimate message was flagged as smishing.

**External results (historical, IMC 2025; labels assigned by GPT-4o, recall only):**
- smishing recall 0.697
- 0 of 55 "hey mum/dad" scams detected

**Leakage (measured):** zero overlap between train, validation and test, by exact text, by
near-duplicate group and by registry hash.

**Class imbalance:** smishing is 8.8% of training rows. Model selection used macro-F1, so the
two minority classes count as much as the majority class.

## Threshold and model selection

- **URL model:** threshold 0.5, fixed before evaluation and recorded in its metadata.
- **SMS model:** chosen from four candidates by validation macro-F1 under a rule frozen before
  testing (`selection_frozen.json`). The test split was evaluated once, after selection.
- Neither model was tuned on test data. The validation figures above are optimistic, because
  validation also served for model selection.

## Limitations and recommendations

1. The URL dataset's template bias means the URL model should stay advisory. A dataset whose
   legitimate URLs have real paths is needed before relying on it.
2. The SMS model misses modern conversational scams. It needs new, licensed data covering
   them, and a new untouched test set: the current one has been used.
3. Re-split the URL data by canonical hash to remove the small near-duplicate overlap.
4. Neither model's scores are calibrated probabilities, and the UI says so.

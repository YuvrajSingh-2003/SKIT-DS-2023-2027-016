# URL model optimization — experiment log (2026-10-29)

All runs: seed 42, XGBoost with the production hyperparameters (300 trees, depth 6, lr 0.1,
subsample/colsample 0.8), unchanged production feature extractor `src/features/url_lexical.py`.
Code: `src/experiments/url_optimization.py` (sha256 `fa33f1ab…f4ad`). Raw results: `results/*.json`.

| Split | File | sha256 |
|---|---|---|
| train (164,759 rows) | `data/processed/url_splits/stratified_train.csv` | `02c64a6f…7a77` |
| validation (35,305) | `stratified_validation.csv` | `3d10e183…462f48d` |
| locked test (35,306) | `stratified_test.csv` | `80de3cae…0bc4` |
| unseen phishing (300, phishing only) | `data/incoming/threat_feeds/openphish-community-20261028T152813Z.txt` | `1990d11d…25e` |

**Template probes** (synthetic and diagnostic, not new data): all 20,227 legitimate validation URLs,
each transformed one way (drop `www.`, `http://`, no scheme, append `/about`, append
`/search?q=news`). The true label stays legitimate, so the metric is the false-positive rate (FPR).

The test split was scored once, at the end of Cycle 3, for all candidates together. It was never used
to choose between them. Because of a labelling bug, it was re-scored to correct the result keys only;
the models and numbers did not change (see Cycle 3).

---

## Cycle 1 — Diagnose and set the baseline; remove the scheme/www shortcut

**Diagnosis (train split, label 1 = legitimate):**
- 94,395 of 94,395 legitimate URLs (100%) are `https://www.<host>` with no path or query. The same
  holds for 20,227 of 20,227 in validation.
- Phishing URLs: 41% have `www`, 48% use https, and 60% have a path or query.
- Every URL with a path, without https, or without `www` is therefore phishing in the training data.
  This is a dataset construction artefact, not a property of the web.
- Leakage: 0 duplicate URLs in train. 0 validation URLs appear in train. 7.7% of validation domains
  also appear in train, which is low. Labels are only {0, 1}.

**Baseline reproduced:** `python -m src.experiments.url_optimization --cycle 1 --baseline --modes neutral`
- Production (`models/url_inference/model.joblib`, sha `2f2e1d49…adc`): validation phishing F1 0.9619,
  FPR 1.24%, AUC 0.9873. This exactly matches `metadata.json`.
- Probe FPR: drop www **85.2%**, http **100%**, no scheme **100%**, `/about` **100%**, query **100%**.
  Production flags essentially every legitimate URL that differs from the template.

**Hypothesis:** if the scheme and `www.` are normalized away before feature extraction, the model
cannot use that shortcut.

**Change (one factor):** input normalization `neutral`: strip the scheme and a leading `www.`, then
prepend `https://`. The model and features are otherwise identical.

**Result:** `models/candidates/url/c1_xgb_neutral/model.joblib`, sha `1e339964…aeb`, 900,392 B,
train time 13.2 s.

| | val phish P/R/F1 | val FPR | val AUC | OpenPhish recall |
|---|---|---|---|---|
| production | 0.983 / 0.942 / 0.962 | 1.24% | 0.987 | 95.0% |
| c1 neutral | 0.945 / 0.706 / 0.808 | 3.07% | 0.884 | 87.3% |

- c1 probe FPR is 3.07% for as-is, drop-www, http and no-scheme: the shortcut is gone.
- The path probes are still **100%**.

**Decision: PASS as a diagnostic, FAIL as a replacement.** About 0.10 of the 0.987 AUC came from the
scheme/www template. The production validation score overstates real-world skill. The path shortcut
is untouched, so Cycle 2 targets it.

## Cycle 2 — Remove the path shortcut (host-only)

**Hypothesis:** if the model only sees the hostname, it cannot use "has a path ⇒ phishing".

**Command:** `python -m src.experiments.url_optimization --cycle 2 --modes host`

**Change (one factor relative to c1):** normalization `host`, which drops path, query and fragment.

**Result:** `models/candidates/url/c2_xgb_host/model.joblib`, sha `e8bdd383…a20fa`, 930,789 B,
train time 12.2 s.
- Validation: phishing P/R/F1 0.887 / 0.629 / 0.736, FPR 6.00%, AUC 0.840.
- OpenPhish recall: 65.7%.
- Probe FPR: **6.00% on every probe**, so the model is fully invariant to the template.

**Decision: INCONCLUSIVE.** This is the only candidate whose behaviour does not depend on the
template. However, its FPR at threshold 0.5 is 5× production's, and it loses most of the path signal
that is real in phishing. PhiUSIIL contains no legitimate URLs with paths, so the path signal cannot
be learned honestly from this dataset. Cycle 3 checks whether the threshold can bring FPR back to
the production level.

## Cycle 3 — Match FPR by threshold; final locked-test evaluation; regression

**Hypothesis:** if the c2 threshold is chosen on validation to match production's 1.24% FPR, it gives
an operating point with an FPR that holds up off-template.

**Command:** `python -m src.experiments.url_optimization --cycle 3 --reuse c2_xgb_host --modes host --fpr-target 0.0124`

**Change (one factor):** threshold 0.5 → 0.7366 (chosen on validation only). The model artifact is
the same as c2.

**Result:**
- Validation: FPR 1.17%, phishing P/R/F1 0.972 / 0.540 / 0.694.
- OpenPhish recall: 59.7%.
- Probe FPR: 1.17% on every probe.

**Final test** (one pass over all candidates):
```
python -m src.experiments.url_optimization --cycle 1 --reuse c1_xgb_neutral --baseline --final
python -m src.experiments.url_optimization --cycle 2 --reuse c2_xgb_host --final
python -m src.experiments.url_optimization --cycle 3 --reuse c2_xgb_host --fpr-target 0.0124 --final
```
- Test figures track validation within 0.003 F1 for every candidate (see `model_comparison.md`).
- A `--reuse` naming bug first mislabelled the c2/c3 result keys as "neutral". After the fix, the c2
  and c3 commands were re-run. Test was used only to re-score; no selection was made from it.

**Regression:** `.venv/bin/python -m pytest -q` → 624 passed. Production model sha unchanged.
Candidate inference was smoke-tested through the latency loop at about 2.6 ms/URL, including feature
extraction.

**Decision: FAIL as a production replacement.** At equal FPR, the template-invariant model catches
54% of phishing, compared with production's 94%. It is still the only model whose 1.2% FPR holds
on real-world-shaped legitimate URLs; production's FPR there is up to 100%.

**What was learned:** the URL model's weakness is the dataset, not the estimator or the tuning. More
tuning on PhiUSIIL cannot fix it. The next step requires legitimate URLs with paths, http and no www,
for example from a licensed crawl or top-sites list with sampled internal links.

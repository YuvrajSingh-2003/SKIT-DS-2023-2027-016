# URL false positives: root cause and resolution decision (2026-10-29)

## Verdict

**The model-level issue is NOT resolved. No candidate is promoted.**
- The production URL model (SHA-256 `2f2e1d492ec3bc96891df3c08d3e80ff158021f6321160e3d55a52707f2d2adc`,
  threshold 0.5) is unchanged.
- The **blocker is data**: there are not enough representative, well-labelled legitimate URLs (and
  recent phishing URLs) under approved licences. The blocker is not model design and not an
  implementation defect.
- The evidence for each claim is below. Every number is reproducible from a committed script and
  results file.

## 1. Baseline (Phase 1)

| Check | Result | Evidence |
|---|---|---|
| Known false positives | `https://example.com/`, `https://example.org/`, `https://wikipedia.org` → p = 0.9998, MEDIUM; `www.` forms → 0.012 / 0.019, SAFE | `tests/test_url_shape_false_positive.py`, `src/experiments/url_shape_false_positive_eval.py` |
| Checksum / threshold | `2f2e1d49…` / 0.5, verified at load | `app/services/ml_detector.py` |
| Feature order, class mapping `[0, 1]`, train/serve parity, trailing-slash equivalence | All correct; each has a regression test | same tests |
| Where the wrong score originates | `ml_detector.py:148` (`predict_proba`), driven by `NoOfSubDomain` (`src/features/url_lexical.py:126`, counts `www`). Flipping only it: 0.9998 → 0.0106 | `test_real_model_known_shortcut_is_characterized` |
| PhiUSIIL validation (production) | recall 0.9421, precision 0.9826, FPR 1.24% (35,305 rows) | `reports/model_optimization/results/url_multisource_validation.json` |
| Real off-template legitimate URLs (Hannousse validation, n = 722) | **98.2% flagged** (Wilson 96.9–98.9%) | same |
| Reproducibility of all earlier candidates | Re-run on 2026-10-29: metrics and gate decisions identical; **model SHA-256 identical for all 7** (c5–c8, H1, L1, L2) | `train_url_multisource.py`, `url_v2_arms.py` |

## 2. Data and feature audit (Phase 2)

**Command:** `python -m src.experiments.url_data_audit`
**Results:** `reports/model_optimization/results/url_data_audit.json`

**Approved training data:**

| Source | Legitimate | Phishing |
|---|---|---|
| PhiUSIIL train | 94,395 | 70,364 |
| Hannousse train (after leakage drop) | 4,003 | 4,024 |

**URL-shape share by source and label** (% of rows):

| | in-template | bare root | no `www` | `http` | path/query |
|---|---|---|---|---|---|
| PhiUSIIL legitimate | **100.0** | 0.0 | 0.0 | 0.0 | 0.0 |
| PhiUSIIL phishing | 1.1 | 33.4 | 58.6 | 51.3 | 28.1 |
| Hannousse legitimate | 16.7 | 12.8 | 36.1 | 54.5 | 60.0 |
| Hannousse phishing | 0.3 | 17.8 | 80.4 | 65.7 | 81.0 |

**Findings:**
- **Collection artefact.** PhiUSIIL legitimate URLs occupy exactly one shape. In PhiUSIIL, which is
  164,759 of the 172,786 training rows, every non-template URL is phishing. The ~4k Hannousse
  legitimate URLs are the only legitimate non-template examples.
- **The shortcut is multivariate, not one feature.** Within-source univariate AUC (direction-free):

  | Feature | AUC within PhiUSIIL | AUC within Hannousse | Reading |
  |---|---|---|---|
  | `IsHTTPS` | 0.757 | 0.556 | Collection artefact |
  | `NoOfSubDomain` | 0.514 | 0.524 | Alone, close to chance; the shortcut lives in interactions with length and count features |

  Removing or changing subdomain count alone therefore cannot fix it (confirmed by c4/c6:
  www-neutral, still 54–60% FPR).
- **Hygiene:**
  - Source identity alone does not predict the label (pooled AUC 0.507; both sources are roughly
    class-balanced).
  - 22 duplicate URLs and 0 URL-level label conflicts.
  - 217 registrable domains carry both labels (platforms, compromised hosts).
  - 497 domains are shared between sources (reported; Hannousse rows sharing a domain with PhiUSIIL
    validation/test are dropped from training).
- **Overlap within shapes.** Even on representative data, legitimate and phishing URLs overlap heavily
  in shape: e.g. 60.0% vs 81.0% path/query and 54.5% vs 65.7% `http` in Hannousse. Lexical shape is
  weak evidence there.
- **Label assumptions.** Hannousse "legitimate" means crawled from popular sites (Alexa seeds, Yandex
  list), not verified per URL. Its phishing labels are 2020 feed entries.

## 3. Candidates (Phase 4)

**Setup:**
- Same estimator family and hyperparameters, seed 42.
- Domain-grouped Hannousse splits; PhiUSIIL stratified splits.
- Validation only; locked test splits never scored.
- **Unchanged** `configs/url_candidate_acceptance.json`.

| Candidate | Data / representation | PhiUSIIL recall | Off-template legit FPR (n=722) | Bare root (n=60) | Hannousse F1 | Decision |
|---|---|---|---|---|---|---|
| A production | PhiUSIIL, 19 lexical | 0.9421 | 98.2% | 78.3% | 0.689 | baseline |
| c5 | + Hannousse | 0.9367 | 54.2% | 73.3% | 0.781 | reject |
| c6 | c5, www-neutral | 0.9636 | 59.8% | 65.0% | 0.781 | reject |
| c7 | c5, source-balanced weights | 0.9077 | 38.4% | 46.7% | 0.793 | reject |
| c8 | Hannousse only, 19 lexical | 0.5308 | 12.6% | 6.7% | 0.804 | reject |
| H1 | v2 host block only | 0.6612 | 17.3% | 23.3% | 0.601 | reject |
| B: L1 | v2 host + path/query + scheme | 0.9850 | 57.3% | 80.0% | 0.765 | reject |
| B: L2 | L1, PhiUSIIL confounded blocks masked | 0.5288 | 15.4% | 16.7% | 0.829 | reject |

- **Gates:** off-template FPR ≤ 5% overall and per shape, PhiUSIIL recall drop ≤ 1 pp, shape guard,
  and more (see the acceptance file).
- **Pattern:** every candidate fails. Candidates that keep PhiUSIIL recall inherit the template
  shortcut; candidates that drop it lose PhiUSIIL recall.
- **Results files:** `url_multisource_validation.json`, `url_v2_arms_validation.json`.

### Data quantity vs model design (C)

**Command:** `python -m src.experiments.url_learning_curve`
**Results:** `url_learning_curve.json`

Trained on representative Hannousse data only and evaluated on its grouped validation split:

| Training rows (domain-grouped subsample) | Off-template FPR | Recall | F1 |
|---|---|---|---|
| ~1.8k (25%, 3 seeds) | 22.4% | 0.785 | 0.793 |
| ~4.0k (50%) | 20.2% | 0.815 | 0.820 |
| ~6.1k (75%) | 17.9% | 0.830 | 0.837 |
| 8.0k (100%, 1 seed) | 20.4% [17.6–23.5] | 0.812 | 0.818 |

Model family at 100% (same features):

| Family | Off-template FPR | Recall |
|---|---|---|
| XGBoost | 20.4% | 0.812 |
| Random forest | 19.0% | 0.817 |
| L2 logistic regression | 15.2% | 0.666 (lower FPR bought with recall) |

**Interpretation:**
- **Model family is not the bottleneck.** The three families sit on the same FPR/recall trade-off.
- **More of the same data helps only slowly:** about 4 pp FPR per 3× rows, within noise of ±3 pp at
  this validation size. Reaching ≤ 5% by scaling 2020 popularity-crawl data is implausible.
- **The limit is data quality plus quantity:**
  - recent, per-URL-verified legitimate URLs across shapes;
  - recent phishing from a licensed source;
  - not more model capacity.

## 4. Decision (Phase 5)

- **No promotion.** Every candidate fails the unchanged acceptance criteria on validation, so no
  locked test split was scored.
- **Unchanged:** threshold, criteria and the production model.
- **Current safe behaviour** (unchanged): the model flag is advisory (MEDIUM at most on its own), with
  an explanatory finding for untrained URL shapes.
- **Blocker:** data. Specifically:
  1. about 16k **verified** legitimate URLs over ≥ 2k domains across bare/`www`/`http`/path/query
     shapes;
  2. a **licensed, recent phishing** source.

  Both are planned in `docs/legitimate_url_collection_plan.md`, which lists approved-candidate sources
  (Wikidata P856, the CISA `.gov` list, GOV.UK, data.gov federal) and is awaiting owner decisions
  D1–D5. No phishing source is cleared; the routes are PhishTank/Cisco or PhishStats permission, or
  APWG eCX.
- **Next action that can realistically resolve it:** the owner records D1 (approve S1–S4) and D4 (send
  the permission requests). Then run the collector (currently dry-run only) and re-run the arms above
  with the new data, against the same gates.

## 5. Reproduction

```bash
.venv/bin/python -m pytest -q tests/test_url_shape_false_positive.py tests/test_url_lexical_v2.py
.venv/bin/python -m src.experiments.url_shape_false_positive_eval     # baseline on the diagnostic URLs
.venv/bin/python -m src.experiments.url_data_audit                    # §2
.venv/bin/python -m src.training.train_url_multisource                # c5–c8
.venv/bin/python -m src.experiments.url_v2_arms                       # H1, L1, L2
.venv/bin/python -m src.experiments.url_learning_curve                # §3 data vs design
```

These need the production URL model file (gitignored; see `docs/SYSTEM.md`). Candidate binaries are
regenerated by the commands above with identical SHA-256 (verified on 2026-10-29).

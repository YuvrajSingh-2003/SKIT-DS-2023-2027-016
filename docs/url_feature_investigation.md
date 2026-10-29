# URL feature-representation investigation (2026-10-29)

- **Scope:** is the URL feature representation the main limitation behind the production URL model's
  false positives on legitimate URLs such as `https://example.com/`, `https://wikipedia.org`, `http`
  URLs and URLs with paths?
- **Constraints:** no model was trained for this report. Production artifacts, inference, thresholds
  and `configs/url_candidate_acceptance.json` are unchanged.
- **Baseline:** commit `21c6a9f`. All numbers are from the committed
  `reports/model_optimization/results/url_multisource_validation.json`, or from inference-only
  analysis reproducible with the snippet in the appendix.

## 1. Feature inventory

**Shared code path:**
- Extractor: `src/features/url_lexical.py::extract_lexical_url_features`.
- Used by training (`src/training/train_url_inference.py`, `train_url_multisource.py`) and serving
  (`app/services/ml_detector.py`). Tested: `test_training_and_serving_use_the_same_feature_extractor`.
- `metadata.json` `feature_names` equals `LEXICAL_URL_FEATURES`, and the order is checked at load.
  The model's classes are `[0, 1]`, also checked at load.

**Preprocessing before extraction:**
- the input is stripped;
- a root-only trailing `/` is removed;
- `http://` is assumed if there is no scheme.

All 19 features are numeric, computed from the URL string alone. Shape link: **D** = direct, **I** =
indirect (grows with a path, query, `www.` or scheme).

| # | Feature | Type | Computation | Shape link |
|---|---|---|---|---|
| 1 | URLLength | int | `len(url)` | I: any path, query or `www.` adds length |
| 2 | DomainLength | int | `len(hostname)` | I: `www.` adds 4 |
| 3 | IsDomainIP | 0/1 | host parses as IP | — |
| 4 | TLDLength | int | length of the last host label | — |
| 5 | NoOfSubDomain | int | `max(labels − 2, 0)` | **D: `www.` counts as a subdomain** |
| 6 | NoOfLettersInURL | int | `[A-Za-z]` count, whole URL | I |
| 7 | LetterRatioInURL | float | letters / length | I |
| 8 | NoOfDegitsInURL | int | `[0-9]` count, whole URL | I: paths and IDs add digits |
| 9 | DegitRatioInURL | float | digits / length | I |
| 10 | NoOfEqualsInURL | int | count of `=` | **D: query presence** |
| 11 | NoOfQMarkInURL | int | count of `?` | **D: query presence** |
| 12 | NoOfAmpersandInURL | int | count of `&` | **D: query presence** |
| 13 | NoOfOtherSpecialCharsInURL | int | punctuation count, *including* `/ : . ? = &` | I: every path segment adds `/`, `www.` adds `.` |
| 14 | SpacialCharRatioInURL | float | special / length | I |
| 15 | HasObfuscation | 0/1 | any of `% @ \` | I: percent-encoding in normal queries |
| 16 | IsHTTPS | 0/1 | scheme is `https` | **D: scheme** |
| 17 | IsURLShortener | 0/1 | host in shortener list | — |
| 18 | URLDepth | int | non-empty path segments | **D: path presence** |
| 19 | HasSuspiciousKeyword | 0/1 | any of 14 tokens (login, verify, …) anywhere in the URL | — (but host and path are not distinguished) |

**Observations:**
- 15 of 19 features encode URL shape directly or indirectly.
- Features 1, 6–9 and 13–15 mix host and path into one count.
- Missing entirely:
  - host-only versus path-only statistics;
  - registrable-domain structure (subdomains other than `www`, label count, hyphens in the
    registrable label);
  - character-distribution features (entropy, consonant runs, n-grams);
  - query-parameter structure;
  - TLD identity.

## 2. Evidence for and against the feature-shortcut hypothesis

**Hypothesis:** the model's decisions on legitimate URLs are driven by URL shape. Shape is encoded
across several correlated features, and PhiUSIIL legitimate URLs never vary in shape.

### For

1. **No legitimate shape variation in the data.**
   - All 134,850 PhiUSIIL legitimate URLs are `https://www.<host>` with no path.
   - In PhiUSIIL train, legitimate `URLDepth` has p99 = max = 0.
   - Legitimate `URLLength` has max 56.
2. **Production behaves like a shape rule.** The rule "phishing unless `https://www.<host>`, root"
   (no learning):

   | Set | Rule F1 | Production F1 | Agreement |
   |---|---|---|---|
   | PhiUSIIL validation | **0.9950** | 0.9619 | 96.96% |
   | Hannousse validation | 0.6974 | 0.6891 | 97.53% |

3. **The hosts are not what is flagged.**
   - Production flags 709 of 722 (98.2%) real off-template legitimate URLs in Hannousse validation.
   - Re-scoring the *same hosts* as `https://www.<host>` flags only 6.8%. (This is a diagnostic string
     transform, not new data.)
4. **The shortcut is distributed, not a single feature.** Counterfactual edits on those 709 false
   positives:

   | Edit | Still flagged |
   |---|---|
   | `NoOfSubDomain ≥ 1` | 98.2% |
   | + `IsHTTPS = 1` | 78.4% |
   | + `URLDepth`, `?`, `=`, `&` counts = 0 | 75.7% |

   The rest is carried by the indirect length and count features: 36% of the false positives exceed
   the longest legitimate training URL, and 19% exceed the maximum special-character count. The model
   is extrapolating outside the legitimate training support.
5. **The `example.com` case:** setting only `NoOfSubDomain` from 0 to 1 moves 0.9998 to 0.0106
   (`tests/test_url_shape_false_positive.py`).
6. **Gain importance** (production): `IsHTTPS` 62.9%, `NoOfDegitsInURL` 15.6%, `URLDepth` 14.8%.
   Importance is correlational and not causal proof; it is consistent with items 2–4.

### Against, or limits of the claim

1. **Representation is not the whole story.**
   - c8, trained only on representative Hannousse data (about 3.3k legitimate training URLs; no
     PhiUSIIL confound), still flags 12.6% (95% CI 10.4–15.2%) of real off-template legitimate URLs.
   - It also reaches only 0.75 recall on Hannousse phishing.
   - So with these 19 features *and* this data volume, the classes overlap substantially even without
     the shortcut.
2. **Collisions are not the bottleneck.** Only 93 of 1,701 Hannousse validation rows share an exact
   feature vector with the other label, implying at least 1.47% irreducible error. A 5% FPR target is
   not ruled out by collisions alone.
3. **Data volume and confounding cannot be separated from representation** with the committed runs.
   c5 to c8 changed the training mix, not the features.

**Conclusion:** the evidence supports "the shortcut is spread across shape-encoding features and is
caused by the PhiUSIIL confound" as the main cause of production's false positives. The evidence does
**not** support "the representation alone is the root cause". c8 shows that, even without the
confound, the current features plus about 3k legitimate URLs are insufficient. Both a representation
change and more data are likely needed; the experiment in §6 separates them.

## 3. Candidate comparison (validation only; locked test splits never scored)

- **Split method:**
  - PhiUSIIL: existing stratified splits.
  - Hannousse: registrable-domain-grouped split, 0 shared domains between its splits.
  - 1,744 Hannousse training rows were dropped because their domain occurs in PhiUSIIL
    validation/test.
  - 388 Hannousse validation rows share a domain with PhiUSIIL train.
- **"Unseen"** = PhiUSIIL validation rows whose registrable domain is absent from the combined
  training set.
- **"Off-tmpl"** = Hannousse validation legitimate URLs not shaped `https://www.<host>` (n = 722).
  The 95% intervals are Wilson.

| Model | PhiUSIIL recall | PhiUSIIL precision | PhiUSIIL FPR | PhiUSIIL unseen recall | Hannousse recall | Hannousse precision | Off-tmpl FPR | Bare-root FPR (n=60) | http FPR (n=503) | Path/query FPR (n=555) | OpenPhish recall (300, local-only) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| production | 0.9421 | 0.9826 | 1.24% | 0.9828 | 0.9680 | 0.5350 | 98.2% [96.9–98.9] | 78.3% [66.4–86.9] | 100% | 100% | 95.0% |
| c5 PhiUSIIL+Hannousse | 0.9367 | 0.9838 | 1.15% | 0.9787 | 0.9385 | 0.6686 | 54.2% [50.5–57.8] | 73.3% [61.0–82.9] | 53.1% | 43.2% | 95.0% |
| c6 c5 + www-neutral | 0.9636 | 0.9917 | 0.60% | 0.9476 | 0.9692 | 0.6542 | 59.8% [56.2–63.3] | 65.0% [52.4–75.8] | 58.6% | 51.5% | 93.7% |
| c7 source-balanced weights | 0.9077 | 0.9838 | 1.12% | 0.9384 | 0.8746 | 0.7259 | 38.4% [34.9–42.0] | 46.7% [34.6–59.1] | 44.7% | 25.8% | 91.7% |
| c8 Hannousse only | 0.5308 | 0.9498 | 2.09% | 0.2716 | 0.7456 | 0.8714 | 12.6% [10.4–15.2] | 6.7% [2.6–15.9] | 13.3% | 15.5% | 76.0% |

**Failed gates** (from the committed `acceptance` block):

| Candidate | Failed gates |
|---|---|
| c5 | shape guard; real off-template FPR; all four per-shape FPR gates |
| c6 | as c5, plus PhiUSIIL unseen-domain recall drop (3.5 pp) |
| c7 | as c6, plus PhiUSIIL recall drop (3.4 pp; CI 3.1–3.7) and OpenPhish drop (3.3 pp) |
| c8 | every gate except real-data F1 |

The conclusion "no candidate passes" is supported. Every candidate misses the 5% off-template gate.
The upper Wilson bound is below 5% only for c8's bare-root group, and that group has n = 60.

## 4. Evaluation and dataset limitations

- **Dataset age:**
  - PhiUSIIL is the 2024 UCI release; its labels are historical.
  - Hannousse is a May 2020 snapshot.
  - Neither has per-row timestamps, so **no time-based holdout is possible**.
  - OpenPhish is a 300-URL local snapshot (licence review pending; not in Git).
- **Label quality:**
  - Hannousse "legitimate" means crawled from Alexa top-500 seeds or a prior Yandex list. It is not
    per-URL verified.
  - Phishing labels come from feeds (PhishTank is community-verified; OpenPhish is automated).
  - 0 label conflicts in either source.
- **Class balance:** PhiUSIIL is 42.7% phishing in every split; Hannousse is 49.7–50.1%.
- **Sample size:** Hannousse validation has 856 legitimate URLs, of which 722 are off-template and only
  60 are bare-root. Per-shape intervals are wide: bare-root ±12–15 pp.
- **Domain grouping is approximate:** last two labels, plus a fixed list of 35 multi-part suffixes; no
  Public Suffix List. Hosting platforms (e.g. `github.io`) collapse to one group.
- **Domain independence is partial:**
  - Hannousse splits are domain-disjoint.
  - PhiUSIIL splits are stratified, not grouped: 7.7% of validation rows have a domain seen in train.
  - Cross-source: 388 Hannousse validation rows share a domain with PhiUSIIL train.
  - The overall figures are therefore not fully domain-independent. Use the "unseen" columns for that
    question.
- **The shape guard** is a synthetic stress test and is not a real FPR. The real FPR comes only from
  the Hannousse held-out rows.

## 5. Ranked feature-engineering recommendations

Each feature would be validated by the same protocol: an ablation against the current 19 features on
identical splits, per-shape FPR, unseen-domain recall, and a train/serve parity test.

| Rank | Recommendation | Present today? | Rationale | Leakage / bias risk | Validation |
|---|---|---|---|---|---|
| 1 | **Split host and path into separate feature blocks** (host: length, digits, hyphens, label count, max label length; path: length, depth, digits, encoded chars, file extension; query: parameter count, max value length) | No; every count mixes host and path | Lets the model learn host signals from all data, while path signals come only from data where both classes have paths. This is the precondition for item 2. | Low | Ablation; per-shape FPR; legitimate support coverage (share of held-out legitimate URLs inside the training range per feature) |
| 2 | **Mask confounded blocks per source:** set path, query and scheme features to *missing* for PhiUSIIL rows; XGBoost learns default directions | No | PhiUSIIL cannot teach path, query or scheme behaviour (legitimate rows never vary). Masking removes the confound without discarding its 164,759 training rows. | Medium: serving rows always have the block present, so test explicitly that served legitimate URLs with paths are in-distribution for the path block (Hannousse-trained) | Compare masked vs unmasked on identical features (one factor) |
| 3 | **Registrable-domain structure, independent of a literal `www.`** (subdomain count excluding `www`, subdomain depth, hyphen and digit counts in the registrable label, brand-like token *in a subdomain*) | Partial: `NoOfSubDomain` counts `www` | `www.` carries no phishing meaning; deep subdomains and brand-in-subdomain do. | Low; no domain identities are memorized | Ablation; check the `example.com` vs `www.example.com` score gap closes on held-out data, not just the diagnostic |
| 4 | **Host character composition:** Shannon entropy, consonant and digit run length, vowel ratio | No | DGA-like and random hosts are common in phishing (e.g. `tokinim-cdng-hkj.lol` in OpenPhish). Independent of shape. | Low; may penalize non-English or brand-new legitimate hosts, so report FPR on those | Ablation; inspect false positives |
| 5 | **Suspicious tokens split by location** (host vs path vs query) | Partial: one flag for the whole URL | `login` in a path is common on legitimate sites; `login` in a subdomain is not. | Low | Ablation; per-shape FPR |
| 6 | **Scheme as context only:** keep `IsHTTPS`, but with item 2's masking so only representative data teaches it | Yes (62.9% gain, confounded) | Not removed: `http` is still weakly informative in 2020+ data. | High if left unmasked | As item 2 |
| 7 | **TLD identity / TLD group** | No (only TLD length) | Some TLDs are over-represented in phishing feeds | **High:** memorizes source-specific TLD mixes and dates quickly | Only with a time-based holdout; not recommended now |
| — | **Character n-grams / embeddings** | No | Highest capacity | High overfitting risk on about 3k legitimate URLs; changes the serving schema substantially | Defer until data volume is ≥ 10× |

**Not recommended:** domain allowlists or popularity features. Popularity is not a safety label, and
per-domain memorization fails on unseen domains (see `docs/url_shape_guard.md`).

## 6. Proposed next experiment (smallest defensible)

**Question:** does the representation change (items 1 + 2, then 3) reduce real off-template false
positives at an acceptable recall cost, independently of data volume?

**Design** (no promotion possible from this experiment alone):
1. **Features:** add a new, versioned extractor `url_lexical_v2`. Production `url_lexical` stays
   unchanged and pinned. It contains blocks for host (items 1 + 3 + 4), path/query (item 1) and scheme
   (item 6). Add a parity test that training and serving call the same v2 function, and test the
   column order.
2. **Data:**
   - PhiUSIIL stratified splits plus the committed Hannousse grouped splits, exactly as in
     `train_url_multisource.py` (same seed, same leakage drop).
   - Report domain overlap per split pair and per source, as now.
3. **Arms** (same estimator, hyperparameters and seed; one factor at a time):
   - **A0** production (reference).
   - **A1** v2 features, no masking.
   - **A2** v2 features, PhiUSIIL path/query/scheme blocks masked.
   - **A3** A2 without the entropy features (item 4) — an ablation, to check that item 4 is not
     carrying the result.
4. **Evaluation:**
   - Validation splits only, reporting for every arm on identical rows:
     - recall, precision, FPR and confusion matrix (overall);
     - unseen-domain recall;
     - per-shape legitimate FPR with Wilson intervals;
     - OpenPhish recall (local);
     - shape guard.
   - Locked test splits are scored only for an arm that passes every gate.
5. **Acceptance:** the **unchanged** `configs/url_candidate_acceptance.json` (original criteria plus
   the `addendum_2026_10_29_b` gates).
6. **Interpretation:**
   - If A2 improves off-template FPR substantially over c5 at the same recall, representation plus
     masking is the lever.
   - If A2 is close to c8's 12.6% FPR, data volume is the binding limit.

**Additional licensed data needed for any promotion** (estimate):
- **Volume:** a ±2 pp Wilson half-width around a 5% FPR needs about 450–500 legitimate URLs per shape
  group in *validation*. Across four shape groups with a 70/15/15 split, that is roughly **13k or more
  legitimate URLs**, spread over **2k or more registrable domains** (the current per-domain cap is 12).
- **Freshness:** recent phishing (2025–2026) for a time-based holdout.
- **Requirements:** a verified licence, per-row collection dates, and shape diversity (bare, `www`,
  `http`, paths, queries).
- **Candidates to verify** (none downloaded; see `docs/url_data_acquisition_plan.md`):
  - Common Crawl URL index sampled by Tranco rank (popularity proxy only);
  - PhishTank (terms require registration);
  - a manually reviewed legitimate sample for headline figures.

**Promotion requirements** (before any artifact replaces production):
- Pass every acceptance gate on validation, then on the locked test splits, scored once.
- Get a new `MODEL_SHA256` pin, regenerated `metadata.json` (feature names and version, extractor
  version, splits, metrics), and an explicit `known_failing_models` decision in the shape guard.
- Update the parity, class-order and feature-order tests.
- Update the real-model characterization tests: replace the "known shortcut" assertions with the new
  expected behaviour.
- Keep the high-risk HIGH regression tests unchanged.
- Re-run the offline smoke test.
- Plan artifact distribution: binaries are gitignored, so either document a verified reproducible
  retrain (same SHA on the deployment machine) or decide on an artifact store.

## 7. Unchanged by this investigation

- **Production URL model:** `models/url_inference/model.joblib`, SHA-256
  `2f2e1d492ec3bc96891df3c08d3e80ff158021f6321160e3d55a52707f2d2adc`, unchanged.
  `metadata.json` and the decision threshold 0.5 are unchanged.
- **Inference:** `app/`, `src/features/` and the scan-route behaviour are unchanged.
- **Acceptance criteria:** `configs/url_candidate_acceptance.json` is unchanged.
- **Other components:** the SMS model, blockchain registry and reputation pre-check are unchanged.
- **Training:** no model was trained. All analysis was inference-only on committed data and the
  existing local candidate binaries (c5–c8, checksums in their committed `config.json`).

## Appendix: reproducing the inference-only analysis

From the repository root, with the production URL model present. For gain importance, the c5–c8
binaries are needed (`python -m src.training.train_url_multisource` regenerates them).

```python
import numpy as np, pandas as pd
from urllib.parse import urlsplit
from app.services import ml_detector
from src.features.url_lexical import extract_lexical_url_dataframe as X
from src.training import train_url_multisource as ms

model, _ = ml_detector._load_model()
val = ms.load_hannousse()[0]["validation"]
legit = val[val.phishing == 0]
off = legit[[not ms.shape_groups(u)["in_template"] for u in legit.url]]
fp = X(off.url)[model.predict_proba(X(off.url))[:, 1] >= 0.5]           # 709 of 722
cf = fp.copy(); cf["NoOfSubDomain"] = cf["NoOfSubDomain"].clip(lower=1)  # -> 98.2% still flagged
cf["IsHTTPS"] = 1                                                        # -> 78.4%
for c in ["URLDepth", "NoOfQMarkInURL", "NoOfEqualsInURL", "NoOfAmpersandInURL"]:
    cf[c] = 0                                                            # -> 75.7%
print((model.predict_proba(cf)[:, 1] >= 0.5).mean())
hosts = off.url[model.predict_proba(X(off.url))[:, 1] >= 0.5].map(
    lambda u: "https://www." + (urlsplit(u).hostname or "").removeprefix("www."))
print((model.predict_proba(X(hosts))[:, 1] >= 0.5).mean())              # -> 0.068
```

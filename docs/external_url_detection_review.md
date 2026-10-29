# External phishing-URL detection projects: review for ChainShield (2026-10-29)

**Purpose:** research and comparison only. Nothing here changes ChainShield's model, inference,
thresholds, acceptance criteria, SMS or blockchain logic.

**How the repositories were inspected:**
- Shallow-cloned on 2026-10-29 into a temporary directory outside this repository and read as text.
- **No external code, notebook or pickled model was executed or loaded.**
- No numbers below were reproduced by us. Each claim is marked:
  - **[code]:** verified by reading source.
  - **[committed result]:** taken from a result file in the repository, not re-run.
  - **[README]:** stated in documentation only.

**ChainShield context:**
- `docs/url_feature_investigation.md`, `docs/url_shape_guard.md`, `docs/datasets.md`
- `configs/url_candidate_acceptance.json`
- `src/features/url_lexical.py`, `app/services/ml_detector.py`

| # | Repository | Commit inspected | Licence |
|---|---|---|---|
| R1 | [Yoyagm/phishing-url-detector](https://github.com/Yoyagm/phishing-url-detector) | `aa56956` (2026-10-13) | **MIT** (`LICENSE`). Bundled `data/public_suffix_list.dat` is **MPL-2.0** (file header). `data/brand_tokens.txt` is derived from Tranco; Tranco's terms were not checked. |
| R2 | [Muneeraothman/phishing-detection-ml](https://github.com/Muneeraothman/phishing-detection-ml) | `913b320` (2026-08-10) | **None found** (no LICENSE file, no licence statement) → all rights reserved by default; **code must not be copied** |
| R3 | [gangeshbaskerr/Phishing-Website-Detection](https://github.com/gangeshbaskerr/Phishing-Website-Detection) | `be501e8` (2024-03-27) | **None found** → **code must not be copied** |
| R4 | [rajeswari-30/phishdriftbench](https://github.com/rajeswari-30/phishdriftbench) | `a34afcc` (2026-08-26) | **MIT** (`LICENSE`, code). Its `CLAUDE.md` was treated as data, not instructions. |

## 1. Comparison

| Aspect | ChainShield (production) | R1 | R2 | R3 | R4 |
|---|---|---|---|---|---|
| **Input to features** | Full URL string [code] | **Canonical host only** [code: `src/phishurl/canonicalize.py`, `features.py`] | Full URL [code: `src/features/extract.py`] | Full URL + **live WHOIS, live HTTP fetch, Alexa API** [code: `URLFeatureExtraction.py` `whois.whois`, `requests.get(url)`, `urlopen(...alexa...)`] | Lexical URL features; separates lookup-based features via a "provenance audit" [README; `src/phishdriftbench/provenance/`] |
| **Features** | 19 lexical, host+path mixed (`src/features/url_lexical.py`) | 51 host-only: shape, entropy, digit/hyphen/vowel ratios, consonant runs, PSL registrable/subdomain split, platform-hosted flag, keyword, brand-in-subdomain-only, top-25 suffix one-hot [code] | 17 lexical incl. `is_https`, `count_slashes_path`, entropy, **train-derived `tld_risk_flag`** [code; `src/features/artifacts/tld_risk.json`] | 17 (9 address-bar, 4 domain incl. DNS/age, 4 HTML/JS) [code] | Not fully inspected; many model variants (`scripts/train_demo_v*.py`) |
| **`www.`** | Counted as a subdomain (the shortcut) [code] | Stripped in canonicalization [code] | In URL; second-level label extraction ignores it [code comment] | Stripped in `getDomain` [code] | Not verified |
| **HTTPS / path / query** | Features [code] | **Removed by design**; a test enforces invariance [code: `tests/test_no_host_leakage.py`] | `is_https` is the top SHAP feature, `count_slashes_path` second [README] | `getDepth`, `https_Domain` features [code] | Path sensitivity measured with synthetic paths [code: `scripts/run_path_sensitivity.py`] |
| **Normalization / malformed input** | `_strip_root_slash`, default `http://` [code] | Pure string surgery; strips scheme, userinfo (last `@`), port, brackets, trailing dot, `www.`; never raises [code] | `urlparse` [code] | regex [code] | Not verified |
| **Train/serve parity** | Same function, tested (`test_training_and_serving_use_the_same_feature_extractor`) | Same Python function, plus a **JS twin parity-tested on 567 URLs (feature diff 0)** [committed result `reports/parity.json`; test `tests/test_parity.py`]; **`feature_spec_sha256` embedded in the model** [README] | Same function imported by train and API [README, code] | Notebook-based; no tests | Tests exist (`tests/test_lexical.py` etc.); parity not verified |
| **Data** | PhiUSIIL + Hannousse 2021 (CC BY 4.0) | PhiUSIIL (train); Tranco + PhishTank (>2024-03-04) + OpenPhish (out-of-distribution eval) [code: `datasets.py`] | PhiUSIIL only [README, code] | PhishTank 5k + **UNB ISCX-URL2016 benign** 5k [README; notebook `sample(n=5000, random_state=12)`] | PhiUSIIL, PhishTank, Tranco [README "Data status"] |
| **Label provenance / dedup** | Exact dedup, conflict check, grouped split | Per-host dedup; conflicting hosts dropped (58) [committed result `reports/metrics.json`]; OOD removes train-seen hosts, pre-cutoff phish and hosts on both lists [code] | Exact URL dedup (`drop_duplicates`) [code] | None visible | **MinHash/LSH near-duplicate dedup** [code: `src/phishdriftbench/eval/dedup.py`], tested [`tests/test_dedup.py`] |
| **Split / domain overlap** | PhiUSIIL stratified (7.7% domain overlap); Hannousse domain-grouped | **`GroupShuffleSplit` by eTLD+1 (ICANN section)**; private-PSL platforms kept as one group and exposed as a feature [code: `train.py`, `psl.py`] | Stratified random 80/20 (domains can leak) [code] | Random 80/20 [README] | **Temporal split + decay curve** [code: `bench/splits.py`, tested]; cross-source / leave-one-source-out [README, scripts] |
| **Temporal validation** | None possible (no per-row dates) | PhishTank submitted after 2024-03-04 [code] | No | No | Yes, PhishTank `submission_time` [README, code] |
| **Metrics** | Recall, precision, FPR, per-shape FPR, Wilson CIs | **Recall at fixed FPR (1%, 0.1%)**, ROC/PR-AUC [code: `evaluate.py`] | Precision/recall/F1/ROC-AUC; threshold chosen on OOF train [README] | Accuracy only [README] | Prevalence-corrected precision (1:10²–1:10⁴), bootstrap CIs [README, code] |
| **Reported results** | Documented in `docs/url_shape_guard.md` | OOD+temporal ROC-AUC 0.937, recall 70.5% @1% FPR; **13,453 / 100,000 Tranco hosts flagged at threshold 0.5** [committed result] | ROC-AUC ≥ 0.998 on PhiUSIIL; self-reports that 4 of 5 real legitimate URLs with paths score ~100% phishing [README] | 85.8% test accuracy [README] | README says "experiments not yet run", but `results/*.csv` exist (e.g. `path_sensitivity.csv`: legitimate flag rate 1.0 with a synthetic path) → **status inconsistent; treat as unverified** |
| **Explainability / ablation** | Gain importance + counterfactuals (our investigation) | Exact TreeSHAP, JS reimplementation [code, README] | SHAP [README] | None | SHAP, ablations across axes [scripts] |
| **Leakage evidence** | PhiUSIIL template confirmed | **Same finding:** PhiUSIIL legitimate = 100% `https://www.`, 0% path/query; also `URLSimilarityIndex` is a label proxy [README; `scripts/leak_audit.py`] | **Same finding** (0 of 107,880 legitimate training URLs have a path) [README] | Not addressed | **Same finding, plus: Tranco legitimate also 0% path** [code docstring `run_path_sensitivity.py`] |

**Independent confirmation.** Three unrelated projects (R1, R2, R4) found the same PhiUSIIL artifact
that `docs/url_feature_investigation.md` measured. R1's committed numbers show a host-only model still
flags **13.5% of Tranco benign hosts at threshold 0.5**. That is in line with our c8 (12.6% on real
off-template legitimate URLs) and c2 (≈6% on transformed probes), and suggests lexical-only models
plateau at a similar false-positive level. These numbers were not reproduced; the datasets and
operating points differ.

## 2. Techniques worth adapting (reimplement, do not copy)

All of these are reimplemented in ChainShield's own style. R1 and R4 are MIT, so ideas and code could
be reused *with* the MIT notice. Reimplementation is preferred, so the serving code stays ours and
small.

| # | Technique | Source | Adaptation for ChainShield |
|---|---|---|---|
| A1 | **Mutation-invariance guard with a negative control.** Mutating anything outside the host must leave the host-block features bit-identical; a planted leak must make the test fail | R1 `tests/test_no_host_leakage.py` | Apply to the host block of the planned `url_lexical_v2`. Our shape guard measures *model output*; this tests the *features* directly and catches regressions before training. |
| A2 | **Frozen Public Suffix List snapshot; ICANN section for grouping, private section as a feature** (`is_platform_hosted`) | R1 `src/phishurl/psl.py`, `data/public_suffix_list.dat` (MPL-2.0) | Replace our 35-suffix approximation (`train_url_multisource.MULTI_PART_SUFFIXES`) for grouping. Committing the PSL file requires keeping its MPL-2.0 header (redistribution permitted). This fixes the known limitation that `*.github.io`/`*.vercel.app` collapse to one group, and adds a "hosted on a user-content platform" feature without a domain allowlist. |
| A3 | **Host composition features:** entropy (host and registrable), max consecutive digits/consonants, vowel ratio, digits in the registrable label, hyphen ratio, subdomain length | R1 `src/phishurl/features.py` | Matches recommendations 3–4 in `docs/url_feature_investigation.md`. Label-independent definitions. |
| A4 | **Brand-in-subdomain-only** (brand token in a subdomain but not in the registrable domain) | R1 `features.py` | Needs a label-independent brand list. R1's comes from Tranco top-1000 (Tranco terms unchecked) → build our own from a licensed source, or omit. |
| A5 | **`feature_spec_sha256` in model metadata;** refuse to score on mismatch | R1 (README; `export_model.py`) | Extends our existing `feature_names` check to detect changed feature *definitions*, not just names. |
| A6 | **Recall at a fixed FPR** as a reported metric, threshold chosen on validation | R1 `src/phishurl/evaluate.py::recall_at_fpr` | Report alongside the existing gates. Do **not** change the 0.5 production threshold without a separate decision. |
| A7 | **Near-duplicate (MinHash/LSH) leakage check** between train and held-out sets | R4 `src/phishdriftbench/eval/dedup.py` | Report the near-duplicate train→validation leakage rate. Requires the `datasketch` dependency → evaluation-only, not serving. |
| A8 | **Temporal split with a decay curve** | R4 `src/phishdriftbench/bench/splits.py` | Only possible once a timestamped source (e.g. PhishTank `submission_time`, which needs registration and terms review) is acquired. |
| A9 | **Prevalence-corrected precision** (alerts per 10⁶ URLs at 1:10²–1:10⁴) | R4 [README] | Report-only; makes the cost of a few-% FPR explicit. |

## 3. Techniques that should not be copied

| Technique | Where | Why not |
|---|---|---|
| Live WHOIS / HTTP fetch / third-party rank lookups at inference | R3 `URLFeatureExtraction.py` | Contacts the target site, which conflicts with ChainShield's no-fetch, hash-only design. Non-deterministic and slow. The Alexa API it calls is discontinued. |
| Target-derived TLD risk list | R2 `src/features/vocab.py`, `artifacts/tld_risk.json` | Encodes source-specific label priors; the list even includes IP fragments (`"238"`, `"24"`) as "TLDs". R2's own error analysis attributes 46% of its false positives to it. |
| Treating Tranco/top-site *domains* as legitimate full URLs | R1 OOD set, R4 merged source | Tranco has **0% paths** (R4, code docstring). Mixing it with feed URLs creates the *reverse* shortcut (bare ⇒ legitimate, path ⇒ phishing). Usable only for host-only models, as R1 does. |
| Using UNB ISCX-URL2016 benign as is | R3 `DataFiles/1.Benign_list_big_final.csv` | Its page states **no licence or terms**. The collection description says domain-only entries were **removed**, giving the opposite shape gap. Its "benign" sample includes torrent-index URLs (first row of R3's copy). |
| Random/stratified splits and accuracy-only reporting | R2, R3 | Domain and campaign leakage, as our investigation shows; accuracy hides the false-positive problem. |
| Host-only as the *production* model | R1 | It removes our path signal, and the path signal matters for recall: ChainShield's c2 host-only candidate lost about 31 pp recall. Use it as a comparison arm, not a replacement. |
| Copying code from R2/R3 at all | — | No licence. |

## 4. Proposed experiment

This extends `docs/url_feature_investigation.md` §6 and replaces nothing there.

**Arms.** Same estimator and hyperparameters as production, same seed, same data and splits as
`train_url_multisource.py`, validation only:

| Arm | Representation | Purpose |
|---|---|---|
| B0 | Production model (unchanged artifact) | Reference |
| H1 | **Host-only** v2 block (A1–A3; canonical host, `www.` stripped, PSL split, composition features) | Upper bound on shape-invariance; R1-style. Expect low path-shape FPR but a recall loss. |
| L1 | **Host block + path/query block + scheme** (v2 lexical) | Representation effect without masking |
| L2 | L1 with path/query/scheme blocks **masked for PhiUSIIL rows** (`docs/url_feature_investigation.md` rec. 2) | Removes the PhiUSIIL confound while keeping its host examples |

**Grouping.** Frozen-PSL eTLD+1 (A2). Report the overlap per split pair and per source, and the
MinHash near-duplicate rate train→validation (A7).

**Reporting per arm, on identical rows:**
- recall, precision, FPR, confusion matrix;
- recall at 1% FPR (A6);
- unseen-domain recall;
- per-shape legitimate FPR with Wilson intervals;
- OpenPhish recall (local-only);
- shape-guard rates.

## 5. Risks, expected benefits, acceptance

**Expected benefits** (hypotheses, not claims):
- H1 and L2 should cut real off-template FPR well below c5's 54%.
- L2 should keep more PhiUSIIL recall than H1.
- The host-block invariance test (A1) prevents the `www.`/scheme shortcut from reappearing.

**Risks:**
- About 3k legitimate training URLs may still cap FPR near c8's 12.6%. R1's 13.5% at threshold 0.5
  suggests the same plateau for host-only features.
- Masking (L2) makes serving-time path features depend only on Hannousse (2020 data).
- Entropy features may penalize non-English or new legitimate hosts. R2 reports this kind of fairness
  issue; report FPR on those hosts.
- Adding the PSL file brings MPL-2.0 file obligations.

**Acceptance:** `configs/url_candidate_acceptance.json`, **unchanged**: the original criteria plus
`addendum_2026_10_29_b`. That means real off-template legitimate FPR ≤ 5% overall and per shape, a
PhiUSIIL recall drop ≤ 1 pp (CI upper ≤ 2 pp), shape guard pass, and no regressions in the high-risk
or model-unavailable tests. Recall at 1% FPR is reported, not gated. The locked test splits are scored
only for an arm that passes every validation gate. Any promotion follows the requirements in
`docs/url_feature_investigation.md` §6.

## 6. Reproduction

Inspection (read-only; nothing executed):

```bash
D=$(mktemp -d)
for r in Yoyagm/phishing-url-detector Muneeraothman/phishing-detection-ml \
         gangeshbaskerr/Phishing-Website-Detection rajeswari-30/phishdriftbench; do
  git clone --depth 1 "https://github.com/$r.git" "$D/$(echo $r | tr / _)"
done
git -C "$D/Yoyagm_phishing-url-detector" rev-parse --short HEAD      # aa56956
less "$D/Yoyagm_phishing-url-detector/src/phishurl/features.py"
less "$D/Yoyagm_phishing-url-detector/tests/test_no_host_leakage.py"
less "$D/rajeswari-30_phishdriftbench/src/phishdriftbench/eval/dedup.py"
less "$D/rajeswari-30_phishdriftbench/results/path_sensitivity.csv"
```

ChainShield baseline numbers that the proposed arms will be compared against (existing, runnable):

```bash
.venv/bin/python -m src.training.train_url_multisource     # B0, c5–c8 on validation
.venv/bin/python -m src.evaluation.url_shape_guard          # shape stress test
```

The H1/L1/L2 arms are **not implemented** yet. External repositories' own commands (e.g. R1
`make audit`) were not run: they download datasets and execute unreviewed code.

## External sources inspected

- https://github.com/Yoyagm/phishing-url-detector
- https://github.com/Muneeraothman/phishing-detection-ml
- https://github.com/gangeshbaskerr/Phishing-Website-Detection
- https://github.com/rajeswari-30/phishdriftbench
- https://www.unb.ca/cic/datasets/url-2016.html (ISCX-URL2016 description; no licence stated)

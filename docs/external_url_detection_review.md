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

---

# Round 2: additional repositories (2026-10-29)

**Selection:** from `gh search repos` ("URLNet", "phishing url detection"), chosen to cover gaps left
by round 1:

| Repository | Gap covered |
|---|---|
| R5 URLNet | Character-level representation |
| R6 DEPHIDES | Large legitimate corpus with paths; also the source of the Yandex URLs inside Hannousse |
| R7 URLTran | Transformer representation |
| R8 vaibhavbichave | Most-starred result; common practice |

**Method:** same as round 1. Shallow clone outside this repository; read as text. **No code executed,
no models or `__pycache__` loaded.** The DEPHIDES text files were read with pandas for
shape/overlap statistics. Those statistics come from our own reading of their committed data and are
**[measured by us]**.

| # | Repository | Commit | Licence |
|---|---|---|---|
| R5 | [Antimalweb/URLNet](https://github.com/Antimalweb/URLNet) | `0f0a92c` (2021-01-12) | **Apache-2.0** (`LICENSE`) |
| R6 | [ebubekirbbr/dephides](https://github.com/ebubekirbbr/dephides) | `e66ef86` (2024-07-30) | **MIT** (`LICENSE`) for the repository. The dataset is derived from Common Crawl and PhishTank, whose upstream terms still apply; **not verified for redistribution** |
| R7 | [bfilar/URLTran](https://github.com/bfilar/URLTran) | `d82a2f2` (2022-08-24) | **None found** → do not copy |
| R8 | [vaibhavbichave/Phishing-URL-Detection](https://github.com/vaibhavbichave/Phishing-URL-Detection) | `c25eae0` (2022-09-22) | **None found** → do not copy |

## R1. Comparison

| Aspect | R5 URLNet | R6 DEPHIDES | R7 URLTran | R8 vaibhavbichave |
|---|---|---|---|---|
| **Representation** | Char-level + word-level + char-in-word CNN embeddings over the **raw full URL**: `char_id_x(urls, …)` reads the unmodified string, scheme and `www.` included [code: `utils.py`, `train.py`]. A `split_url` helper strips scheme/`www.` but is not used for the char input [code] | Char-level deep models (`src/`) [README]; not inspected in depth | BERT WordPiece tokens over the raw URL, `max_length=128` [code: `data_prep.py`] | 30 ternary features from the old UCI "Phishing Websites" set [data: `phishing.csv`] |
| **Network at inference** | None | None [README] | None | **Yes:** `requests.get(url)`, `whois.whois`, `googlesearch`, Alexa API [code: `feature.py`] |
| **`www.` / HTTPS / path** | All visible to the model as characters | All visible | All visible | Hand features (`Hppts`, `SubDomains`, …) |
| **Train/serve parity** | Same tokenization code; dictionaries saved with the model [README, code] | Not verified | Same tokenizer [code] | **None:** trains on precomputed UCI features, serves with its own live-fetch reimplementation [code vs data] |
| **Data** | None shipped; format `label<TAB>url` [README] | **5,202,841 URLs** (big; Google Drive on request) / **520,285** (small, committed). Legitimate from **Common Crawl** (URLs on top-100k CC domains, `dataset/top100k_cc.txt`), phishing from **PhishTank** [README] | Benign = Alexa top-50k *domains* + the author's **personal Chrome history** (60k); malicious = OpenPhish/PhishTank/Phishing.Database [README] | UCI 2015-era dataset (11k rows), no URLs |
| **Shape profile** | n/a | Small dataset, 60k-row sample [measured by us]: legitimate HTTPS **66.5%** vs phishing **2.3%**; `www.` 72.1% vs 28.2%; root-only 1.7% vs 6.8%. Every row has a scheme | Bare legitimate domains vs full phishing URLs → path/shape shortcut by construction | n/a |
| **Dedup / conflicts** | none | 502 duplicate URLs in 520,284 rows, 0 label conflicts [measured by us] | none | none |
| **Split / domain overlap** | **Random per-class split**, `np.random.seed(10)` [code: `utils.py::prep_train_test`] | Given 70/20/10 split; **77% of test rows share a registrable domain (last two labels) with train** [measured by us] | `train_test_split` random [code] | random (notebook) |
| **Temporal validation** | No | No (no per-row dates in the files) | No | No |
| **Metrics reported** | AUC [README, `auc.py`] | Accuracy/precision/recall per architecture [README, `test_results/`; not re-run] | Paper-reported [README] | Accuracy [README] |

## R2. Techniques worth adapting (reimplement)

| # | Technique | Source | Adaptation |
|---|---|---|---|
| A10 | **Character-in-word (subword) features over host and path tokens, separately** | R5 `utils.py::ngram_id_x`, `get_words` (Apache-2.0; would need NOTICE if copied; reimplement instead) | A gradient-boosting-compatible version: hashed char 3–5-grams of the **canonical host** and, separately, of the **path tokens**. Our `url_feature_investigation.md` deferred n-grams because of data volume; R6 could change that (see A11). Must keep the A1 host-invariance test and the PhiUSIIL path masking (L2), or n-grams will learn `https://www.` even faster than the 19 lexical features. |
| A11 | **Large legitimate-with-path corpus from Common Crawl, seeded by top CC domains** | R6 `dataset/`, `top100k_cc.txt` | A candidate source for the volume gap (≫ 13k legitimate URLs). Before use: **(1)** verify Common Crawl and PhishTank terms for this derived redistribution; **(2)** re-split by PSL eTLD+1 (their split leaks 77% of test domains); **(3)** treat the scheme as confounded (66.5% vs 2.3% HTTPS) → mask `IsHTTPS`/scheme features for R6 rows, as for PhiUSIIL; **(4)** report shape profiles per source; **(5)** popularity-proxy labels only. |
| A12 | **Saved tokenization dictionaries as part of the model artifact** | R5 [README] | For any n-gram arm: hash function and n-gram spec go into `metadata.json` and the feature-spec hash (A5). |

## R3. Do not copy

| Technique | Where | Why |
|---|---|---|
| Raw full-URL char/token models trained on shape-confounded sources | R5, R7 | The highest-capacity representation amplifies the PhiUSIIL/Tranco shortcut. Our evidence shows the shortcut is distributed across many features; characters encode it directly. |
| Personal browser history as "benign" data | R7 README | Personal data, not reproducible, and selection-biased. Also incompatible with ChainShield's privacy stance. |
| Live fetch / WHOIS / search lookups at inference | R8 `feature.py` | Contacts the target, non-deterministic, and the Alexa API is dead. Same as R3 in round 1. |
| Training on precomputed third-party features and serving a reimplementation | R8 | No parity guarantee: the train/serve skew our tests exist to prevent. |
| Using R6's published split as is | R6 | 77% domain overlap train→test inflates results. |
| Copying R7/R8 code | — | No licence. |

## R4. Effect on the proposed experiment (§4)

- **No change to B0/H1/L1/L2** or to the unchanged acceptance criteria.
- **Optional data arm L2+D** (only after the licence check in A11): L2 trained additionally on
  DEPHIDES-small, re-split by PSL eTLD+1, with scheme features masked for those rows. Evaluated on the
  **same** Hannousse and PhiUSIIL validation rows as every other arm. DEPHIDES held-out rows are a
  third, separately reported validation set.
- **Optional representation arm N1** (after L2+D, only if L2+D still misses the gates): A10 hashed
  host/path char n-grams with the same masking. Deferred because it changes the serving feature schema
  the most.

**Additional risks:**
- DEPHIDES legitimate URLs are "on popular CC domains", not verified safe.
- Its PhishTank rows are older and mostly `http`.
- Adding it shifts the training mix heavily (520k vs 171k rows), so report per-source weights.
- The big dataset is not in the repository (Google Drive on request) and was **not** requested.

## R5. Reproduction (inspection only)

```bash
D=$(mktemp -d)
for r in Antimalweb/URLNet ebubekirbbr/dephides bfilar/URLTran vaibhavbichave/Phishing-URL-Detection; do
  git clone --depth 1 "https://github.com/$r.git" "$D/$(echo $r | tr / _)"
done
less "$D/Antimalweb_URLNet/utils.py"                 # char_id_x / prep_train_test
less "$D/vaibhavbichave_Phishing-URL-Detection/feature.py"   # live requests/whois at inference
python -I - "$D/ebubekirbbr_dephides/dataset/small_dataset" <<'PY'
import sys, pandas as pd
from urllib.parse import urlsplit
rows = []
for split in ("train", "val", "test"):
    for line in open(f"{sys.argv[1]}/{split}.txt", encoding="utf-8", errors="replace"):
        label, _, url = line.rstrip("\n").partition("\t")
        if url: rows.append((split, label, url))
d = pd.DataFrame(rows, columns=["split", "label", "url"])
host = d.url.map(lambda u: urlsplit(u).hostname or "" if "[" not in u else "")
reg = host.str.split(".").str[-2:].str.join(".")
print(d.groupby("label").url.apply(lambda s: s.str.startswith("https").mean()))   # full set: legitimate 0.666, phishing 0.022 (table: 60k sample)
print(reg[d.split == "test"].isin(set(reg[d.split == "train"])).mean())            # 0.770
PY
```

Nothing from R5–R8 was executed. The R6 big dataset was not downloaded.

### Round 2 sources

- https://github.com/Antimalweb/URLNet
- https://github.com/ebubekirbbr/dephides
- https://github.com/bfilar/URLTran
- https://github.com/vaibhavbichave/Phishing-URL-Detection

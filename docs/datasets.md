# Dataset Sources, Licenses, Labels and Provenance

Status of every dataset ChainShield uses or may use. Verified on 2026-10-28 from
the official pages linked below and, where a file is in the repository, from the
file itself. Nothing here was trained on.

**Rule:** a dataset may be used for training only when its row in the
[eligibility table](#training-eligibility) is "Eligible". "Pending file check"
means the license and label names are confirmed on the official page, but the
downloaded file has not yet been checked against them.

## Canonical labels

| Task | Canonical labels | Positive class |
|---|---|---|
| URL phishing | `phishing`, `legitimate` | `phishing` |
| SMS smishing | `legitimate`, `generic_spam`, `smishing` | `smishing` only |

`generic_spam` is never mapped to `smishing`. Mappings are implemented in
`src/data/clean.py` (`LABEL_MAP`); labels with no verified meaning
(`phishing`, `0`, `1` for SMS data) are rejected, not guessed.

## Sources

### PhiUSIIL Phishing URL dataset (URL task)

- Official page: https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset
- Citation: Prasad, A. & Chandra, S. (2024). PhiUSIIL Phishing URL (Website). UCI
  Machine Learning Repository. Paper DOI: 10.1016/j.cose.2023.103545
- License: CC BY 4.0 (stated on the UCI page)
- Label definition (UCI page): "Label 1 corresponds to a legitimate URL, label 0 to a
  phishing URL."
- Mapping: `0` → `phishing`, `1` → `legitimate`
- Local file: `data/raw/PhiUSIIL_Phishing_URL_Dataset.csv` (tracked, added in commit 6ff0ab3)
  - SHA-256: `8e7e0331987e0f4dee0ca29df3b04e1913c19f2d60802c9a929c3e02aed2ff9a`
  - 235,795 rows, 56 columns; label counts 134,850 (`1`) and 100,945 (`0`), which match
    the published class counts, confirming the mapping from the data itself
  - 425 duplicate URLs; no missing labels
- Known limitation: every legitimate URL has the form `https://www.<domain>` with no
  path or query (100% of label `1` rows; 2.4% of label `0` rows). A model trained on it
  learns that template: on the validation split, the one-line rule "phishing unless the
  URL is `https://www.<domain>`" scored F1 0.997, above the trained model's 0.962. Its
  scores are not evidence of real-world accuracy.

### UCI SMS Spam Collection (SMS task)

- Official page: https://archive.ics.uci.edu/dataset/228/sms+spam+collection
- License: CC BY 4.0 (stated on the UCI page); cite Almeida & Gómez Hidalgo
- Size: 5,574 messages; 4,827 `ham`, 747 `spam` (from the page's source breakdown)
- Format: one text file, each line `<label>\t<message>`
- Label meaning: the page describes generic mobile-phone spam research. It does not
  describe phishing or smishing.
- Mapping: `ham` → `legitimate`, `spam` → `generic_spam`
- Contributes **no** `smishing` rows.
- Local file: not present in the repository.

### SMS Phishing Dataset, Mishra & Soni (SMS task)

- Official page: https://data.mendeley.com/datasets/f45bkkt8pr/1
- DOI: 10.17632/f45bkkt8pr.1; Version 1; published 2022-06-20
- License: CC BY 4.0 (stated on the Mendeley page)
- Labels on the page: Ham 4,844, Spam 489, Smishing 638 (total 5,971)
- Mapping: `ham` → `legitimate`, `spam` → `generic_spam`, `smishing` → `smishing`
- Collection: images and screenshots gathered from the Internet and converted to text
  with Python; labels assigned by source of extraction. OCR noise is likely.
- Known limitation: the smishing class is broad (includes prize and premium-rate scams).
- **File verified 2026-10-28** (downloaded via the Mendeley public API into the gitignored
  `data/incoming/mishra_soni/`):
  - `Dataset_5971.zip` SHA-256 `9bbf3188fdad81495d8e82825648b9b63b53fc86841a3d26c02629990b233cc3`,
    identical to the SHA-256 published by Mendeley; contains one file, `Dataset_5971.csv`
  - `Dataset_5971.csv` SHA-256 `649844f1c62a6b27e145eaf17a65f7010c56c390e11a794ea8329993a05ba71e`,
    UTF-8, 5,971 rows, columns `LABEL`, `TEXT`, `URL`, `EMAIL`, `PHONE`
  - Raw `LABEL` strings use mixed case: `ham` 4,844; `Smishing` 616 + `smishing` 22;
    `spam` 466 + `Spam` 23. After `standardize_label` (case-insensitive) the counts are
    legitimate 4,844, smishing 638, generic_spam 489, exactly the published figures.
  - No missing or blank text or labels.
  - Duplicates: 22 exact duplicate texts; 140 after normalization.
  - 34 normalized texts carry conflicting labels (every one is `spam` vs `smishing`,
    two rows each).
  - `URL`/`EMAIL`/`PHONE` flags use inconsistent case (`No`/`yes`). They are not read.
- **Preparation policy (Stage 1.3, approved)**, implemented in
  `src/data/prepare_sources.py` (`prepare_mishra_soni`). The frozen `clean.py` is not
  changed; it stops on any conflict, while this policy excludes conflicts.
  1. Read only `LABEL` and `TEXT`. Missing or blank values fail closed.
  2. Map labels case-insensitively with `standardize_label`; unknown or unresolved labels
     fail closed with the row position.
  3. Normalize text with `normalize_text` (lowercase, trim, collapse whitespace).
  4. Exclude **every row** of any normalized text that carries more than one canonical
     label. No label is chosen and no row is relabelled. Rationale: the source assigned
     labels by where each text was found, so a text present under two labels has no
     reliable label, and keeping either copy would put a disputed label into training.
  5. Exclude **every row** of any remaining normalized text that is a near-duplicate
     (rapidfuzz `ratio` ≥ 92, the threshold in `clean.NEAR_DUPLICATE_THRESHOLD`, compared
     across all pairs of texts with different labels) of a text with a different label.
     Same rationale: a near-identical message under two labels has no reliable label.
     Exclusion is by text, so a text in several pairs is counted once. (Stage 1.4)
  6. Keep one row per remaining normalized text: the row earliest in the file (stable
     sort on text, label, source row). Output order does not depend on input order.
- **Row accounting (computed 2026-10-28 from the verified CSV; originals unchanged):**

  | Step | Rows |
  |---|---|
  | Original rows | 5,971 (legitimate 4,844; smishing 638; generic_spam 489) |
  | Conflicting normalized texts | 34 |
  | Rows affected by label conflicts | 68 |
  | Rows excluded for label conflicts | 68 (smishing 34; generic_spam 34) |
  | Near-duplicate conflict pairs (≥ 92, all `smishing` vs `generic_spam`) | 19 pairs, 35 distinct texts (3 texts are in two pairs) |
  | Rows excluded for near-duplicate conflicts | 37 (smishing 20; generic_spam 17); 2 of these are same-label repeats of an involved text |
  | Same-label duplicate rows removed | 104 |
  | **Final usable rows** | **5,762** (legitimate 4,834; smishing 510; generic_spam 418) |

  68 + 37 + 104 + 5,762 = 5,971. Each row is counted in exactly one step: exact-conflict
  exclusion first, then near-duplicate exclusion on the remaining rows, then same-label
  duplicate removal. The counts are also stored, with the source CSV checksum, in the
  gitignored `data/incoming/mishra_soni/preparation_metadata.json`.
- No cross-label near-duplicates remain, so the frozen `clean.py` will not stop on this data.

### Fishing for Smishing, IMC 2025 (SMS task, external evaluation candidate)

- Official repository: https://github.com/reportsmishing/Smishing-Dataset-IMC25
- License: CC BY 4.0 (LICENSE.txt read directly)
- Contents: `dataset/final_dataset_output.csv` ("labeled smishing dataset"), `time_day.csv`
- Paper: Agarwal et al., "Fishing for Smishing", ACM IMC 2025, DOI 10.1145/3730567.3764431
- **File verified 2026-10-28** (downloaded from the repository's `main` branch into the
  gitignored `data/incoming/imc2025/`):
  - `final_dataset_output.csv` SHA-256 `1bbd1e9e82c3ea023112207b80da268a5c4a07d2353c2b0898360ab037fa9a64`,
    UTF-8, 33,869 rows, 12 columns: `time`, `sender_id`, `telephone_number_type`,
    `original_network_name`, `original_network_country`, `text`, `translation`, `language`,
    `url_shortener`, `named_entity`, `scam_type`, `lure_principles`
  - `LICENSE.txt` SHA-256 `7e7170e3cebf88a9f60c7b8421418323c09304da1af4d5e90f4da1dc1c8a2661` (CC BY 4.0)
  - The GitHub branch is not versioned like a DOI release; record this checksum with any use.
- **There is no label column.** Every row is a user-reported suspicious text. `scam_type`
  counts: banking 15,277; others 6,922; delivery 3,810; government 3,248; telecom 2,226;
  spam 1,710; wrong number 332; hey mum/dad 263; missing 81.
- How `scam_type` was assigned (paper §3.3.6 and §3.4): by GPT-4o, using a prompt tuned on
  a 150-text human consensus set (κ = 0.93 against it, English only). Rows are not
  individually human-verified.
- Meaning of `spam` (paper §3.3.6, §5.2): annoying unsolicited messages, kept apart from
  scams that cause financial harm. The paper notes user reports "need to be checked for
  spam before being marked as scam".
- Meaning of `others` (paper §5.2): mixed; includes conversation, investment and
  cryptocurrency scams, tech-company impersonation, and OTP messages that may be benign.
- **Evaluation-only mapping (Stage 1.3)**, implemented in `src/data/prepare_sources.py`
  (`IMC_SCAM_TYPE_TREATMENT`, `map_imc_for_evaluation`). The original `scam_type` value is
  kept unchanged in `source_scam_type`; any string not in the table fails closed (the
  match is exact and case-sensitive; the file uses `delivery`, not the prompt's
  `Delivery/Parcel`). Definitions are quoted from the paper's annotation prompt (Appendix D.2).

  | `scam_type` | Evaluation label | Evidence |
  |---|---|---|
  | `banking` | `smishing` | Impersonates a bank or financial institution and asks to click a link, text back or call |
  | `delivery` | `smishing` | Impersonates a parcel or delivery company and asks to click, text back or call |
  | `government` | `smishing` | Impersonates a government organization and asks to click, text back or call |
  | `telecom` | `smishing` | Impersonates a mobile network operator and asks to click, text back or call |
  | `hey mum/dad` | `smishing` | Addressed to mum/dad, asks to text back citing a broken phone or new number; §5 describes these as conversational scams that deceive users into sending funds |
  | `wrong number` | excluded (unresolved) | Defined as a text that "looks like a normal greeting or asking about someone and/or to reply back". The criterion does not establish scam intent per row; genuine mistaken texts fit it too |
  | `spam` | `generic_spam`, reported separately | "Illicit marketing message including casino, betting, random draws". Never counted as smishing or legitimate |
  | `others` | excluded (unresolved) | "Does not fit" the other categories; §5.2 reports it mixes scam types with OTP messages that may be harmless |
  | missing | excluded | No category |

  Further rules: only English rows are evaluated (the classifier is English-only);
  normalized texts with conflicting evaluation labels are excluded; same-label repeats are
  reduced to one row. Every row is marked `split = external_evaluation_only`.
- **Evaluation accounting (computed 2026-10-28; original file unchanged):**

  | `scam_type` | Included smishing | Separate generic spam | Duplicate removed | Label conflict | Unresolved | Non-English | Missing |
  |---|---|---|---|---|---|---|---|
  | banking | 6,445 | | 4,050 | | | 4,782 | |
  | delivery | 1,241 | | 429 | 6 | | 2,134 | |
  | government | 1,341 | | 581 | | | 1,326 | |
  | telecom | 1,398 | | 228 | 4 | | 596 | |
  | hey mum/dad | 55 | | 22 | | | 186 | |
  | wrong number | | | | | 304 | 28 | |
  | spam | | 1,188 | 188 | 11 | | 323 | |
  | others | | | | | 4,586 | 2,336 | |
  | missing | | | | | | 80 | 1 |
  | **Total** | **10,480** | **1,188** | **5,498** | **21** | **4,890** | **11,791** | **1** |

  Total rows 33,869. English rows 22,078 (= 33,869 − 11,791).
- **Limitations of any IMC result:**
  - Labels were assigned by GPT-4o, not checked by a person per row. Results are
    agreement with dataset-assigned labels, not verified real-world performance.
  - There are no legitimate messages, so IMC measures smishing recall only. It cannot
    measure precision or false-positive rate.
  - The rows are user-reported texts, so they over-represent messages people noticed and
    reported.
  - `spam` ("random draws") overlaps in content with Mishra & Soni's broad smishing class,
    which includes prize scams; the two sources may draw the line differently.
- **Usage rule:** IMC must never be used for training, validation, threshold selection,
  feature selection or hyperparameter tuning. Enforcement (Stage 1.4):
  - `data/incoming/imc2025/evaluation_manifest.json` (gitignored) records the source, the
    `external_evaluation_only` split and the SHA-256 of every normalized IMC text (24,763
    fingerprints, all rows and languages). It holds hashes only, no text.
  - `assert_training_eligible` fails closed: it requires a `source` column whose values are
    all approved for training (currently `mishra_soni`), rejects evaluation-only rows, and
    rejects any row whose normalized text matches an IMC fingerprint, even after columns
    are removed or rewritten and case or whitespace is changed.
  - `src/training/guarded_training.py` is the mandatory training entry point. It checks
    `data/processed/train.csv` and `val.csv` with the guard before calling the frozen
    `train_baseline`. A missing or malformed manifest refuses training.
  - The prepared Mishra & Soni data shares no text with IMC (it passes the guard).
  - Limitation: `train_baseline.py` itself is frozen and can still be called directly,
    bypassing the wrapper. Training data produced by the current `split.py` must carry the
    `source` column for the wrapper to accept it.
- No legitimate messages. Suitable for measuring recall on smishing, not precision.
- **Privacy:** described as pseudo-anonymized, but some `telephone_number_type` cells hold
  values that look like phone numbers, and `sender_id`, `original_network_*` and
  `named_entity` describe senders. `load_imc_for_evaluation` reads only `text`,
  `scam_type` and `language` (the last is not personal data and is needed for the
  English filter); no other column is parsed. `text` itself may contain numbers and
  links, so no message text is printed, logged or placed in errors.

### vinit9638 SMS-scam-detection-dataset (used by `src/data/merge_github_dataset.py`)

- Repository: https://github.com/vinit9638/SMS-scam-detection-dataset
- **License: none.** No license file or statement. Without a license the data cannot be
  assumed to be reusable or redistributable.
- Labels: `ham`, `spam` only (README). No smishing class.
- Size: 138,813 rows, 41 languages; `lang` is filled for a subset only
- Provenance: not stated ("curated")
- Local file: not present.

### SmishTank (SMS task)

- Paper: https://arxiv.org/abs/2402.18430 (about 1,090 user-submitted smishing samples)
- **Dataset license: not verified.** The CC BY-NC-SA 4.0 license on the arXiv record
  covers the paper, not the dataset. `https://smishtank.com/dataset` returned HTTP 404
  on 2026-10-28.
- Contains smishing only; no legitimate class.

### Roman Urdu phishing SMS (Zenodo 21810885)

- Not verified in Stage 1. Code-mixed Roman Urdu/English; low priority for an
  English pipeline.

## SMS train/validation/test split (Stage 1.6)

Produced by `src/data/split_prepared.py` from the 5,762 prepared Mishra & Soni rows.

- **Grouping:** every row is a node; rows are connected when their normalized texts have
  rapidfuzz `ratio` ≥ 92 (all pairs compared). Connected components are indivisible groups,
  so chains (A~B, B~C) stay together.
- **Group audit:** 5,463 groups; 5,300 singletons; 163 multi-row groups holding 462 rows;
  largest groups 14, 10, 9, 9 rows. No group mixes labels. Smishing is the most clustered
  class: its 510 rows form only 319 groups (261 of its rows are in multi-row groups), so
  there are about 319 independent smishing examples.
- **Assignment:** seed 42; groups shuffled with `numpy.random.default_rng(42)`, stably sorted
  largest first, each placed in the split with the greatest remaining per-class need
  against 70/15/15 targets. A group larger than the smallest split target is refused.
- **Result:**

  | Split | Rows | legitimate | smishing | generic_spam | smishing groups |
  |---|---|---|---|---|---|
  | train | 4,032 | 3,384 | 356 | 292 | 223 |
  | val | 865 | 725 | 77 | 63 | 48 |
  | test | 865 | 725 | 77 | 63 | 48 |

  4,032 + 865 + 865 = 5,762. Class proportions agree within 0.1 percentage points.
- **Verification** (in memory and again from the written files): no group in two splits;
  no cross-split pair at ratio ≥ 92 (was 259 pairs with the earlier row-level split); no
  normalized duplicate across splits; labels, text and provenance unchanged; two runs
  give identical assignments; every file passes the training guard against all IMC
  fingerprints.
- **Files** (gitignored): `data/processed/train.csv`, `val.csv`, `test.csv`, plus
  `sms_split_metadata.json` with seed, algorithm, counts and file SHA-256 values. Columns:
  `text, label, category, source, source_row, group_id`; only `text` is a model input.
- **The test split is locked** for final evaluation: not for model selection, threshold
  tuning or feature decisions. Preprocessing and vocabulary are fitted on train only.

## Training eligibility

| Dataset | Task | License | Labels | Status |
|---|---|---|---|---|
| PhiUSIIL | URL | CC BY 4.0, verified | verified from page and file | **Eligible**, with the template limitation above |
| UCI SMS Spam | SMS | CC BY 4.0, verified | verified from page | **Pending file check** (no smishing rows) |
| Mishra & Soni | SMS | CC BY 4.0, verified | verified from file; counts match publisher | **Training-eligible** after `prepare_mishra_soni` (5,762 rows) |
| IMC 2025 | SMS | CC BY 4.0, verified | no label column; `scam_type` is LLM-assigned | **External evaluation only** (smishing recall, generic spam separately); never training or tuning |
| vinit9638 | SMS | **none** | `ham`/`spam` only | **Not eligible** |
| SmishTank | SMS | **unverified** | smishing only | **Not eligible** until terms are confirmed |
| Roman Urdu | SMS | unverified | unverified | Not assessed |

## Consequences for the existing SMS pipeline

- `src/data/merge_github_dataset.py` merges UCI SMS Spam with vinit9638. Neither source
  has a `smishing` class, and vinit9638 has no license. Under the canonical labels the
  merged data would contain only `legitimate` and `generic_spam`. It cannot train a
  smishing detector, and vinit9638 should not be used until it is licensed.
- The historical `experiments.csv` results were produced from that kind of data
  (spam vs. ham). They measure spam detection, not smishing detection.
- The only verified sources with a `smishing` class are Mishra & Soni (training) and
  IMC 2025 (external evaluation).

## Open items

1. Done 2026-10-28: Mishra & Soni and IMC 2025 downloaded and checked (see above).
2. Done (Stage 1.3): the 34 conflicting texts (68 rows) are excluded.
3. Done (Stage 1.3): IMC mapping documented; IMC is evaluation-only.
4. Done (Stage 1.4): the 19 cross-label near-duplicate pairs (37 rows) are excluded.
5. SmishTank and vinit9638 are excluded (terms unverified / no license).
6. Done 2026-10-28: the seeder registers only `smishing` for messages; `spam` is counted
   as generic spam and never registered (docs/SYSTEM.md, Blockchain → Seeder).
7. Open (found 2026-10-28): the PhiUSIIL stratified URL splits contain URLs that differ only
   in case, default port or trailing slash. After canonicalization (`canonicalize_url`), 124
   URLs are shared by train and validation, 113 by train and test, and 26 by validation and
   test. There are no exact-string duplicates. A future re-split should group by canonical
   hash. Measured with `src/evaluation/verify_production_models.py`; see
   docs/submission/ML_EVALUATION.md.
8. Registry proposals use only the Mishra & Soni train and validation smishing rows (never the
   locked test split) and PhiUSIIL label-0 URLs. They contain hashes and provenance only. The
   PhiUSIIL labels are historical (2024) and do not show that a URL is malicious today
   (data/threat_registry/REVIEW.md).

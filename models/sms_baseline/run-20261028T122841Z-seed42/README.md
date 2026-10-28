# SMS baseline run-20261028T122841Z-seed42

Selected model: `char25_C10` — TF-IDF char_wb 2–5-grams (min_df=2, sublinear_tf) on
normalized text + multinomial LogisticRegression (C=10, class_weight=balanced, seed 42).
Selected on validation macro-F1 among 4 candidates (all in validation_candidates.json).
Decision policy: argmax; no threshold tuning.

## Reproduce
    python -m src.training.train_sms_baseline train          # new run dir; never overwrites
    python -m src.training.train_sms_baseline test <run_dir> # once, after selection is frozen
    python -m src.training.train_sms_baseline imc  <run_dir> # after the test result exists
Inputs are checked by the training guard (approved source, IMC fingerprints) and by
checksums in data/processed/sms_split_metadata.json. An independent retrain
(repro-check-of-run-20261028T122841Z-seed42) gave identical validation results and predictions.

## Results (details in the JSON files)
- Validation macro-F1 0.9245; smishing P 0.958 R 0.896.
- Locked test (evaluated once): macro-F1 0.8929 [0.840, 0.932]; smishing P 0.892 [0.792, 0.959],
  R 0.857 [0.746, 0.934]; generic_spam→smishing 8/63; legitimate→smishing 0/725
  (95% one-sided upper bound ≈ 0.42% by the rule of three over 714 legitimate groups).
  Intervals: group bootstrap over 819 near-duplicate groups, 2000 replicates.
- IMC 2025 (external, GPT-4o labels, English, recall only): smishing recall 0.697
  [0.668, 0.725] on 10,480 texts (7,148 groups); hey mum/dad 0/55; delivery 0.44.

## Limitations
- Small minority classes: ~319 independent smishing groups in total; intervals are wide.
- Mishra & Soni text came from OCR of web screenshots; smishing class is broad.
- Large drop on IMC (0.86 internal vs 0.70 external recall): the model does not
  generalize to newer/other smishing styles, and misses conversational scams entirely.
- IMC labels are model-assigned and IMC has no legitimate class: no precision or
  false-positive estimate is possible from it.
- generic_spam is often confused with smishing (8/63 test; 361/1188 IMC spam predicted smishing).
- English only. No message text is stored in any artifact here.

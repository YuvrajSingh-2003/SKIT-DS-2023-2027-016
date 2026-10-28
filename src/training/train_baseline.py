"""Train baseline models (LogisticRegression and LinearSVC) on category prediction.

Features:
- Scales handcrafted features with MaxAbsScaler (fit on train, applied to val).
- Evaluates raw text vs NLP-preprocessed text combined with TF-IDF (1, 2) and handcrafted features.
- Trains LogisticRegression and LinearSVC with max_iter=5000 and class_weight='balanced'.
- Runs single train/val evaluation with per-category reports (zero_division=0).
- Runs 5-fold Stratified Cross-Validation on train+val combined (never test.csv).
- Computes binary smishing metrics (positive = the 4 scam categories). generic_spam rows are excluded from
  these metrics and reported as a separate stratum. Unsupported categories raise ValueError.
- Logs results to experiments.csv by default. An existing file is never deleted
  unless train_baseline(overwrite=True) is passed explicitly.
- Validates text, category and label values before fitting (validate_training_frame).
"""
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import numpy as np
import pandas as pd
from scipy.sparse import hstack
from sklearn.base import clone
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import MaxAbsScaler
from sklearn.svm import LinearSVC

from src.text_features import extract_text_features, extract_url_features, preprocess_text

DATA_DIR = Path("data/processed")
EXPERIMENTS_PATH = Path("experiments.csv")
RANDOM_STATE = 42


def load_data() -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Load train.csv and val.csv from data/processed."""
    train_df = pd.read_csv(DATA_DIR / "train.csv")
    val_df = pd.read_csv(DATA_DIR / "val.csv")
    return train_df, val_df


def extract_handcrafted_features(texts: Iterable[str]) -> np.ndarray:
    """Extract 7-dimensional handcrafted features for a sequence of texts."""
    feature_rows = []
    for text in texts:
        url_feats = extract_url_features(text)
        text_feats = extract_text_features(text)
        row = [
            int(url_feats["has_url"]),
            int(url_feats["shortener_used"]),
            int(url_feats["ip_as_domain"]),
            int(url_feats["https_present"]),
            float(text_feats["length"]),
            int(text_feats["has_urgent_word"]),
            int(text_feats["has_money_word"]),
        ]
        feature_rows.append(row)
    return np.array(feature_rows, dtype=float)


# Categories produced by src/data/categorize.py assign_category().
BENIGN_CATEGORY = "benign"
GENERIC_SPAM_CATEGORY = "generic_spam"
SMISHING_CATEGORIES = frozenset(
    {"prize_premium_scam", "free_offer_scam", "payment_scam", "other_scam"}
)
SUPPORTED_CATEGORIES = SMISHING_CATEGORIES | {BENIGN_CATEGORY, GENERIC_SPAM_CATEGORY}

# The canonical label each category must carry in the 'label' column.
CATEGORY_TO_LABEL = {
    BENIGN_CATEGORY: "legitimate",
    GENERIC_SPAM_CATEGORY: "generic_spam",
    **{category: "smishing" for category in SMISHING_CATEGORIES},
}


def validate_training_frame(df: pd.DataFrame, name: str = "dataset") -> None:
    """Raise ValueError before fitting if text, category or label values are invalid.

    Checks, in order: required columns; missing or blank text; missing
    categories; unsupported categories; and, when a 'label' column is present,
    that each label matches its category (legitimate/benign, generic_spam,
    smishing). Nothing is dropped; the caller decides what to do.
    """
    required = {"text", "category"}
    absent = sorted(required - set(df.columns))
    if absent:
        raise ValueError(f"{name}: missing required column(s) {absent}")

    text_missing = df["text"].isna() | df["text"].astype(str).str.strip().eq("")
    category_missing = df["category"].isna()
    if text_missing.any() or category_missing.any():
        raise ValueError(
            f"{name}: {int(text_missing.sum())} row(s) with missing or blank text and "
            f"{int(category_missing.sum())} row(s) with a missing category"
        )

    unsupported = sorted({str(c) for c in df["category"].unique() if c not in SUPPORTED_CATEGORIES})
    if unsupported:
        raise ValueError(f"{name}: unsupported category value(s) {unsupported}")

    if "label" in df.columns:
        expected = df["category"].map(CATEGORY_TO_LABEL)
        actual = df["label"].astype(str).str.strip().str.lower()
        mismatch = actual != expected
        if mismatch.any():
            example = df.loc[mismatch, ["label", "category"]].iloc[0].to_dict()
            raise ValueError(
                f"{name}: {int(mismatch.sum())} row(s) where label does not match category "
                f"(first: {example})"
            )


def to_binary_labels(series: pd.Series) -> pd.Series:
    """Map each category to 'smishing', 'benign' or 'generic_spam'.

    Only the four scam categories become the positive 'smishing' label.
    Unsupported values raise ValueError, including missing values and
    misspellings, so they cannot silently become smishing.
    """
    missing = series.isna()
    if missing.any():
        raise ValueError(f"{int(missing.sum())} missing category value(s)")

    unsupported = sorted({str(c) for c in series.unique() if c not in SUPPORTED_CATEGORIES})
    if unsupported:
        raise ValueError(f"Unsupported category value(s): {unsupported}")

    return series.map(
        lambda c: "smishing" if c in SMISHING_CATEGORIES else c
    )


def binary_smishing_metrics(y_true: pd.Series, y_pred) -> dict:
    """Binary smishing metrics with generic spam kept out of the primary result.

    Primary metrics use rows whose true category is not generic_spam. In that
    subset, 'smishing' is the positive class and every other prediction,
    including a predicted generic_spam, is a negative prediction.

    Generic spam is reported separately as its own stratum: how often it is
    predicted as smishing. It is never counted in the primary metrics.

    Precision convention: when no primary row is predicted as smishing,
    precision is reported as 0.0 (zero_division=0). That value means "no
    positive predictions", not a measured precision. Check
    predicted_smishing_rows before reading precision. Recall and F1 follow the
    same convention. The convention is unchanged here.
    """
    y_pred = pd.Series(y_pred, index=y_true.index)
    y_true_bin = to_binary_labels(y_true)
    y_pred_bin = to_binary_labels(y_pred)

    primary = y_true_bin != "generic_spam"
    y_true_ind = (y_true_bin[primary] == "smishing").astype(int)
    y_pred_ind = (y_pred_bin[primary] == "smishing").astype(int)

    generic = y_true_bin == "generic_spam"
    generic_pred = y_pred_bin[generic]

    # With no primary rows there is nothing to score, so the metrics are None.
    if primary.sum() == 0:
        precision = recall = f1 = None
    else:
        precision = precision_score(y_true_ind, y_pred_ind, zero_division=0)
        recall = recall_score(y_true_ind, y_pred_ind, zero_division=0)
        f1 = f1_score(y_true_ind, y_pred_ind, zero_division=0)

    return {
        "primary_rows": int(primary.sum()),
        "predicted_smishing_rows": int(y_pred_ind.sum()),
        "generic_spam_rows_excluded": int(generic.sum()),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "generic_spam_flagged_as_smishing": int((generic_pred == "smishing").sum()),
        "generic_spam_flagged_rate": (
            float((generic_pred == "smishing").mean()) if generic.any() else None
        ),
    }


def write_experiment_rows(rows: List[Dict[str, Any]], path: Path = EXPERIMENTS_PATH) -> None:
    """Write all result rows to path, replacing any existing file atomically.

    The rows go to a temporary file in the same directory, which then replaces
    path in one step. If writing fails, the temporary file is removed and an
    existing file at path is left byte-for-byte unchanged.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    frame = pd.DataFrame(rows)

    fd, temp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            frame.to_csv(handle, index=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    except BaseException:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise


def run_stratified_cv(
    combined_texts: pd.Series,
    combined_hc: np.ndarray,
    combined_y: pd.Series,
    model_template: Any,
    n_splits: int = 5,
) -> Tuple[float, float, float, float]:
    """Run 5-fold Stratified Cross-Validation on train+val combined."""
    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=RANDOM_STATE)
    fold_accs = []
    fold_macro_f1s = []

    for fold_train_idx, fold_val_idx in skf.split(combined_texts, combined_y):
        # 1. TF-IDF
        vec = TfidfVectorizer(ngram_range=(1, 2))
        X_tr_tfidf = vec.fit_transform(combined_texts.iloc[fold_train_idx])
        X_val_tfidf = vec.transform(combined_texts.iloc[fold_val_idx])

        # 2. Scale handcrafted features using MaxAbsScaler (fit on train only)
        scaler = MaxAbsScaler()
        X_tr_hc = scaler.fit_transform(combined_hc[fold_train_idx])
        X_val_hc = scaler.transform(combined_hc[fold_val_idx])

        # 3. Combine
        X_tr = hstack([X_tr_tfidf, X_tr_hc])
        X_val = hstack([X_val_tfidf, X_val_hc])

        # 4. Train & Evaluate
        clf = clone(model_template)
        clf.fit(X_tr, combined_y.iloc[fold_train_idx])
        preds = clf.predict(X_val)

        fold_accs.append(accuracy_score(combined_y.iloc[fold_val_idx], preds))
        fold_macro_f1s.append(
            f1_score(
                combined_y.iloc[fold_val_idx],
                preds,
                average="macro",
                zero_division=0,
            )
        )

    return (
        float(np.mean(fold_accs)),
        float(np.std(fold_accs)),
        float(np.mean(fold_macro_f1s)),
        float(np.std(fold_macro_f1s)),
    )


def train_baseline(
    experiments_path: Path = EXPERIMENTS_PATH, overwrite: bool = False
) -> None:
    """Public training entry point. Always enforces the data-eligibility guard.

    Delegates to guarded_training.guarded_train_baseline, which validates the
    evaluation manifest and a single snapshot of train.csv/val.csv (approved
    source on every row, no evaluation-only text) and then runs the private
    implementation on exactly that snapshot. There is no way to skip the guard.
    """
    from src.training.guarded_training import guarded_train_baseline  # lazy: avoids a circular import

    guarded_train_baseline(experiments_path=experiments_path, overwrite=overwrite)


def _train_baseline_unguarded(
    experiments_path: Path = EXPERIMENTS_PATH, overwrite: bool = False
) -> None:
    """Private implementation. Called only by guarded_train_baseline (and by tests
    that replace load_data and the estimators). Not a training entry point.

    Run the baseline experiments and write results to experiments_path.

    If experiments_path already exists and overwrite is False, this raises
    FileExistsError before any data is read. With overwrite=True the existing
    file is replaced only after every experiment has finished and the results
    are written to a temporary file. If anything fails before that point, the
    existing file is left byte-for-byte unchanged.
    """
    experiments_path = Path(experiments_path)
    if experiments_path.exists() and not overwrite:
        raise FileExistsError(
            f"{experiments_path} already exists. Pass overwrite=True to replace it "
            "after a successful run, or a different experiments_path to keep it."
        )

    train_df, val_df = load_data()
    # Validate labels and text before any fitting; invalid rows raise, never drop.
    validate_training_frame(train_df, "train")
    validate_training_frame(val_df, "validation")

    combined_df = pd.concat([train_df, val_df], ignore_index=True)

    y_train = train_df["category"]
    y_val = val_df["category"]
    y_combined = combined_df["category"]

    print(
        "Population summary (train / validation):\n"
        f"  rows: {len(train_df)} / {len(val_df)}\n"
        f"  generic_spam rows: {int((y_train == GENERIC_SPAM_CATEGORY).sum())} / "
        f"{int((y_val == GENERIC_SPAM_CATEGORY).sum())}\n"
        f"  smishing rows: {int(y_train.isin(sorted(SMISHING_CATEGORIES)).sum())} / "
        f"{int(y_val.isin(sorted(SMISHING_CATEGORIES)).sum())}\n"
        f"  benign rows: {int((y_train == BENIGN_CATEGORY).sum())} / "
        f"{int((y_val == BENIGN_CATEGORY).sum())}\n"
        "Experiments:\n"
        "  MULTICLASS: all 6 categories are fitted and scored (macro-F1, accuracy, "
        "per-category report, 5-fold CV).\n"
        "  BINARY SMISHING: positive = the 4 scam categories; generic_spam rows are "
        "excluded from these metrics and reported as a separate stratum.\n"
    )

    majority_class = y_val.mode()[0]
    majority_acc = (y_val == majority_class).mean()
    print(f"Majority-class baseline ('{majority_class}') accuracy: {majority_acc:.4f}\n")

    experiments = [
        ("raw", train_df["text"], val_df["text"], combined_df["text"]),
        (
            "nlp",
            train_df["text"].apply(preprocess_text),
            val_df["text"].apply(preprocess_text),
            combined_df["text"].apply(preprocess_text),
        ),
    ]

    models = {
        "logistic_regression": LogisticRegression(
            class_weight="balanced", max_iter=5000, random_state=RANDOM_STATE
        ),
        "linear_svc": LinearSVC(
            class_weight="balanced", max_iter=5000, random_state=RANDOM_STATE
        ),
    }

    # Results are collected in memory and written once, after every experiment succeeds.
    rows: List[Dict[str, Any]] = []

    for prep_name, X_train_text, X_val_text, X_comb_text in experiments:
        print(f"\n{'='*70}")
        print(f">>> Preprocessing: {prep_name.upper()} <<<")
        print(f"{'='*70}")

        # 1. Build TF-IDF (ngram_range=(1, 2))
        vectorizer = TfidfVectorizer(ngram_range=(1, 2))
        X_train_tfidf = vectorizer.fit_transform(X_train_text)
        X_val_tfidf = vectorizer.transform(X_val_text)

        # 2. Extract handcrafted features
        X_train_hc_raw = extract_handcrafted_features(X_train_text)
        X_val_hc_raw = extract_handcrafted_features(X_val_text)
        X_comb_hc_raw = extract_handcrafted_features(X_comb_text)

        # 3. Scale handcrafted features with MaxAbsScaler (fit on train only)
        scaler = MaxAbsScaler()
        X_train_hc_scaled = scaler.fit_transform(X_train_hc_raw)
        X_val_hc_scaled = scaler.transform(X_val_hc_raw)

        # 4. Hstack TF-IDF and scaled handcrafted features
        X_train = hstack([X_train_tfidf, X_train_hc_scaled])
        X_val = hstack([X_val_tfidf, X_val_hc_scaled])

        for model_name, model in models.items():
            print(f"\n-------------------------------------------------------")
            print(f"Evaluating Model: {model_name} | Preprocessing: {prep_name}")
            print(f"-------------------------------------------------------")

            # --- A. Single Train / Val Evaluation ---
            model.fit(X_train, y_train)
            preds = model.predict(X_val)

            acc = accuracy_score(y_val, preds)
            macro_f1 = f1_score(y_val, preds, average="macro", zero_division=0)
            weighted_f1 = f1_score(y_val, preds, average="weighted", zero_division=0)
            report = classification_report(y_val, preds, zero_division=0)

            # --- B. Binary Smishing Evaluation (generic spam excluded, reported separately) ---
            binary = binary_smishing_metrics(y_val, preds)
            # None (no primary rows) is logged as NaN so the numeric output stays valid.
            bin_prec = float("nan") if binary["precision"] is None else binary["precision"]
            bin_rec = float("nan") if binary["recall"] is None else binary["recall"]
            bin_f1 = float("nan") if binary["f1"] is None else binary["f1"]

            # --- C. 5-Fold Stratified Cross-Validation on train+val combined ---
            cv_acc_mean, cv_acc_std, cv_f1_mean, cv_f1_std = run_stratified_cv(
                combined_texts=X_comb_text,
                combined_hc=X_comb_hc_raw,
                combined_y=y_combined,
                model_template=model,
                n_splits=5,
            )

            # Print All Metrics
            print(f"Validation Accuracy:    {acc:.4f}")
            print(f"Validation Macro-F1:    {macro_f1:.4f}")
            print(f"Validation Weighted-F1: {weighted_f1:.4f}")
            print(f"\nBinary Smishing Metrics (positive = smishing; {binary['primary_rows']} rows, "
                  f"{binary['generic_spam_rows_excluded']} generic_spam rows excluded):")
            print(f"  Precision: {bin_prec:.4f}")
            print(f"  Recall:    {bin_rec:.4f}")
            print(f"  F1-Score:  {bin_f1:.4f}")
            if binary["predicted_smishing_rows"] == 0:
                print("  Note: no smishing predicted; precision is 0.0 by convention "
                      "(zero_division=0), not a measured value. NaN means no primary rows.")
            if binary["generic_spam_flagged_rate"] is None:
                print("  Generic spam stratum: no generic_spam rows in validation")
            else:
                print(
                    f"  Generic spam stratum: {binary['generic_spam_flagged_as_smishing']}"
                    f" of {binary['generic_spam_rows_excluded']} flagged as smishing"
                    f" (rate {binary['generic_spam_flagged_rate']:.4f})"
                )
            print(f"\n5-Fold Stratified Cross-Validation (train+val combined):")
            print(f"  CV Accuracy: {cv_acc_mean:.4f} \u00b1 {cv_acc_std:.4f}")
            print(f"  CV Macro-F1: {cv_f1_mean:.4f} \u00b1 {cv_f1_std:.4f}")
            print("\nPer-Category Classification Report:")
            print(report)

            rows.append(
                {
                    "model": model_name,
                    "preprocessing": prep_name,
                    "accuracy": acc,
                    "macro_f1": macro_f1,
                    "weighted_f1": weighted_f1,
                    "cv_accuracy_mean": cv_acc_mean,
                    "cv_accuracy_std": cv_acc_std,
                    "cv_macro_f1_mean": cv_f1_mean,
                    "cv_macro_f1_std": cv_f1_std,
                    "binary_precision": bin_prec,
                    "binary_recall": bin_rec,
                    "binary_f1": bin_f1,
                }
            )

    write_experiment_rows(rows, experiments_path)
    print(f"\nAll experiments successfully written to {experiments_path}")


if __name__ == "__main__":
    from src.training.guarded_training import guarded_train_baseline

    guarded_train_baseline()


"""Train the URL inference model served by the ChainShield /scan endpoint.

Pipeline:
    1. Read the project's stratified splits (URL + label columns only).
    2. Compute lexical features from the URL string (src/features/url_lexical.py).
    3. Fit candidate models on the training split only.
    4. Select the candidate by validation macro-F1.
    5. Score the held-out test split ONCE with the selected model.
    6. Save the model and a metadata file with the real metrics.

Label convention (from the PhiUSIIL dataset): 0 = phishing, 1 = legitimate.
The model is trained with phishing as the positive class, so
`predict_proba(...)[:, 1]` is the phishing probability.

Run from the project root:
    python -m src.training.train_url_inference
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd
import sklearn
import xgboost
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    average_precision_score,
    accuracy_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

from src.features.url_lexical import (
    LEXICAL_URL_FEATURES,
    extract_lexical_url_dataframe,
)

SPLIT_DIRECTORY = Path("data/processed/url_splits")
TRAIN_FILE = "stratified_train.csv"
VALIDATION_FILE = "stratified_validation.csv"
TEST_FILE = "stratified_test.csv"

MODEL_DIRECTORY = Path("models/url_inference")
MODEL_FILE = "model.joblib"
METADATA_FILE = "metadata.json"

RANDOM_STATE = 42
PHISHING_THRESHOLD = 0.5


def load_split(filename: str) -> tuple[pd.DataFrame, pd.Series]:
    """Load one split and return lexical features and phishing targets."""
    frame = pd.read_csv(SPLIT_DIRECTORY / filename, usecols=["URL", "label"])
    frame = frame.dropna(subset=["URL", "label"])

    labels = pd.to_numeric(frame["label"]).astype("int8")
    if not set(labels.unique()).issubset({0, 1}):
        raise ValueError(f"{filename} contains labels other than 0 and 1.")

    features = extract_lexical_url_dataframe(frame["URL"].astype(str))
    phishing_target = (labels == 0).astype("int8")

    return features, phishing_target


def build_candidates() -> dict:
    """Candidate models. All use class balancing for the imbalanced labels."""
    scaled_logistic = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
            (
                "classifier",
                LogisticRegression(
                    class_weight="balanced",
                    max_iter=1000,
                    random_state=RANDOM_STATE,
                ),
            ),
        ]
    )

    boosted_trees = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            (
                "classifier",
                XGBClassifier(
                    n_estimators=300,
                    max_depth=6,
                    learning_rate=0.1,
                    subsample=0.8,
                    colsample_bytree=0.8,
                    objective="binary:logistic",
                    eval_metric="logloss",
                    random_state=RANDOM_STATE,
                    n_jobs=-1,
                ),
            ),
        ]
    )

    return {
        "logistic_regression": scaled_logistic,
        "xgboost": boosted_trees,
    }


def score(y_true: pd.Series, probabilities) -> dict:
    """Metrics for the phishing (positive) class at PHISHING_THRESHOLD."""
    predictions = (probabilities >= PHISHING_THRESHOLD).astype("int8")
    matrix = confusion_matrix(y_true, predictions, labels=[0, 1])

    return {
        "threshold": PHISHING_THRESHOLD,
        "accuracy": float(accuracy_score(y_true, predictions)),
        "phishing_precision": float(precision_score(y_true, predictions, zero_division=0)),
        "phishing_recall": float(recall_score(y_true, predictions, zero_division=0)),
        "phishing_f1": float(f1_score(y_true, predictions, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, probabilities)),
        "pr_auc": float(average_precision_score(y_true, probabilities)),
        "confusion_matrix": {
            "true_legitimate_pred_legitimate": int(matrix[0][0]),
            "true_legitimate_pred_phishing": int(matrix[0][1]),
            "true_phishing_pred_legitimate": int(matrix[1][0]),
            "true_phishing_pred_phishing": int(matrix[1][1]),
        },
        "rows": int(len(y_true)),
    }


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def train_url_inference_model() -> dict:
    """Train candidates, select on validation, score test once, save artifacts."""
    X_train, y_train = load_split(TRAIN_FILE)
    X_val, y_val = load_split(VALIDATION_FILE)

    validation_results = {}
    fitted = {}

    for name, model in build_candidates().items():
        print(f"Fitting {name} on {len(X_train)} training rows...")
        model.fit(X_train, y_train)
        fitted[name] = model

        probabilities = model.predict_proba(X_val)[:, 1]
        validation_results[name] = score(y_val, probabilities)
        print(
            f"  validation phishing_f1={validation_results[name]['phishing_f1']:.4f}"
            f" roc_auc={validation_results[name]['roc_auc']:.4f}"
        )

    selected_name = max(
        validation_results,
        key=lambda name: validation_results[name]["phishing_f1"],
    )
    selected = fitted[selected_name]

    X_test, y_test = load_split(TEST_FILE)
    test_metrics = score(y_test, selected.predict_proba(X_test)[:, 1])

    MODEL_DIRECTORY.mkdir(parents=True, exist_ok=True)
    model_path = MODEL_DIRECTORY / MODEL_FILE
    joblib.dump(selected, model_path)

    metadata = {
        "model_name": selected_name,
        "feature_names": LEXICAL_URL_FEATURES,
        "label_convention": "positive class = phishing (source label 0)",
        "phishing_threshold": PHISHING_THRESHOLD,
        "split_files": {
            "train": TRAIN_FILE,
            "validation": VALIDATION_FILE,
            "test": TEST_FILE,
        },
        "validation_results": validation_results,
        "test_results": test_metrics,
        "model_sha256": sha256_of(model_path),
        "library_versions": {
            "scikit-learn": sklearn.__version__,
            "xgboost": xgboost.__version__,
            "pandas": pd.__version__,
        },
        "trained_at": datetime.now(timezone.utc).isoformat(),
    }

    with open(MODEL_DIRECTORY / METADATA_FILE, "w", encoding="utf-8") as handle:
        json.dump(metadata, handle, indent=2)

    print(f"\nSelected model: {selected_name}")
    print(json.dumps(test_metrics, indent=2))
    print(f"Saved model to: {model_path}")

    return metadata


if __name__ == "__main__":
    train_url_inference_model()

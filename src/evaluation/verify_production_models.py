"""Re-measure the two production models on their validation splits (read-only).

What it does:
  * loads each model through the backend's own checksum-verified loader
    (app/services/ml_detector.py, app/services/sms_detector.py);
  * measures them on the VALIDATION split only and compares the result with the
    metrics recorded at training time (a reproducibility check, not a new
    unbiased evaluation: validation was used for model selection);
  * checks that per-request inference (the API path) gives the same scores as
    batch inference on a sample;
  * checks for leakage between train/validation/test (exact duplicates, shared
    near-duplicate groups, shared registry hashes);
  * copies the recorded test results as HISTORICAL. The locked SMS test split
    is not read for predictions, and no model is retrained or modified.

No message text or URL is written to the output; only counts and metrics.

    python -m src.evaluation.verify_production_models --out <new file>.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support, roc_auc_score

PROJECT_ROOT = Path(__file__).resolve().parents[2]
URL_SPLITS = PROJECT_ROOT / "data" / "processed" / "url_splits"
SMS_SPLITS = PROJECT_ROOT / "data" / "processed"
SMS_RUN = PROJECT_ROOT / "models" / "sms_baseline" / "run-20261028T122841Z-seed42"
URL_METADATA = PROJECT_ROOT / "models" / "url_inference" / "metadata.json"


def _sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _binary(y_true, y_pred) -> dict:
    p, r, f, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {"precision": float(p), "recall": float(r), "f1": float(f),
            "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}}


def evaluate_url(sample_size: int = 300) -> dict:
    from app.services import ml_detector
    from src.features.url_lexical import extract_lexical_url_dataframe

    model, metadata = ml_detector._load_model()
    threshold = metadata["phishing_threshold"]
    val = pd.read_csv(URL_SPLITS / "stratified_validation.csv", usecols=["URL", "label"])
    y = (val["label"] == 0).astype(int).to_numpy()             # source label 0 = phishing
    scores = model.predict_proba(extract_lexical_url_dataframe(val["URL"]))[:, 1]
    measured = {**_binary(y, (scores >= threshold).astype(int)), "roc_auc": float(roc_auc_score(y, scores))}
    recorded = metadata["validation_results"].get(metadata["model_name"], {})

    rng = np.random.default_rng(0)
    idx = rng.choice(len(val), size=min(sample_size, len(val)), replace=False)
    api_scores = [ml_detector.predict_phishing(val["URL"].iloc[i])["probability"] for i in idx]
    max_diff = float(np.max(np.abs(np.array(api_scores) - scores[idx])))

    has_path = val["URL"].str.replace(r"^https?://[^/]+", "", regex=True).str.strip("/").str.len() > 0
    legit = y == 0
    return {
        "model": metadata["model_name"], "threshold": threshold,
        "split_file_sha256": _sha256(URL_SPLITS / "stratified_validation.csv"),
        "validation_rows": int(len(val)), "validation_phishing": int(y.sum()),
        "validation_measured": measured,
        "validation_recorded_at_training": {k: recorded.get(k) for k in
                                            ("phishing_precision", "phishing_recall", "phishing_f1", "roc_auc")},
        "api_path_matches_batch": {"sample": int(len(idx)), "max_abs_score_difference": max_diff},
        "template_artifact": {
            "legitimate_with_path_or_query": int((legit & has_path).sum()),
            "legitimate_total": int(legit.sum()),
            "phishing_with_path_or_query": int((~legit & has_path).sum()),
            "phishing_total": int((~legit).sum()),
            "false_positives_with_path": int(((scores >= threshold) & legit & has_path).sum()),
        },
        "test_historical": metadata.get("test_results"),
    }


def evaluate_sms() -> dict:
    from app.services import sms_detector

    model, _ = sms_detector._load()
    classes = list(sms_detector.CLASSES)
    val = pd.read_csv(SMS_SPLITS / "val.csv")
    proba = model.predict_proba(val["text"].tolist())
    order = [list(model.classes_).index(c) for c in classes]
    pred = [classes[i] for i in np.argmax(proba[:, order], axis=1)]
    p, r, f, s = precision_recall_fscore_support(val["label"], pred, labels=classes, zero_division=0)
    per_class = {c: {"precision": float(p[i]), "recall": float(r[i]), "f1": float(f[i]), "support": int(s[i])}
                 for i, c in enumerate(classes)}
    cm = confusion_matrix(val["label"], pred, labels=classes)
    frozen = json.loads((SMS_RUN / "selection_frozen.json").read_text(encoding="utf-8"))
    test = json.loads((SMS_RUN / "test_evaluation.json").read_text(encoding="utf-8"))

    smishing_true = val["label"] == "smishing"
    missed = smishing_true & (pd.Series(pred) != "smishing")
    has_link = val["text"].str.contains(r"https?://|www\.|\.(?:com|co|uk|in)\b", regex=True)
    return {
        "model": frozen["selected"]["name"],
        "split_file_sha256": _sha256(SMS_SPLITS / "val.csv"),
        "validation_rows": int(len(val)),
        "validation_measured": {
            "per_class": per_class,
            "macro_f1": float(np.mean(f)),
            "confusion_matrix": {"labels": classes, "rows_true_cols_pred": cm.tolist()},
        },
        "validation_recorded_at_selection": frozen.get("validation"),
        "missed_smishing": {"count": int(missed.sum()),
                            "predicted_as": pd.Series(pred)[missed].value_counts().to_dict(),
                            "with_link_like_text": int((missed & has_link).sum())},
        "test_historical": {"evaluated_at": test.get("evaluated_at"), "rows": test.get("rows"),
                            "metrics": test.get("metrics")},
    }


def leakage_checks() -> dict:
    from src.blockchain.hashing import generate_message_hash, generate_url_hash

    sms = {s: pd.read_csv(SMS_SPLITS / f"{s}.csv") for s in ("train", "val", "test")}
    url = {s: pd.read_csv(URL_SPLITS / f"stratified_{s}.csv", usecols=["URL"])
           for s in ("train", "validation", "test")}

    def overlaps(sets: dict) -> dict:
        names = list(sets)
        return {f"{a}&{b}": len(sets[a] & sets[b]) for i, a in enumerate(names) for b in names[i + 1:]}

    msg_hashes = {s: {generate_message_hash(t) for t in df["text"]} for s, df in sms.items()}
    url_hashes = {}
    for s, df in url.items():
        hashes = set()
        for u in df["URL"]:
            try:
                hashes.add(generate_url_hash(u))
            except ValueError:
                pass
        url_hashes[s] = hashes
    return {
        "sms_exact_text": overlaps({s: set(df["text"]) for s, df in sms.items()}),
        "sms_group_id": overlaps({s: set(df["group_id"]) for s, df in sms.items()}),
        "sms_registry_hash": overlaps(msg_hashes),
        "sms_class_counts": {s: df["label"].value_counts().to_dict() for s, df in sms.items()},
        "url_exact": overlaps({s: set(df["URL"]) for s, df in url.items()}),
        "url_registry_hash": overlaps(url_hashes),
    }


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    out = Path(args.out)
    if out.exists():
        raise FileExistsError(f"Refusing to overwrite {out}")
    report = {"generated_at": datetime.now(timezone.utc).isoformat(),
              "note": "Validation re-measurement and leakage checks; test results are historical copies.",
              "url_model": evaluate_url(), "sms_model": evaluate_sms(), "leakage": leakage_checks()}
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=1), encoding="utf-8")
    print(json.dumps({"url_validation": report["url_model"]["validation_measured"],
                      "sms_validation_macro_f1": report["sms_model"]["validation_measured"]["macro_f1"],
                      "leakage": {k: v for k, v in report["leakage"].items() if k != "sms_class_counts"}}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Stage 2 SMS baseline: train, select on validation, test once, evaluate on IMC.

Three canonical classes (legitimate, generic_spam, smishing). Model: TF-IDF +
multinomial LogisticRegression (class_weight='balanced'). Four candidates; the
selection rule is fixed in SELECTION_RULE. Decision policy: argmax, no threshold.

Data access:
* train/val come only from guarded_training.load_verified_inputs (manifest
  validated; approved source on every row; no IMC fingerprint; one snapshot).
* Features come from 'text' only. Provenance columns are never features.
* test.csv is read only by evaluate_test, only after selection is frozen, and only once.
* IMC is read only by evaluate_imc, only after the test result is recorded.

Every run writes to a new directory under models/sms_baseline/ and refuses to
overwrite. No message text is written to any artifact.

    python -m src.training.train_sms_baseline train
    python -m src.training.train_sms_baseline test <run_dir>
    python -m src.training.train_sms_baseline imc <run_dir>
"""
import hashlib
import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, f1_score, precision_recall_fscore_support
from sklearn.pipeline import Pipeline

from src.data import prepare_sources as ps
from src.data.clean import normalize_text
from src.data.split_prepared import near_duplicate_groups
from src.training import guarded_training as gt

CLASSES = ["legitimate", "generic_spam", "smishing"]
SEED = 42
RUNS_DIR = Path("models/sms_baseline")
SPLIT_METADATA = Path("data/processed/sms_split_metadata.json")
IMC_PATH = Path("data/incoming/imc2025/final_dataset_output.csv")
BOOTSTRAP_REPLICATES = 2000

CANDIDATES = [
    {"name": "word12_C1", "analyzer": "word", "ngram_range": [1, 2], "C": 1.0},
    {"name": "word12_C10", "analyzer": "word", "ngram_range": [1, 2], "C": 10.0},
    {"name": "char25_C1", "analyzer": "char_wb", "ngram_range": [2, 5], "C": 1.0},
    {"name": "char25_C10", "analyzer": "char_wb", "ngram_range": [2, 5], "C": 10.0},
]
SELECTION_RULE = "max validation macro-F1; ties: higher validation smishing F1, then candidate order"


# ── helpers ───────────────────────────────────────────────────────────

def _sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _write_json(path: Path, data) -> None:
    if path.exists():
        raise FileExistsError(f"Refusing to overwrite {path}")
    path.write_text(json.dumps(data, indent=1, default=float), encoding="utf-8")


def build_pipeline(candidate: dict) -> Pipeline:
    return Pipeline([
        ("tfidf", TfidfVectorizer(
            analyzer=candidate["analyzer"], ngram_range=tuple(candidate["ngram_range"]),
            min_df=2, sublinear_tf=True, preprocessor=normalize_text, lowercase=False,
        )),
        ("clf", LogisticRegression(
            C=candidate["C"], class_weight="balanced", max_iter=5000, random_state=SEED,
        )),
    ])


def metrics(y_true, y_pred) -> dict:
    """Per-class and averaged metrics plus the smishing false-positive breakdown.

    Undefined precision (no predictions of a class) is reported as 0.0 and
    flagged in 'undefined_precision'.
    """
    y_true, y_pred = np.asarray(y_true), np.asarray(y_pred)
    p, r, f, s = precision_recall_fscore_support(y_true, y_pred, labels=CLASSES, zero_division=0)
    cm = confusion_matrix(y_true, y_pred, labels=CLASSES)
    predicted = cm.sum(axis=0)

    def to_smishing(source):
        mask = y_true == source
        count = int((y_pred[mask] == "smishing").sum())
        return {"count": count, "of": int(mask.sum()), "rate": count / mask.sum() if mask.any() else None}

    return {
        "per_class": {c: {"precision": p[i], "recall": r[i], "f1": f[i], "support": int(s[i])}
                      for i, c in enumerate(CLASSES)},
        "macro_f1": f1_score(y_true, y_pred, labels=CLASSES, average="macro", zero_division=0),
        "weighted_f1": f1_score(y_true, y_pred, labels=CLASSES, average="weighted", zero_division=0),
        "confusion_matrix": {"labels": CLASSES, "rows_true_cols_pred": cm.tolist()},
        "undefined_precision": [c for i, c in enumerate(CLASSES) if predicted[i] == 0],
        "generic_spam_predicted_smishing": to_smishing("generic_spam"),
        "legitimate_predicted_smishing": to_smishing("legitimate"),
    }


def group_bootstrap(y_true, y_pred, groups, seed: int = SEED, replicates: int = BOOTSTRAP_REPLICATES) -> dict:
    """95% percentile intervals, resampling near-duplicate groups (not rows) with replacement.

    Assumes groups are independent and rows within a group are not.
    """
    y_true, y_pred, groups = np.asarray(y_true), np.asarray(y_pred), np.asarray(groups)
    unique = np.unique(groups)
    index_by_group = {g: np.flatnonzero(groups == g) for g in unique}
    rng = np.random.default_rng(seed)
    stats = {k: [] for k in ("smishing_recall", "smishing_precision", "macro_f1",
                             "generic_spam_to_smishing_rate", "legitimate_to_smishing_rate")}
    for _ in range(replicates):
        idx = np.concatenate([index_by_group[g] for g in rng.choice(unique, size=len(unique))])
        t, pr = y_true[idx], y_pred[idx]
        sm_true, sm_pred = t == "smishing", pr == "smishing"
        if sm_true.any():
            stats["smishing_recall"].append((sm_pred & sm_true).sum() / sm_true.sum())
        if sm_pred.any():
            stats["smishing_precision"].append((sm_pred & sm_true).sum() / sm_pred.sum())
        if len(set(t)) > 1:
            stats["macro_f1"].append(f1_score(t, pr, labels=CLASSES, average="macro", zero_division=0))
        for key, cls in (("generic_spam_to_smishing_rate", "generic_spam"), ("legitimate_to_smishing_rate", "legitimate")):
            mask = t == cls
            if mask.any():
                stats[key].append((pr[mask] == "smishing").mean())
    return {
        "method": "group bootstrap over near-duplicate groups, percentile 95% interval",
        "replicates": replicates, "seed": seed, "groups": int(len(unique)),
        "intervals": {k: [float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))] if v else None
                      for k, v in stats.items()},
    }


def _versions() -> dict:
    import rapidfuzz, scipy
    return {"python": platform.python_version(), "scikit-learn": sklearn.__version__,
            "numpy": np.__version__, "pandas": pd.__version__, "scipy": scipy.__version__,
            "joblib": joblib.__version__, "rapidfuzz": rapidfuzz.__version__}


# ── train and select (train + validation only) ────────────────────────

def train(runs_dir: Path = RUNS_DIR, evaluation_manifest: Path = gt.EVALUATION_MANIFEST,
          split_metadata: Path = SPLIT_METADATA, run_name: str = None) -> Path:
    train_df, val_df = gt.load_verified_inputs(evaluation_manifest)   # guard + single snapshot
    for frame in (train_df, val_df):
        unknown = set(frame["label"]) - set(CLASSES)
        if unknown:
            raise ValueError(f"Unexpected label(s) {sorted(unknown)}")

    run_name = run_name or datetime.now(timezone.utc).strftime("run-%Y%m%dT%H%M%SZ") + f"-seed{SEED}"
    run_dir = Path(runs_dir) / run_name
    run_dir.mkdir(parents=True, exist_ok=False)   # never reuse a run directory

    split_meta = json.loads(Path(split_metadata).read_text())
    config = {
        "stage": 2, "classes": CLASSES, "seed": SEED, "candidates": CANDIDATES,
        "selection_rule": SELECTION_RULE, "decision_policy": "argmax of predicted probabilities; no threshold tuning",
        "features": "TF-IDF on normalize_text(text) only; min_df=2, sublinear_tf; fitted on train only",
        "model": "LogisticRegression(multinomial lbfgs, class_weight='balanced', max_iter=5000)",
        "data": {
            "source": "Mishra & Soni SMS Phishing Dataset, Mendeley DOI 10.17632/f45bkkt8pr.1 (CC BY 4.0)",
            "source_csv_sha256": split_meta["source_csv_sha256"],
            "preparation": "prepare_sources.prepare_mishra_soni: exact and near-duplicate (>=92) label conflicts excluded; same-label duplicates removed",
            "split": "split_prepared.split_prepared: near-duplicate groups (>=92), seed 42, 70/15/15",
            "split_metadata_sha256": _sha256(split_metadata),
            "split_files_sha256": split_meta["files_sha256"],
            "evaluation_manifest_sha256": _sha256(evaluation_manifest),
            "rows": {"train": len(train_df), "val": len(val_df)},
        },
        "versions": _versions(),
        "command": "python -m src.training.train_sms_baseline train",
    }
    _write_json(run_dir / "config.json", config)

    results, fitted = [], {}
    for candidate in CANDIDATES:
        pipeline = build_pipeline(candidate).fit(train_df["text"], train_df["label"])
        val_metrics = metrics(val_df["label"], pipeline.predict(val_df["text"]))
        results.append({"candidate": candidate, "validation": val_metrics})
        fitted[candidate["name"]] = pipeline
    _write_json(run_dir / "validation_candidates.json", results)

    best = max(range(len(results)), key=lambda i: (
        results[i]["validation"]["macro_f1"],
        results[i]["validation"]["per_class"]["smishing"]["f1"],
        -i,
    ))
    selected = results[best]
    joblib.dump(fitted[selected["candidate"]["name"]], run_dir / "model.joblib")
    _write_json(run_dir / "selection_frozen.json", {
        "selected": selected["candidate"], "rule": SELECTION_RULE,
        "validation": selected["validation"],
        "model_sha256": _sha256(run_dir / "model.joblib"),
        "frozen_at": datetime.now(timezone.utc).isoformat(),
    })
    _reload_check(run_dir)
    _write_checksums(run_dir)
    return run_dir


def _reload_check(run_dir: Path) -> None:
    model = joblib.load(Path(run_dir) / "model.joblib")
    predictions = model.predict(["synthetic example one", "another synthetic message"])
    if not set(predictions) <= set(CLASSES):
        raise AssertionError("Reloaded model produced an unknown class")


def _write_checksums(run_dir: Path) -> None:
    run_dir = Path(run_dir)
    lines = [f"{_sha256(p)}  {p.name}" for p in sorted(run_dir.iterdir())
             if p.is_file() and p.name != "checksums.sha256"]
    (run_dir / "checksums.sha256").write_text("\n".join(lines) + "\n")


def _verify_frozen(run_dir: Path) -> dict:
    run_dir = Path(run_dir)
    frozen_path = run_dir / "selection_frozen.json"
    if not frozen_path.is_file():
        raise RuntimeError("Model selection is not frozen; refusing to evaluate")
    frozen = json.loads(frozen_path.read_text())
    if _sha256(run_dir / "model.joblib") != frozen["model_sha256"]:
        raise RuntimeError("model.joblib does not match the frozen selection")
    return frozen


# ── locked internal test (once) ───────────────────────────────────────

def evaluate_test(run_dir: Path, data_dir: Path = None, split_metadata: Path = SPLIT_METADATA,
                  evaluation_manifest: Path = gt.EVALUATION_MANIFEST) -> dict:
    run_dir = Path(run_dir)
    _verify_frozen(run_dir)
    out = run_dir / "test_evaluation.json"
    if out.exists():
        raise FileExistsError("The locked test set was already evaluated for this run")

    data_dir = Path(data_dir) if data_dir else gt.baseline.DATA_DIR
    test_path = data_dir / "test.csv"
    expected = json.loads(Path(split_metadata).read_text())["files_sha256"]["test"]
    if _sha256(test_path) != expected:
        raise ValueError("test.csv does not match the split metadata checksum")
    test_df = pd.read_csv(test_path)
    ps.assert_training_eligible(test_df, ps.load_evaluation_fingerprints(evaluation_manifest))

    predictions = joblib.load(run_dir / "model.joblib").predict(test_df["text"])
    result = {
        "rows": len(test_df), "test_sha256": expected,
        "metrics": metrics(test_df["label"], predictions),
        "uncertainty": group_bootstrap(test_df["label"], predictions, test_df["group_id"]),
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
    }
    _write_json(out, result)
    _write_checksums(run_dir)
    return result


# ── external IMC evaluation (after the test result is recorded) ───────

def evaluate_imc(run_dir: Path, imc_path: Path = IMC_PATH) -> dict:
    run_dir = Path(run_dir)
    _verify_frozen(run_dir)
    if not (run_dir / "test_evaluation.json").is_file():
        raise RuntimeError("Record the locked test result before external evaluation")
    out = run_dir / "imc_evaluation.json"
    if out.exists():
        raise FileExistsError("IMC was already evaluated for this run")
    if Path(imc_path).resolve() == IMC_PATH.resolve() and _sha256(imc_path) != ps.IMC_SOURCE_SHA256:
        raise ValueError("IMC file does not match its verified checksum")

    frame, accounting = ps.map_imc_for_evaluation(ps.load_imc_for_evaluation(imc_path))
    model = joblib.load(run_dir / "model.joblib")

    def predict_counts(status):
        part = frame[frame["eval_status"] == status]
        predictions = model.predict(part["text"]) if len(part) else np.array([])
        return part, predictions

    smishing, sm_pred = predict_counts("included_smishing")
    spam, spam_pred = predict_counts("separate_generic_spam")
    recall = float((sm_pred == "smishing").mean()) if len(sm_pred) else None

    interval = None
    if len(smishing):
        groups = near_duplicate_groups(smishing["text"])
        boot = group_bootstrap(np.array(["smishing"] * len(smishing)), sm_pred, groups)
        interval = {"smishing_recall": boot["intervals"]["smishing_recall"], "groups": boot["groups"],
                    "method": boot["method"], "replicates": boot["replicates"]}

    by_category = {}
    for category, part in smishing.groupby("source_scam_type"):
        p = model.predict(part["text"])
        by_category[category] = {"rows": len(part), "predicted_smishing": int((p == "smishing").sum()),
                                 "recall": float((p == "smishing").mean())}

    result = {
        "interpretation": "Agreement with GPT-4o-assigned IMC labels on English user-reported texts; "
                          "not verified real-world performance. No legitimate class: precision, "
                          "specificity and false-positive rate cannot be estimated from IMC.",
        "imc_sha256": ps.IMC_SOURCE_SHA256,
        "accounting": accounting,
        "primary_smishing_recall": {"rows": len(smishing), "recall": recall, "interval_95": interval,
                                    "by_category": by_category},
        "generic_spam_separate": {
            "rows": len(spam),
            "predicted": {c: int((spam_pred == c).sum()) for c in CLASSES},
        },
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
    }
    _write_json(out, result)
    _write_checksums(run_dir)
    return result


if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    if command == "train":
        print(train())
    elif command == "test":
        print(json.dumps(evaluate_test(sys.argv[2])["metrics"], indent=1, default=float))
    elif command == "imc":
        print(json.dumps(evaluate_imc(sys.argv[2])["primary_smishing_recall"], indent=1, default=float))
    else:
        raise SystemExit(__doc__)

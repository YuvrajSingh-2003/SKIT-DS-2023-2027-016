"""SMS model optimization experiments (three-class: legitimate / generic_spam / smishing).

Candidates are saved under models/candidates/sms/<name>/; the production
model in models/sms_baseline/ is only read. Every candidate is a scikit-learn
estimator whose predict / predict_proba take raw message strings and whose
classes_ are the production class names, so it is a drop-in for
app/services/sms_detector.py's interface.

Vectorizers, feature selection and scaling are all inside the pipeline and
fitted on the training split only. Selection uses validation; the locked test
split is scored only with --final.

    python -m src.experiments.sms_optimization --cycle 1 --candidates A_retrain B_svm_char
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from scipy import sparse
from sklearn.base import BaseEstimator, ClassifierMixin, TransformerMixin
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.feature_selection import SelectKBest, chi2
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.preprocessing import LabelEncoder, MaxAbsScaler
from sklearn.svm import LinearSVC
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier

from src.data.clean import normalize_text
from src.training.train_sms_baseline import CLASSES, metrics

DATA = Path("data/processed")
PRODUCTION = Path("models/sms_baseline/run-20261028T122841Z-seed42/model.joblib")
CANDIDATE_ROOT = Path("models/candidates/sms")
RESULTS_ROOT = Path("reports/model_optimization/results")
SEED = 42

_URL = re.compile(r"https?://|www\.|\b[a-z0-9-]+\.(?:com|net|org|in|co|ly|me|info|biz|xyz)\b", re.I)
_PHONE = re.compile(r"(?:\+?\d[\d\s-]{8,}\d)")
_MONEY = re.compile(r"[$£€₹]|\b(?:rs\.?|inr|usd|cash|prize|won|reward)\b", re.I)
_URGENT = re.compile(r"\b(?:urgent|immediately|now|expire[sd]?|suspend(?:ed)?|verify|final)\b", re.I)
NUMERIC_FEATURES = ["chars", "words", "digit_ratio", "upper_ratio", "has_url", "has_phone",
                    "has_money", "has_urgent", "exclamations"]


class SmsNumericFeatures(BaseEstimator, TransformerMixin):
    """Nine documented, stateless numeric features computed from the raw text."""

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        rows = []
        for text in X:
            t = str(text)
            n = max(len(t), 1)
            rows.append([
                len(t), len(t.split()), sum(c.isdigit() for c in t) / n,
                sum(c.isupper() for c in t) / n, bool(_URL.search(t)), bool(_PHONE.search(t)),
                bool(_MONEY.search(t)), bool(_URGENT.search(t)), t.count("!"),
            ])
        return sparse.csr_matrix(np.asarray(rows, dtype=float))


class BalancedXGB(BaseEstimator, ClassifierMixin):
    """XGBoost with string labels and balanced sample weights."""

    def __init__(self, n_estimators=400, max_depth=4, learning_rate=0.1, random_state=SEED):
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.learning_rate = learning_rate
        self.random_state = random_state

    def fit(self, X, y):
        self.encoder_ = LabelEncoder().fit(CLASSES)
        self.classes_ = self.encoder_.classes_
        self.model_ = XGBClassifier(
            n_estimators=self.n_estimators, max_depth=self.max_depth,
            learning_rate=self.learning_rate, subsample=0.8, colsample_bytree=0.5,
            objective="multi:softprob", eval_metric="mlogloss", tree_method="hist",
            random_state=self.random_state, n_jobs=8,
        )
        self.model_.fit(X, self.encoder_.transform(y), sample_weight=compute_sample_weight("balanced", y))
        return self

    def predict_proba(self, X):
        return self.model_.predict_proba(X)

    def predict(self, X):
        return self.classes_[self.predict_proba(X).argmax(axis=1)]


def _tfidf(analyzer, ngrams):
    return TfidfVectorizer(analyzer=analyzer, ngram_range=ngrams, min_df=2, sublinear_tf=True,
                           preprocessor=normalize_text, lowercase=False)


def build(name: str, seed: int = SEED):
    if name == "A_retrain":  # production configuration, refitted
        return Pipeline([("tfidf", _tfidf("char_wb", (2, 5))),
                         ("clf", LogisticRegression(C=10.0, class_weight="balanced", max_iter=5000, random_state=seed))])
    if name == "B_svm_char":
        return Pipeline([("tfidf", _tfidf("char_wb", (2, 5))),
                         ("clf", CalibratedClassifierCV(
                             LinearSVC(C=0.5, class_weight="balanced", random_state=seed), cv=5, method="sigmoid"))])
    if name == "C_xgb_word_k2000":
        return Pipeline([("tfidf", _tfidf("word", (1, 2))), ("select", SelectKBest(chi2, k=2000)),
                         ("clf", BalancedXGB(random_state=seed))])
    if name == "D_xgb_word_k2000_numeric":
        text = Pipeline([("tfidf", _tfidf("word", (1, 2))), ("select", SelectKBest(chi2, k=2000))])
        numeric = Pipeline([("num", SmsNumericFeatures()), ("scale", MaxAbsScaler())])
        return Pipeline([("features", FeatureUnion([("text", text), ("numeric", numeric)])),
                         ("clf", BalancedXGB(random_state=seed))])
    if name == "E_xgb_char_k5000_numeric":
        text = Pipeline([("tfidf", _tfidf("char_wb", (2, 5))), ("select", SelectKBest(chi2, k=5000))])
        numeric = Pipeline([("num", SmsNumericFeatures()), ("scale", MaxAbsScaler())])
        return Pipeline([("features", FeatureUnion([("text", text), ("numeric", numeric)])),
                         ("clf", BalancedXGB(random_state=seed))])
    raise ValueError(name)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(split: str):
    frame = pd.read_csv(DATA / f"{split}.csv")
    return frame["text"].astype(str).tolist(), frame["label"].to_numpy(), frame["group_id"].to_numpy()


def evaluate(model, texts, y) -> dict:
    pred = np.asarray(model.predict(texts))
    m = metrics(y, pred)
    legit = y == "legitimate"
    m["legitimate_fpr"] = float((pred[legit] != "legitimate").mean())  # legit flagged as spam/smishing
    m["predictions"] = pred.tolist()
    return m


def paired_bootstrap(y, pred_a, pred_b, groups, reps=2000) -> dict:
    """Group-resampled macro-F1 difference (b - a) on the same rows."""
    from sklearn.metrics import f1_score
    rng = np.random.default_rng(SEED)
    unique = np.unique(groups)
    index = {g: np.flatnonzero(groups == g) for g in unique}
    diffs = []
    for _ in range(reps):
        rows = np.concatenate([index[g] for g in rng.choice(unique, len(unique))])
        diffs.append(f1_score(y[rows], pred_b[rows], labels=CLASSES, average="macro", zero_division=0)
                     - f1_score(y[rows], pred_a[rows], labels=CLASSES, average="macro", zero_division=0))
    diffs = np.asarray(diffs)
    return {"mean": float(diffs.mean()), "ci95": [float(np.percentile(diffs, 2.5)), float(np.percentile(diffs, 97.5))],
            "p_b_not_better": float((diffs <= 0).mean())}


def latency_ms(model) -> float:
    message = "URGENT: your account is suspended, verify now at http://bit.ly/x1 or call 08001234567"
    model.predict_proba([message])
    start = time.perf_counter()
    for _ in range(200):
        model.predict_proba([message])
    return (time.perf_counter() - start) / 200 * 1000


def summarize(name, m) -> str:
    pc = m["per_class"]
    return (f"{name}: macroF1={m['macro_f1']:.4f} legitF1={pc['legitimate']['f1']:.4f} "
            f"spamF1={pc['generic_spam']['f1']:.4f} smishF1={pc['smishing']['f1']:.4f} "
            f"legitFPR={m['legitimate_fpr']:.4f} cm={m['confusion_matrix']['rows_true_cols_pred']}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cycle", required=True)
    parser.add_argument("--candidates", nargs="*", default=[])
    parser.add_argument("--seeds", nargs="+", type=int, default=[SEED])
    parser.add_argument("--final", nargs="*", help="candidate dirs to score on the locked test split")
    args = parser.parse_args()

    RESULTS_ROOT.mkdir(parents=True, exist_ok=True)
    split = "test" if args.final is not None else "val"
    texts, y, groups = load(split)
    production = joblib.load(PRODUCTION)
    base = evaluate(production, texts, y)
    results = {"split": split, "split_sha256": sha256(DATA / f"{split}.csv"),
               "production": {"artifact": str(PRODUCTION), "sha256": sha256(PRODUCTION),
                              "size_bytes": PRODUCTION.stat().st_size, "latency_ms": latency_ms(production),
                              split: {k: v for k, v in base.items() if k != "predictions"}}}
    print(summarize("production", base))

    if args.final is not None:
        jobs = [(name, joblib.load(CANDIDATE_ROOT / name / "model.joblib"), None) for name in args.final]
    else:
        train_texts, train_y, _ = load("train")
        jobs = []
        for name in args.candidates:
            for seed in args.seeds:
                tag = name if seed == SEED else f"{name}_seed{seed}"
                start = time.perf_counter()
                model = build(name, seed).fit(train_texts, train_y)
                jobs.append((tag, model, time.perf_counter() - start))

    for tag, model, train_seconds in jobs:
        out_dir = CANDIDATE_ROOT / tag
        out_dir.mkdir(parents=True, exist_ok=True)
        artifact = out_dir / "model.joblib"
        if train_seconds is not None:
            joblib.dump(model, artifact)
        assert list(model.classes_) == sorted(CLASSES) or set(model.classes_) == set(CLASSES)
        m = evaluate(model, texts, y)
        entry = {"artifact": str(artifact), "sha256": sha256(artifact), "size_bytes": artifact.stat().st_size,
                 "train_seconds": train_seconds, "latency_ms": latency_ms(model),
                 "agreement_with_production": float((np.asarray(m["predictions"]) == np.asarray(base["predictions"])).mean()),
                 "macro_f1_vs_production": paired_bootstrap(y, np.asarray(base["predictions"]), np.asarray(m["predictions"]), groups),
                 split: {k: v for k, v in m.items() if k != "predictions"}}
        if train_seconds is not None:
            (out_dir / "config.json").write_text(json.dumps(
                {"candidate": tag, "seed": tag.split("_seed")[-1] if "_seed" in tag else SEED,
                 "pipeline": repr(model), "train_split_sha256": sha256(DATA / "train.csv"),
                 "selection_split_sha256": sha256(DATA / "val.csv"), "train_seconds": train_seconds,
                 "model_sha256": entry["sha256"]}, indent=2, default=str))
        results[tag] = entry
        print(summarize(tag, m), f"| d_macroF1={entry['macro_f1_vs_production']['mean']:+.4f} "
              f"CI{[round(x, 4) for x in entry['macro_f1_vs_production']['ci95']]} "
              f"train={train_seconds and round(train_seconds, 1)}s lat={entry['latency_ms']:.2f}ms size={entry['size_bytes']}")

    path = RESULTS_ROOT / f"sms_cycle{args.cycle}{'_final' if args.final is not None else ''}.json"
    path.write_text(json.dumps(results, indent=2, default=float))
    print("wrote", path)


if __name__ == "__main__":
    main()

"""URL model optimization experiments (cycles 1-3).

Trains candidate URL models next to, never over, the production model in
models/url_inference/. Every candidate reuses the production lexical feature
extractor (src/features/url_lexical.py) unchanged; candidates differ only in
how the URL string is normalized *before* that extractor runs:

    raw      the URL as stored (production behaviour)
    neutral  scheme and a leading "www." removed, then "https://" prepended,
             so the scheme/www template of the PhiUSIIL legitimate class
             cannot be used as a shortcut
    host     like neutral, but path, query and fragment are dropped too, so
             the model only sees the hostname

Selection uses the validation split and the template probes only. The locked
test split is scored only with --final.

Run from the project root, for example:
    python -m src.experiments.url_optimization --cycle 1 --modes raw neutral
"""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path
from urllib.parse import urlsplit

import joblib
import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support, roc_auc_score
from sklearn.pipeline import Pipeline
from xgboost import XGBClassifier

from src.features.url_lexical import extract_lexical_url_dataframe

SPLITS = Path("data/processed/url_splits")
OPENPHISH = Path("data/incoming/threat_feeds/openphish-community-20261028T152813Z.txt")
PRODUCTION_MODEL = Path("models/url_inference/model.joblib")
CANDIDATE_ROOT = Path("models/candidates/url")
RESULTS_ROOT = Path("reports/model_optimization/results")
SEED = 42


def normalize(url: str, mode: str) -> str:
    if mode == "raw":
        return url
    value = str(url).strip()
    parts = urlsplit(value if "://" in value else f"http://{value}")
    host = parts.netloc.lower()
    if host.startswith("www."):
        host = host[4:]
    if mode == "host":
        return f"https://{host}"
    rest = parts.path + (f"?{parts.query}" if parts.query else "") + (
        f"#{parts.fragment}" if parts.fragment else ""
    )
    return f"https://{host}{rest}"


def features(urls: pd.Series, mode: str) -> pd.DataFrame:
    return extract_lexical_url_dataframe(urls.astype(str).map(lambda u: normalize(u, mode)))


def load(name: str) -> tuple[pd.Series, np.ndarray]:
    frame = pd.read_csv(SPLITS / name, usecols=["URL", "label"]).dropna()
    return frame["URL"].astype(str).reset_index(drop=True), (frame["label"].to_numpy() == 0).astype(int)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_model() -> Pipeline:
    # Same estimator and hyperparameters as src/training/train_url_inference.py.
    return Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("classifier", XGBClassifier(
            n_estimators=300, max_depth=6, learning_rate=0.1, subsample=0.8,
            colsample_bytree=0.8, objective="binary:logistic", eval_metric="logloss",
            random_state=SEED, n_jobs=-1,
        )),
    ])


def metrics(y: np.ndarray, p: np.ndarray, threshold: float) -> dict:
    pred = (p >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    prec, rec, f1, sup = precision_recall_fscore_support(y, pred, labels=[0, 1], zero_division=0)
    return {
        "threshold": threshold,
        "legitimate": {"precision": prec[0], "recall": rec[0], "f1": f1[0], "support": int(sup[0])},
        "phishing": {"precision": prec[1], "recall": rec[1], "f1": f1[1], "support": int(sup[1])},
        "macro_f1": float(f1.mean()),
        "fpr": fp / (fp + tn),
        "roc_auc": float(roc_auc_score(y, p)),
        "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


PROBES = {
    # Transform applied to *legitimate* validation URLs; ideal output is
    # still "legitimate", so the probe reports a false-positive rate.
    "legit_as_is": lambda u: u,
    "legit_drop_www": lambda u: u.replace("://www.", "://", 1),
    "legit_http": lambda u: u.replace("https://", "http://", 1),
    "legit_no_scheme": lambda u: u.split("://", 1)[-1],
    "legit_path_about": lambda u: u.rstrip("/") + "/about",
    "legit_path_query": lambda u: u.rstrip("/") + "/search?q=news",
}


def score_model(model, mode: str, val_urls, val_y, threshold: float) -> dict:
    p_val = model.predict_proba(features(val_urls, mode))[:, 1]
    out = {"validation": metrics(val_y, p_val, threshold), "probes": {}}
    legit = val_urls[val_y == 0]
    for name, fn in PROBES.items():
        p = model.predict_proba(features(legit.map(fn), mode))[:, 1]
        out["probes"][name] = {"fpr": float((p >= threshold).mean()), "rows": int(len(p))}
    feed = pd.Series([l.strip() for l in OPENPHISH.read_text().splitlines() if l.strip()])
    p = model.predict_proba(features(feed, mode))[:, 1]
    out["openphish_recall"] = {"recall": float((p >= threshold).mean()), "rows": int(len(p))}
    one = features(pd.Series(["https://www.example.com/login"]), mode)
    start = time.perf_counter()
    for _ in range(200):
        model.predict_proba(features(pd.Series(["https://www.example.com/login"]), mode))
    out["latency_ms_single_url_incl_features"] = (time.perf_counter() - start) / 200 * 1000
    del one
    return out


def threshold_at_fpr(y, p, target_fpr: float) -> float:
    legit = np.sort(p[y == 0])
    return float(legit[int(np.ceil(len(legit) * (1 - target_fpr))) - 1] + 1e-6)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cycle", type=int, required=True)
    parser.add_argument("--modes", nargs="+", default=["neutral"])
    parser.add_argument("--baseline", action="store_true", help="score the production model")
    parser.add_argument("--fpr-target", type=float, help="choose threshold on validation for this FPR")
    parser.add_argument("--reuse", help="score an existing candidate dir instead of training")
    parser.add_argument("--final", action="store_true", help="score the locked test split")
    args = parser.parse_args()

    RESULTS_ROOT.mkdir(parents=True, exist_ok=True)
    val_urls, val_y = load("stratified_validation.csv")
    results = {}

    if args.baseline:
        model = joblib.load(PRODUCTION_MODEL)
        results["production_raw"] = {
            "artifact": str(PRODUCTION_MODEL), "sha256": sha256(PRODUCTION_MODEL),
            "size_bytes": PRODUCTION_MODEL.stat().st_size,
            **score_model(model, "raw", val_urls, val_y, 0.5),
        }

    for mode in args.modes:
        name = f"c{args.cycle}_xgb_{mode}"
        out_dir = CANDIDATE_ROOT / (args.reuse or name)
        if args.reuse:
            model = joblib.load(out_dir / "model.joblib")
            mode = json.loads((out_dir / "config.json").read_text())["normalization"]
            name = f"c{args.cycle}_reuse_{args.reuse}"
            train_seconds = None
        else:
            train_urls, train_y = load("stratified_train.csv")
            start = time.perf_counter()
            X = features(train_urls, mode)
            model = build_model().fit(X, train_y)
            train_seconds = time.perf_counter() - start
            out_dir.mkdir(parents=True, exist_ok=True)
            joblib.dump(model, out_dir / "model.joblib")
        threshold = 0.5
        if args.fpr_target is not None:
            p = model.predict_proba(features(val_urls, mode))[:, 1]
            threshold = threshold_at_fpr(val_y, p, args.fpr_target)
            name = f"{name}_thr"
        artifact = out_dir / "model.joblib"
        config = {
            "normalization": mode, "estimator": "xgboost (production hyperparameters)",
            "seed": SEED, "threshold": threshold, "train_split": "stratified_train.csv",
            "train_split_sha256": sha256(SPLITS / "stratified_train.csv"),
            "selection_split": "stratified_validation.csv",
            "selection_split_sha256": sha256(SPLITS / "stratified_validation.csv"),
            "feature_extractor": "src.features.url_lexical.extract_lexical_url_dataframe (unchanged)",
            "train_seconds": train_seconds, "model_sha256": sha256(artifact),
        }
        if not args.reuse:
            (out_dir / "config.json").write_text(json.dumps(config, indent=2))
        results[name] = {"artifact": str(artifact), "size_bytes": artifact.stat().st_size, **config,
                         **score_model(model, mode, val_urls, val_y, threshold)}
        if args.final:
            test_urls, test_y = load("stratified_test.csv")
            p = model.predict_proba(features(test_urls, mode))[:, 1]
            results[name]["test"] = metrics(test_y, p, threshold)

    if args.final and args.baseline:
        test_urls, test_y = load("stratified_test.csv")
        p = joblib.load(PRODUCTION_MODEL).predict_proba(features(test_urls, "raw"))[:, 1]
        results["production_raw"]["test"] = metrics(test_y, p, 0.5)

    suffix = "_final" if args.final else ""
    path = RESULTS_ROOT / f"cycle{args.cycle}{suffix}.json"
    path.write_text(json.dumps(results, indent=2, default=float))
    for name, r in results.items():
        v = r["validation"]
        print(f"{name}: val macroF1={v['macro_f1']:.4f} phishF1={v['phishing']['f1']:.4f} "
              f"FPR={v['fpr']:.4f} AUC={v['roc_auc']:.4f} openphish={r['openphish_recall']['recall']:.3f}")
        print("   probes:", {k: round(x["fpr"], 4) for k, x in r["probes"].items()})
        if "test" in r:
            t = r["test"]
            print(f"   TEST macroF1={t['macro_f1']:.4f} FPR={t['fpr']:.4f} AUC={t['roc_auc']:.4f}")
    print("wrote", path)


if __name__ == "__main__":
    main()

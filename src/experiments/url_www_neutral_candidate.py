"""Candidate: remove a leading "www." before feature extraction (www_neutral).

Hypothesis: the false positive on bare domains comes from NoOfSubDomain (and
the www letters) encoding the PhiUSIIL template. If "www." is removed from the
host before the unchanged production feature extractor runs, in both training
and inference, the model cannot use it.

Evaluated against configs/url_candidate_acceptance.json (declared before the
first run). Same estimator and hyperparameters as production, seed 42, same
stratified splits. Validation only; the locked test split is not scored
because the candidate is not eligible for promotion (see the acceptance file).

    python -m src.experiments.url_www_neutral_candidate

The candidate artifact is written to models/candidates/url/c4_www_neutral/
(gitignored binary; config.json with checksum).
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import joblib
import numpy as np
import pandas as pd

from app.services import ml_detector
from src.evaluation import url_shape_guard as guard
from src.experiments.url_optimization import build_model
from src.features.url_lexical import extract_lexical_url_dataframe

SPLITS = Path("data/processed/url_splits")
OPENPHISH = Path("data/incoming/threat_feeds/openphish-community-20261028T152813Z.txt")
ACCEPTANCE = Path("configs/url_candidate_acceptance.json")
OUT_DIR = Path("models/candidates/url/c4_www_neutral")
RESULTS = Path("reports/model_optimization/results/url_www_neutral_candidate.json")
SEED = 42
DIAGNOSTIC_URLS = ["https://example.com/", "https://www.example.com/", "https://example.org/",
                   "https://www.wikipedia.org/", "https://wikipedia.org/"]


def strip_www(url: str) -> str:
    parts = urlsplit(url if "://" in url else f"http://{url}")
    netloc = parts.netloc
    if netloc.lower().startswith("www."):
        netloc = netloc[4:]
    return urlunsplit(parts._replace(netloc=netloc))


def features(urls: pd.Series, neutral: bool) -> pd.DataFrame:
    urls = urls.astype(str)
    return extract_lexical_url_dataframe(urls.map(strip_www) if neutral else urls)


def recall_ci(hits_a: np.ndarray, hits_b: np.ndarray, reps: int = 2000) -> list[float]:
    """Paired bootstrap 95% CI of recall(a) - recall(b) in percentage points."""
    rng = np.random.default_rng(SEED)
    n = len(hits_a)
    diffs = [(hits_a[i].mean() - hits_b[i].mean()) * 100
             for i in (rng.integers(0, n, n) for _ in range(reps))]
    return [float(np.percentile(diffs, 2.5)), float(np.percentile(diffs, 97.5))]


def main() -> None:
    criteria = json.loads(ACCEPTANCE.read_text())["criteria"]
    train = pd.read_csv(SPLITS / "stratified_train.csv", usecols=["URL", "Domain", "label"])
    val = pd.read_csv(SPLITS / "stratified_validation.csv", usecols=["URL", "Domain", "label"])
    y_train = (train.label == 0).astype(int).to_numpy()
    y_val = (val.label == 0).astype(int).to_numpy()

    start = time.perf_counter()
    candidate = build_model().fit(features(train.URL, True), y_train)
    train_seconds = time.perf_counter() - start
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(candidate, OUT_DIR / "model.joblib")
    sha = hashlib.sha256((OUT_DIR / "model.joblib").read_bytes()).hexdigest()
    (OUT_DIR / "config.json").write_text(json.dumps({
        "normalization": "www_neutral", "threshold": 0.5, "seed": SEED,
        "estimator": "xgboost (production hyperparameters)", "train_split": "stratified_train.csv",
        "train_seconds": train_seconds, "model_sha256": sha}, indent=2))

    baseline, _ = ml_detector._load_model()
    models = {"baseline": (baseline, False), "www_neutral": (candidate, True)}
    unseen = ~val.Domain.isin(set(train.Domain)).to_numpy()
    feed = pd.Series([l.strip() for l in OPENPHISH.read_text().splitlines() if l.strip()]) \
        if OPENPHISH.is_file() else None

    out, hits = {"model_sha256": {"baseline": ml_detector.MODEL_SHA256, "www_neutral": sha},
                 "train_seconds": train_seconds}, {}
    for name, (model, neutral) in models.items():
        p = model.predict_proba(features(val.URL, neutral))[:, 1]
        pred = (p >= 0.5).astype(int)
        tn = int(((pred == 0) & (y_val == 0)).sum()); fp = int(((pred == 1) & (y_val == 0)).sum())
        fn = int(((pred == 0) & (y_val == 1)).sum()); tp = int(((pred == 1) & (y_val == 1)).sum())
        hits[name] = pred[y_val == 1]
        r = {"confusion": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
             "phishing_recall": tp / (tp + fn), "phishing_precision": tp / (tp + fp),
             "legitimate_fpr": fp / (fp + tn),
             "unseen_domain_phishing_recall": float(pred[unseen & (y_val == 1)].mean()),
             "unseen_domain_rows": int(unseen.sum())}
        if feed is not None:
            r["openphish_recall"] = float((model.predict_proba(features(feed, neutral))[:, 1] >= 0.5).mean())
        scorer = (lambda u, m=model, n=neutral: m.predict_proba(features(u, n))[:, 1])
        _, summary = guard.run_guard(scorer, 0.5, guard.sample_legitimate(guard.load_config()))
        r["shape_guard_flag_rate"] = summary["flag_rate"]
        r["shape_guard_status"] = guard.check(summary, guard.load_config(),
                                              ml_detector.MODEL_SHA256 if name == "baseline" else sha)["status"]
        r["diagnostic_urls"] = {u: round(float(model.predict_proba(features(pd.Series([u]), neutral))[0, 1]), 4)
                                for u in DIAGNOSTIC_URLS}
        out[name] = r

    b, c = out["baseline"], out["www_neutral"]
    drop = (b["phishing_recall"] - c["phishing_recall"]) * 100
    ci = recall_ci(hits["baseline"], hits["www_neutral"])
    checks = {
        "phishing_recall_drop_pp": (round(drop, 3), drop <= criteria["phishing_recall_drop_max_pp"]),
        "phishing_recall_drop_ci95_pp": ([round(x, 3) for x in ci], ci[1] <= criteria["phishing_recall_drop_ci95_upper_max_pp"]),
        "in_template_fpr_increase_pp": (round((c["legitimate_fpr"] - b["legitimate_fpr"]) * 100, 3),
                                        (c["legitimate_fpr"] - b["legitimate_fpr"]) * 100 <= criteria["in_template_legitimate_fpr_increase_max_pp"]),
        "unseen_domain_recall_drop_pp": (round((b["unseen_domain_phishing_recall"] - c["unseen_domain_phishing_recall"]) * 100, 3),
                                         (b["unseen_domain_phishing_recall"] - c["unseen_domain_phishing_recall"]) * 100 <= criteria["unseen_domain_subset_phishing_recall_drop_max_pp"]),
        "url_shape_guard": (c["shape_guard_status"], c["shape_guard_status"] == "pass"),
        "real_off_template_legitimate_eval": ("no licensed data available", False),
    }
    if feed is not None:
        d = (b["openphish_recall"] - c["openphish_recall"]) * 100
        checks["openphish_recall_drop_pp"] = (round(d, 3), d <= criteria["openphish_recall_drop_max_pp"])
    out["acceptance"] = {k: {"value": v, "pass": ok} for k, (v, ok) in checks.items()}
    out["decision"] = "promote" if all(ok for _, ok in checks.values()) else "reject"

    RESULTS.write_text(json.dumps(out, indent=2, default=float))
    for name in models:
        r = out[name]
        print(f"{name}: recall={r['phishing_recall']:.4f} precision={r['phishing_precision']:.4f} "
              f"fpr={r['legitimate_fpr']:.4f} unseen_recall={r['unseen_domain_phishing_recall']:.4f} "
              f"openphish={r.get('openphish_recall')} guard={r['shape_guard_status']}")
        print("   guard:", r["shape_guard_flag_rate"])
        print("   urls:", r["diagnostic_urls"])
    for k, v in out["acceptance"].items():
        print(f"  {'PASS' if v['pass'] else 'FAIL'} {k}: {v['value']}")
    print("decision:", out["decision"], "| wrote", RESULTS)


if __name__ == "__main__":
    main()

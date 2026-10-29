"""Experiment arms B0 / H1 / L1 / L2 on approved data (PhiUSIIL + Hannousse 2021).

    H1  host block only (src/experiments/url_lexical_v2.py)
    L1  host + path/query + scheme blocks
    L2  L1, with path/query and scheme blocks set to missing for PhiUSIIL rows
        (its legitimate URLs never vary in those, so they cannot teach them);
        XGBoost learns default directions for missing values

Same data, splits, leakage removal, seed and estimator hyperparameters as
src/training/train_url_multisource.py, and the same, unchanged acceptance
gates (configs/url_candidate_acceptance.json). Validation only; L2+D is
blocked (docs/dephides_licence_audit.md). Production is untouched.

    python -m src.experiments.url_v2_arms
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from xgboost import XGBClassifier

from app.services import ml_detector
from src.evaluation import url_shape_guard as guard
from src.experiments import url_lexical_v2 as v2
from src.training import train_url_multisource as ms

ARMS = {"H1_host_only": (v2.HOST_FEATURES, False),
        "L1_lexical_v2": (v2.ALL_FEATURES, False),
        "L2_lexical_v2_masked": (v2.ALL_FEATURES, True)}
MASKED = v2.PATH_FEATURES + v2.SCHEME_FEATURES
OUT = Path("reports/model_optimization/results/url_v2_arms_validation.json")
DIAGNOSTIC = ["https://example.com/", "https://www.example.com/", "https://example.org/", "https://wikipedia.org/",
              "https://www.wikipedia.org/", "http://example.com/", "https://example.com/docs/intro?lang=en",
              "http://192.168.1.1/secure/login.php?acct=1"]


def estimator() -> XGBClassifier:
    # Production hyperparameters (src/training/train_url_inference.py); no imputer, so
    # masked values stay missing.
    return XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.1, subsample=0.8, colsample_bytree=0.8,
                         objective="binary:logistic", eval_metric="logloss", random_state=ms.SEED, n_jobs=-1)


class Arm:
    def __init__(self, model, columns):
        self.model, self.columns = model, columns

    def proba(self, urls: pd.Series) -> np.ndarray:
        return self.model.predict_proba(v2.extract_dataframe(pd.Series(list(urls)), self.columns))[:, 1]


def main() -> int:
    acceptance = json.loads(ms.ACCEPTANCE.read_text())
    han, report = ms.load_hannousse()
    phi = {s: ms.load_phiusiil(s) for s in ("train", "validation")}
    held_out = set(phi["validation"]["url"].map(ms.registrable_domain)) | set(
        ms.load_phiusiil("test")["url"].map(ms.registrable_domain))
    han["train"] = han["train"][~han["train"]["group"].isin(held_out)].reset_index(drop=True)
    train = pd.concat([phi["train"], han["train"][["url", "phishing", "source"]]], ignore_index=True)
    train_groups = set(train["url"].map(ms.registrable_domain))
    X_all = v2.extract_dataframe(train["url"])
    sets = {"phiusiil": phi["validation"], "hannousse": han["validation"]}
    feed = (pd.Series([l.strip() for l in ms.OPENPHISH.read_text().splitlines() if l.strip()])
            if ms.OPENPHISH.is_file() else None)
    guard_config = guard.load_config()
    guard_urls = guard.sample_legitimate(guard_config)

    baseline, _ = ml_detector._load_model()
    scorers = {"production": (lambda u: baseline.predict_proba(ms.features(pd.Series(list(u)), False))[:, 1],
                              ml_detector.MODEL_SHA256, None)}
    for name, (columns, masked) in ARMS.items():
        X = X_all[columns].copy()
        if masked:
            X.loc[(train["source"] == "phiusiil").to_numpy(), [c for c in MASKED if c in columns]] = np.nan
        start = time.perf_counter()
        model = estimator().fit(X, train["phishing"].to_numpy())
        seconds = time.perf_counter() - start
        out_dir = ms.CANDIDATE_ROOT / name
        out_dir.mkdir(parents=True, exist_ok=True)
        joblib.dump(model, out_dir / "model.joblib")
        sha = hashlib.sha256((out_dir / "model.joblib").read_bytes()).hexdigest()
        (out_dir / "config.json").write_text(json.dumps({
            "feature_spec": v2.FEATURE_SPEC_VERSION, "features": columns, "masked_for_phiusiil": MASKED if masked else [],
            "estimator": "XGBClassifier (production hyperparameters, no imputer)", "seed": ms.SEED,
            "training_rows": len(train), "hannousse_sha256": ms.HANNOUSSE_SHA256, "train_seconds": seconds,
            "threshold": 0.5, "model_sha256": sha}, indent=2))
        arm = Arm(model, columns)
        scorers[name] = (arm.proba, sha, columns)

    results, decisions = {}, {}
    for name, (proba, sha, _) in scorers.items():
        r = {"model_sha256": sha}
        for set_name, frame in sets.items():
            r[set_name] = ms.evaluate_probabilities(proba(frame["url"]), frame, train_groups)
        if feed is not None:
            r["openphish_recall"] = float((proba(feed) >= 0.5).mean())
        _, summary = guard.run_guard(lambda u, f=proba: f(u), 0.5, guard_urls)
        r["shape_guard"] = {"flag_rate": summary["flag_rate"], "status": guard.check(summary, guard_config, sha)["status"]}
        r["diagnostic_urls"] = {u: round(float(proba(pd.Series([u]))[0]), 4) for u in DIAGNOSTIC}
        results[name] = r
    for name in ARMS:
        gates = ms.gates(results["production"], results[name], acceptance["criteria"], acceptance["addendum_2026_10_29_b"])
        decisions[name] = {"gates": gates, "decision": "eligible" if all(g["pass"] for g in gates.values()) else "reject"}

    OUT.write_text(json.dumps({"split": "validation", "data_report": report, "training_rows": len(train),
                               "feature_spec": v2.FEATURE_SPEC_VERSION, "models": ms._strip_private(results),
                               "acceptance": decisions,
                               "blocked_arms": {"L2+D": "docs/dephides_licence_audit.md"}}, indent=2, default=float))
    for name, r in results.items():
        p, h = r["phiusiil"]["overall"], r["hannousse"]
        print(f"{name:22} phi recall={p['phishing_recall']:.4f} fpr={p['legitimate_fpr']:.4f} | han recall="
              f"{h['overall']['phishing_recall']:.4f} prec={h['overall']['phishing_precision']:.4f} "
              f"offtmpl_fpr={h['off_template_legitimate']['fpr']:.4f} | openphish={r.get('openphish_recall')}")
        print("   shape FPR:", {k: (v["rows"], None if v["fpr"] is None else round(v["fpr"], 4))
                                for k, v in h["legitimate_fpr_by_shape"].items()})
        print("   guard:", r["shape_guard"]["status"], r["shape_guard"]["flag_rate"])
        print("   urls:", r["diagnostic_urls"])
    for name, d in decisions.items():
        print(f"\n{name}: {d['decision']}")
        for k, g in d["gates"].items():
            print(f"  {'PASS' if g['pass'] else 'FAIL'} {k}: {g['value']}")
    print("wrote", OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

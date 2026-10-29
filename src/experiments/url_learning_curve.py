"""Is the URL false-positive problem limited by data quantity or by model design?

Trains on the representative approved source only (Hannousse 2021 grouped
train split; no PhiUSIIL, so no template confound) and evaluates on the
Hannousse grouped VALIDATION split (locked test split untouched):

1. Learning curve: the v2 feature model (XGBoost, production hyperparameters)
   on registrable-domain-grouped subsamples of 25/50/75/100% of training,
   3 seeds each. If the off-template legitimate FPR is still falling at 100%,
   more representative data is expected to help (data quantity).
2. Model family at 100%: XGBoost vs L2-regularised logistic regression vs
   random forest on the same v2 features. If families agree, model design is
   not the bottleneck.

Diagnostic only: no candidate here is eligible for promotion (none is
trained on PhiUSIIL, so the PhiUSIIL recall gates cannot be met by
construction). Acceptance criteria are not applied or changed.

    python -m src.experiments.url_learning_curve
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from src.experiments import url_lexical_v2 as v2
from src.experiments.url_v2_arms import estimator as xgb_estimator
from src.training import train_url_multisource as ms

OUT = Path("reports/model_optimization/results/url_learning_curve.json")
FRACTIONS = (0.25, 0.5, 0.75, 1.0)
SEEDS = (0, 1, 2)


def grouped_subsample(frame: pd.DataFrame, fraction: float, seed: int) -> pd.DataFrame:
    """Keep a random `fraction` of registrable-domain groups (never split a group)."""
    groups = np.array(sorted(frame["group"].unique()))
    rng = np.random.default_rng(seed)
    keep = set(rng.choice(groups, size=max(1, int(round(fraction * len(groups)))), replace=False))
    return frame[frame["group"].isin(keep)]


def families() -> dict:
    return {
        "xgboost": xgb_estimator,
        "logistic_regression": lambda: make_pipeline(StandardScaler(), LogisticRegression(C=1.0, max_iter=2000)),
        "random_forest": lambda: RandomForestClassifier(n_estimators=300, min_samples_leaf=2, random_state=ms.SEED, n_jobs=-1),
    }


def summarize(p: np.ndarray, validation: pd.DataFrame, train_groups: set) -> dict:
    r = ms.evaluate_probabilities(p, validation, train_groups)
    o = r["overall"]
    return {"phishing_recall": o["phishing_recall"], "phishing_precision": o["phishing_precision"],
            "phishing_f1": o["phishing_f1"], "off_template_fpr": r["off_template_legitimate"]["fpr"],
            "off_template_ci95": r["off_template_legitimate"]["ci95"],
            "bare_root_fpr": r["legitimate_fpr_by_shape"]["bare_root"]["fpr"],
            "path_or_query_fpr": r["legitimate_fpr_by_shape"]["path_or_query"]["fpr"]}


def main() -> int:
    han, _ = ms.load_hannousse()
    train, validation = han["train"], han["validation"]
    X_val = v2.extract_dataframe(validation["url"])
    curve = []
    for fraction in FRACTIONS:
        runs = []
        for seed in SEEDS if fraction < 1.0 else SEEDS[:1]:
            part = grouped_subsample(train, fraction, seed)
            model = xgb_estimator().fit(v2.extract_dataframe(part["url"]), part["phishing"].to_numpy())
            runs.append({"seed": seed, "rows": len(part), "domains": int(part["group"].nunique()),
                         **summarize(model.predict_proba(X_val)[:, 1], validation, set(part["group"]))})
        mean = {k: float(np.mean([r[k] for r in runs])) for k in ("rows", "phishing_recall", "phishing_f1",
                                                                  "off_template_fpr", "bare_root_fpr")}
        curve.append({"fraction": fraction, "runs": runs, "mean": mean})
        print(f"fraction {fraction:.2f}: rows~{mean['rows']:.0f} off-template FPR {mean['off_template_fpr']:.4f} "
              f"bare-root FPR {mean['bare_root_fpr']:.4f} recall {mean['phishing_recall']:.4f} F1 {mean['phishing_f1']:.4f}")

    X_train = v2.extract_dataframe(train["url"])
    family_results = {}
    for name, make in families().items():
        X_fit = X_train.fillna(0.0) if name != "xgboost" else X_train
        model = make().fit(X_fit, train["phishing"].to_numpy())
        family_results[name] = summarize(model.predict_proba(X_val.fillna(0.0) if name != "xgboost" else X_val)[:, 1],
                                         validation, set(train["group"]))
        r = family_results[name]
        print(f"{name:20} off-template FPR {r['off_template_fpr']:.4f} {r['off_template_ci95']} "
              f"recall {r['phishing_recall']:.4f} F1 {r['phishing_f1']:.4f}")

    OUT.write_text(json.dumps({"train_source": "hannousse grouped train (all rows, no PhiUSIIL)",
                               "evaluated_on": "hannousse grouped validation", "feature_spec": v2.FEATURE_SPEC_VERSION,
                               "learning_curve": curve, "model_family": family_results}, indent=2))
    print("wrote", OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

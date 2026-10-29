"""Data and feature audit of the approved URL training data (no training).

Measures, on the approved sources (PhiUSIIL stratified train, Hannousse 2021
grouped train):
- rows by label x source x URL shape;
- univariate AUC of every production feature (and the v2 blocks) for the
  label, computed WITHIN each source and on the POOLED data. A feature whose
  pooled AUC is far from its within-source AUC is carrying source identity;
  an AUC near 1.0 within PhiUSIIL but near 0.5 within Hannousse marks a
  collection artefact rather than a phishing signal;
- how well the SOURCE alone predicts the label in the pooled data;
- duplicates, label conflicts and domain overlap between sources.

    python -m src.experiments.url_data_audit
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

from src.experiments import url_lexical_v2 as v2
from src.features.url_lexical import LEXICAL_URL_FEATURES, extract_lexical_url_dataframe
from src.training import train_url_multisource as ms

OUT = Path("reports/model_optimization/results/url_data_audit.json")


def univariate_auc(values: pd.Series, y: np.ndarray) -> float | None:
    """Direction-free AUC (max(AUC, 1-AUC)); None if a class or variation is missing."""
    if len(set(y)) < 2 or values.nunique() < 2:
        return None
    auc = roc_auc_score(y, values.to_numpy())
    return float(max(auc, 1 - auc))


def feature_table(frame: pd.DataFrame, X: pd.DataFrame) -> dict:
    y = frame["phishing"].to_numpy()
    out = {}
    for name in X.columns:
        row = {"pooled": univariate_auc(X[name], y)}
        for source in sorted(frame["source"].unique()):
            mask = (frame["source"] == source).to_numpy()
            row[source] = univariate_auc(X[name][mask], y[mask])
        out[name] = row
    return out


def main() -> int:
    han, _ = ms.load_hannousse()
    phi = ms.load_phiusiil("train")
    train = pd.concat([phi, han["train"][["url", "phishing", "source"]]], ignore_index=True)
    shapes = pd.DataFrame([ms.shape_groups(u) for u in train["url"]])

    report = {"rows": {s: {"legitimate": int(((train.source == s) & (train.phishing == 0)).sum()),
                           "phishing": int(((train.source == s) & (train.phishing == 1)).sum())}
                       for s in sorted(train.source.unique())}}
    shape_rows = {}
    for s in sorted(train.source.unique()):
        for label, name in ((0, "legitimate"), (1, "phishing")):
            mask = ((train.source == s) & (train.phishing == label)).to_numpy()
            shape_rows[f"{s}/{name}"] = {k: round(float(shapes[k][mask].mean()), 4) for k in shapes.columns}
    report["shape_share_by_source_and_label"] = shape_rows
    report["source_only_label_auc_pooled"] = univariate_auc((train.source == "hannousse").astype(int), train.phishing.to_numpy())

    X_prod = extract_lexical_url_dataframe(train["url"])
    X_v2 = v2.extract_dataframe(train["url"])
    report["production_features_auc"] = feature_table(train, X_prod[LEXICAL_URL_FEATURES])
    report["v2_features_auc"] = feature_table(train, X_v2)

    groups = train["url"].map(ms.registrable_domain)
    report["hygiene"] = {
        "duplicate_urls": int(train["url"].duplicated().sum()),
        "url_label_conflicts": int((train.groupby("url").phishing.nunique() > 1).sum()),
        "registrable_domains_with_both_labels": int((train.assign(g=groups).groupby("g").phishing.nunique() > 1).sum()),
        "registrable_domains_shared_between_sources": len(set(groups[train.source == "phiusiil"]) &
                                                          set(groups[train.source == "hannousse"])),
    }
    OUT.write_text(json.dumps(report, indent=2))

    print(json.dumps(report["rows"]), "| source-only AUC:", round(report["source_only_label_auc_pooled"], 4))
    print(json.dumps(report["hygiene"]))
    fmt = lambda v: "  n/a" if v is None else f"{v:.3f}"
    print(f"\n{'production feature':28} pooled  phiusiil hannousse")
    for name, row in sorted(report["production_features_auc"].items(), key=lambda kv: -(kv[1]['phiusiil'] or 0)):
        print(f"{name:28} {fmt(row['pooled'])}  {fmt(row['phiusiil'])}   {fmt(row['hannousse'])}")
    print("wrote", OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

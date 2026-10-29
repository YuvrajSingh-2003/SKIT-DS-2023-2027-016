"""Cycle 3 reproducibility check: grouped 5-fold CV of A vs B on train+val (test untouched).

    python -m src.experiments.sms_group_cv
"""
import json, numpy as np, pandas as pd, time
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.metrics import f1_score
from src.experiments.sms_optimization import build, CLASSES
d = pd.concat([pd.read_csv(f"data/processed/{s}.csv") for s in ("train", "val")], ignore_index=True)
X, y, g = d.text.astype(str).to_numpy(), d.label.to_numpy(), d.group_id.to_numpy()
out = {"protocol": "StratifiedGroupKFold(5, shuffle, seed 42) on train+val by near-duplicate group_id; test untouched", "folds": []}
for k, (tr, te) in enumerate(StratifiedGroupKFold(5, shuffle=True, random_state=42).split(X, y, g)):
    row = {}
    for name in ("A_retrain", "B_svm_char"):
        p = build(name).fit(X[tr], y[tr]).predict(X[te])
        row[name] = {"macro_f1": f1_score(y[te], p, labels=CLASSES, average="macro"),
                     "per_class_f1": dict(zip(CLASSES, f1_score(y[te], p, labels=CLASSES, average=None))),
                     "legit_fpr": float((p[y[te] == "legitimate"] != "legitimate").mean())}
    out["folds"].append(row); print(k, {n: round(r["macro_f1"], 4) for n, r in row.items()})
diff = [f["B_svm_char"]["macro_f1"] - f["A_retrain"]["macro_f1"] for f in out["folds"]]
out["B_minus_A_macro_f1"] = {"per_fold": diff, "mean": float(np.mean(diff)), "folds_B_better": int(sum(x > 0 for x in diff))}
for n in ("A_retrain", "B_svm_char"):
    out[n] = {"mean_macro_f1": float(np.mean([f[n]["macro_f1"] for f in out["folds"]])), "std": float(np.std([f[n]["macro_f1"] for f in out["folds"]]))}
print(json.dumps({k: v for k, v in out.items() if k != "folds"}, indent=1, default=float))
open("reports/model_optimization/results/sms_cycle3_groupcv.json", "w").write(json.dumps(out, indent=2, default=float))

"""Multi-source URL training: PhiUSIIL + Hannousse & Yahiouche (2021).

Why: every PhiUSIIL legitimate URL is https://www.<host> with no path, so a
model trained on it alone flags bare domains, http and paths. The Hannousse
& Yahiouche dataset (Mendeley 10.17632/c2gw7fy2j4.3, CC BY 4.0, built May
2020) has crawled legitimate URLs with those shapes (Alexa top-500 seeds,
12 URLs per domain, plus Yandex-sourced URLs from Sahingoz et al.) and
PhishTank/OpenPhish phishing URLs.

Pipeline (deterministic, seed 42):
  1. PhiUSIIL: the existing stratified splits, unchanged.
  2. Hannousse: exact-URL dedupe, label-conflict removal, then a split by
     approximate registrable domain (StratifiedGroupKFold, 20 folds:
     14 train / 3 validation / 3 test), so no domain spans two splits.
  3. Cross-source leakage: Hannousse training rows whose registrable domain
     occurs in PhiUSIIL validation/test are dropped (counts recorded).
  4. Features: the unchanged production extractor
     (src.features.url_lexical.extract_lexical_url_dataframe), optionally
     after removing a leading "www." (candidate www_neutral).
  5. Same estimator and hyperparameters as production.

There is no per-row timestamp in either source, so no time-based holdout is
possible; the two sources are single snapshots (PhiUSIIL 2024 release,
Hannousse May 2020).

    python -m src.training.train_url_multisource            # validation only
    python -m src.training.train_url_multisource --final c5_multisource
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
from sklearn.model_selection import StratifiedGroupKFold

from app.services import ml_detector
from src.evaluation import url_shape_guard as guard
from src.experiments.url_optimization import build_model
from src.experiments.url_www_neutral_candidate import strip_www
from src.features.url_lexical import extract_lexical_url_dataframe

SEED = 42
PHIUSIIL = Path("data/processed/url_splits")
HANNOUSSE = Path("data/raw/hannousse_2021/dataset_B_05_2020.csv")
HANNOUSSE_SHA256 = "21093e2902e5441c86a6daf95e86e7c332046e477fdf109a579d7bd81e586d6c"
OPENPHISH = Path("data/incoming/threat_feeds/openphish-community-20261028T152813Z.txt")
ACCEPTANCE = Path("configs/url_candidate_acceptance.json")
CANDIDATE_ROOT = Path("models/candidates/url")
RESULTS = Path("reports/model_optimization/results")

# Multi-label public suffixes seen in the data; everything else uses the last
# two labels. An approximation (no PSL dependency), applied identically to all
# sources and splits.
MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.in", "co.jp",
    "co.nz", "co.za", "com.br", "com.cn", "com.mx", "com.tr", "com.ar", "com.co", "com.sg",
    "com.my", "com.hk", "com.tw", "com.ua", "co.kr", "co.id", "com.pk", "com.ng", "com.vn",
    "com.ph", "com.sa", "com.eg", "gov.in", "ac.in", "edu.au", "ne.jp", "or.jp",
}
# name -> (www_neutral, training mix)
#   all       PhiUSIIL train + Hannousse train, unweighted
#   balanced  same rows; sample weights give each source equal total weight
#   hannousse Hannousse train only
CANDIDATES = {
    "c5_multisource": (False, "all"),
    "c6_multisource_www_neutral": (True, "all"),
    "c7_multisource_balanced": (False, "balanced"),
    "c8_hannousse_only": (False, "hannousse"),
}


def registrable_domain(url: str) -> str:
    host = (urlsplit(url if "://" in url else f"http://{url}").hostname or "").lower().rstrip(".")
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def shape_groups(url: str) -> dict:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    root = parts.path in ("", "/") and not parts.query
    www = host.startswith("www.")
    return {"in_template": parts.scheme == "https" and www and root, "bare_root": not www and root,
            "no_www": not www, "http": parts.scheme == "http", "path_or_query": not root}


def load_phiusiil(split: str) -> pd.DataFrame:
    frame = pd.read_csv(PHIUSIIL / f"stratified_{split}.csv", usecols=["URL", "label"])
    frame = frame.rename(columns={"URL": "url"})
    frame["phishing"] = (frame["label"] == 0).astype(int)
    frame["source"] = "phiusiil"
    return frame[["url", "phishing", "source"]]


def load_hannousse() -> tuple[dict, dict]:
    digest = hashlib.sha256(HANNOUSSE.read_bytes()).hexdigest()
    if digest != HANNOUSSE_SHA256:
        raise RuntimeError(f"{HANNOUSSE} checksum {digest} != expected {HANNOUSSE_SHA256}")
    raw = pd.read_csv(HANNOUSSE, usecols=["url", "status"])
    report = {"rows": len(raw)}
    raw["url"] = raw["url"].astype(str).str.strip()
    labels_per_url = raw.groupby("url")["status"].nunique()
    conflicts = set(labels_per_url[labels_per_url > 1].index)
    report["label_conflict_urls_dropped"] = len(conflicts)
    raw = raw[~raw["url"].isin(conflicts)]
    before = len(raw)
    raw = raw.drop_duplicates("url").reset_index(drop=True)
    report["exact_duplicates_dropped"] = before - len(raw)
    raw["phishing"] = (raw["status"] == "phishing").astype(int)
    raw["source"] = "hannousse"
    raw["group"] = raw["url"].map(registrable_domain)

    folds = StratifiedGroupKFold(n_splits=20, shuffle=True, random_state=SEED)
    assignment = np.empty(len(raw), dtype=object)
    for fold, (_, index) in enumerate(folds.split(raw, raw["phishing"], raw["group"])):
        assignment[index] = "train" if fold < 14 else ("validation" if fold < 17 else "test")
    raw["split"] = assignment
    splits = {name: raw[raw["split"] == name].reset_index(drop=True) for name in ("train", "validation", "test")}
    report["rows_by_split"] = {k: len(v) for k, v in splits.items()}
    report["group_overlap_between_splits"] = {
        f"{a}-{b}": len(set(splits[a]["group"]) & set(splits[b]["group"]))
        for a, b in (("train", "validation"), ("train", "test"), ("validation", "test"))}
    return splits, report


def features(urls: pd.Series, neutral: bool) -> pd.DataFrame:
    urls = urls.astype(str)
    return extract_lexical_url_dataframe(urls.map(strip_www) if neutral else urls)


def binary_metrics(y: np.ndarray, p: np.ndarray) -> dict:
    pred = p >= 0.5
    tn = int((~pred & (y == 0)).sum()); fp = int((pred & (y == 0)).sum())
    fn = int((~pred & (y == 1)).sum()); tp = int((pred & (y == 1)).sum())
    recall = tp / (tp + fn) if tp + fn else None
    precision = tp / (tp + fp) if tp + fp else None
    f1 = 2 * precision * recall / (precision + recall) if recall and precision else 0.0
    return {"confusion": {"tn": tn, "fp": fp, "fn": fn, "tp": tp}, "phishing_recall": recall,
            "phishing_precision": precision, "phishing_f1": f1,
            "legitimate_fpr": fp / (fp + tn) if fp + tn else None}


def wilson(k: int, n: int) -> list[float] | None:
    if not n:
        return None
    z, phat = 1.96, k / n
    centre = (phat + z * z / (2 * n)) / (1 + z * z / n)
    half = z * np.sqrt(phat * (1 - phat) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return [float(centre - half), float(centre + half)]


def evaluate(model, neutral: bool, frame: pd.DataFrame, train_groups: set) -> dict:
    p = model.predict_proba(features(frame["url"], neutral))[:, 1]
    y = frame["phishing"].to_numpy()
    out = {"overall": binary_metrics(y, p)}
    shapes = pd.DataFrame([shape_groups(u) for u in frame["url"]])
    legit = y == 0
    out["legitimate_fpr_by_shape"] = {}
    for name in shapes.columns:
        mask = shapes[name].to_numpy() & legit
        flagged = int((p[mask] >= 0.5).sum())
        out["legitimate_fpr_by_shape"][name] = {
            "rows": int(mask.sum()), "flagged": flagged,
            "fpr": flagged / mask.sum() if mask.sum() else None, "ci95": wilson(flagged, int(mask.sum()))}
    off = (~shapes["in_template"].to_numpy()) & legit
    flagged = int((p[off] >= 0.5).sum())
    out["off_template_legitimate"] = {"rows": int(off.sum()), "flagged": flagged,
                                      "fpr": flagged / off.sum() if off.sum() else None,
                                      "ci95": wilson(flagged, int(off.sum()))}
    unseen = ~frame["url"].map(registrable_domain).isin(train_groups).to_numpy()
    out["unseen_domains"] = {"rows": int(unseen.sum()), **binary_metrics(y[unseen], p[unseen])}
    out["_phishing_hits"] = (p[y == 1] >= 0.5)
    return out


def recall_drop_ci(baseline_hits: np.ndarray, candidate_hits: np.ndarray, reps: int = 2000) -> list[float]:
    rng = np.random.default_rng(SEED)
    n = len(baseline_hits)
    diffs = [(baseline_hits[i].mean() - candidate_hits[i].mean()) * 100
             for i in (rng.integers(0, n, n) for _ in range(reps))]
    return [float(np.percentile(diffs, 2.5)), float(np.percentile(diffs, 97.5))]


def gates(base: dict, cand: dict, criteria: dict, addendum: dict) -> dict:
    phi_b, phi_c = base["phiusiil"], cand["phiusiil"]
    drop = (phi_b["overall"]["phishing_recall"] - phi_c["overall"]["phishing_recall"]) * 100
    ci = recall_drop_ci(phi_b["_phishing_hits"], phi_c["_phishing_hits"])
    unseen_drop = (phi_b["unseen_domains"]["phishing_recall"] - phi_c["unseen_domains"]["phishing_recall"]) * 100
    fpr_up = (phi_c["overall"]["legitimate_fpr"] - phi_b["overall"]["legitimate_fpr"]) * 100
    han = cand["hannousse"]
    result = {
        "phiusiil_recall_drop_pp": (round(drop, 3), drop <= criteria["phishing_recall_drop_max_pp"]),
        "phiusiil_recall_drop_ci95_pp": ([round(x, 3) for x in ci], ci[1] <= criteria["phishing_recall_drop_ci95_upper_max_pp"]),
        "phiusiil_in_template_fpr_increase_pp": (round(fpr_up, 3), fpr_up <= criteria["in_template_legitimate_fpr_increase_max_pp"]),
        "phiusiil_unseen_domain_recall_drop_pp": (round(unseen_drop, 3), unseen_drop <= criteria["unseen_domain_subset_phishing_recall_drop_max_pp"]),
        "url_shape_guard": (cand["shape_guard"]["status"], cand["shape_guard"]["status"] == "pass"),
        "real_off_template_legitimate_fpr": (round(han["off_template_legitimate"]["fpr"], 4),
                                             han["off_template_legitimate"]["fpr"] <= addendum["off_template_legitimate_fpr_max"]),
        "real_eval_phishing_f1_vs_baseline": ((round(han["overall"]["phishing_f1"], 4), round(base["hannousse"]["overall"]["phishing_f1"], 4)),
                                              han["overall"]["phishing_f1"] >= base["hannousse"]["overall"]["phishing_f1"]),
    }
    for name, row in han["legitimate_fpr_by_shape"].items():
        if name == "in_template" or row["rows"] < addendum["per_shape_min_rows_to_gate"]:
            continue
        result[f"real_fpr_{name}"] = (round(row["fpr"], 4), row["fpr"] <= addendum["per_shape_legitimate_fpr_max"])
    if "openphish_recall" in cand:
        d = (base["openphish_recall"] - cand["openphish_recall"]) * 100
        result["openphish_recall_drop_pp"] = (round(d, 3), d <= criteria["openphish_recall_drop_max_pp"])
    return {k: {"value": v, "pass": bool(ok)} for k, (v, ok) in result.items()}


def score_all(models: dict, sets: dict, train_groups: set, feed) -> dict:
    out = {}
    guard_config = guard.load_config()
    guard_urls = guard.sample_legitimate(guard_config)
    for name, (model, neutral, sha) in models.items():
        r = {"model_sha256": sha}
        for set_name, frame in sets.items():
            r[set_name] = evaluate(model, neutral, frame, train_groups)
        if feed is not None:
            r["openphish_recall"] = float((model.predict_proba(features(feed, neutral))[:, 1] >= 0.5).mean())
        scorer = (lambda u, m=model, n=neutral: m.predict_proba(features(u, n))[:, 1])
        _, summary = guard.run_guard(scorer, 0.5, guard_urls)
        r["shape_guard"] = {"flag_rate": summary["flag_rate"],
                            "status": guard.check(summary, guard_config, sha)["status"]}
        r["diagnostic_urls"] = {u: round(float(model.predict_proba(features(pd.Series([u]), neutral))[0, 1]), 4)
                                for u in ["https://example.com/", "https://www.example.com/", "https://example.org/",
                                          "https://wikipedia.org/", "https://www.wikipedia.org/",
                                          "http://example.com/", "https://example.com/docs/intro?lang=en",
                                          "http://192.168.1.1/secure/login.php?acct=1"]}
        out[name] = r
    return out


def _strip_private(obj):
    if isinstance(obj, dict):
        return {k: _strip_private(v) for k, v in obj.items() if not k.startswith("_")}
    return obj


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--final", nargs="*", help="score the locked test splits for these candidates")
    args = parser.parse_args(argv)
    acceptance = json.loads(ACCEPTANCE.read_text())
    criteria, addendum = acceptance["criteria"], acceptance["addendum_2026_10_29_b"]

    han, han_report = load_hannousse()
    phi = {s: load_phiusiil(s) for s in ("train", "validation", "test")}
    held_out_groups = set(phi["validation"]["url"].map(registrable_domain)) | set(phi["test"]["url"].map(registrable_domain))
    leak = han["train"]["group"].isin(held_out_groups)
    han_report["hannousse_train_rows_dropped_for_phiusiil_heldout_domains"] = int(leak.sum())
    han["train"] = han["train"][~leak].reset_index(drop=True)
    for split in ("validation", "test"):
        han_report[f"hannousse_{split}_rows_with_domain_in_phiusiil_train"] = int(
            han[split]["group"].isin(set(phi["train"]["url"].map(registrable_domain))).sum())

    train = pd.concat([phi["train"], han["train"][["url", "phishing", "source"]]], ignore_index=True)
    train_groups = set(train["url"].map(registrable_domain))
    baseline, _ = ml_detector._load_model()
    models = {"production": (baseline, False, ml_detector.MODEL_SHA256)}

    final = args.final is not None
    for name, (neutral, mix) in CANDIDATES.items():
        out_dir = CANDIDATE_ROOT / name
        if final:
            if name not in args.final:
                continue
            config = json.loads((out_dir / "config.json").read_text())
            artifact = out_dir / "model.joblib"
            sha = hashlib.sha256(artifact.read_bytes()).hexdigest()
            if sha != config["model_sha256"]:
                raise RuntimeError(f"{artifact} checksum mismatch")
            models[name] = (joblib.load(artifact), neutral, sha)
            continue
        rows = train if mix != "hannousse" else train[train["source"] == "hannousse"]
        weights = None
        if mix == "balanced":
            per_source = rows["source"].map(rows["source"].value_counts())
            weights = (len(rows) / (2 * per_source)).to_numpy()
        start = time.perf_counter()
        model = build_model().fit(features(rows["url"], neutral), rows["phishing"].to_numpy(),
                                  classifier__sample_weight=weights)
        seconds = time.perf_counter() - start
        out_dir.mkdir(parents=True, exist_ok=True)
        joblib.dump(model, out_dir / "model.joblib")
        sha = hashlib.sha256((out_dir / "model.joblib").read_bytes()).hexdigest()
        (out_dir / "config.json").write_text(json.dumps({
            "normalization": "www_neutral" if neutral else "raw", "training_mix": mix,
            "threshold": 0.5, "seed": SEED,
            "estimator": "xgboost (production hyperparameters)",
            "training_data": {"phiusiil": "stratified_train.csv", "hannousse_2021": "grouped train split",
                              "rows": len(rows), "phishing_rows": int(rows["phishing"].sum())},
            "hannousse_sha256": HANNOUSSE_SHA256, "train_seconds": seconds, "model_sha256": sha}, indent=2))
        models[name] = (model, neutral, sha)

    split = "test" if final else "validation"
    sets = {"phiusiil": phi[split], "hannousse": han[split]}
    feed = (pd.Series([l.strip() for l in OPENPHISH.read_text().splitlines() if l.strip()])
            if OPENPHISH.is_file() else None)
    scored = score_all(models, sets, train_groups, feed)
    decisions = {}
    if not final:
        for name in CANDIDATES:
            g = gates(scored["production"], scored[name], criteria, addendum)
            decisions[name] = {"gates": g, "decision": "eligible" if all(v["pass"] for v in g.values()) else "reject"}

    out = {"split": split, "data_report": han_report, "training_rows": len(train),
           "models": _strip_private(scored), "acceptance": decisions,
           "openphish": "included" if feed is not None else "skipped: local-only snapshot not present"}
    path = RESULTS / f"url_multisource_{split}.json"
    path.write_text(json.dumps(out, indent=2, default=float))

    print(json.dumps(han_report, indent=1))
    for name, r in scored.items():
        for s in sets:
            o = r[s]["overall"]
            print(f"{name:28} {s:9} recall={o['phishing_recall']:.4f} prec={o['phishing_precision']:.4f} "
                  f"fpr={o['legitimate_fpr']:.4f} offtmpl_fpr={r[s]['off_template_legitimate']['fpr']} "
                  f"unseen_recall={r[s]['unseen_domains']['phishing_recall']:.4f}")
        print(f"   shape_guard={r['shape_guard']['status']} {r['shape_guard']['flag_rate']} openphish={r.get('openphish_recall')}")
        print("   hannousse legit FPR by shape:",
              {k: (v['rows'], None if v['fpr'] is None else round(v['fpr'], 4)) for k, v in r['hannousse']['legitimate_fpr_by_shape'].items()})
        print("   urls:", r["diagnostic_urls"])
    for name, d in decisions.items():
        print(f"\n{name}: {d['decision']}")
        for k, v in d["gates"].items():
            print(f"  {'PASS' if v['pass'] else 'FAIL'} {k}: {v['value']}")
    print("wrote", path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

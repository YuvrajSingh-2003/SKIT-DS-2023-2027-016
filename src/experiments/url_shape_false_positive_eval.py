"""Reproduce the URL-shape false positive and evaluate the candidate mitigation.

Offline. Needs the pinned production URL model (gitignored; copy it, see
docs/SYSTEM.md). The OpenPhish snapshot is optional and local-only (licence
review required); it is skipped if absent.

    python -m src.experiments.url_shape_false_positive_eval

Part 1 scores the reported URLs through the real scan route with the registry
mocked as a miss (no RPC, no fetching; URLs are strings only).

Part 2 evaluates the REJECTED candidate "if the URL shape is outside the
model's trained legitimate shape and only the model says phishing, report
UNKNOWN instead of MEDIUM": it counts how many known-phishing URLs would lose
their MEDIUM verdict.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

import pandas as pd

from app.routes import scan as scan_route
from app.schemas.scan import ScanRequest
from app.services import ml_detector
from app.services.security_checker import calculate_risk_level, check_url_security
from src.features.url_lexical import extract_lexical_url_dataframe

REPORTED_URLS = [
    "https://example.com", "https://example.com/", "https://www.example.com",
    "https://www.example.com/", "https://example.org/", "https://www.wikipedia.org",
    "https://wikipedia.org",
]
VALIDATION = Path("data/processed/url_splits/stratified_validation.csv")
OPENPHISH = Path("data/incoming/threat_feeds/openphish-community-20261028T152813Z.txt")
OUTPUT = Path("reports/model_optimization/results/url_shape_false_positive_eval.json")
REGISTRY_MISS = {"available": True, "found": False, "verdict": None, "threat_type": None,
                 "confidence": None, "error": None, "status": "no_match"}


def in_trained_legit_shape(url: str) -> bool:
    parts = urlsplit(url)
    return (parts.scheme == "https" and (parts.hostname or "").startswith("www.")
            and parts.path in ("", "/") and not parts.query and not parts.fragment)


def reported_urls() -> list[dict]:
    rows = []
    for url in REPORTED_URLS:
        served = str(ScanRequest(url=url).url)
        features = extract_lexical_url_dataframe(pd.Series([served])).iloc[0]
        with patch.object(scan_route, "check_blockchain_threat", return_value=REGISTRY_MISS):
            result = scan_route._build_scan_result(served)
        rows.append({
            "input": url, "served": served, "ml_probability": round(result["ml_probability"], 4),
            "ml_label": result["ml_label"], "risk_level": result["risk_level"],
            "heuristic_findings": check_url_security(served)["findings"],
            "shape_note": any("unvalidated" in f for f in result["findings"]),
            "NoOfSubDomain": int(features["NoOfSubDomain"]), "URLLength": int(features["URLLength"]),
        })
    return rows


def candidate_impact(urls: list[str], model) -> dict:
    probabilities = model.predict_proba(extract_lexical_url_dataframe(pd.Series(urls)))[:, 1]
    before, after = Counter(), Counter()
    for url, p in zip(urls, probabilities):
        base = calculate_risk_level(check_url_security(url)["findings"])
        verdict = "MEDIUM" if (p >= 0.5 and base == "SAFE") else base
        before[verdict] += 1
        if p >= 0.5 and base == "SAFE" and not in_trained_legit_shape(url):
            verdict = "UNKNOWN"
        after[verdict] += 1
    moved = after["UNKNOWN"] - before["UNKNOWN"]
    return {"rows": len(urls), "before": dict(before), "after": dict(after),
            "medium_to_unknown": moved, "medium_to_unknown_rate": moved / len(urls)}


def main() -> None:
    model, _ = ml_detector._load_model()
    out = {"model_sha256": ml_detector.MODEL_SHA256, "reported_urls": reported_urls(), "candidate": {}}
    frame = pd.read_csv(VALIDATION, usecols=["URL", "label"])
    sets = {"validation_phishing": frame.loc[frame.label == 0, "URL"].astype(str).tolist(),
            "validation_legitimate": frame.loc[frame.label == 1, "URL"].astype(str).tolist()}
    if OPENPHISH.is_file():
        sets["openphish_20261028"] = [l.strip() for l in OPENPHISH.read_text().splitlines() if l.strip()]
    else:
        out["candidate"]["openphish_20261028"] = "skipped: local-only snapshot not present"
    for name, urls in sets.items():
        out["candidate"][name] = candidate_impact(urls, model)

    for row in out["reported_urls"]:
        print(f"{row['input']:28} p={row['ml_probability']:<7} {row['ml_label']:10} "
              f"{row['risk_level']:7} subdomains={row['NoOfSubDomain']} note={row['shape_note']}")
    for name, result in out["candidate"].items():
        print(name, result if isinstance(result, str) else
              f"MEDIUM->UNKNOWN {result['medium_to_unknown']}/{result['rows']} "
              f"({result['medium_to_unknown_rate']:.1%})")
    OUTPUT.write_text(json.dumps(out, indent=2))
    print("wrote", OUTPUT)


if __name__ == "__main__":
    main()

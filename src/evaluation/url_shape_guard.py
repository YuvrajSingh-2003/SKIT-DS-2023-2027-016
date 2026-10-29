"""URL-shape regression guard.

Takes a fixed, seeded sample of *legitimate* validation URLs, applies controlled
shape transformations (drop "www.", downgrade the scheme to http, append a
realistic path, append a realistic query string) and measures how often a URL
model flags the transformed URLs as phishing.

This is a controlled stress test of shape dependence. The transformed URLs are
synthetic, so the rates are NOT real-world false-positive estimates.

Ceilings and the per-model exemption live in configs/url_shape_guard.json.
tests/test_url_shape_guard.py enforces them.

    python -m src.evaluation.url_shape_guard                 # production model
    python -m src.evaluation.url_shape_guard --candidate models/candidates/url/c2_xgb_host
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit, urlunsplit

import numpy as np
import pandas as pd

from src.features.url_lexical import extract_lexical_url_dataframe

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = PROJECT_ROOT / "configs" / "url_shape_guard.json"
REPORT_DIRECTORY = PROJECT_ROOT / "reports" / "url_shape_guard"

# Realistic, keyword-neutral suffixes (no "login", "verify", ... so the
# guard measures shape dependence, not keyword sensitivity).
PATHS = ["/about", "/contact", "/products/item-1042", "/blog/2024/05/spring-recipes",
         "/en-us/support", "/news/world", "/careers", "/docs/getting-started"]
QUERIES = ["?q=news", "?page=2", "?utm_source=newsletter", "?lang=en",
           "?ref=homepage&id=381", "?category=books"]

Scorer = Callable[[pd.Series], np.ndarray]  # URLs -> phishing probabilities


def _pick(options: list[str], url: str) -> str:
    digest = hashlib.sha256(url.encode("utf-8")).digest()
    return options[digest[0] % len(options)]


def _drop_www(url: str) -> str | None:
    parts = urlsplit(url)
    if not parts.netloc.lower().startswith("www."):
        return None  # not applicable
    return urlunsplit(parts._replace(netloc=parts.netloc[4:]))


def _http_scheme(url: str) -> str | None:
    parts = urlsplit(url)
    if parts.scheme.lower() != "https":
        return None
    return urlunsplit(parts._replace(scheme="http"))


def _add_path(url: str) -> str | None:
    parts = urlsplit(url)
    if parts.path.strip("/") or parts.query:
        return None
    return urlunsplit(parts._replace(path=_pick(PATHS, url)))


def _add_query(url: str) -> str | None:
    parts = urlsplit(url)
    if parts.query:
        return None
    return urlunsplit(parts._replace(path=parts.path or "/", query=_pick(QUERIES, url)[1:]))


TRANSFORMS: dict[str, Callable[[str], str | None]] = {
    "as_is": lambda url: url,
    "drop_www": _drop_www,
    "http_scheme": _http_scheme,
    "add_path": _add_path,
    "add_query": _add_query,
}


def load_config(path: Path = CONFIG_PATH) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def sample_legitimate(config: dict) -> pd.Series:
    """Seeded sample of legitimate (source label 1) validation URLs."""
    path = PROJECT_ROOT / config["source_split"]
    frame = pd.read_csv(path, usecols=["URL", "label"])
    legit = frame.loc[frame["label"] == 1, "URL"].astype(str)
    sample = legit.sample(n=min(config["sample_size"], len(legit)), random_state=config["seed"])
    return sample.sort_index().reset_index(drop=True)


def build_cases(urls: pd.Series) -> pd.DataFrame:
    rows = []
    for url in urls:
        for name, transform in TRANSFORMS.items():
            transformed = transform(url)
            if transformed is not None:
                rows.append({"original_url": url, "transform": name, "transformed_url": transformed})
    return pd.DataFrame(rows)


def run_guard(scorer: Scorer, threshold: float, urls: pd.Series) -> tuple[pd.DataFrame, dict]:
    cases = build_cases(urls)
    cases["phishing_probability"] = scorer(cases["transformed_url"])
    cases["predicted_label"] = np.where(cases["phishing_probability"] >= threshold, "phishing", "legitimate")
    flagged = cases["predicted_label"] == "phishing"
    rates = {name: float(flagged[cases["transform"] == name].mean()) for name in TRANSFORMS
             if (cases["transform"] == name).any()}
    counts = cases["transform"].value_counts().to_dict()
    return cases, {"threshold": threshold, "flag_rate": rates, "cases_per_transform": counts}


def check(summary: dict, config: dict, model_sha256: str | None) -> dict:
    """Apply the configured criteria. Returns {"status", "violations", ...}.

    status: "pass" | "fail" | "known_failing" (exempt artifact within its ratchet)
    """
    rates = summary["flag_rate"]
    target_violations = [
        f"{name}: {rate:.4f} > max {config['max_flag_rate'][name]:.4f}"
        for name, rate in rates.items() if rate > config["max_flag_rate"][name]
    ]
    base = rates.get("as_is", 0.0)
    target_violations += [
        f"{name}: gap {rate - base:+.4f} over as_is > {config['max_gap_over_as_is']:.4f}"
        for name, rate in rates.items() if name != "as_is" and rate - base > config["max_gap_over_as_is"]
    ]

    exemption = config.get("known_failing_models", {}).get(model_sha256 or "")
    if exemption is None:
        return {"status": "fail" if target_violations else "pass", "violations": target_violations}

    tolerance = exemption["ratchet_tolerance"]
    ratchet_violations = [
        f"{name}: {rates[name]:.4f} > recorded {recorded:.4f} + {tolerance:.2f}"
        for name, recorded in exemption["recorded_flag_rate"].items()
        if name in rates and rates[name] > recorded + tolerance
    ]
    if ratchet_violations:
        return {"status": "fail", "violations": ratchet_violations, "target_violations": target_violations}
    if not target_violations:
        return {"status": "fail", "violations": [
            "exempt model now meets the target ceilings; remove its known_failing_models entry"]}
    return {"status": "known_failing", "violations": [], "target_violations": target_violations}


def production_scorer() -> tuple[Scorer, float, str]:
    """Scorer for the deployed model, loaded through the serving code's checksum gate."""
    from app.services import ml_detector

    model, metadata = ml_detector._load_model()
    scorer = lambda urls: model.predict_proba(extract_lexical_url_dataframe(urls.astype(str)))[:, 1]
    return scorer, float(metadata["phishing_threshold"]), ml_detector.MODEL_SHA256


def candidate_scorer(directory: Path) -> tuple[Scorer, float, str]:
    """Scorer for an experiment candidate (models/candidates/url/<name>)."""
    import joblib
    from src.experiments.url_optimization import normalize

    config = json.loads((directory / "config.json").read_text())
    artifact = directory / "model.joblib"
    sha = hashlib.sha256(artifact.read_bytes()).hexdigest()
    if sha != config["model_sha256"]:
        raise RuntimeError(f"{artifact} does not match the checksum in its config.json")
    model = joblib.load(artifact)
    mode = config["normalization"]
    scorer = lambda urls: model.predict_proba(
        extract_lexical_url_dataframe(urls.astype(str).map(lambda u: normalize(u, mode))))[:, 1]
    return scorer, float(config["threshold"]), sha


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, help="candidate directory instead of production")
    parser.add_argument("--threshold", type=float, help="override the model's decision threshold")
    args = parser.parse_args(argv)

    config = load_config()
    scorer, threshold, sha = candidate_scorer(args.candidate) if args.candidate else production_scorer()
    threshold = args.threshold if args.threshold is not None else threshold
    cases, summary = run_guard(scorer, threshold, sample_legitimate(config))
    result = check(summary, config, sha)

    REPORT_DIRECTORY.mkdir(parents=True, exist_ok=True)
    name = f"{'production' if not args.candidate else args.candidate.name}_thr{threshold:.4f}"
    cases.to_csv(REPORT_DIRECTORY / f"{name}_cases.csv", index=False)
    report = {"generated_at": datetime.now(timezone.utc).isoformat(), "model_sha256": sha,
              "nature": "controlled stress test on transformed legitimate validation URLs; not a real-world FPR",
              "config_sha256": hashlib.sha256(CONFIG_PATH.read_bytes()).hexdigest(),
              **summary, **result}
    (REPORT_DIRECTORY / f"{name}_summary.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    return 0 if result["status"] in {"pass", "known_failing"} else 1


if __name__ == "__main__":
    raise SystemExit(main())

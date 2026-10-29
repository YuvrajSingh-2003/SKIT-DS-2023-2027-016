"""URL-shape regression guard (controlled stress test, not a real-world FPR).

The unit tests run everywhere. The model test needs the gitignored model
artifact: it is skipped when the artifact is absent, unless
CHAINSHIELD_REQUIRE_MODELS=1, in which case a missing artifact fails.
"""

import os

import numpy as np
import pandas as pd
import pytest

from app.services import ml_detector
from src.evaluation import url_shape_guard as guard

CONFIG = guard.load_config()
URLS = pd.Series(["https://www.example.com", "https://www.wikipedia.org"])


def test_transforms_produce_expected_shapes():
    cases = guard.build_cases(pd.Series(["https://www.example.com"]))
    by_name = dict(zip(cases["transform"], cases["transformed_url"]))

    assert by_name["as_is"] == "https://www.example.com"
    assert by_name["drop_www"] == "https://example.com"
    assert by_name["http_scheme"] == "http://www.example.com"
    assert by_name["add_path"].startswith("https://www.example.com/") and "?" not in by_name["add_path"]
    assert by_name["add_query"].startswith("https://www.example.com/?")
    assert set(cases["original_url"]) == {"https://www.example.com"}


def test_transforms_skip_inapplicable_urls():
    assert guard._drop_www("https://example.com") is None
    assert guard._http_scheme("http://www.example.com") is None
    assert guard._add_path("https://www.example.com/a") is None
    assert guard._add_query("https://www.example.com/?a=1") is None


def test_transforms_are_deterministic():
    first = guard.build_cases(URLS)
    assert first.equals(guard.build_cases(URLS))


def test_suffixes_avoid_suspicious_keywords():
    from src.data.url_features import SUSPICIOUS_KEYWORDS

    for suffix in guard.PATHS + guard.QUERIES:
        assert not any(word in suffix.lower() for word in SUSPICIOUS_KEYWORDS), suffix


def _template_scorer(urls):
    return np.array([0.0 if u.startswith("https://www.") and u.count("/") == 2 else 1.0 for u in urls])


def test_shape_dependent_model_fails_the_criterion():
    _, summary = guard.run_guard(_template_scorer, 0.5, URLS)
    assert guard.check(summary, CONFIG, model_sha256="not-exempt")["status"] == "fail"


def test_shape_invariant_model_passes_the_criterion():
    _, summary = guard.run_guard(lambda urls: np.zeros(len(urls)), 0.5, URLS)
    assert guard.check(summary, CONFIG, model_sha256="not-exempt")["status"] == "pass"


def test_gap_limit_catches_shape_dependence_below_the_ceiling():
    config = {**CONFIG, "max_flag_rate": {k: 1.0 for k in CONFIG["max_flag_rate"]}}
    summary = {"flag_rate": {"as_is": 0.0, "drop_www": 0.04}}
    assert guard.check(summary, config, None)["status"] == "fail"


def test_exemption_is_bound_to_one_artifact_and_ratchets():
    sha = next(iter(CONFIG["known_failing_models"]))
    recorded = CONFIG["known_failing_models"][sha]["recorded_flag_rate"]

    assert guard.check({"flag_rate": dict(recorded)}, CONFIG, sha)["status"] == "known_failing"
    assert guard.check({"flag_rate": dict(recorded)}, CONFIG, "retrained-artifact")["status"] == "fail"

    worse = {**recorded, "as_is": recorded["as_is"] + 0.05}
    assert guard.check({"flag_rate": worse}, CONFIG, sha)["status"] == "fail"

    fixed = {name: 0.0 for name in recorded}
    assert guard.check({"flag_rate": fixed}, CONFIG, sha)["status"] == "fail"  # stale exemption


def test_config_ceilings_cover_every_transform():
    assert set(CONFIG["max_flag_rate"]) == set(guard.TRANSFORMS)
    assert all(0.0 < value < 1.0 for value in CONFIG["max_flag_rate"].values())


def test_deployed_url_model_meets_shape_guard():
    if not ml_detector.MODEL_PATH.is_file():
        if os.environ.get("CHAINSHIELD_REQUIRE_MODELS") == "1":
            pytest.fail("URL model artifact missing and CHAINSHIELD_REQUIRE_MODELS=1")
        pytest.skip("URL model artifact not present (gitignored); set CHAINSHIELD_REQUIRE_MODELS=1 to require it")

    scorer, threshold, sha = guard.production_scorer()
    cases, summary = guard.run_guard(scorer, threshold, guard.sample_legitimate(CONFIG))

    # The batch scorer must match the serving path exactly.
    for url in cases["transformed_url"].iloc[::997]:
        served = ml_detector.predict_phishing(url)["probability"]
        assert served == pytest.approx(float(scorer(pd.Series([url]))[0]), abs=1e-12)

    result = guard.check(summary, CONFIG, sha)
    assert result["status"] != "fail", result["violations"]

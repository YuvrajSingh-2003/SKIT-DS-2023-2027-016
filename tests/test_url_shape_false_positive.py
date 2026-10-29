"""Regression tests for the URL-shape false positive (e.g. https://example.com/).

Root cause (docs/url_shape_guard.md, "Observed false positive"): the production
URL model's legitimate training class contains only https://www.<host> URLs with
no path, so NoOfSubDomain == 0 never occurs for a legitimate URL. The pipeline
itself is correct; these tests pin that down and cover the scan-route behaviour:
the verdict is unchanged, and an explicit note explains why the flag is weak.

All tests run offline. Route tests use a stubbed model and registry; the
real-model tests skip if the pinned artifact is absent.
"""

import json
from unittest.mock import patch

import pandas as pd
import pytest

from app.routes import scan as scan_route
from app.routes.scan import scan_url
from app.schemas.scan import ScanRequest
from app.services import ml_detector
from src.features.url_lexical import LEXICAL_URL_FEATURES, extract_lexical_url_dataframe

REGISTRY_MISS = {"available": True, "found": False, "verdict": None, "threat_type": None,
                 "confidence": None, "error": None, "status": "no_match"}
REGISTRY_THREAT = {**REGISTRY_MISS, "found": True, "verdict": 1, "status": "match_threat"}
REGISTRY_DOWN = {**REGISTRY_MISS, "available": False, "status": "unavailable", "error": "down"}
ML_PHISHING = {"available": True, "probability": 0.9998, "label": "phishing",
               "model_name": "xgboost", "error": None}
ML_LEGITIMATE = {**ML_PHISHING, "probability": 0.012, "label": "legitimate"}
ML_DOWN = {"available": False, "probability": None, "label": None, "model_name": None,
           "error": "URL model artifact not found"}


def _served(url: str) -> str:
    """The exact string the route receives (pydantic HttpUrl normalization)."""
    return str(ScanRequest(url=url).url)


def _scan(url, registry, ml):
    with patch("app.routes.scan.check_blockchain_threat", return_value=registry), \
         patch("app.routes.scan.predict_phishing", return_value=ml) as model, \
         patch("app.routes.scan.save_scan"):
        return scan_url(ScanRequest(url=url), db=None), model


def _shape_notes(findings):
    return [f for f in findings if "unvalidated" in f]


# ── the pipeline is not the cause ─────────────────────────────────────

@pytest.mark.parametrize("bare, slashed", [
    ("https://example.com", "https://example.com/"),
    ("https://www.example.com", "https://www.example.com/"),
])
def test_trailing_slash_does_not_change_features(bare, slashed):
    assert _served(bare) == _served(slashed) == slashed
    a = extract_lexical_url_dataframe(pd.Series([bare]))
    b = extract_lexical_url_dataframe(pd.Series([slashed]))
    assert a.equals(b)


def test_www_changes_only_host_derived_features():
    plain = extract_lexical_url_dataframe(pd.Series(["https://example.com/"])).iloc[0]
    www = extract_lexical_url_dataframe(pd.Series(["https://www.example.com/"])).iloc[0]
    differing = {name for name in LEXICAL_URL_FEATURES if plain[name] != www[name]}
    assert differing <= {"URLLength", "DomainLength", "NoOfSubDomain", "NoOfLettersInURL",
                         "LetterRatioInURL", "NoOfOtherSpecialCharsInURL", "SpacialCharRatioInURL"}
    assert (plain["NoOfSubDomain"], www["NoOfSubDomain"]) == (0, 1)


def test_model_with_unexpected_classes_is_refused(tmp_path, monkeypatch):
    class WrongClasses:
        classes_ = ["legitimate", "phishing"]

        def predict_proba(self, _):
            raise AssertionError("must not be called")

    (tmp_path / "model.joblib").write_bytes(b"stub")
    (tmp_path / "metadata.json").write_text(json.dumps({
        "model_name": "stub", "feature_names": LEXICAL_URL_FEATURES,
        "phishing_threshold": 0.5, "model_sha256": ml_detector.MODEL_SHA256}))
    monkeypatch.setattr(ml_detector, "MODEL_PATH", tmp_path / "model.joblib")
    monkeypatch.setattr(ml_detector, "METADATA_PATH", tmp_path / "metadata.json")
    monkeypatch.setattr(ml_detector, "_sha256", lambda _: ml_detector.MODEL_SHA256)
    monkeypatch.setattr(ml_detector.joblib, "load", lambda _: WrongClasses())
    monkeypatch.setattr(ml_detector, "_loaded", None)

    result = ml_detector.predict_phishing("https://example.com/")

    assert result["available"] is False and result["label"] is None
    assert "classes are not [0, 1]" in result["error"]


# ── scan route: verdict unchanged, explanation added ──────────────────

@pytest.mark.parametrize("url, reasons", [
    ("https://example.com", ["no 'www.' prefix"]),
    ("https://example.com/", ["no 'www.' prefix"]),
    ("https://example.org/", ["no 'www.' prefix"]),
    ("https://shop.example.com/", ["no 'www.' prefix"]),
])
def test_bare_or_non_www_host_keeps_medium_and_explains(url, reasons):
    response, _ = _scan(url, REGISTRY_MISS, ML_PHISHING)

    assert response["risk_level"] == "MEDIUM"                      # verdict unchanged
    assert response["decision_source"] == "ml"
    assert response["ml_label"] == "phishing"                      # model output reported as-is
    assert scan_route.ML_PHISHING_ADVISORY in response["findings"]
    notes = _shape_notes(response["findings"])
    assert len(notes) == 1 and all(reason in notes[0] for reason in reasons)
    assert response["blockchain_status"] == "no_match"


def test_www_host_has_no_shape_note():
    response, _ = _scan("https://www.example.com/", REGISTRY_MISS, ML_LEGITIMATE)
    assert response["risk_level"] == "SAFE"
    assert _shape_notes(response["findings"]) == []


def test_www_host_flagged_by_model_has_no_shape_note():
    # Inside the trained shape the flag is not explained away.
    response, _ = _scan("https://www.example.com/", REGISTRY_MISS, ML_PHISHING)
    assert response["risk_level"] == "MEDIUM"
    assert _shape_notes(response["findings"]) == []


def test_http_scheme_is_named_and_heuristics_still_count():
    response, _ = _scan("http://example.com/", REGISTRY_MISS, ML_PHISHING)
    assert response["risk_level"] == "MEDIUM"
    assert "URL is not using HTTPS" in response["findings"]
    note = _shape_notes(response["findings"])[0]
    assert "no 'www.' prefix" in note and "scheme is not HTTPS" in note


def test_non_root_path_gets_both_notes():
    response, _ = _scan("https://example.com/docs/intro", REGISTRY_MISS, ML_PHISHING)
    assert scan_route.PATH_OR_QUERY_NOTE in response["findings"]
    assert len(_shape_notes(response["findings"])) == 1   # host note; path has its own note


def test_high_risk_detection_is_preserved():
    response, _ = _scan("http://192.168.1.1/secure/login.php?acct=1", REGISTRY_MISS, ML_PHISHING)
    assert response["risk_level"] == "HIGH"


def test_model_legitimate_off_template_has_no_shape_note():
    response, _ = _scan("https://example.com/", REGISTRY_MISS, ML_LEGITIMATE)
    assert response["risk_level"] == "SAFE"
    assert _shape_notes(response["findings"]) == []


def test_registry_threat_skips_model_and_note():
    response, model = _scan("https://example.com/", REGISTRY_THREAT, ML_LEGITIMATE)
    assert response["risk_level"] == "HIGH" and response["decision_source"] == "blockchain"
    model.assert_not_called()
    assert _shape_notes(response["findings"]) == []


def test_registry_unavailable_keeps_medium_with_note():
    response, _ = _scan("https://example.com/", REGISTRY_DOWN, ML_PHISHING)
    assert response["risk_level"] == "MEDIUM"
    assert len(_shape_notes(response["findings"])) == 1


def test_model_unavailable_is_unknown_without_note():
    response, _ = _scan("https://example.com/", REGISTRY_MISS, ML_DOWN)
    assert response["risk_level"] == "UNKNOWN"
    assert _shape_notes(response["findings"]) == []


# ── real pinned artifact: characterize the known shortcut ─────────────

def _real_model_or_skip():
    if not ml_detector.MODEL_PATH.is_file():
        pytest.skip("URL model artifact not present (gitignored); see LOCAL_ARTIFACTS / docs/SYSTEM.md")
    model, _ = ml_detector._load_model()
    return model


def test_real_model_class_order_and_feature_order():
    model = _real_model_or_skip()
    assert [int(c) for c in model.classes_] == [0, 1]
    _, metadata = ml_detector._load_model()
    assert metadata["feature_names"] == LEXICAL_URL_FEATURES


def test_real_model_known_shortcut_is_characterized():
    """Documents the CURRENT pinned model's behaviour. If a retrained model fixes
    the shortcut, update this test together with configs/url_shape_guard.json."""
    model = _real_model_or_skip()
    if ml_detector.MODEL_SHA256 != "2f2e1d492ec3bc96891df3c08d3e80ff158021f6321160e3d55a52707f2d2adc":
        pytest.skip("characterization is specific to the 2026-10-28 production model")

    def score(url):
        return ml_detector.predict_phishing(_served(url))["probability"]

    for bare, www in [("https://example.com", "https://www.example.com"),
                      ("https://example.org/", "https://www.example.org/"),
                      ("https://wikipedia.org", "https://www.wikipedia.org")]:
        assert score(www) < 0.5 <= score(bare)

    # The flip is driven by NoOfSubDomain alone.
    features = extract_lexical_url_dataframe(pd.Series(["https://example.com/"]))
    assert model.predict_proba(features)[0, 1] >= 0.5
    features["NoOfSubDomain"] = 1
    assert model.predict_proba(features)[0, 1] < 0.5


# ── training/inference parity and held-out regression ─────────────────

def test_training_and_serving_use_the_same_feature_extractor():
    from src.training import train_url_inference

    assert train_url_inference.extract_lexical_url_dataframe is ml_detector.extract_lexical_url_dataframe
    assert train_url_inference.LEXICAL_URL_FEATURES is ml_detector.LEXICAL_URL_FEATURES


@pytest.mark.parametrize("url, expected", [
    ("https://www.example.com/", "https://example.com/"),
    ("https://example.com/", "https://example.com/"),
    ("http://WWW.Example.com/a?b=1", "http://Example.com/a?b=1"),
    ("https://www2.example.com/", "https://www2.example.com/"),
    ("https://shop.www.example.com/", "https://shop.www.example.com/"),
])
def test_www_neutral_candidate_normalization(url, expected):
    from src.experiments.url_www_neutral_candidate import strip_www

    assert strip_www(url) == expected
    assert strip_www(strip_www(url)) == strip_www(url)


def test_real_model_reproduces_recorded_validation_confusion():
    """Held-out regression: the pinned model must still produce exactly the
    validation confusion matrix recorded in its metadata."""
    model = _real_model_or_skip()
    _, metadata = ml_detector._load_model()
    split = ml_detector.PROJECT_ROOT / "data/processed/url_splits/stratified_validation.csv"
    frame = pd.read_csv(split, usecols=["URL", "label"])
    probabilities = model.predict_proba(extract_lexical_url_dataframe(frame["URL"].astype(str)))[:, 1]
    predicted = probabilities >= metadata["phishing_threshold"]
    phishing = (frame["label"] == 0).to_numpy()
    recorded = metadata["validation_results"][metadata["model_name"]]["confusion_matrix"]

    assert int((~phishing & ~predicted).sum()) == recorded["true_legitimate_pred_legitimate"]
    assert int((~phishing & predicted).sum()) == recorded["true_legitimate_pred_phishing"]
    assert int((phishing & ~predicted).sum()) == recorded["true_phishing_pred_legitimate"]
    assert int((phishing & predicted).sum()) == recorded["true_phishing_pred_phishing"]


def test_acceptance_criteria_are_declared_and_require_real_data():
    criteria = json.loads((ml_detector.PROJECT_ROOT / "configs/url_candidate_acceptance.json")
                          .read_text())["criteria"]
    assert criteria["phishing_recall_drop_max_pp"] <= 1.0
    assert "REQUIRED" in criteria["real_off_template_legitimate_eval"]

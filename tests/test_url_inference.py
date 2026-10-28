"""Tests for lexical URL features and the URL inference model service."""

from unittest.mock import patch

import pytest

from app.services import ml_detector
from src.features.url_lexical import (
    LEXICAL_URL_FEATURES,
    extract_lexical_url_features,
)


# ── Lexical features ──────────────────────────────────────────────────

def test_feature_vector_has_every_declared_feature():
    features = extract_lexical_url_features("https://example.com/a?b=c")

    assert list(features) == LEXICAL_URL_FEATURES


def test_https_and_subdomain_counts():
    features = extract_lexical_url_features("https://a.b.example.com/")

    assert features["IsHTTPS"] == 1
    assert features["NoOfSubDomain"] == 2


def test_ip_host_is_detected():
    features = extract_lexical_url_features("http://192.168.1.1/login")

    assert features["IsDomainIP"] == 1
    assert features["IsHTTPS"] == 0
    assert features["HasSuspiciousKeyword"] == 1


def test_url_shortener_is_detected():
    assert extract_lexical_url_features("https://bit.ly/abc")["IsURLShortener"] == 1
    assert extract_lexical_url_features("https://example.com")["IsURLShortener"] == 0


def test_scheme_less_input_is_parsed_as_host():
    features = extract_lexical_url_features("example.com/path")

    assert features["URLDepth"] == 1
    assert features["DomainLength"] == len("example.com")


def test_features_are_deterministic():
    url = "https://secure-login.example.net/verify?x=1&y=2"

    assert extract_lexical_url_features(url) == extract_lexical_url_features(url)


# ── Inference service ─────────────────────────────────────────────────

def test_missing_artifact_is_reported_not_safe(tmp_path, monkeypatch):
    monkeypatch.setattr(ml_detector, "MODEL_PATH", tmp_path / "model.joblib")
    monkeypatch.setattr(ml_detector, "METADATA_PATH", tmp_path / "metadata.json")
    monkeypatch.setattr(ml_detector, "_loaded", None)

    result = ml_detector.predict_phishing("https://example.com")

    assert result["available"] is False
    assert result["label"] is None
    assert "artifact not found" in result["error"]


def test_inference_exception_is_reported_not_safe():
    class BrokenModel:
        def predict_proba(self, _):
            raise ValueError("boom")

    metadata = {
        "model_name": "broken",
        "feature_names": LEXICAL_URL_FEATURES,
        "phishing_threshold": 0.5,
    }

    with patch.object(
        ml_detector, "_load_model", return_value=(BrokenModel(), metadata)
    ):
        result = ml_detector.predict_phishing("https://example.com")

    assert result["available"] is False
    assert result["label"] is None
    assert result["error"] == "URL model inference failed"


def test_feature_mismatch_marks_model_unavailable(tmp_path, monkeypatch):
    import json

    model_path = tmp_path / "model.joblib"
    metadata_path = tmp_path / "metadata.json"
    model_path.write_bytes(b"not used")
    metadata_path.write_text(json.dumps({"feature_names": ["Wrong"]}))

    monkeypatch.setattr(ml_detector, "MODEL_PATH", model_path)
    monkeypatch.setattr(ml_detector, "METADATA_PATH", metadata_path)
    monkeypatch.setattr(ml_detector, "_loaded", None)

    result = ml_detector.predict_phishing("https://example.com")

    assert result["available"] is False
    assert "feature list does not match" in result["error"]


@pytest.mark.skipif(
    not ml_detector.MODEL_PATH.is_file(),
    reason="URL model artifact not trained; run src.training.train_url_inference",
)
def test_trained_artifact_predicts_probabilities_in_range():
    phishing = ml_detector.predict_phishing(
        "http://192.168.1.1/secure/login.php?acct=1"
    )
    benign = ml_detector.predict_phishing("https://example.com")

    for result in (phishing, benign):
        assert result["available"] is True
        assert 0.0 <= result["probability"] <= 1.0
        assert result["label"] in {"phishing", "legitimate"}

    assert phishing["label"] == "phishing"



# ── 2026-10-28: pinned URL model checksum ─────────────────────────────

def test_pinned_checksum_matches_the_real_artifact():
    if not ml_detector.MODEL_PATH.is_file():
        pytest.skip("URL model artifact not present")
    assert ml_detector._sha256(ml_detector.MODEL_PATH) == ml_detector.MODEL_SHA256


def test_altered_model_file_is_refused_before_loading(tmp_path, monkeypatch):
    import json
    import shutil

    if not ml_detector.METADATA_PATH.is_file():
        pytest.skip("URL model metadata not present")
    shutil.copy(ml_detector.METADATA_PATH, tmp_path / "metadata.json")
    (tmp_path / "model.joblib").write_bytes(b"not the pinned model")
    loads = []
    monkeypatch.setattr(ml_detector.joblib, "load", lambda *a: loads.append(a))
    monkeypatch.setattr(ml_detector, "MODEL_PATH", tmp_path / "model.joblib")
    monkeypatch.setattr(ml_detector, "METADATA_PATH", tmp_path / "metadata.json")
    monkeypatch.setattr(ml_detector, "_loaded", None)

    result = ml_detector.predict_phishing("https://example.com")

    assert result["available"] is False and result["label"] is None
    assert "pinned checksum" in result["error"]
    assert loads == []          # never deserialized


def test_metadata_for_a_different_model_is_refused(tmp_path, monkeypatch):
    import json
    import shutil

    if not ml_detector.MODEL_PATH.is_file():
        pytest.skip("URL model artifact not present")
    shutil.copy(ml_detector.MODEL_PATH, tmp_path / "model.joblib")
    metadata = json.loads(ml_detector.METADATA_PATH.read_text())
    metadata["model_sha256"] = "0" * 64
    (tmp_path / "metadata.json").write_text(json.dumps(metadata))
    monkeypatch.setattr(ml_detector, "MODEL_PATH", tmp_path / "model.joblib")
    monkeypatch.setattr(ml_detector, "METADATA_PATH", tmp_path / "metadata.json")
    monkeypatch.setattr(ml_detector, "_loaded", None)

    result = ml_detector.predict_phishing("https://example.com")

    assert result["available"] is False
    assert "metadata does not match" in result["error"]


def test_valid_pinned_model_loads_and_predicts(monkeypatch):
    if not ml_detector.MODEL_PATH.is_file():
        pytest.skip("URL model artifact not present")
    monkeypatch.setattr(ml_detector, "_loaded", None)

    result = ml_detector.predict_phishing("https://example.com")

    assert result["available"] is True and result["label"] in {"phishing", "legitimate"}

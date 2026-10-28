from unittest.mock import patch

from app.routes.scan import scan_url
from app.schemas.scan import ScanRequest


BLOCKCHAIN_MISS = {
    "available": True,
    "found": False,
    "verdict": None,
    "threat_type": None,
    "confidence": None,
    "error": None,
}

BLOCKCHAIN_UNAVAILABLE = {
    "available": False,
    "found": False,
    "verdict": None,
    "threat_type": None,
    "confidence": None,
    "error": "Could not connect to Sepolia RPC",
}

ML_PHISHING = {
    "available": True,
    "probability": 0.93,
    "label": "phishing",
    "model_name": "xgboost",
    "error": None,
}

ML_LEGITIMATE = {
    "available": True,
    "probability": 0.02,
    "label": "legitimate",
    "model_name": "xgboost",
    "error": None,
}

ML_UNAVAILABLE = {
    "available": False,
    "probability": None,
    "label": None,
    "model_name": None,
    "error": "URL model artifact not found",
}


def _scan(url, blockchain_result, ml_result):
    """Run the scan route with the blockchain and ML components stubbed."""
    with patch(
        "app.routes.scan.check_blockchain_threat",
        return_value=blockchain_result,
    ) as mock_blockchain, patch(
        "app.routes.scan.predict_phishing",
        return_value=ml_result,
    ) as mock_ml, patch("app.routes.scan.save_scan") as mock_save:
        response = scan_url(ScanRequest(url=url), db=None)

    return response, mock_blockchain, mock_ml, mock_save


def test_blockchain_threat_returns_threat_and_skips_model():
    blockchain_result = {
        "available": True,
        "found": True,
        "verdict": 1,
        "threat_type": 1,
        "confidence": 90,
        "error": None,
    }

    response, _, mock_ml, mock_save = _scan(
        "https://example.com", blockchain_result, ML_LEGITIMATE
    )

    assert response["decision_source"] == "blockchain"
    assert response["blockchain_available"] is True
    assert response["blockchain_found"] is True
    assert any(
        "Blockchain registry identifies this URL as a threat" in finding
        for finding in response["findings"]
    )
    assert response["risk_level"] == "HIGH"
    assert response["ml_available"] is False
    mock_ml.assert_not_called()
    mock_save.assert_called_once()


def test_blockchain_miss_calls_ml_fallback():
    response, _, mock_ml, mock_save = _scan(
        "https://example.com/account", BLOCKCHAIN_MISS, ML_PHISHING
    )

    mock_ml.assert_called_once_with("https://example.com/account")
    assert response["decision_source"] == "ml"
    assert response["blockchain_found"] is False
    assert response["ml_available"] is True
    assert response["ml_label"] == "phishing"
    assert response["ml_probability"] == 0.93
    # The URL model is advisory (2026-10-28): it raises risk to MEDIUM, never HIGH alone.
    assert response["risk_level"] == "MEDIUM"
    assert response["ml_status"] == "ok"
    mock_save.assert_called_once()


def test_blockchain_miss_with_legitimate_prediction_is_not_forced_high():
    response, _, mock_ml, _ = _scan(
        "https://example.com", BLOCKCHAIN_MISS, ML_LEGITIMATE
    )

    mock_ml.assert_called_once()
    assert response["decision_source"] == "ml"
    assert response["ml_label"] == "legitimate"
    assert response["risk_level"] == "SAFE"


def test_blockchain_miss_is_not_reported_as_safety_verdict():
    # A registry miss alone must not produce SAFE: the scan's verdict still
    # comes from the model, and the response must say the registry found nothing.
    response, _, _, _ = _scan(
        "https://example.com", BLOCKCHAIN_MISS, ML_LEGITIMATE
    )

    assert response["blockchain_available"] is True
    assert response["blockchain_found"] is False


def test_blockchain_unavailable_falls_back_to_ml_and_says_so():
    response, _, mock_ml, mock_save = _scan(
        "https://example.com", BLOCKCHAIN_UNAVAILABLE, ML_PHISHING
    )

    mock_ml.assert_called_once()
    assert response["status"] == "processed"
    assert response["blockchain_available"] is False
    assert response["blockchain_found"] is False
    assert response["blockchain_error"] == "Could not connect to Sepolia RPC"
    assert "blockchain registry unavailable" in response["message"]
    assert response["decision_source"] == "ml"
    mock_save.assert_called_once()


def test_unexpected_blockchain_exception_still_runs_ml():
    with patch(
        "app.routes.scan.check_blockchain_threat",
        side_effect=RuntimeError("Unexpected RPC failure"),
    ), patch(
        "app.routes.scan.predict_phishing", return_value=ML_LEGITIMATE
    ) as mock_ml, patch("app.routes.scan.save_scan"):
        response = scan_url(ScanRequest(url="https://example.com"), db=None)

    mock_ml.assert_called_once()
    assert response["status"] == "processed"
    assert response["blockchain_available"] is False
    assert response["blockchain_found"] is False


def test_model_unavailable_never_reports_safe():
    response, _, _, _ = _scan(
        "https://example.com", BLOCKCHAIN_MISS, ML_UNAVAILABLE
    )

    assert response["decision_source"] == "unavailable"
    assert response["risk_level"] == "UNKNOWN"
    assert response["ml_available"] is False
    assert response["ml_error"] == "URL model artifact not found"
    assert "not a safety verdict" in response["message"]


def test_path_or_query_adds_reliability_note():
    response, _, _, _ = _scan(
        "https://example.com/docs/page?id=1", BLOCKCHAIN_MISS, ML_LEGITIMATE
    )

    assert any(
        "path or query string" in finding for finding in response["findings"]
    )


def test_database_failure_is_reported_not_hidden():
    with patch(
        "app.routes.scan.check_blockchain_threat",
        return_value=BLOCKCHAIN_MISS,
    ), patch(
        "app.routes.scan.predict_phishing", return_value=ML_LEGITIMATE
    ), patch(
        "app.routes.scan.save_scan",
        side_effect=RuntimeError("disk I/O error"),
    ):
        from unittest.mock import MagicMock

        db = MagicMock()
        response = scan_url(ScanRequest(url="https://example.com"), db=db)

    assert response["status"] == "processed"
    assert response["persisted"] is False
    assert "could not be saved" in response["message"]
    db.rollback.assert_called_once()


# ── 2026-10-28: advisory URL model, explicit registry and model status ──

def test_ml_phishing_is_advisory_and_explained():
    response, _, _, _ = _scan("https://example.com", BLOCKCHAIN_MISS, ML_PHISHING)

    assert response["risk_level"] == "MEDIUM"
    assert any("advisory" in f for f in response["findings"])


def test_heuristic_high_risk_is_not_lowered_by_the_advisory_policy():
    # Three or more heuristic findings already give HIGH before the model is consulted.
    response, _, _, _ = _scan("http://192.168.1.1/login/verify/account", BLOCKCHAIN_MISS, ML_PHISHING)

    assert response["risk_level"] == "HIGH"


def test_registry_threat_reports_status_and_model_not_run():
    threat = {**BLOCKCHAIN_MISS, "status": "match_threat", "found": True, "verdict": 1}
    response, _, mock_ml, _ = _scan("https://example.com", threat, ML_LEGITIMATE)

    assert response["blockchain_status"] == "match_threat"
    assert response["ml_status"] == "not_run"
    assert response["risk_level"] == "HIGH"
    mock_ml.assert_not_called()


def test_registered_non_threat_is_not_treated_as_a_threat():
    benign = {**BLOCKCHAIN_MISS, "status": "match_non_threat", "found": True, "verdict": 0}
    response, _, mock_ml, _ = _scan("https://example.com", benign, ML_LEGITIMATE)

    mock_ml.assert_called_once()
    assert response["blockchain_status"] == "match_non_threat"
    assert response["blockchain_found"] is True          # original meaning kept
    assert response["decision_source"] == "ml"
    assert response["risk_level"] != "HIGH"
    assert not any("identifies this URL as a threat" in f for f in response["findings"])


def test_status_fields_for_miss_unavailable_and_model_error():
    miss, _, _, _ = _scan("https://example.com", {**BLOCKCHAIN_MISS, "status": "no_match"}, ML_LEGITIMATE)
    down, _, _, _ = _scan("https://example.com", {**BLOCKCHAIN_UNAVAILABLE, "status": "unavailable"}, ML_UNAVAILABLE)

    assert miss["blockchain_status"] == "no_match" and miss["ml_status"] == "ok"
    assert down["blockchain_status"] == "unavailable" and down["ml_status"] == "error"
    assert down["risk_level"] == "UNKNOWN"


def test_existing_response_fields_are_still_present():
    response, _, _, _ = _scan("https://example.com", BLOCKCHAIN_MISS, ML_LEGITIMATE)

    for field in ("url", "status", "message", "protocol", "domain", "path", "https", "uses_ip",
                  "risk_level", "findings", "blockchain_available", "blockchain_found"):
        assert field in response


# ── 2026-10-28: no SAFE without the registry ──────────────────────────

REGISTRY_DOWN = {**BLOCKCHAIN_UNAVAILABLE, "status": "unavailable"}
REGISTRY_MISS = {**BLOCKCHAIN_MISS, "status": "no_match"}


def test_registry_unavailable_and_model_legitimate_is_unknown_not_safe():
    response, _, _, _ = _scan("https://example.com", REGISTRY_DOWN, ML_LEGITIMATE)

    assert response["risk_level"] == "UNKNOWN"
    assert response["blockchain_status"] == "unavailable"
    assert any("inconclusive, not safe" in f for f in response["findings"])
    assert "blockchain registry unavailable" in response["message"]


def test_registry_checked_and_model_legitimate_can_still_be_safe():
    response, _, _, _ = _scan("https://example.com", REGISTRY_MISS, ML_LEGITIMATE)

    assert response["risk_level"] == "SAFE"
    assert not any("inconclusive" in f for f in response["findings"])


def test_registry_and_model_both_unavailable_is_unknown():
    response, _, _, _ = _scan("https://example.com", REGISTRY_DOWN, ML_UNAVAILABLE)

    assert response["risk_level"] == "UNKNOWN"
    assert response["ml_status"] == "error"


def test_registry_outage_does_not_suppress_model_phishing_signal():
    response, _, _, _ = _scan("https://example.com", REGISTRY_DOWN, ML_PHISHING)

    assert response["risk_level"] == "MEDIUM"
    assert any("advisory" in f for f in response["findings"])


def test_registry_outage_keeps_strong_heuristic_high():
    response, _, _, _ = _scan("http://192.168.1.1/login/verify/account", REGISTRY_DOWN, ML_LEGITIMATE)

    assert response["risk_level"] == "HIGH"


def test_registry_outage_keeps_heuristic_medium():
    # Plain http is one heuristic finding -> MEDIUM, which the outage must not change.
    response, _, _, _ = _scan("http://example.com", REGISTRY_DOWN, ML_LEGITIMATE)

    assert response["risk_level"] == "MEDIUM"

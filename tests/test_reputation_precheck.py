"""Reputation pre-check prototype: unit tests and scan-route integration."""

from unittest.mock import patch

import pytest

from app.routes import scan as scan_route
from app.routes.scan import scan_url
from app.schemas.scan import ScanRequest
from app.services import reputation_precheck as rp

DOMAINS = frozenset({"example.com", "google.com", "github.io", "bit.ly", "paypal.com"})


@pytest.mark.parametrize("url", [
    "https://example.com", "https://example.com/", "http://www.example.com/",
    "https://WWW.Example.COM", "https://example.com./",
])
def test_applies_to_bare_homepage_of_listed_domain(url):
    result = rp.evaluate(url, DOMAINS)
    assert result["applies"] is True
    assert result["matched_domain"] == "example.com"


@pytest.mark.parametrize("url, reason", [
    # Known phishing patterns hosted on popular domains: paths and queries.
    ("https://docs.google.com/forms/d/e/1FAIpQLSf/viewform", "path"),
    ("https://sites.google.com/view/paypal-account-restore", "path"),
    ("https://google.com/url?q=http://evil.example", "query"),
    ("https://example.com/#login", "fragment"),
    ("https://paypal.com/signin/verify", "path"),
    # Subdomains other than www. are user-controllable on many platforms.
    ("https://evil.github.io/", "not on the list"),
    ("https://login.paypal.com/", "not on the list"),
    ("https://paypal.com.evil-site.ru/", "not on the list"),
    # Hosting/sharing apex and shorteners never qualify, even if listed.
    ("https://github.io/", "hosting"),
    ("https://bit.ly/", "hosting"),
    # Unknown domains.
    ("https://example.org/", "not on the list"),
    ("https://examp1e.com/", "not on the list"),
    # Obfuscation and unusual authority.
    ("https://user@example.com/", "userinfo"),
    ("https://example.com:8443/", "port"),
    ("http://93.184.216.34/", "IP"),
    ("https://xn--exmple-cua.com/", "punycode"),
    ("https://exämple.com/", "non-ASCII"),
    # Malformed / non-http.
    ("ftp://example.com/", "http(s)"),
    ("example.com", "http(s)"),
    ("https://[::1", "malformed"),
    ("", "http(s)"),
])
def test_does_not_apply(url, reason):
    result = rp.evaluate(url, DOMAINS)
    assert result["applies"] is False
    assert reason.lower() in result["reason"].lower()


def test_disabled_by_default(monkeypatch, tmp_path):
    listing = tmp_path / "top.csv"
    listing.write_text("1,example.com\n")
    monkeypatch.delenv(rp.ENABLE_ENV, raising=False)
    monkeypatch.setenv(rp.LIST_ENV, str(listing))
    assert rp.evaluate("https://example.com/") == {
        "status": "not_applied", "applies": False, "reason": "disabled", "matched_domain": None}


def test_enabled_without_list_does_not_apply(monkeypatch):
    monkeypatch.setenv(rp.ENABLE_ENV, "1")
    monkeypatch.delenv(rp.LIST_ENV, raising=False)
    assert rp.evaluate("https://example.com/")["reason"] == "no reputation list configured"


def test_list_file_formats_and_top_n(monkeypatch, tmp_path):
    listing = tmp_path / "top.csv"
    listing.write_text("# comment\n1,Example.com\n2,google.com\nthird.com\n")
    assert rp.load_domain_list(listing, 2) == frozenset({"example.com", "google.com"})

    monkeypatch.setenv(rp.ENABLE_ENV, "1")
    monkeypatch.setenv(rp.LIST_ENV, str(listing))
    monkeypatch.setenv(rp.TOP_N_ENV, "2")
    assert rp.evaluate("https://www.google.com/")["applies"] is True
    assert rp.evaluate("https://third.com/")["applies"] is False


def test_result_never_carries_a_safety_verdict():
    result = rp.evaluate("https://example.com/", DOMAINS)
    assert set(result) == {"status", "applies", "reason", "matched_domain"}
    assert "safe" not in str(result).lower()


# ── scan route integration ────────────────────────────────────────────

REGISTRY_MISS = {"available": True, "found": False, "verdict": None, "threat_type": None,
                 "confidence": None, "error": None, "status": "no_match"}
REGISTRY_THREAT = {**REGISTRY_MISS, "found": True, "verdict": 1, "status": "match_threat"}
ML_PHISHING = {"available": True, "probability": 0.93, "label": "phishing",
               "model_name": "xgboost", "error": None}


def _scan(url, registry, monkeypatch, tmp_path, enabled):
    listing = tmp_path / "top.csv"
    listing.write_text("1,example.com\n2,paypal.com\n")
    monkeypatch.setenv(rp.LIST_ENV, str(listing))
    if enabled:
        monkeypatch.setenv(rp.ENABLE_ENV, "1")
    else:
        monkeypatch.delenv(rp.ENABLE_ENV, raising=False)
    with patch("app.routes.scan.check_blockchain_threat", return_value=registry), \
         patch("app.routes.scan.predict_phishing", return_value=ML_PHISHING) as ml, \
         patch("app.routes.scan.save_scan"):
        return scan_url(ScanRequest(url=url), db=None), ml


def test_disabled_precheck_leaves_verdict_unchanged(monkeypatch, tmp_path):
    response, _ = _scan("https://example.com", REGISTRY_MISS, monkeypatch, tmp_path, enabled=False)
    assert response["risk_level"] == "MEDIUM"
    assert scan_route.ML_PHISHING_ADVISORY in response["findings"]
    assert scan_route.REPUTATION_PRECHECK_NOTE not in response["findings"]


def test_enabled_precheck_withholds_model_advisory_on_listed_homepage(monkeypatch, tmp_path):
    response, ml = _scan("https://example.com", REGISTRY_MISS, monkeypatch, tmp_path, enabled=True)
    ml.assert_called_once()  # the model still runs; its output is recorded
    assert response["ml_label"] == "phishing"
    assert scan_route.REPUTATION_PRECHECK_NOTE in response["findings"]
    assert scan_route.ML_PHISHING_ADVISORY not in response["findings"]
    # Advisory withheld, but popularity never yields SAFE.
    assert response["risk_level"] == "UNKNOWN"


def test_enabled_precheck_keeps_heuristic_risk(monkeypatch, tmp_path):
    response, _ = _scan("http://example.com", REGISTRY_MISS, monkeypatch, tmp_path, enabled=True)
    assert response["risk_level"] == "MEDIUM"  # "not using HTTPS" heuristic still counts
    assert scan_route.REPUTATION_PRECHECK_NOTE in response["findings"]


def test_enabled_precheck_never_overrides_registry_threat(monkeypatch, tmp_path):
    response, ml = _scan("https://example.com", REGISTRY_THREAT, monkeypatch, tmp_path, enabled=True)
    assert response["risk_level"] == "HIGH"
    assert response["decision_source"] == "blockchain"
    ml.assert_not_called()


def test_enabled_precheck_does_not_produce_safe_without_registry(monkeypatch, tmp_path):
    unavailable = {**REGISTRY_MISS, "available": False, "status": "unavailable", "error": "down"}
    response, _ = _scan("https://example.com", unavailable, monkeypatch, tmp_path, enabled=True)
    assert response["risk_level"] == "UNKNOWN"


@pytest.mark.parametrize("url", [
    "https://paypal.com/signin/verify",     # path on a listed domain
    "https://secure.paypal.com/",           # subdomain of a listed domain
    "https://unknown-shop.example.net/",    # unknown domain
])
def test_enabled_precheck_keeps_normal_path_for_other_urls(url, monkeypatch, tmp_path):
    response, _ = _scan(url, REGISTRY_MISS, monkeypatch, tmp_path, enabled=True)
    assert scan_route.ML_PHISHING_ADVISORY in response["findings"]
    assert scan_route.REPUTATION_PRECHECK_NOTE not in response["findings"]
    assert response["risk_level"] in {"MEDIUM", "HIGH"}

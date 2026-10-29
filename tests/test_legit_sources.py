"""Licensed URL collection: policy, parsers and dry-run planner.

All fixtures are SYNTHETIC (reserved example domains / hand-written payloads),
not observations from the sources. Network access is blocked for every test.
"""

import json
import socket

import pytest

from src.data.legit_sources import collect, parsers, policy, registry

PSL_TEXT = """// ===BEGIN ICANN DOMAINS===
com
org
uk
co.uk
gov
*.ck
!www.ck
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
github.io
// ===END PRIVATE DOMAINS===
"""


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("network access attempted")
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


@pytest.fixture
def psl(tmp_path):
    path = tmp_path / "psl.dat"
    path.write_text(PSL_TEXT)
    import hashlib
    return policy.PublicSuffixList.load(path, hashlib.sha256(PSL_TEXT.encode()).hexdigest())


def test_psl_requires_frozen_checksum(tmp_path):
    path = tmp_path / "psl.dat"
    path.write_text(PSL_TEXT)
    with pytest.raises(ValueError, match="checksum"):
        policy.PublicSuffixList.load(path, "0" * 64)


@pytest.mark.parametrize("host, expected", [
    ("www.example.com", ("example.com", "icann")),
    ("a.b.example.co.uk", ("example.co.uk", "icann")),
    ("user.github.io", ("github.io", "private")),
    ("foo.bar.ck", ("foo.bar.ck", "icann")),      # wildcard *.ck
    ("www.ck", ("www.ck", "icann")),              # exception !www.ck
    ("agency.gov", ("agency.gov", "icann")),
])
def test_psl_split(psl, host, expected):
    assert psl.split(host) == expected


@pytest.mark.parametrize("url, reason", [
    ("https://user:pw@example.org/", "userinfo"),
    ("https://example.org/contact/jane.doe@example.org", "email_address"),
    ("https://example.org/a?session=abc", "sensitive_query_key"),
    ("https://example.org/a?api_key=1", "sensitive_query_key"),
    ("https://example.org/a?q=news&page=2", None),
])
def test_privacy_filter_excludes_rather_than_redacts(url, reason):
    assert policy.privacy_exclusion(url) == reason


def test_shape_flags():
    s = policy.shape("http://www.example.org:8080/a?b=1")
    assert (s["scheme"], s["has_www"], s["is_root"], s["has_query"], s["has_port"]) == ("http", True, False, True, True)
    assert policy.shape("example.gov", host_only=True)["is_host_only"] is True


def test_popularity_never_verifies():
    label, reason = policy.assign_label(side="legitimate", label_basis="popularity", url_declared_by_source=True,
                                        host="example.org", psl_section="icann", conflicting=False)
    assert (label, reason) == (policy.UNCERTAIN, "popularity_only")


def test_host_ownership_does_not_verify_other_paths():
    label, reason = policy.assign_label(side="legitimate", label_basis="first_party_registry",
                                        url_declared_by_source=False, host="example.gov",
                                        psl_section="icann", conflicting=False)
    assert (label, reason) == (policy.UNCERTAIN, "host_evidence_does_not_verify_path")


def test_platform_hosts_are_uncertain_unless_first_party():
    kwargs = dict(side="legitimate", label_basis="first_party_registry", url_declared_by_source=True,
                  psl_section="private", conflicting=False)
    assert policy.assign_label(host="org.github.io", **kwargs)[0] == policy.UNCERTAIN
    assert policy.assign_label(host="org.github.io", platform_first_party=True, **kwargs)[0] == policy.VERIFIED_LEGITIMATE


def test_conflicts_are_uncertain_and_first_party_is_verified():
    base = dict(side="legitimate", label_basis="first_party_enumeration", url_declared_by_source=True,
                host="www.example.org", psl_section="icann")
    assert policy.assign_label(conflicting=True, **base) == (policy.UNCERTAIN, "conflicting_sources")
    assert policy.assign_label(conflicting=False, **base) == (policy.VERIFIED_LEGITIMATE, None)


def test_labels_are_never_upgraded_without_new_evidence():
    assert not policy.upgrade_allowed(policy.UNCERTAIN, policy.VERIFIED_LEGITIMATE, new_evidence=False)
    assert policy.upgrade_allowed(policy.VERIFIED_LEGITIMATE, policy.UNCERTAIN, new_evidence=False)


def _record(psl, url, **overrides):
    provenance = dict(label=policy.VERIFIED_LEGITIMATE, label_basis="first_party_registry", uncertain_reason=None,
                      source="S1", source_record_id="Q1", source_snapshot="fixture", terms_url="https://example.org/terms",
                      terms_retrieved_at="2026-10-29", terms_sha256="0" * 64, collected_at="2026-10-29T00:00:00Z",
                      collector_version="test", batch_id="b1", split=None, canonicalizer_version="test")
    provenance.update(overrides)
    return policy.build_record(url, psl=psl, host_only=False, **provenance)


def test_record_schema_and_validation(psl):
    record = _record(psl, "https://www.example.org/")
    assert policy.validate_record(record) == []
    assert record["registrable_domain"] == "example.org" and record["psl_version"] == psl.sha256
    bad = _record(psl, "https://www.example.org/", label=policy.VERIFIED_LEGITIMATE, label_basis="popularity")
    assert "verified_legitimate requires first-party basis" in policy.validate_record(bad)
    assert "uncertain without reason" in policy.validate_record(_record(psl, "https://example.org/", label=policy.UNCERTAIN))


def test_batch_checksum_is_deterministic_and_order_independent(psl):
    a, b = _record(psl, "https://a.example.org/"), _record(psl, "https://b.example.org/")
    assert policy.batch_sha256([a, b]) == policy.batch_sha256([b, a])
    assert policy.batch_sha256([a]) != policy.batch_sha256([a, b])


def test_parsers_on_synthetic_payloads():
    wd = {"results": {"bindings": [{"item": {"value": "http://www.wikidata.org/entity/Q1"},
                                    "url": {"value": "https://www.example.org/"}},
                                   {"item": {"value": "http://www.wikidata.org/entity/Q2"}, "url": {"value": "ftp://x"}}]}}
    assert parsers.wikidata_p856(wd) == [("https://www.example.org/", "Q1", False, True)]
    assert parsers.dotgov_csv("Domain name,Domain type\nEXAMPLE.GOV,Federal\n") == [("example.gov", "example.gov", True, True)]
    xml = ('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://www.example.org/a</loc></url></urlset>')
    assert parsers.govuk_sitemap(xml) == [("https://www.example.org/a", "https://www.example.org/a", False, True)]
    dg = {"result": {"results": [
        {"id": "p1", "organization": {"type": "Federal Government"}, "resources": [{"id": "r1", "url": "https://data.example.gov/x?f=csv"}]},
        {"id": "p2", "organization": {"type": "State Government"}, "resources": [{"id": "r2", "url": "https://state.example.org/y"}]}]}}
    assert parsers.datagov_package_search(dg) == [("https://data.example.gov/x?f=csv", "p1/r1", False, True)]


def test_no_source_is_approved_yet():
    assert all(s.status != registry.APPROVED for s in registry.SOURCES.values())


@pytest.mark.parametrize("source_id", sorted(registry.SOURCES))
def test_execute_always_refuses(source_id):
    with pytest.raises(collect.NotApproved):
        collect.execute(source_id)


def test_dry_run_plans(capsys):
    assert collect.main(["--all"]) == 0
    plans = {p["source"]: p for p in json.loads(capsys.readouterr().out)}
    assert all(p["dry_run"] and not p["network_io"] and not p["would_collect"] for p in plans.values())
    assert plans["S2"]["requests"][0]["url"].endswith("/b80a2cc9f1e07893d6df7203a39e199d81622603/current-full.csv")
    assert plans["S5"]["label_ceiling"] == "uncertain"
    assert plans["S7"]["requests"] == [] and plans["P2"]["requests"] == []
    assert collect.main(["--source", "P1", "--execute"]) == 2


def test_phishing_side_has_no_cleared_source():
    phishing = [s for s in registry.SOURCES.values() if s.side == "phishing"]
    assert phishing and all(s.status in (registry.BLOCKED, registry.REJECTED) for s in phishing)

"""Tests for src/blockchain/prepare_batch.py (offline; no RPC, no transactions)."""
import csv
import json
from pathlib import Path

import pytest

from src.blockchain import prepare_batch as pb
from src.blockchain.hashing import generate_message_hash, generate_url_hash

STAMP = "2026-10-28T00:00:00+00:00"


def url(value, **kw):
    args = dict(source="test", source_record_id="r", verification_status=pb.VERIFIED,
                evidence="e", retrieved_at=STAMP, license_ok=True)
    args.update(kw)
    return pb.make_candidate(value, pb.THREAT_TYPE_URL, **args)


def msg(value, **kw):
    args = dict(source="test", source_record_id="r", verification_status=pb.VERIFIED,
                evidence="e", retrieved_at=STAMP, license_ok=True)
    args.update(kw)
    return pb.make_candidate(value, pb.THREAT_TYPE_MESSAGE, **args)


def test_hash_matches_existing_pipeline_and_is_deterministic():
    entry = url("http://Phish.Example/login")
    assert entry["hash"] == generate_url_hash("http://Phish.Example/login")
    assert entry["hash"] == url("http://Phish.Example/login")["hash"]
    assert msg("Verify your account now")["hash"] == generate_message_hash("Verify your account now")


def test_synthetic_hash_compatibility():
    assert generate_url_hash(pb.SYNTHETIC_TEST_URL) == pb.SYNTHETIC_TEST_URL_HASH
    assert pb.synthetic_candidate()["hash"] == pb.SYNTHETIC_TEST_URL_HASH


def test_url_and_message_types_are_separate():
    u, m = url("http://same.example/"), msg("http://same.example/")
    assert u["hash"] != m["hash"]
    assert (u["threat_type_int"], m["threat_type_int"]) == (1, 0)
    result = pb.apply_eligibility([u, m])
    assert len(result["proposed"]) == 2


def test_manifest_entries_contain_no_raw_values():
    entry = msg("Your parcel is held, pay at http://x.example")
    assert "Your parcel" not in json.dumps(entry)
    assert "x.example" not in json.dumps(url("http://x.example/a"))


def test_duplicates_are_excluded():
    result = pb.apply_eligibility([url("http://a.example/"), url("HTTP://A.EXAMPLE/")])
    assert len(result["proposed"]) == 1
    assert [e["exclusion_reason"] for e in result["excluded"]] == ["duplicate_hash"]


@pytest.mark.parametrize("bad", ["", "   ", None])
def test_invalid_inputs_are_excluded_not_raised(bad):
    entry = url(bad)
    assert entry["hash"] is None and entry["exclusion_reason"] == "malformed_input"
    assert pb.apply_eligibility([entry])["proposed"] == []


def test_unverified_and_unlicensed_sources_excluded():
    result = pb.apply_eligibility([url("http://b.example/", verification_status=pb.AUTOMATED),
                                   url("http://c.example/", license_ok=False)])
    reasons = sorted(e["exclusion_reason"] for e in result["excluded"])
    assert reasons == ["license_review_required", "not_source_verified"]
    assert result["proposed"] == []


def test_synthetic_never_proposed():
    result = pb.apply_eligibility([pb.synthetic_candidate(), url(pb.SYNTHETIC_TEST_URL)])
    assert result["proposed"] == []
    assert len(result["synthetic"]) == 2


def test_already_registered_excluded_and_unknown_kept():
    entries = [url("http://d.example/"), url("http://e.example/"), url("http://f.example/")]
    statuses = {entries[0]["hash"]: "match_threat", entries[1]["hash"]: "no_match",
                entries[2]["hash"]: "unavailable"}
    report = pb.check_registry(entries, lambda h, t: statuses[h])
    assert report["performed"] and report["statuses"]["match_threat"] == 1
    assert [e["already_registered"] for e in entries] == [True, False, None]
    result = pb.apply_eligibility(entries)
    assert [e["exclusion_reason"] for e in result["excluded"]] == ["already_registered"]
    assert len(result["proposed"]) == 2


def test_lookup_receives_matching_threat_type():
    seen = []
    pb.check_registry([url("http://g.example/"), msg("hello")], lambda h, t: seen.append(t) or "no_match")
    assert seen == [1, 0]


def test_missing_rpc_reports_unavailable(monkeypatch):
    # Import first: the checker loads the project .env at import time, which must
    # happen before the variables are removed for this test.
    import app.services.blockchain_checker  # noqa: F401
    monkeypatch.delenv("SEPOLIA_RPC_URL", raising=False)
    monkeypatch.delenv("WEB3_PROVIDER_URI", raising=False)
    assert pb.read_only_lookup(pb.SYNTHETIC_TEST_URL_HASH, 1) == "unavailable"


def test_no_lookup_means_check_not_performed():
    entry = url("http://h.example/")
    assert pb.check_registry([entry], None)["performed"] is False
    assert entry["already_registered"] is None


def test_batch_limit_defers_deterministically():
    entries = [url(f"http://n{i}.example/") for i in range(5)]
    a = pb.apply_eligibility(entries, url_batch_limit=2)
    b = pb.apply_eligibility(list(reversed(entries)), url_batch_limit=2)
    assert [e["hash"] for e in a["proposed"]] == [e["hash"] for e in b["proposed"]]
    assert len(a["deferred"]) == 3


def test_module_cannot_submit_transactions():
    source = Path(pb.__file__).read_text()
    for forbidden in ("submitThreat", "sign_transaction", "send_raw_transaction",
                      "send_transaction", "PRIVATE_KEY", "build_transaction"):
        assert forbidden not in source


def test_write_manifest_refuses_overwrite(tmp_path):
    out = tmp_path / "m.json"
    pb.write_manifest({"a": 1}, out)
    with pytest.raises(FileExistsError):
        pb.write_manifest({"a": 2}, out)
    assert json.loads(out.read_text()) == {"a": 1}


def test_missing_source_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        pb.phiusiil_candidates(tmp_path / "missing.csv", STAMP)


def _write(path, header, rows):
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(header)
        writer.writerows(rows)


def test_mishra_loader_uses_raw_text_and_excludes_test_split(tmp_path):
    raw = tmp_path / "raw.csv"
    _write(raw, ["LABEL", "TEXT"], [["ham", "hi"], ["Smishing", "Pay NOW at x"], ["Smishing", "Claim prize"]])
    header = ["text", "label", "category", "source", "source_row", "group_id"]
    _write(tmp_path / "train.csv", header, [["pay now at x", "smishing", "", "mishra_soni", "1", "g1"],
                                            ["hi", "legitimate", "", "mishra_soni", "0", "g0"]])
    _write(tmp_path / "val.csv", header, [])
    _write(tmp_path / "test.csv", header, [["claim prize", "smishing", "", "mishra_soni", "2", "g2"]])
    out = pb.mishra_soni_candidates(raw, tmp_path, STAMP)
    assert len(out) == 2
    assert out[0]["hash"] == generate_message_hash("Pay NOW at x")
    assert out[1]["exclusion_reason"] == "in_locked_test_split"


def test_mishra_loader_rejects_misaligned_rows(tmp_path):
    raw = tmp_path / "raw.csv"
    _write(raw, ["LABEL", "TEXT"], [["ham", "hi"]])
    header = ["text", "label", "category", "source", "source_row", "group_id"]
    _write(tmp_path / "train.csv", header, [["hi", "smishing", "", "mishra_soni", "0", "g0"]])
    _write(tmp_path / "val.csv", header, [])
    _write(tmp_path / "test.csv", header, [])
    with pytest.raises(ValueError):
        pb.mishra_soni_candidates(raw, tmp_path, STAMP)


def test_phiusiil_loader_keeps_only_label_zero(tmp_path):
    path = tmp_path / "p.csv"
    path.write_text("﻿FILENAME,URL,label\nf1,http://bad.example/,0\nf2,https://www.good.example,1\n",
                    encoding="utf-8")
    out = pb.phiusiil_candidates(path, STAMP)
    assert len(out) == 1 and out[0]["source_record_id"] == "f1"


def test_openphish_loader_is_excluded_pending_license(tmp_path):
    path = tmp_path / "feed.txt"
    path.write_text("http://op.example/a\n\n", encoding="utf-8")
    out = pb.openphish_candidates(path, STAMP)
    assert len(out) == 1
    assert pb.apply_eligibility(out)["excluded"][0]["exclusion_reason"] == "license_review_required"


def _grouped(value, domain, tld):
    entry = url(value)
    entry["_group"], entry["tld"] = domain, tld
    return entry


def test_stratified_selection_one_per_domain_proportional_tlds():
    entries = [_grouped(f"http://a.com/{i}", "a.com", "com") for i in range(5)]
    entries += [_grouped("http://b.com/", "b.com", "com"), _grouped("http://c.ru/", "c.ru", "ru"),
                _grouped("http://d.xyz/", "d.xyz", "xyz")]
    picked = pb.select_stratified(entries, 3)
    assert len({e["_group"] for e in picked}) == 3
    assert {e["tld"] for e in picked} == {"com", "ru", "xyz"}
    assert [e["hash"] for e in picked] == [e["hash"] for e in pb.select_stratified(list(reversed(entries)), 3)]


def test_stratified_selection_follows_tld_proportions():
    entries = [_grouped(f"http://c{i}.com/", f"c{i}.com", "com") for i in range(8)]
    entries += [_grouped(f"http://r{i}.ru/", f"r{i}.ru", "ru") for i in range(2)]
    picked = pb.select_stratified(entries, 5)
    assert sorted(e["tld"] for e in picked) == ["com"] * 4 + ["ru"]


def test_stratified_selection_through_eligibility_defers_the_rest():
    entries = [_grouped(f"http://a.com/{i}", "a.com", "com") for i in range(4)]
    result = pb.apply_eligibility(entries, url_batch_limit=10, selection="stratified")
    assert len(result["proposed"]) == 1 and len(result["deferred"]) == 3


def test_manifest_drops_in_memory_domain(tmp_path):
    entry = _grouped("http://secret-domain.example/x", "secret-domain.example", "example")
    manifest = pb.build_manifest([entry], {"performed": False}, 10, {}, "stratified")
    text = json.dumps(manifest)
    assert "secret-domain" not in text and "_group" not in text
    assert manifest["url_selection"]["distinct_domains"] == 1
    assert "None has been independently confirmed" in manifest["label_basis"]


def test_check_manifest_is_bounded_paced_and_read_only():
    manifest = {"generated_at": "t", "network": {}, "proposed": [url("http://p.example/"), msg("m")]}
    before = json.dumps(manifest)
    pauses = []
    report = pb.check_manifest(manifest, lambda h, t: "no_match", delay=0.5, sleep=pauses.append)
    assert pauses == [0.5] and report["counts"] == {"no_match": 2}
    assert all(r["already_registered"] is False for r in report["results"])
    assert json.dumps(manifest) == before
    with pytest.raises(ValueError):
        pb.check_manifest(manifest, lambda h, t: "no_match", max_lookups=1, sleep=lambda s: None)


def test_check_mode_stops_without_rpc(monkeypatch, tmp_path):
    monkeypatch.delenv("SEPOLIA_RPC_URL", raising=False)
    monkeypatch.delenv("WEB3_PROVIDER_URI", raising=False)
    called = []
    monkeypatch.setattr(pb, "read_only_lookup", lambda h, t: called.append(h) or "no_match")
    src = tmp_path / "m.json"
    src.write_text(json.dumps({"proposed": [url("http://q.example/")]}))
    code = pb.main(["--check-manifest", str(src), "--out", str(tmp_path / "r.json")],
                   env_file=tmp_path / "missing.env")
    assert code == 2
    assert called == [] and not (tmp_path / "r.json").exists()


def test_check_summary_separates_existing_new_and_failed():
    entries = [url(f"http://s{i}.example/") for i in range(4)]
    statuses = iter(["match_threat", "no_match", "unavailable", "match_non_threat"])
    report = pb.check_manifest({"proposed": entries}, lambda h, t: next(statuses), sleep=lambda s: None)
    assert {k: v for k, v in report["summary"].items() if k != "note"} == {
        "existing_threat": 1, "existing_non_threat": 1, "new_candidates": 1, "failed_or_unknown": 1}
    assert report["results"][2]["already_registered"] is None


def test_rpc_detection_reads_only_env_file_keys(monkeypatch, tmp_path):
    monkeypatch.delenv("SEPOLIA_RPC_URL", raising=False)
    monkeypatch.delenv("WEB3_PROVIDER_URI", raising=False)
    assert pb.rpc_configured(tmp_path / "missing.env") is False
    env = tmp_path / ".env"
    env.write_text("OTHER=1\n")
    assert pb.rpc_configured(env) is False
    env.write_text("SEPOLIA_RPC_URL=https://rpc.invalid/x\n")
    assert pb.rpc_configured(env) is True


# ── scope modes (URL-only / messages-only / combined) ─────────────────

def _sources(tmp_path):
    phi = tmp_path / "phi.csv"
    phi.write_text("﻿FILENAME,URL,Domain,TLD,label\n"
                   "f1,http://bad-one.example/login,bad-one.example,example,0\n"
                   "f2,http://bad-two.test/verify,bad-two.test,test,0\n"
                   "f3,https://www.good.example,www.good.example,example,1\n", encoding="utf-8")
    raw = tmp_path / "raw.csv"
    _write(raw, ["LABEL", "TEXT"], [["Smishing", "Your parcel fee is due at x.example"],
                                    ["Smishing", "Locked test message"], ["ham", "hello"]])
    header = ["text", "label", "category", "source", "source_row", "group_id"]
    splits = tmp_path / "splits"
    splits.mkdir()
    _write(splits / "train.csv", header, [["your parcel fee is due at x.example", "smishing", "", "mishra_soni", "0", "g0"]])
    _write(splits / "val.csv", header, [])
    _write(splits / "test.csv", header, [["locked test message", "smishing", "", "mishra_soni", "1", "g1"]])
    return ["--phiusiil", str(phi), "--mishra-raw", str(raw), "--splits-dir", str(splits)]


def _main(tmp_path, args, name="out.json"):
    out = tmp_path / name
    code = pb.main(args + ["--out", str(out)], env_file=tmp_path / "missing.env")
    return code, (json.loads(out.read_text()) if out.exists() else None)


def test_urls_only_works_without_sms_sources(tmp_path):
    args = _sources(tmp_path)
    args[3] = str(tmp_path / "absent.csv")            # --mishra-raw
    args[5] = str(tmp_path / "absent-splits")         # --splits-dir
    code, m = _main(tmp_path, args + ["--urls-only"])
    assert code == 0 and m["scope"] == "urls"
    assert {e["threat_type"] for e in m["proposed"]} == {"URL"}
    assert m["summary"]["proposed_url"] == 2 and "mishra_soni" not in m["sources"]
    assert m["synthetic"] and m["synthetic"][0]["hash"] not in {e["hash"] for e in m["proposed"]}


def test_messages_only_works_without_phiusiil(tmp_path):
    args = _sources(tmp_path)
    args[1] = str(tmp_path / "absent.csv")
    code, m = _main(tmp_path, args + ["--messages-only"])
    assert code == 0 and m["scope"] == "messages"
    assert [e["threat_type_int"] for e in m["proposed"]] == [0]
    assert m["summary"]["excluded_by_reason"] == {"in_locked_test_split": 1}
    assert set(m["sources"]["mishra_soni"]["splits_sha256"]) == {"train", "val", "test"}


def test_combined_mode_and_privacy(tmp_path):
    code, m = _main(tmp_path, _sources(tmp_path))
    assert code == 0 and m["scope"] == "all"
    assert m["summary"]["proposed_url"] == 2 and m["summary"]["proposed_message"] == 1
    text = json.dumps(m)
    for raw in ("bad-one", "bad-two", "parcel", "Locked test", "http"):
        assert raw not in text


def test_missing_sources_are_reported_and_nothing_written(tmp_path, capsys):
    args = _sources(tmp_path)
    args[1] = str(tmp_path / "gone.csv")
    code, m = _main(tmp_path, args)
    assert code == 3 and m is None
    assert str(tmp_path / "gone.csv") in capsys.readouterr().out


def test_url_and_message_flags_are_exclusive(tmp_path):
    with pytest.raises(SystemExit):
        pb.main(["--out", str(tmp_path / "x.json"), "--urls-only", "--messages-only"])


# ── contract and runtime compatibility ────────────────────────────────

def test_threat_type_encoding_matches_contract_enum():
    source = (Path(pb.PROJECT_ROOT) / "contracts" / "ThreatRegistry.sol").read_text()
    enum_body = source[source.index("enum ThreatType"):].split("}")[0]
    names = [line.strip().split(",")[0].split()[0] for line in enum_body.splitlines()[1:] if line.strip()]
    assert names == ["MESSAGE", "URL"]
    assert (pb.THREAT_TYPE_MESSAGE, pb.THREAT_TYPE_URL) == (0, 1)


def test_keccak_not_nist_sha3():
    import hashlib
    from Crypto.Hash import keccak
    k = keccak.new(digest_bits=256, data=b"url:https://a.example/").hexdigest()
    assert generate_url_hash("https://a.example/") == "0x" + k
    assert k != hashlib.sha3_256(b"url:https://a.example/").hexdigest()
    assert keccak.new(digest_bits=256, data=b"").hexdigest().startswith("c5d24601")


def test_prepared_hashes_equal_what_runtime_checker_queries(monkeypatch):
    from app.services import blockchain_checker as bc
    queried = []
    monkeypatch.setattr(bc, "_lookup_hash", lambda h, t: queried.append((h, t)) or {"status": "no_match"})
    bc.check_blockchain_threat("HTTP://Bad.Example:80/a")
    bc.check_message_threat("Pay now  at x.example")
    assert queried == [(url("HTTP://Bad.Example:80/a")["hash"], 1), (msg("Pay now  at x.example")["hash"], 0)]


@pytest.mark.parametrize("status,expected", [("match_threat", True), ("match_non_threat", True),
                                             ("no_match", False), ("unavailable", None)])
def test_read_only_lookup_maps_registry_outcomes(monkeypatch, status, expected):
    from app.services import blockchain_checker as bc
    monkeypatch.setattr(bc, "_lookup_hash", lambda h, t: {"status": status})
    entry = url("http://r.example/")
    pb.check_registry([entry], pb.read_only_lookup)
    assert entry["registry_status"] == status and entry["already_registered"] is expected

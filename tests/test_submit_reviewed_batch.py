"""Tests for src/blockchain/submit_reviewed_batch.py.

Everything runs against an in-memory fake chain and temporary files. No network,
no real key, and nothing is ever sent to Sepolia.
"""
import csv
import hashlib
import json
from types import SimpleNamespace

import pytest

from src.blockchain import submit_reviewed_batch as sb
from src.blockchain.hashing import generate_message_hash

OWNER = sb.EXPECTED_OWNER
TEXTS = ["Your account is locked, call 0800 000 000 now", "Claim your prize at win.example today"]


# ── fixtures: temporary manifest, raw CSV and test split ──────────────

def _write_csv(path, header, rows):
    with open(path, "w", newline="", encoding="utf-8") as handle:
        w = csv.writer(handle); w.writerow(header); w.writerows(rows)


@pytest.fixture
def files(tmp_path, monkeypatch):
    raw = tmp_path / "raw.csv"
    _write_csv(raw, ["LABEL", "TEXT"], [["Smishing", TEXTS[0]], ["ham", "hello"], ["Smishing", TEXTS[1]], ["Smishing", "locked test message"]])
    test = tmp_path / "test.csv"
    _write_csv(test, ["text", "label", "category", "source", "source_row", "group_id"], [["x", "smishing", "", "mishra_soni", "3", "g"]])
    entries = [{"hash": generate_message_hash(TEXTS[0]), "source_record_id": "row 0"},
               {"hash": generate_message_hash(TEXTS[1]), "source_record_id": "row 2"}]
    for e in entries:
        e.update(threat_type="MESSAGE", threat_type_int=0, proposed_verdict=1, proposed_confidence=100)
    manifest = tmp_path / "final.json"
    manifest.write_text(json.dumps({"network": {"chain_id": sb.CHAIN_ID, "contract_address": sb.CONTRACT_ADDRESS},
                                    "proposed": entries}))
    sha = hashlib.sha256(manifest.read_bytes()).hexdigest()
    monkeypatch.setattr(sb, "EXPECTED_MANIFEST_SHA256", sha)
    monkeypatch.setattr(sb, "EXPECTED_COUNT", 2)
    monkeypatch.setattr(sb, "RAW_CSV", raw)
    monkeypatch.setattr(sb, "TEST_SPLIT", test)
    return SimpleNamespace(manifest=manifest, raw=raw, test=test, entries=entries, sha=sha, tmp=tmp_path)


# ── fake chain ─────────────────────────────────────────────────────────

class Call:
    def __init__(self, fn):
        self.fn = fn

    def call(self):
        return self.fn()


class FakeChain:
    """Minimal stand-in for web3 + the ThreatRegistry contract."""

    def __init__(self, *, chain_id=sb.CHAIN_ID, code=b"\x60", owner=OWNER, registered=(), fail_send_at=None,
                 revert_at=None, timeout_at=None, pending_extra=0, mine_on_timeout=False):
        self.chain_id, self._code, self._owner = chain_id, code, owner
        self.registry = {bytes.fromhex(h[2:]): (0, 1, 100) for h in registered}
        self.fail_send_at, self.revert_at, self.timeout_at = fail_send_at, revert_at, timeout_at
        self.pending_extra, self.mine_on_timeout = pending_extra, mine_on_timeout
        self.sent, self._pending = [], {}
        self.eth = self
        self.address = sb.CONTRACT_ADDRESS
        self.functions = self

    # eth
    def get_code(self, address):
        return self._code

    def get_transaction_count(self, address, block):
        return len(self.sent) + (self.pending_extra if block == "pending" else 0)

    def send_raw_transaction(self, raw):
        n = len(self.sent)
        if self.fail_send_at == n:
            raise ValueError("nonce too low (rpc https://secret.invalid/key)")
        self.sent.append(raw)
        self._pending[raw] = n
        return bytes([n]) * 32

    def wait_for_transaction_receipt(self, tx_hash, timeout):
        n = tx_hash[0]
        key = self._keys[n]
        if self.timeout_at == n:
            if self.mine_on_timeout:
                self.registry[key] = (0, 1, 100)
            raise TimeoutError("no receipt")
        if self.revert_at == n:
            return {"status": 0, "blockNumber": 100 + n}
        self.registry[key] = (0, 1, 100)
        return {"status": 1, "blockNumber": 100 + n, "gasUsed": 260_000}

    # contract functions
    def owner(self):
        return Call(lambda: self._owner)

    def threatExists(self, key):
        return Call(lambda: key in self.registry)

    def getThreat(self, key):
        return Call(lambda: self.registry[key] + (1, OWNER))

    def submitThreat(self, key, t, v, c):
        assert (t, v, c) == (0, 1, 100)
        chain = self
        class Tx:
            def build_transaction(self, params):
                assert params["from"] == OWNER and params["chainId"] == sb.CHAIN_ID
                chain._keys = getattr(chain, "_keys", {})
                chain._keys[len(chain.sent)] = key
                return {"to": sb.CONTRACT_ADDRESS, "data": key.hex(), **params}
        return Tx()


class FakeAccount:
    address = OWNER

    def sign_transaction(self, tx):
        return SimpleNamespace(raw_transaction=json.dumps(tx, sort_keys=True).encode(), hash=b"\x00" * 32)


def _log(tmp):
    return sb._Log(tmp / "log.jsonl")


def _events(tmp):
    return [json.loads(line)["event"] for line in (tmp / "log.jsonl").read_text().splitlines()]


# ── manifest checks ────────────────────────────────────────────────────

def test_valid_manifest_passes(files):
    assert [e["hash"] for e in sb.load_and_verify_manifest(files.manifest)] == [e["hash"] for e in files.entries]


def test_checksum_mismatch_stops(files):
    files.manifest.write_text(files.manifest.read_text() + " ")
    with pytest.raises(sb.SubmissionError, match="SHA-256"):
        sb.load_and_verify_manifest(files.manifest)


def test_count_mismatch_stops(files, monkeypatch):
    monkeypatch.setattr(sb, "EXPECTED_COUNT", 3)
    with pytest.raises(sb.SubmissionError, match="approved count"):
        sb.load_and_verify_manifest(files.manifest)


def _rewrite(files, monkeypatch, mutate):
    data = json.loads(files.manifest.read_text()); mutate(data)
    files.manifest.write_text(json.dumps(data))
    monkeypatch.setattr(sb, "EXPECTED_MANIFEST_SHA256", hashlib.sha256(files.manifest.read_bytes()).hexdigest())


def test_hash_that_does_not_rederive_stops(files, monkeypatch):
    _rewrite(files, monkeypatch, lambda d: d["proposed"][0].update(hash="0x" + "ab" * 32))
    with pytest.raises(sb.SubmissionError, match="re-derive"):
        sb.load_and_verify_manifest(files.manifest)


def test_duplicate_hashes_in_manifest_stop(files, monkeypatch):
    _rewrite(files, monkeypatch, lambda d: d["proposed"][1].update(hash=d["proposed"][0]["hash"]))
    with pytest.raises(sb.SubmissionError, match="duplicate"):
        sb.load_and_verify_manifest(files.manifest)


def test_locked_test_row_stops(files, monkeypatch):
    _rewrite(files, monkeypatch, lambda d: d["proposed"][1].update(source_record_id="row 3", hash=generate_message_hash("locked test message")))
    with pytest.raises(sb.SubmissionError, match="locked test"):
        sb.load_and_verify_manifest(files.manifest)


def test_wrong_verdict_in_manifest_stops(files, monkeypatch):
    _rewrite(files, monkeypatch, lambda d: d["proposed"][0].update(proposed_verdict=0))
    with pytest.raises(sb.SubmissionError, match="type/verdict"):
        sb.load_and_verify_manifest(files.manifest)


# ── chain and signer checks ────────────────────────────────────────────

def test_wrong_chain_stops():
    with pytest.raises(sb.SubmissionError, match="chain"):
        sb.verify_chain(FakeChain(chain_id=1), FakeChain())


def test_wrong_contract_address_stops():
    c = FakeChain(); c.address = "0x" + "1" * 40
    with pytest.raises(sb.SubmissionError, match="contract address"):
        sb.verify_chain(FakeChain(), c)


def test_missing_contract_code_stops():
    with pytest.raises(sb.SubmissionError, match="no contract code"):
        sb.verify_chain(FakeChain(code=b""), FakeChain(code=b""))


def test_wrong_owner_stops():
    with pytest.raises(sb.SubmissionError, match="owner"):
        sb.verify_chain(FakeChain(), FakeChain(owner="0x" + "2" * 40))


def test_wrong_signer_stops():
    with pytest.raises(sb.SubmissionError, match="not the contract owner"):
        sb.verify_signer(FakeChain(), "0x" + "3" * 40, OWNER)


def test_pending_transactions_stop():
    with pytest.raises(sb.SubmissionError, match="pending"):
        sb.verify_signer(FakeChain(pending_extra=1), OWNER, OWNER)


# ── submission behaviour ───────────────────────────────────────────────

def test_happy_path_writes_each_once_and_logs(files):
    chain = FakeChain()
    log = _log(files.tmp)
    result = sb.submit(files.entries, chain, chain, FakeAccount(), log); log.close()
    assert result["stopped"] is None and len(result["completed"]) == 2 and len(chain.sent) == 2
    assert _events(files.tmp) == ["sent", "confirmed", "sent", "confirmed"]


def test_already_registered_is_skipped_never_resubmitted(files):
    chain = FakeChain(registered=[files.entries[0]["hash"]])
    p = sb.plan(files.entries, chain)
    assert [e["hash"] for e in p["already_registered"]] == [files.entries[0]["hash"]] and len(p["to_write"]) == 1
    log = _log(files.tmp)
    result = sb.submit(files.entries, chain, chain, FakeAccount(), log); log.close()   # recheck inside submit
    assert result["skipped"] == [files.entries[0]["hash"]] and len(chain.sent) == 1


def test_registered_with_conflicting_verdict_stops_planning(files):
    chain = FakeChain(registered=[files.entries[0]["hash"]])
    chain.registry[bytes.fromhex(files.entries[0]["hash"][2:])] = (0, 0, 100)
    with pytest.raises(sb.SubmissionError, match="different type/verdict"):
        sb.plan(files.entries, chain)


def test_send_failure_stops_and_reports_remaining_without_leaking_urls(files):
    chain = FakeChain(fail_send_at=0)
    log = _log(files.tmp)
    result = sb.submit(files.entries, chain, chain, FakeAccount(), log); log.close()
    assert result["stopped"] == "send_failed" and result["remaining"] == 2 and chain.sent == []
    text = (files.tmp / "log.jsonl").read_text()
    assert "secret.invalid" not in text and "<url>" in text


def test_reverted_transaction_stops(files):
    chain = FakeChain(revert_at=0)
    log = _log(files.tmp)
    result = sb.submit(files.entries, chain, chain, FakeAccount(), log); log.close()
    assert result["stopped"] == "reverted" and len(chain.sent) == 1 and result["completed"] == []


@pytest.mark.parametrize("mined", [False, True])
def test_uncertain_status_stops_without_retry(files, mined):
    chain = FakeChain(timeout_at=0, mine_on_timeout=mined)
    log = _log(files.tmp)
    result = sb.submit(files.entries, chain, chain, FakeAccount(), log); log.close()
    assert result["stopped"] == "uncertain" and len(chain.sent) == 1          # never resent
    assert result["registered_now"] is mined and "uncertain_tx" in result
    assert _events(files.tmp) == ["sent", "uncertain_no_receipt"]


def test_log_refuses_to_overwrite(files):
    (files.tmp / "log.jsonl").write_text("existing")
    with pytest.raises(FileExistsError):
        sb._Log(files.tmp / "log.jsonl")


# ── command-line flow ──────────────────────────────────────────────────

def _main(files, monkeypatch, chain, *argv, answer=None, signer=FakeAccount):
    monkeypatch.setenv("SEPOLIA_RPC_URL", "https://rpc.invalid/test")
    chain.to_checksum_address = lambda a: a
    chain.contract = lambda address, abi: chain
    asked = []
    code = sb.main(["--manifest", str(files.manifest), "--log", str(files.tmp / "run.jsonl"), *argv],
                   w3_factory=lambda url: chain, signer_factory=signer,
                   prompt=lambda text: asked.append(text) or (answer or ""))
    return code, asked


def test_default_run_is_read_only(files, monkeypatch):
    chain = FakeChain()
    def no_signer():
        raise AssertionError("signer must not be loaded in a read-only run")
    code, asked = _main(files, monkeypatch, chain, signer=no_signer)
    assert code == 0 and chain.sent == [] and asked == [] and not (files.tmp / "run.jsonl").exists()


def test_submit_requires_exact_confirmation(files, monkeypatch):
    chain = FakeChain()
    code, asked = _main(files, monkeypatch, chain, "--submit", answer="yes")
    assert code == 3 and chain.sent == []
    assert sb.CONTRACT_ADDRESS in asked[0] and files.sha in asked[0] and "Writes: 2" in asked[0] and str(sb.CHAIN_ID) in asked[0]


def test_submit_with_exact_confirmation_writes(files, monkeypatch):
    chain = FakeChain()
    code, _ = _main(files, monkeypatch, chain, "--submit", answer=f"SUBMIT 2 TO {sb.CONTRACT_ADDRESS}")
    assert code == 0 and len(chain.sent) == 2


def test_cli_wrong_chain_sends_nothing(files, monkeypatch):
    chain = FakeChain(chain_id=1)
    code, _ = _main(files, monkeypatch, chain, "--submit", answer=f"SUBMIT 2 TO {sb.CONTRACT_ADDRESS}")
    assert code == 4 and chain.sent == []


def test_module_never_prints_or_accepts_key_on_command_line():
    source = open(sb.__file__, encoding="utf-8").read()
    assert "--private-key" not in source and "print(key" not in source and "private_key=" not in source

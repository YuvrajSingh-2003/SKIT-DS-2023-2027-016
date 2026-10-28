"""Tests for src/blockchain/registry_preflight.py with a fake Web3 (no network, no keys)."""
import json
from pathlib import Path

import pytest

from src.blockchain import registry_preflight as rp

CONFIG = {"chainId": 11155111, "contractAddress": "0x62bFA47Fe851545365b152B746475925100CEc96"}
OWNER = "0x00000000000000000000000000000000000000aa"


def _entry(n, type_int=1):
    return {"hash": "0x" + f"{n:064x}", "threat_type": "URL" if type_int else "MESSAGE",
            "threat_type_int": type_int, "proposed_verdict": 1, "proposed_confidence": 100}


def _manifest(entries):
    return {"generated_at": "t", "scope": "urls", "proposed": entries,
            "network": {"chain_id": 11155111, "contract_address": CONFIG["contractAddress"]}}


class _Call:
    def __init__(self, fn):
        self.fn = fn

    def call(self):
        return self.fn()

    def estimate_gas(self, tx):
        return self.fn(tx)


class FakeWeb3:
    def __init__(self, registry, chain_id=11155111, code=b"\x60", fail=()):
        self.registry, self.fail, self.estimates = registry, set(fail), []
        self.eth = self
        self.chain_id, self._code, self.gas_price = chain_id, code, 2_000_000_000

    def to_checksum_address(self, a):
        return a

    def get_code(self, address):
        return self._code

    def contract(self, address, abi):
        return self

    @property
    def functions(self):
        return self

    def owner(self):
        return _Call(lambda: OWNER)

    def threatCount(self):
        return _Call(lambda: len(self.registry))

    def threatExists(self, key):
        def run():
            if key in self.fail:
                raise TimeoutError("rpc")
            return key in self.registry
        return _Call(run)

    def getThreat(self, key):
        return _Call(lambda: self.registry[key])

    def get_function_by_name(self, name):
        assert name == "submitThreat"
        def write(key, t, verdict, confidence):
            def estimate(tx):
                assert tx == {"from": OWNER}
                self.estimates.append((key, t, verdict, confidence))
                return 70000
            return _Call(estimate)
        return write


def _key(n):
    return bytes.fromhex(f"{n:064x}")


def test_classifies_existing_new_and_failed_separately():
    web3 = FakeWeb3({_key(1): (1, 1, 100), _key(2): (1, 0, 50)}, fail={_key(4)})
    report = rp.preflight(_manifest([_entry(i) for i in (1, 2, 3, 4)]), web3,
                          config=CONFIG, abi=[], sleep=lambda s: None)
    s = report["summary"]
    assert (s["existing_threat"], s["existing_non_threat"], s["new_candidates"], s["failed_or_unknown"]) == (1, 1, 1, 1)
    assert [r["registry_status"] for r in report["results"]] == ["match_threat", "match_non_threat", "no_match", "unavailable"]
    assert s["writes_needed"] == 1 and s["total_gas_estimate"] == 70000
    assert s["indicative_cost_eth"] == 70000 * 2_000_000_000 / 10**18
    assert web3.estimates == [(_key(3), 1, 1, 100)]          # estimated only for the new hash
    assert report["contract_owner"] == OWNER


def test_type_mismatch_is_an_error_not_a_match():
    web3 = FakeWeb3({_key(5): (0, 1, 100)})
    report = rp.preflight(_manifest([_entry(5, 1)]), web3, config=CONFIG, abi=[], sleep=lambda s: None)
    assert report["results"][0]["registry_status"] == "error_type_mismatch"
    assert report["summary"]["failed_or_unknown"] == 1


@pytest.mark.parametrize("kwargs,message", [({"chain_id": 1}, "chain ID"), ({"code": b""}, "No contract code")])
def test_wrong_network_or_missing_contract_stops(kwargs, message):
    with pytest.raises(rp.PreflightError, match=message):
        rp.preflight(_manifest([_entry(1)]), FakeWeb3({}, **kwargs), config=CONFIG, abi=[], sleep=lambda s: None)


def test_manifest_for_other_contract_is_rejected():
    manifest = _manifest([_entry(1)])
    manifest["network"]["contract_address"] = "0x" + "1" * 40
    with pytest.raises(rp.PreflightError, match="differs"):
        rp.preflight(manifest, FakeWeb3({}), config=CONFIG, abi=[], sleep=lambda s: None)


def test_bounded():
    with pytest.raises(rp.PreflightError):
        rp.preflight(_manifest([_entry(i) for i in range(3)]), FakeWeb3({}), config=CONFIG, abi=[],
                     max_hashes=2, sleep=lambda s: None)


def test_cli_without_rpc_stops_and_writes_nothing(monkeypatch, tmp_path):
    for name in rp.RPC_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    src = tmp_path / "m.json"
    src.write_text(json.dumps(_manifest([_entry(1)])))
    factory_calls = []
    code = rp.main(["--manifest", str(src), "--out", str(tmp_path / "r.json")],
                   env_file=tmp_path / "missing.env", web3_factory=factory_calls.append)
    assert code == 2 and factory_calls == [] and not (tmp_path / "r.json").exists()


def test_cli_with_fake_network_writes_report_without_rpc_url(monkeypatch, tmp_path):
    monkeypatch.setenv("SEPOLIA_RPC_URL", "https://user:secret@rpc.invalid/key123")
    src = tmp_path / "m.json"
    src.write_text(json.dumps(_manifest([_entry(1)])))
    out = tmp_path / "r.json"
    code = rp.main(["--manifest", str(src), "--out", str(out), "--delay", "0"],
                   env_file=tmp_path / "missing.env", web3_factory=lambda u: FakeWeb3({}))
    assert code == 0
    text = out.read_text()
    assert "secret" not in text and "key123" not in text and "rpc.invalid" not in text
    assert json.loads(text)["summary"]["new_candidates"] == 1


def test_rpc_url_reads_env_file_without_exporting_other_keys(monkeypatch, tmp_path):
    for name in rp.RPC_ENV_VARS + ("SIGNER_PRIVATE_KEY",):
        monkeypatch.delenv(name, raising=False)
    env = tmp_path / ".env"
    env.write_text("SIGNER_PRIVATE_KEY=0xdead\nSEPOLIA_RPC_URL=https://rpc.invalid/x\n")
    assert rp.rpc_url(env) == "https://rpc.invalid/x"
    import os
    assert "SIGNER_PRIVATE_KEY" not in os.environ


def test_module_cannot_sign_or_send():
    source = Path(rp.__file__).read_text()
    for forbidden in ("sign_transaction", "send_raw_transaction", "send_transaction", "transact(",
                      "build_transaction", "PRIVATE_KEY", "Account", "middleware"):
        assert forbidden not in source

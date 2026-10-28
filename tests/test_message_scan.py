"""Message scanning: SMS service, decision policy, persistence, registry lookup.

Synthetic messages only. In-memory SQLite (the live chainshield.db is never
opened). Web3 is replaced with a fake, so no network or blockchain access.
"""

import logging
import shutil
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database.database import Base
from app.database.message_models import MessageScan, ensure_message_table
from app.routes import message as route
from app.schemas.message import MAX_MESSAGE_CHARS, MessageScanRequest
from app.services import blockchain_checker as bc
from app.services import sms_detector as sms

SECRET = "zz synthetic private text zz"
NO_MATCH = {"status": "no_match", "available": True, "found": False, "verdict": None,
            "threat_type": None, "confidence": None, "error": None}


def _model(label, available=True, error=None):
    probabilities = {c: (0.9 if c == label else 0.05) for c in sms.CLASSES} if available else None
    return {"available": available, "label": label if available else None, "probabilities": probabilities,
            "model_version": "sms_baseline/test" if available else None, "model_name": "x", "error": error}


@pytest.fixture
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    ensure_message_table(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


@pytest.fixture
def fresh_model_cache(monkeypatch):
    monkeypatch.setattr(sms, "_loaded", None)


# ── request validation ────────────────────────────────────────────────

class TestRequest:

    @pytest.mark.parametrize("text", ["", "   ", "\n\t"])
    def test_empty_or_blank_is_rejected(self, text):
        with pytest.raises(ValidationError):
            MessageScanRequest(text=text)

    def test_too_long_is_rejected(self):
        with pytest.raises(ValidationError):
            MessageScanRequest(text="a" * (MAX_MESSAGE_CHARS + 1))

    @pytest.mark.parametrize("payload", [{}, {"text": None}, {"text": 123}, {"message": "hi"}])
    def test_malformed_payload_is_rejected(self, payload):
        with pytest.raises(ValidationError):
            MessageScanRequest(**payload)


# ── SMS model service ─────────────────────────────────────────────────

class TestSmsDetector:

    def test_real_model_returns_known_class_and_probabilities(self, fresh_model_cache):
        result = sms.classify_message("Are we still meeting for lunch tomorrow?")

        assert result["available"] is True
        assert result["label"] in sms.CLASSES
        assert sum(result["probabilities"].values()) == pytest.approx(1.0)
        assert result["model_version"] == f"sms_baseline/{sms.MODEL_RUN}"

    def test_missing_model_is_unavailable_not_legitimate(self, fresh_model_cache, monkeypatch, tmp_path):
        monkeypatch.setattr(sms, "MODEL_DIR", tmp_path)

        result = sms.classify_message(SECRET)

        assert result["available"] is False and result["label"] is None
        assert "not found" in result["error"]

    def test_altered_model_file_is_refused(self, fresh_model_cache, monkeypatch, tmp_path):
        shutil.copy(sms.MODEL_DIR / "selection_frozen.json", tmp_path)
        (tmp_path / "model.joblib").write_bytes(b"not the pinned model")
        monkeypatch.setattr(sms, "MODEL_DIR", tmp_path)

        result = sms.classify_message(SECRET)

        assert result["available"] is False
        assert "pinned checksum" in result["error"]

    def test_inference_failure_is_reported_without_text(self, monkeypatch, caplog):
        class Broken:
            classes_ = list(sms.CLASSES)

            def predict_proba(self, _):
                raise RuntimeError(SECRET)

        monkeypatch.setattr(sms, "_loaded", (Broken(), {"model_version": "v", "model_name": "n", "model_sha256": "h"}))
        with caplog.at_level(logging.DEBUG):
            result = sms.classify_message(SECRET)

        assert result["available"] is False and result["error"] == "SMS model inference failed"
        assert SECRET not in caplog.text


# ── decision policy ───────────────────────────────────────────────────

class TestDecisionPolicy:

    @pytest.mark.parametrize("label, verdict, risk", [
        ("smishing", "likely_smishing", "MEDIUM"),
        ("generic_spam", "generic_spam", "LOW"),
        ("legitimate", "likely_legitimate", "LOW"),
    ])
    def test_each_model_class_maps_to_a_distinct_verdict(self, monkeypatch, label, verdict, risk):
        monkeypatch.setattr(route, "check_message_threat", lambda t: NO_MATCH)
        monkeypatch.setattr(route, "classify_message", lambda t: _model(label))

        result, _ = route.build_message_result("hello there")

        assert (result["verdict"], result["risk_level"], result["decision_source"]) == (verdict, risk, "ml")
        assert result["risk_level"] != "SAFE"

    def test_registry_threat_match_is_high_and_labelled_as_registry(self, monkeypatch):
        monkeypatch.setattr(route, "check_message_threat", lambda t: {**NO_MATCH, "status": "match_threat", "found": True})
        monkeypatch.setattr(route, "classify_message", lambda t: _model("legitimate"))

        result, _ = route.build_message_result("hello")

        assert result["verdict"] == "smishing_registry_match"
        assert result["risk_level"] == "HIGH" and result["decision_source"] == "blockchain"
        assert result["model"]["label"] == "legitimate"   # model evidence kept separate

    def test_non_threat_registry_entry_is_not_reported_as_threat(self, monkeypatch):
        monkeypatch.setattr(route, "check_message_threat", lambda t: {**NO_MATCH, "status": "match_non_threat"})
        monkeypatch.setattr(route, "classify_message", lambda t: _model("legitimate"))

        result, _ = route.build_message_result("hello")

        assert result["verdict"] == "likely_legitimate"

    def test_model_unavailable_is_unknown_never_safe(self, monkeypatch):
        monkeypatch.setattr(route, "check_message_threat", lambda t: NO_MATCH)
        monkeypatch.setattr(route, "classify_message", lambda t: _model(None, available=False, error="missing"))

        result, _ = route.build_message_result("hello")

        assert (result["verdict"], result["risk_level"]) == ("unavailable", "UNKNOWN")
        assert result["model"]["status"] == "error"

    def test_registry_unavailable_is_stated(self, monkeypatch):
        monkeypatch.setattr(route, "check_message_threat", lambda t: {**NO_MATCH, "status": "unavailable", "available": False, "error": "RPC endpoint is not configured"})
        monkeypatch.setattr(route, "classify_message", lambda t: _model("smishing"))

        result, _ = route.build_message_result("hello")

        assert "registry unavailable" in result["message"]
        assert result["registry"]["status"] == "unavailable"

    def test_link_finding_and_no_text_in_response(self, monkeypatch):
        monkeypatch.setattr(route, "check_message_threat", lambda t: NO_MATCH)
        monkeypatch.setattr(route, "classify_message", lambda t: _model("smishing"))
        text = f"{SECRET} visit http://bit.ly/abc urgent"

        result, has_url = route.build_message_result(text)

        assert has_url is True
        assert any("link" in f.lower() for f in result["findings"])
        assert SECRET not in repr(result)


# ── persistence ───────────────────────────────────────────────────────

class TestPersistence:

    def test_scan_persists_metadata_only(self, monkeypatch, db):
        monkeypatch.setattr(route, "check_message_threat", lambda t: NO_MATCH)
        monkeypatch.setattr(route, "classify_message", lambda t: _model("generic_spam"))

        result = route.scan_message(MessageScanRequest(text=SECRET), db=db)

        assert result["persisted"] is True and result["scan_id"] == 1
        history = route.message_history(db=db)
        assert history[0]["verdict"] == "generic_spam" and history[0]["message_length"] == len(SECRET)
        assert SECRET not in repr(history)
        columns = {c["name"] for c in inspect(db.get_bind()).get_columns("message_scans")}
        assert not {"text", "message", "message_hash", "content"} & columns

    def test_database_failure_is_reported_not_hidden(self, monkeypatch, db):
        monkeypatch.setattr(route, "check_message_threat", lambda t: NO_MATCH)
        monkeypatch.setattr(route, "classify_message", lambda t: _model("smishing"))
        monkeypatch.setattr(route, "save_message_scan", lambda *a: (_ for _ in ()).throw(RuntimeError("disk")))

        result = route.scan_message(MessageScanRequest(text="hi"), db=db)

        assert result["persisted"] is False
        assert "could not be saved" in result["message"]
        assert result["verdict"] == "likely_smishing"

    def test_message_table_is_separate_from_url_history(self):
        assert MessageScan.__tablename__ == "message_scans"
        assert "message_scans" in Base.metadata.tables and "scans" in Base.metadata.tables


# ── read-only registry lookup ─────────────────────────────────────────

class _FakeWeb3:
    """Minimal stand-in for web3.Web3: records view calls, cannot write."""

    calls = []

    def __init__(self, config):
        self._config = config
        self.eth = SimpleNamespace(chain_id=config["chain_id"], get_code=lambda a: config["code"],
                                   contract=self._contract)

    HTTPProvider = staticmethod(lambda url, request_kwargs=None: None)
    to_checksum_address = staticmethod(lambda a: a)

    def is_connected(self):
        return self._config["connected"]

    def _contract(self, address, abi):
        cfg = self._config

        def exists(h):
            _FakeWeb3.calls.append(h)
            return SimpleNamespace(call=lambda: cfg["exists"])

        def get(h):
            return SimpleNamespace(call=lambda: cfg["threat"])

        return SimpleNamespace(functions=SimpleNamespace(threatExists=exists, getThreat=get))


@pytest.fixture
def fake_chain(monkeypatch):
    def install(**overrides):
        config = {"connected": True, "chain_id": 11155111, "code": b"\x01", "exists": False,
                  "threat": (0, 1, 90, 0, "0x0")}
        config.update(overrides)
        _FakeWeb3.calls = []
        monkeypatch.setenv("SEPOLIA_RPC_URL", "http://fake.invalid")
        monkeypatch.setattr(bc, "Web3", type("W", (_FakeWeb3,), {"__init__": lambda self, p: _FakeWeb3.__init__(self, config)}))
    return install


class TestRegistryLookup:

    def test_no_rpc_configured_is_unavailable(self, monkeypatch):
        monkeypatch.delenv("SEPOLIA_RPC_URL", raising=False)
        monkeypatch.delenv("WEB3_PROVIDER_URI", raising=False)

        assert bc.check_message_threat("hello")["status"] == "unavailable"

    def test_wrong_chain_is_unavailable(self, fake_chain):
        fake_chain(chain_id=1)
        result = bc.check_message_threat("hello")
        assert result["status"] == "unavailable" and "does not match" in result["error"]

    def test_no_match(self, fake_chain):
        fake_chain(exists=False)
        assert bc.check_message_threat("hello")["status"] == "no_match"

    def test_message_threat_match_uses_keccak_message_hash(self, fake_chain):
        from src.blockchain.hashing import generate_message_hash
        fake_chain(exists=True, threat=(bc.THREAT_TYPE_MESSAGE, 1, 95, 0, "0x0"))

        result = bc.check_message_threat("Hello there")

        assert result["status"] == "match_threat"
        assert _FakeWeb3.calls == [bytes.fromhex(generate_message_hash("Hello there")[2:])]

    def test_non_threat_verdict(self, fake_chain):
        fake_chain(exists=True, threat=(bc.THREAT_TYPE_MESSAGE, 0, 50, 0, "0x0"))
        assert bc.check_message_threat("hello")["status"] == "match_non_threat"

    def test_wrong_threat_type_fails_closed(self, fake_chain):
        fake_chain(exists=True, threat=(bc.THREAT_TYPE_URL, 1, 95, 0, "0x0"))
        result = bc.check_message_threat("hello")
        assert result["status"] == "unavailable" and result["found"] is False

    def test_url_lookup_keeps_its_existing_fields(self, fake_chain):
        fake_chain(exists=True, threat=(bc.THREAT_TYPE_URL, 1, 90, 0, "0x0"))
        result = bc.check_blockchain_threat("https://example.com")
        assert result["available"] and result["found"] and result["verdict"] == 1
        assert result["status"] == "match_threat"

    def test_rpc_exception_is_unavailable(self, fake_chain, monkeypatch):
        fake_chain()
        monkeypatch.setattr(bc, "Web3", lambda p: (_ for _ in ()).throw(ConnectionError("down")))
        monkeypatch.setattr(bc.Web3, "HTTPProvider", lambda *a, **k: None, raising=False)
        assert bc.check_message_threat("hello")["status"] == "unavailable"

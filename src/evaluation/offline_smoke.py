"""Offline end-to-end smoke test for a fresh installation.

Exercises the real URL and SMS models (checksum-verified by the serving code)
through the real route functions, with:
- the blockchain registry MOCKED (miss / threat hit / unavailable) — no RPC,
  no transactions;
- a temporary SQLite database (the live chainshield.db is never opened);
- outbound network connections blocked for the whole run;
- only synthetic inputs (reserved .example domain, private IP, invented SMS).

    python -m src.evaluation.offline_smoke
    python src/evaluation/offline_smoke.py      # equivalent

Exit code 0 = every check passed. Expected verdicts were observed with the
pinned production models on 2026-10-29; a different model checksum is refused
by the serving code and reported as a failure here.
"""

from __future__ import annotations

import asyncio
import os
import socket
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

if __package__ in (None, ""):  # run as a file path: make the project root importable
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

BENIGN_URL = "https://www.wikipedia.org"
SHAPE_VARIANT_URL = "https://wikipedia.org"          # same site, no "www." (known false positive)
SYNTHETIC_PHISHING_URL = "http://192.168.1.1/secure/login.php?acct=1"  # private IP; pattern only
BENIGN_SMS = "Hi, are we still meeting for lunch at 1pm tomorrow?"
SYNTHETIC_SMISHING_SMS = ("URGENT: your bank account has been suspended. Verify your details now at "
                          "http://secure-bank-verify.example/login or it will be closed.")

_REGISTRY = {"available": True, "found": False, "verdict": None, "threat_type": None,
             "confidence": None, "error": None}
REGISTRY_MISS = {**_REGISTRY, "status": "no_match"}
REGISTRY_THREAT = {**_REGISTRY, "found": True, "verdict": 1, "threat_type": 1, "confidence": 90,
                   "status": "match_threat"}
REGISTRY_DOWN = {**_REGISTRY, "available": False, "status": "unavailable", "error": "mocked: no RPC"}


def _block_network():
    def refuse(self, address, *args, **kwargs):
        if self.family == socket.AF_UNIX:
            return _connect(self, address, *args, **kwargs)
        raise OSError(f"offline smoke test: network connection to {address!r} blocked")

    _connect = socket.socket.connect
    socket.socket.connect = refuse
    socket.create_connection = lambda *a, **k: (_ for _ in ()).throw(
        OSError("offline smoke test: network blocked"))


def main() -> int:
    workdir = Path(tempfile.mkdtemp(prefix="chainshield-smoke-"))
    os.environ["CHAINSHIELD_DATABASE_URL"] = f"sqlite:///{workdir / 'smoke.db'}"
    for name in ("SEPOLIA_RPC_URL", "WEB3_PROVIDER_URI", "SIGNER_PRIVATE_KEY", "ETH_PRIVATE_KEY"):
        os.environ.pop(name, None)
    precheck_env = os.environ.pop("CHAINSHIELD_REPUTATION_PRECHECK", None)
    _block_network()

    import app.server as server
    from app.database.database import SessionLocal
    from app.routes import message as message_route
    from app.routes import scan as scan_route
    from app.schemas.message import MessageScanRequest
    from app.schemas.scan import ScanRequest
    from app.services import ml_detector, reputation_precheck, sms_detector

    async def startup():
        async with server.app.router.lifespan_context(server.app):
            pass
    asyncio.run(startup())

    results = []

    def check(name, condition, detail=""):
        results.append((name, bool(condition), detail))

    def scan_url(url, registry):
        db = SessionLocal()
        try:
            with patch.object(scan_route, "check_blockchain_threat", return_value=registry):
                return scan_route.scan_url(ScanRequest(url=url), db=db)
        finally:
            db.close()

    def scan_sms(text, registry):
        db = SessionLocal()
        try:
            with patch.object(message_route, "check_message_threat", return_value=registry):
                return message_route.scan_message(MessageScanRequest(text=text), db=db)
        finally:
            db.close()

    # Models load through their checksum gates.
    try:
        ml_detector._load_model()
        check("URL model loads (pinned SHA-256 verified)", True, ml_detector.MODEL_SHA256[:12])
    except Exception as error:
        check("URL model loads (pinned SHA-256 verified)", False, str(error))
    try:
        sms_detector._load()
        check("SMS model loads (pinned SHA-256 verified)", True, sms_detector.MODEL_SHA256[:12])
    except Exception as error:
        check("SMS model loads (pinned SHA-256 verified)", False, str(error))

    check("Reputation pre-check disabled by default", not reputation_precheck.is_enabled(),
          "env var was set and ignored for this run" if precheck_env else "")

    r = scan_url(BENIGN_URL, REGISTRY_MISS)
    check("URL benign + registry miss -> ML fallback, SAFE",
          r["decision_source"] == "ml" and r["ml_label"] == "legitimate" and r["risk_level"] == "SAFE",
          f"{r['risk_level']} p={r['ml_probability']:.3f}")

    r = scan_url(BENIGN_URL, REGISTRY_DOWN)
    check("URL benign + registry unavailable -> UNKNOWN (never SAFE)", r["risk_level"] == "UNKNOWN",
          r["risk_level"])

    r = scan_url(SYNTHETIC_PHISHING_URL, REGISTRY_MISS)
    check("URL synthetic phishing pattern + miss -> ML phishing, HIGH via heuristics",
          r["ml_label"] == "phishing" and r["risk_level"] == "HIGH" and r["decision_source"] == "ml",
          f"{r['risk_level']} findings={len(r['findings'])}")

    with patch.object(scan_route, "predict_phishing") as model:
        r = scan_url(BENIGN_URL, REGISTRY_THREAT)
    check("URL registry threat hit -> HIGH from blockchain, model not consulted",
          r["risk_level"] == "HIGH" and r["decision_source"] == "blockchain" and not model.called,
          r["risk_level"])

    r = scan_url(SHAPE_VARIANT_URL, REGISTRY_MISS)
    check("URL-shape known issue reproduced (no www -> advisory phishing, MEDIUM, explained)",
          r["ml_label"] == "phishing" and r["risk_level"] == "MEDIUM"
          and scan_route.ML_PHISHING_ADVISORY in r["findings"]
          and any("unvalidated" in f for f in r["findings"]),
          f"{r['risk_level']} p={r['ml_probability']:.4f}")

    r = scan_sms(BENIGN_SMS, REGISTRY_MISS)
    check("SMS benign + miss -> likely_legitimate, LOW (not SAFE)",
          r["verdict"] == "likely_legitimate" and r["risk_level"] == "LOW", r["verdict"])

    r = scan_sms(SYNTHETIC_SMISHING_SMS, REGISTRY_MISS)
    check("SMS synthetic smishing + miss -> likely_smishing, MEDIUM",
          r["verdict"] == "likely_smishing" and r["risk_level"] == "MEDIUM", r["verdict"])

    r = scan_sms(BENIGN_SMS, REGISTRY_THREAT)
    check("SMS registry threat hit -> smishing_registry_match, HIGH",
          r["verdict"] == "smishing_registry_match" and r["risk_level"] == "HIGH", r["verdict"])

    db = SessionLocal()
    try:
        url_history = scan_route.scan_history(db=db)
        sms_history = message_route.message_history(db=db)
    finally:
        db.close()
    check("History persisted to the temporary database", len(url_history) == 5 and len(sms_history) == 3,
          f"url={len(url_history)} sms={len(sms_history)}")
    check("SMS history stores no message text",
          BENIGN_SMS not in repr(sms_history) and SYNTHETIC_SMISHING_SMS not in repr(sms_history))

    width = max(len(name) for name, _, _ in results)
    for name, ok, detail in results:
        print(f"{'PASS' if ok else 'FAIL'}  {name.ljust(width)}  {detail}")
    failed = sum(not ok for _, ok, _ in results)
    print(f"\n{len(results) - failed}/{len(results)} checks passed; temp dir {workdir}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

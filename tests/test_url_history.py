"""URL history registry status (2026-10-28).

In-memory or temporary SQLite only; the live chainshield.db is never opened.
"""

import sqlite3

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import database as db_module
from app.database.database import Base
from app.database.models import Scan
from app.services.scan_database import get_scans, history_blockchain_status, save_scan


def _result(status, available, found):
    return {
        "url": "https://example.com/", "status": "processed", "message": "m", "protocol": "https",
        "domain": "example.com", "path": "/", "https": True, "uses_ip": False, "risk_level": "UNKNOWN",
        "findings": [], "decision_source": "ml", "blockchain_available": available,
        "blockchain_found": found, "blockchain_status": status, "ml_available": True,
        "ml_probability": 0.1, "ml_label": "legitimate", "ml_model_name": "xgboost",
    }


@pytest.fixture
def session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine, tables=[Scan.__table__])
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


@pytest.mark.parametrize("status, available, found", [
    ("match_threat", True, True),
    ("match_non_threat", True, True),
    ("no_match", True, False),
    ("unavailable", False, False),
])
def test_new_scans_keep_their_exact_registry_status(session, status, available, found):
    save_scan(session, _result(status, available, found))

    history = get_scans(session)

    assert history[-1]["blockchain_status"] == status
    # Original fields are unchanged and still returned.
    assert history[-1]["blockchain_available"] is available
    assert history[-1]["blockchain_found"] is found


def test_registered_non_threat_is_not_reported_as_threat_in_history(session):
    save_scan(session, _result("match_non_threat", True, True))

    assert get_scans(session)[-1]["blockchain_status"] != "match_threat"


@pytest.mark.parametrize("available, found, expected", [
    (None, None, "not_recorded"),
    (False, False, "unavailable"),
    (True, False, "no_match"),
    (True, True, "match_unclassified"),   # verdict unknown: never treated as a threat
])
def test_legacy_rows_are_classified_conservatively(session, available, found, expected):
    save_scan(session, _result(None, available, found))

    status = get_scans(session)[-1]["blockchain_status"]

    assert status == expected
    assert status != "match_threat"


def test_history_status_helper_prefers_the_stored_value():
    row = type("Row", (), {"blockchain_status": "match_threat", "blockchain_available": False,
                           "blockchain_found": False})()
    assert history_blockchain_status(row) == "match_threat"


def test_migration_adds_column_and_keeps_existing_rows(tmp_path, monkeypatch):
    path = tmp_path / "old.db"
    con = sqlite3.connect(path)
    con.execute(
        "CREATE TABLE scans (id INTEGER PRIMARY KEY, url VARCHAR, status VARCHAR, message VARCHAR, "
        "protocol VARCHAR, domain VARCHAR, path VARCHAR, https BOOLEAN, uses_ip BOOLEAN, "
        "risk_level VARCHAR, findings TEXT, decision_source VARCHAR, blockchain_available BOOLEAN, "
        "blockchain_found BOOLEAN, ml_available BOOLEAN, ml_probability FLOAT, ml_label VARCHAR, "
        "ml_model_name VARCHAR)"
    )
    con.execute("INSERT INTO scans (id, url, status, message, protocol, domain, path, https, uses_ip, "
                "risk_level, findings, blockchain_available, blockchain_found) VALUES "
                "(1, 'https://example.com/', 'processed', 'm', 'https', 'example.com', '/', 1, 0, "
                "'SAFE', '[]', 1, 1)")
    con.commit()
    con.close()

    engine = create_engine(f"sqlite:///{path}")
    monkeypatch.setattr(db_module, "engine", engine)
    db_module.ensure_schema()

    columns = [r[1] for r in sqlite3.connect(path).execute("PRAGMA table_info(scans)")]
    assert "blockchain_status" in columns
    history = get_scans(sessionmaker(bind=engine)())
    assert len(history) == 1
    assert history[0]["blockchain_status"] == "match_unclassified"
    db_module.ensure_schema()   # idempotent

"""Entry point and database-initialization regression tests.

Each check runs in a subprocess with CHAINSHIELD_DATABASE_URL pointing at a
temporary file and the working directory set to a temporary folder, so the live
chainshield.db is never opened.
"""
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _run(code: str, cwd: Path, db_url: str | None) -> str:
    env = {k: v for k, v in os.environ.items()
           if k not in ("CHAINSHIELD_DATABASE_URL", "SEPOLIA_RPC_URL", "WEB3_PROVIDER_URI")}
    env["PYTHONPATH"] = str(PROJECT_ROOT)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    if db_url:
        env["CHAINSHIELD_DATABASE_URL"] = db_url
    done = subprocess.run([sys.executable, "-c", code], cwd=cwd, env=env,
                          capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr
    return done.stdout


def test_importing_the_app_does_not_touch_the_database(tmp_path):
    db = tmp_path / "isolated.db"
    _run("import app.server", tmp_path, f"sqlite:///{db}")
    assert not db.exists()
    assert not (tmp_path / "chainshield.db").exists()


def test_full_app_registers_every_documented_route(tmp_path):
    out = _run(
        "import app.server as s\n"
        "print(sorted((p, m.upper()) for p, ops in s.app.openapi()['paths'].items() for m in ops))",
        tmp_path, f"sqlite:///{tmp_path / 'isolated.db'}")
    for route in [("/", "GET"), ("/scan", "POST"), ("/scan/history", "GET"),
                  ("/message/scan", "POST"), ("/message/history", "GET")]:
        assert repr(route) in out


def test_url_only_app_lacks_message_routes(tmp_path):
    # Documents why the server must run app.server:app, not main:app.
    out = _run("import main\nprint(sorted(main.app.openapi()['paths']))",
               tmp_path, f"sqlite:///{tmp_path / 'isolated.db'}")
    assert "'/scan'" in out and "/message/scan" not in out


def test_startup_creates_schema_in_configured_database(tmp_path):
    db = tmp_path / "isolated.db"
    _run(
        "import asyncio, app.server as s\n"
        "async def go():\n"
        "    async with s.app.router.lifespan_context(s.app):\n"
        "        pass\n"
        "asyncio.run(go())",
        tmp_path, f"sqlite:///{db}")
    with sqlite3.connect(db) as con:
        tables = {r[0] for r in con.execute("select name from sqlite_master where type='table'")}
        columns = {r[1] for r in con.execute("pragma table_info(scans)")}
    assert {"scans", "message_scans"} <= tables
    assert "blockchain_status" in columns
    assert not (tmp_path / "chainshield.db").exists()


def test_default_database_is_anchored_to_project_root(tmp_path):
    out = _run("from app.database.database import DATABASE_URL\nprint(DATABASE_URL)", tmp_path, None)
    assert out.strip() == f"sqlite:///{PROJECT_ROOT / 'chainshield.db'}"

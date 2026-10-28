"""Full ChainShield API: the existing URL app plus message scanning.

    uvicorn app.server:app --host 127.0.0.1 --port 8000

main.py provides /, /scan and /scan/history; their behavior is unchanged
(main.py now runs schema setup at startup instead of at import). This module adds /message/scan and /message/history
and, at server startup, creates the metadata-only message_scans table if it is
missing (additive; no existing table is changed).
"""
from app.database.message_models import ensure_message_table
from app.routes.message import router as message_router
from main import STARTUP_HOOKS, app

app.include_router(message_router)

STARTUP_HOOKS.append(ensure_message_table)

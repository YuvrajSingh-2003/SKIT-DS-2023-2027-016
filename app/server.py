"""Full ChainShield API: the existing URL app plus message scanning.

    uvicorn app.server:app --host 127.0.0.1 --port 8000

main.py (frozen in Stage 0) is imported unchanged, so /, /scan and /scan/history
behave exactly as before. This module adds /message/scan and /message/history
and creates the metadata-only message_scans table if it is missing (additive;
no existing table is changed).
"""
from app.database.message_models import ensure_message_table
from app.routes.message import router as message_router
from main import app

app.include_router(message_router)

ensure_message_table()

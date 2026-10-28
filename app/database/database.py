import logging
import os
from pathlib import Path

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker, declarative_base

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Anchored to the project root so the database does not depend on the working
# directory. CHAINSHIELD_DATABASE_URL overrides it (e.g. an isolated test database).
DATABASE_URL = os.getenv(
    "CHAINSHIELD_DATABASE_URL", f"sqlite:///{PROJECT_ROOT / 'chainshield.db'}"
)

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()
from app.database import models

# Columns added after the first release. create_all does not alter existing
# tables, so they are added explicitly. Old rows keep NULL for these columns.
ADDED_SCAN_COLUMNS = {
    "decision_source": "VARCHAR",
    "blockchain_available": "BOOLEAN",
    "blockchain_found": "BOOLEAN",
    "blockchain_status": "VARCHAR",
    "ml_available": "BOOLEAN",
    "ml_probability": "FLOAT",
    "ml_label": "VARCHAR",
    "ml_model_name": "VARCHAR",
}


def ensure_schema():
    """Create tables and add any missing scan columns."""
    Base.metadata.create_all(bind=engine)

    existing = {column["name"] for column in inspect(engine).get_columns("scans")}

    with engine.begin() as connection:
        for name, sql_type in ADDED_SCAN_COLUMNS.items():
            if name not in existing:
                logger.info("Adding scans.%s column", name)
                connection.execute(
                    text(f"ALTER TABLE scans ADD COLUMN {name} {sql_type}")
                )


import logging

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker, declarative_base

logger = logging.getLogger(__name__)

DATABASE_URL = "sqlite:///./chainshield.db"

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


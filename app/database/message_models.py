"""Message-scan history table (metadata only).

Kept in its own module so the frozen app/database/models.py is unchanged.
No message text and no hash of the text is stored: short messages could be
recovered from a hash by guessing.
"""
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String

from app.database.database import Base, engine


class MessageScan(Base):

    __tablename__ = "message_scans"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    verdict = Column(String, nullable=False)
    risk_level = Column(String, nullable=False)
    decision_source = Column(String, nullable=False)

    model_label = Column(String, nullable=True)
    model_version = Column(String, nullable=True)
    probability_legitimate = Column(Float, nullable=True)
    probability_generic_spam = Column(Float, nullable=True)
    probability_smishing = Column(Float, nullable=True)

    registry_status = Column(String, nullable=False)
    message_length = Column(Integer, nullable=False)
    has_url = Column(Boolean, nullable=False)


def ensure_message_table(bind=engine) -> None:
    """Create the message_scans table if it is missing. Additive; touches no other table."""
    MessageScan.__table__.create(bind=bind, checkfirst=True)

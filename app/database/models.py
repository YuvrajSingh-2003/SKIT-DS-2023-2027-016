from sqlalchemy import Column, Integer, String, Boolean, Float, Text
from app.database.database import Base


class Scan(Base):

    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)

    url = Column(String)
    status = Column(String)
    message = Column(String)

    protocol = Column(String)
    domain = Column(String)
    path = Column(String)

    https = Column(Boolean)
    uses_ip = Column(Boolean)

    risk_level = Column(String)

    findings = Column(Text)

    # Decision and component state. NULL in rows saved before these columns existed.
    decision_source = Column(String, nullable=True)
    blockchain_available = Column(Boolean, nullable=True)
    blockchain_found = Column(Boolean, nullable=True)
    # match_threat | match_non_threat | no_match | unavailable. NULL in rows saved
    # before this column existed (added 2026-10-28).
    blockchain_status = Column(String, nullable=True)
    ml_available = Column(Boolean, nullable=True)
    ml_probability = Column(Float, nullable=True)
    ml_label = Column(String, nullable=True)
    ml_model_name = Column(String, nullable=True)

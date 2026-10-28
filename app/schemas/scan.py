from typing import Optional

from pydantic import BaseModel, HttpUrl


class ScanRequest(BaseModel):

    url: HttpUrl


class ScanResponse(BaseModel):

    url: str
    status: str
    message: str
    protocol: str
    domain: str
    path: str
    https: bool
    uses_ip: bool
    risk_level: str
    findings: list[str]

    # Which component produced the decision: "blockchain", "ml" or "unavailable".
    decision_source: str = "unavailable"

    blockchain_available: bool = False
    blockchain_found: bool = False
    blockchain_error: Optional[str] = None
    # match_threat | match_non_threat | no_match | unavailable (added 2026-10-28; additive)
    blockchain_status: str = "unavailable"


    ml_available: bool = False
    ml_probability: Optional[float] = None
    ml_label: Optional[str] = None
    ml_model_name: Optional[str] = None
    ml_error: Optional[str] = None
    # not_run (registry threat decided) | error (model unavailable) | ok (added; additive)
    ml_status: Optional[str] = None

    # False when the scan completed but could not be written to history.
    persisted: bool = True

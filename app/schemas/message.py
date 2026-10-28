from typing import Optional

from pydantic import BaseModel, Field, field_validator

MAX_MESSAGE_CHARS = 2000


class MessageScanRequest(BaseModel):

    text: str = Field(..., min_length=1, max_length=MAX_MESSAGE_CHARS)

    @field_validator("text")
    @classmethod
    def not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("text must not be blank")
        return value


class ModelResult(BaseModel):

    # "ok" (prediction made), "error" (model unavailable or failed).
    status: str
    label: Optional[str] = None            # legitimate | generic_spam | smishing
    probabilities: Optional[dict[str, float]] = None
    model_version: Optional[str] = None
    model_name: Optional[str] = None
    error: Optional[str] = None


class RegistryResult(BaseModel):

    # match_threat | match_non_threat | no_match | unavailable
    status: str
    error: Optional[str] = None


class MessageScanResponse(BaseModel):

    status: str = "processed"
    # smishing_registry_match | likely_smishing | generic_spam | likely_legitimate | unavailable
    verdict: str
    # HIGH (registry match) | MEDIUM | LOW | UNKNOWN. Never SAFE: a model is not proof.
    risk_level: str
    decision_source: str                    # blockchain | ml | unavailable
    message: str
    model: ModelResult
    registry: RegistryResult
    findings: list[str]
    limitations: list[str]
    message_length: int
    scan_id: Optional[int] = None
    persisted: bool = False


class MessageHistoryItem(BaseModel):

    id: int
    created_at: str
    verdict: str
    risk_level: str
    decision_source: str
    model_label: Optional[str] = None
    model_version: Optional[str] = None
    probability_legitimate: Optional[float] = None
    probability_generic_spam: Optional[float] = None
    probability_smishing: Optional[float] = None
    registry_status: str
    message_length: int
    has_url: bool

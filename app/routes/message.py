"""POST /message/scan and GET /message/history.

Decision policy (registry first, model second, never SAFE):
  registry match_threat         -> verdict smishing_registry_match, HIGH, source blockchain
  model smishing                -> likely_smishing, MEDIUM, source ml
  model generic_spam            -> generic_spam, LOW, source ml (not smishing)
  model legitimate              -> likely_legitimate, LOW, source ml (not proof of safety)
  model unavailable, no match   -> unavailable, UNKNOWN (never treated as safe)

The message is held in memory only for the request. It is not logged, not
persisted and never sent anywhere except as a Keccak-256 hash in a read-only
registry view call.
"""
import logging

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.dependencies import get_db
from app.schemas.message import MessageHistoryItem, MessageScanRequest, MessageScanResponse
from app.services.blockchain_checker import STATUS_MATCH_THREAT, check_message_threat
from app.services.message_database import get_message_scans, save_message_scan
from app.services.sms_detector import classify_message
from src.text_features import extract_text_features, extract_url_features

router = APIRouter()
logger = logging.getLogger(__name__)

LIMITATIONS = [
    "Model predictions can be wrong; they are not proof that a message is or is not a scam.",
    "The model was trained on a small English dataset (Mishra & Soni, 2022) and missed many "
    "newer scam styles in external testing, including all 'hey mum/dad' conversational scams.",
    "A registry miss does not mean the message is safe; the registry holds only known hashes.",
    "Links inside the message are not scanned here; check them with the URL scanner.",
]

_MODEL_VERDICTS = {
    "smishing": ("likely_smishing", "MEDIUM", "Model classifies this message as likely smishing"),
    "generic_spam": ("generic_spam", "LOW", "Model classifies this message as generic spam, not smishing"),
    "legitimate": ("likely_legitimate", "LOW", "Model classifies this message as likely legitimate"),
}


def _findings(text: str) -> tuple:
    url = extract_url_features(text)
    words = extract_text_features(text)
    findings = []
    if url["has_url"]:
        findings.append("Contains a link (scan it separately with the URL scanner)")
    if url["shortener_used"]:
        findings.append("Uses a URL shortener")
    if url["ip_as_domain"]:
        findings.append("Link uses an IP address instead of a domain")
    if words["has_urgent_word"]:
        findings.append("Contains urgency wording")
    if words["has_money_word"]:
        findings.append("Mentions money or payment")
    return findings, bool(url["has_url"])


def build_message_result(text: str) -> tuple:
    """Return (response dict, has_url). Pure decision logic, no HTTP or database."""
    registry = check_message_threat(text)
    model = classify_message(text)
    findings, has_url = _findings(text)

    model_part = {
        "status": "ok" if model["available"] else "error",
        "label": model["label"],
        "probabilities": model["probabilities"],
        "model_version": model["model_version"],
        "model_name": model["model_name"],
        "error": model["error"],
    }

    if registry["status"] == STATUS_MATCH_THREAT:
        verdict, risk, source = "smishing_registry_match", "HIGH", "blockchain"
        message = "This exact message (after canonicalization) is registered as a known threat"
    elif model["available"]:
        verdict, risk, message = _MODEL_VERDICTS[model["label"]]
        source = "ml"
    else:
        verdict, risk, source = "unavailable", "UNKNOWN", "unavailable"
        message = "Detection unavailable: the message model could not run; this is not a safety verdict"

    if registry["status"] == "unavailable":
        message += "; threat registry unavailable during this scan"

    response = {
        "status": "processed",
        "verdict": verdict,
        "risk_level": risk,
        "decision_source": source,
        "message": message,
        "model": model_part,
        "registry": {"status": registry["status"], "error": registry["error"]},
        "findings": findings,
        "limitations": LIMITATIONS,
        "message_length": len(text),
        "scan_id": None,
        "persisted": False,
    }
    return response, has_url


@router.post("/message/scan", response_model=MessageScanResponse)
def scan_message(request: MessageScanRequest, db: Session = Depends(get_db)):
    result, has_url = build_message_result(request.text)

    try:
        scan = save_message_scan(db, result, has_url)
        result["scan_id"] = scan.id
        result["persisted"] = True
    except Exception:
        logger.error("Failed to persist message scan metadata")
        db.rollback()
        result["message"] += "; result could not be saved to history"

    return result


@router.get("/message/history", response_model=list[MessageHistoryItem])
def message_history(db: Session = Depends(get_db)):
    return get_message_scans(db)

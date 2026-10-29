import logging
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.schemas.scan import ScanRequest, ScanResponse
from app.services.url_processor import process_url
from app.services.blockchain_checker import check_blockchain_threat
from app.services.ml_detector import predict_phishing
from app.services import reputation_precheck
from app.services.security_checker import (
    check_url_security,
    calculate_risk_level,
)
from app.services.scan_database import save_scan, get_scans
from app.database.dependencies import get_db

router = APIRouter()
logger = logging.getLogger(__name__)

DECISION_BLOCKCHAIN = "blockchain"
DECISION_ML = "ml"
DECISION_UNAVAILABLE = "unavailable"

ML_STATUS_NOT_RUN = "not_run"
ML_STATUS_ERROR = "error"
ML_STATUS_OK = "ok"

# The URL model is advisory: on its own it can raise risk to MEDIUM, never HIGH.
# Evidence: its training data has a fixed template for legitimate URLs (see
# docs/datasets.md), so a "phishing" prediction is not reliable enough for HIGH.
ML_PHISHING_ADVISORY = "URL model predicts phishing (advisory; not a confirmed threat)"

REGISTRY_UNAVAILABLE_NOTE = (
    "Threat registry unavailable and no threat signal found; result is inconclusive, "
    "not safe (unavailable service, not threat evidence)"
)

# Only reachable when the disabled-by-default reputation pre-check applies.
REPUTATION_PRECHECK_NOTE = (
    "Bare homepage of a domain on the configured reputation list; the URL "
    "model's phishing advisory was not applied (popularity is not a safety "
    "verdict; registry and heuristic checks still apply)"
)

PATH_OR_QUERY_NOTE = (
    "URL has a path or query string; the URL model was trained on "
    "data where legitimate URLs never have one, so its prediction "
    "for this URL is unreliable"
)


# The URL model's legitimate training class is 100% https://www.<host> with no path
# (docs/url_shape_guard.md). Its "phishing" label for any other shape is unvalidated:
# e.g. https://example.com/ scores 0.9998 while https://www.example.com/ scores 0.012.
# The verdict is unchanged (suppressing it would also hide ~45% of current phishing
# feed URLs); the note tells the user why the flag is weak evidence.
URL_SHAPE_NOTE = (
    "The URL model flagged this URL, but its {reasons}; the model was trained on data "
    "where every legitimate URL is https://www.<host>, so for this URL shape the flag "
    "is unvalidated and is not evidence of phishing on its own"
)


def _untrained_shape_reasons(url: str) -> list[str]:
    """Ways the scheme/host differ from the model's only legitimate training shape.

    Path and query are covered separately by PATH_OR_QUERY_NOTE.
    """
    parsed = urlparse(url)
    reasons = []
    if not (parsed.hostname or "").lower().startswith("www."):
        reasons.append("host has no 'www.' prefix")
    if parsed.scheme.lower() != "https":
        reasons.append("scheme is not HTTPS")
    return reasons


def _unavailable_blockchain_result(error: str | None = None) -> dict:
    return {
        "status": "unavailable",
        "available": False,
        "found": False,
        "verdict": None,
        "threat_type": None,
        "confidence": None,
        "error": error,
    }


def _lookup_blockchain(url: str) -> dict:
    """Read-only registry lookup. Never raises."""
    try:
        return check_blockchain_threat(url)
    except Exception:
        logger.exception("Unexpected blockchain lookup failure")
        return _unavailable_blockchain_result("Blockchain lookup failed")


def _has_path_or_query(url: str) -> bool:
    parsed = urlparse(url)
    return bool(parsed.path.strip("/") or parsed.query)


def _build_scan_result(url: str) -> dict:
    processed_url = process_url(url)
    security_result = check_url_security(url)
    findings = list(security_result["findings"])

    blockchain_result = _lookup_blockchain(url)
    blockchain_threat = (
        blockchain_result.get("available", False)
        and blockchain_result.get("found", False)
        and blockchain_result.get("verdict") == 1
    )

    ml_result = {
        "available": False,
        "probability": None,
        "label": None,
        "model_name": None,
        "error": None,
    }

    if blockchain_threat:
        # A confirmed registry match is decisive; the model is not consulted.
        decision_source = DECISION_BLOCKCHAIN
        ml_status = ML_STATUS_NOT_RUN
        findings.append("Blockchain registry identifies this URL as a threat")
        risk_level = "HIGH"
        message = "URL matched a known threat in the blockchain registry"
    else:
        # Registry miss or registry unavailable: fall back to the model.
        ml_result = predict_phishing(url)

        if ml_result["available"]:
            decision_source = DECISION_ML
            ml_status = ML_STATUS_OK
            # Heuristics set the base level (computed before advisory notes are added).
            risk_level = calculate_risk_level(findings)
            if ml_result["label"] == "phishing":
                if reputation_precheck.evaluate(url)["applies"]:
                    # The advisory is withheld, but popularity never earns SAFE.
                    if risk_level == "SAFE":
                        risk_level = "UNKNOWN"
                    findings.append(REPUTATION_PRECHECK_NOTE)
                else:
                    if risk_level == "SAFE":
                        risk_level = "MEDIUM"
                    findings.append(ML_PHISHING_ADVISORY)
                    reasons = _untrained_shape_reasons(url)
                    if reasons:
                        findings.append(URL_SHAPE_NOTE.format(reasons=" and ".join(reasons)))
            message = "URL processed; URL model prediction is advisory, not a confirmed threat"
            # SAFE needs the registry check. With the registry unavailable, "no heuristic
            # findings + advisory model says legitimate" is not enough reassurance, so the
            # result is UNKNOWN. This only ever withholds SAFE; it never lowers a risk level.
            if risk_level == "SAFE" and not blockchain_result.get("available", False):
                risk_level = "UNKNOWN"
                findings.append(REGISTRY_UNAVAILABLE_NOTE)
            if _has_path_or_query(url):
                findings.append(PATH_OR_QUERY_NOTE)
        else:
            # A failed model must never be reported as SAFE.
            decision_source = DECISION_UNAVAILABLE
            ml_status = ML_STATUS_ERROR
            risk_level = "UNKNOWN"
            message = (
                "URL processed; URL model unavailable, result is not a "
                "safety verdict"
            )

    if not blockchain_result.get("available", False):
        message += "; blockchain registry unavailable during this scan"

    return {
        "url": url,
        "status": "processed",
        "message": message,
        "protocol": processed_url["protocol"],
        "domain": processed_url["domain"],
        "path": processed_url["path"],
        "https": security_result["https"],
        "uses_ip": security_result["uses_ip"],
        "risk_level": risk_level,
        "findings": findings,
        "decision_source": decision_source,
        "blockchain_available": blockchain_result.get("available", False),
        "blockchain_found": blockchain_result.get("found", False),
        "blockchain_error": blockchain_result.get("error"),
        # Explicit registry outcome. blockchain_found keeps its original meaning
        # (hash registered, any verdict); only match_threat means a known threat.
        "blockchain_status": blockchain_result.get("status", "unavailable"),
        "ml_status": ml_status,
        "ml_available": ml_result["available"],
        "ml_probability": ml_result["probability"],
        "ml_label": ml_result["label"],
        "ml_model_name": ml_result["model_name"],
        "ml_error": ml_result["error"],
    }


@router.post("/scan", response_model=ScanResponse)
def scan_url(
    request: ScanRequest,
    db: Session = Depends(get_db),
):
    logger.info("Scan request received")

    url = str(request.url)

    try:
        result = _build_scan_result(url)
    except Exception:
        logger.exception("Error while processing URL")
        raise HTTPException(
            status_code=500,
            detail="An error occurred while processing the URL",
        )

    # Persistence failures are reported explicitly; the scan result is still returned.
    try:
        save_scan(db, result)
        result["persisted"] = True
    except Exception:
        logger.exception("Failed to persist scan result")
        db.rollback()
        result["persisted"] = False
        result["message"] += "; result could not be saved to history"

    return result


@router.get("/scan/history")
def scan_history(
    db: Session = Depends(get_db),
):
    return get_scans(db)

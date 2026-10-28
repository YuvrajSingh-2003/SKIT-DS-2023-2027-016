import json

from sqlalchemy.orm import Session

from app.database.models import Scan


def save_scan(db: Session, result: dict):

    scan = Scan(
        url=result["url"],
        status=result["status"],
        message=result["message"],
        protocol=result["protocol"],
        domain=result["domain"],
        path=result["path"],
        https=result["https"],
        uses_ip=result["uses_ip"],
        risk_level=result["risk_level"],
        findings=json.dumps(result["findings"]),
        decision_source=result.get("decision_source"),
        blockchain_available=result.get("blockchain_available"),
        blockchain_found=result.get("blockchain_found"),
        blockchain_status=result.get("blockchain_status"),
        ml_available=result.get("ml_available"),
        ml_probability=result.get("ml_probability"),
        ml_label=result.get("ml_label"),
        ml_model_name=result.get("ml_model_name"),
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    return scan


def history_blockchain_status(scan) -> str:
    """Registry status for a history row.

    Rows saved since 2026-10-28 store the exact status. Older rows only have
    blockchain_available/blockchain_found, and blockchain_found does not say whether
    the registered entry was a threat, so it is never reported as match_threat:
      not_recorded        no registry information was saved
      unavailable         the registry could not be checked
      no_match            the registry was checked and had no entry
      match_unclassified  an entry existed but its verdict was not recorded
    """
    if scan.blockchain_status:
        return scan.blockchain_status
    if scan.blockchain_available is None:
        return "not_recorded"
    if not scan.blockchain_available:
        return "unavailable"
    if not scan.blockchain_found:
        return "no_match"
    return "match_unclassified"


def get_scans(db: Session):

    scans = db.query(Scan).order_by(Scan.id).all()

    results = []

    for scan in scans:

        results.append({
            "id": scan.id,
            "url": scan.url,
            "status": scan.status,
            "message": scan.message,
            "protocol": scan.protocol,
            "domain": scan.domain,
            "path": scan.path,
            "https": scan.https,
            "uses_ip": scan.uses_ip,
            "risk_level": scan.risk_level,
            "findings": json.loads(scan.findings),
            # NULL means the value was not recorded for this scan (older rows).
            "decision_source": scan.decision_source,
            "blockchain_available": scan.blockchain_available,
            "blockchain_found": scan.blockchain_found,
            "blockchain_status": history_blockchain_status(scan),
            "ml_available": scan.ml_available,
            "ml_probability": scan.ml_probability,
            "ml_label": scan.ml_label,
            "ml_model_name": scan.ml_model_name,
        })

    return results

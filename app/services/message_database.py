from sqlalchemy.orm import Session

from app.database.message_models import MessageScan


def save_message_scan(db: Session, result: dict, has_url: bool) -> MessageScan:
    probabilities = result["model"].get("probabilities") or {}
    scan = MessageScan(
        verdict=result["verdict"],
        risk_level=result["risk_level"],
        decision_source=result["decision_source"],
        model_label=result["model"].get("label"),
        model_version=result["model"].get("model_version"),
        probability_legitimate=probabilities.get("legitimate"),
        probability_generic_spam=probabilities.get("generic_spam"),
        probability_smishing=probabilities.get("smishing"),
        registry_status=result["registry"]["status"],
        message_length=result["message_length"],
        has_url=has_url,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def get_message_scans(db: Session, limit: int = 200) -> list[dict]:
    scans = db.query(MessageScan).order_by(MessageScan.id.desc()).limit(limit).all()
    return [
        {
            "id": s.id,
            "created_at": s.created_at.isoformat() if s.created_at else "",
            "verdict": s.verdict,
            "risk_level": s.risk_level,
            "decision_source": s.decision_source,
            "model_label": s.model_label,
            "model_version": s.model_version,
            "probability_legitimate": s.probability_legitimate,
            "probability_generic_spam": s.probability_generic_spam,
            "probability_smishing": s.probability_smishing,
            "registry_status": s.registry_status,
            "message_length": s.message_length,
            "has_url": s.has_url,
        }
        for s in scans
    ]

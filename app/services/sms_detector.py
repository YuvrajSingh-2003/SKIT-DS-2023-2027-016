"""SMS/message classification with the frozen Stage 2 baseline.

Classes: legitimate, generic_spam, smishing (kept distinct). The model is a
fitted scikit-learn Pipeline (TF-IDF + LogisticRegression); it is never refit
here. Because joblib loading can execute code, the file is loaded only when its
SHA-256 matches the pinned value from the run's frozen selection.

Failures are reported as available=False with an error. They never become a
'legitimate' prediction. Message text is never logged.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from pathlib import Path

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MODEL_RUN = "run-20261028T122841Z-seed42"
MODEL_DIR = PROJECT_ROOT / "models" / "sms_baseline" / MODEL_RUN
MODEL_SHA256 = "9f753dd5235537c77b046044a058592c9c64f791fc4608abce0d3eb0a5b85815"
CLASSES = ("legitimate", "generic_spam", "smishing")

_lock = threading.Lock()
_loaded = None  # (model, metadata)


class SmsModelUnavailable(RuntimeError):
    """The model artifact is missing, altered or unloadable."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load():
    global _loaded
    if _loaded is not None:
        return _loaded
    with _lock:
        if _loaded is not None:
            return _loaded

        model_path = MODEL_DIR / "model.joblib"
        frozen_path = MODEL_DIR / "selection_frozen.json"
        if not model_path.is_file() or not frozen_path.is_file():
            raise SmsModelUnavailable("SMS model artifact not found")
        if _sha256(model_path) != MODEL_SHA256:
            raise SmsModelUnavailable("SMS model artifact does not match its pinned checksum")

        try:
            frozen = json.loads(frozen_path.read_text(encoding="utf-8"))
            import joblib

            model = joblib.load(model_path)
        except Exception as error:
            logger.exception("Failed to load SMS model")
            raise SmsModelUnavailable("SMS model artifact could not be loaded") from error

        if set(getattr(model, "classes_", ())) != set(CLASSES):
            raise SmsModelUnavailable("SMS model classes do not match the expected classes")

        metadata = {
            "model_version": f"sms_baseline/{MODEL_RUN}",
            "model_name": frozen.get("selected", {}).get("name"),
            "model_sha256": MODEL_SHA256,
        }
        _loaded = (model, metadata)
        return _loaded


def classify_message(text: str) -> dict:
    """Classify one message.

    Returns {available, label, probabilities, model_version, model_name, error}.
    probabilities are the model's predict_proba values for each class; they
    are not calibrated real-world likelihoods.
    """
    result = {
        "available": False,
        "label": None,
        "probabilities": None,
        "model_version": None,
        "model_name": None,
        "error": None,
    }

    try:
        model, metadata = _load()
    except SmsModelUnavailable as error:
        result["error"] = str(error)
        return result

    result["model_version"] = metadata["model_version"]
    result["model_name"] = metadata["model_name"]

    try:
        probabilities = model.predict_proba([text])[0]
        classes = list(model.classes_)
    except Exception:
        logger.error("SMS model inference failed")  # no message content, no traceback with locals
        result["error"] = "SMS model inference failed"
        return result

    scores = {label: float(probabilities[classes.index(label)]) for label in CLASSES}
    result["available"] = True
    result["probabilities"] = scores
    result["label"] = max(CLASSES, key=lambda label: scores[label])
    return result


def model_status() -> dict:
    """Whether the SMS model can be loaded, without classifying anything."""
    try:
        _, metadata = _load()
        return {"available": True, **metadata}
    except SmsModelUnavailable as error:
        return {"available": False, "error": str(error)}

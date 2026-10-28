"""URL inference model used when the blockchain registry has no match.

The model is loaded lazily from models/url_inference/ (produced by
`python -m src.training.train_url_inference`). Missing artifacts and
inference failures are reported through the returned dict as
`available=False` with an `error`. They are never converted into a
safe prediction.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from pathlib import Path

import joblib
import pandas as pd

from src.features.url_lexical import (
    LEXICAL_URL_FEATURES,
    extract_lexical_url_dataframe,
)

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MODEL_DIRECTORY = PROJECT_ROOT / "models" / "url_inference"
MODEL_PATH = MODEL_DIRECTORY / "model.joblib"
METADATA_PATH = MODEL_DIRECTORY / "metadata.json"

# SHA-256 of the trained URL model (models/url_inference/model.joblib, trained
# 2026-10-28). joblib.load can execute code, so only this exact file is loaded.
# Retraining produces a new file; update this value only after verifying it.
MODEL_SHA256 = "2f2e1d492ec3bc96891df3c08d3e80ff158021f6321160e3d55a52707f2d2adc"

_load_lock = threading.Lock()
_loaded = None  # tuple(model, metadata) once loaded successfully


class ModelUnavailableError(RuntimeError):
    """The model artifact is missing or could not be loaded."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_model():
    """Load and cache the model and metadata. Raises ModelUnavailableError."""
    global _loaded

    if _loaded is not None:
        return _loaded

    with _load_lock:
        if _loaded is not None:
            return _loaded

        if not MODEL_PATH.is_file() or not METADATA_PATH.is_file():
            raise ModelUnavailableError(
                "URL model artifact not found; run "
                "`python -m src.training.train_url_inference`"
            )

        try:
            with open(METADATA_PATH, encoding="utf-8") as handle:
                metadata = json.load(handle)
        except Exception as error:
            logger.exception("Failed to read URL model metadata")
            raise ModelUnavailableError(
                "URL model metadata could not be read"
            ) from error

        if metadata.get("feature_names") != LEXICAL_URL_FEATURES:
            raise ModelUnavailableError(
                "URL model feature list does not match the feature code; "
                "retrain the model"
            )

        if _sha256(MODEL_PATH) != MODEL_SHA256:
            raise ModelUnavailableError(
                "URL model artifact does not match its pinned checksum"
            )
        if metadata.get("model_sha256") != MODEL_SHA256:
            raise ModelUnavailableError(
                "URL model metadata does not match the pinned model"
            )

        try:
            model = joblib.load(MODEL_PATH)
        except Exception as error:
            logger.exception("Failed to load URL model artifact")
            raise ModelUnavailableError(
                "URL model artifact could not be loaded"
            ) from error

        _loaded = (model, metadata)
        return _loaded


def predict_phishing(url: str) -> dict:
    """Return the phishing prediction for a URL.

    Returns:
        {
            "available": bool,
            "probability": float | None,   # phishing probability
            "label": "phishing" | "legitimate" | None,
            "threshold": float | None,
            "model_name": str | None,
            "error": str | None,
        }
    """
    result = {
        "available": False,
        "probability": None,
        "label": None,
        "threshold": None,
        "model_name": None,
        "error": None,
    }

    try:
        model, metadata = _load_model()
    except ModelUnavailableError as error:
        result["error"] = str(error)
        return result

    result["model_name"] = metadata.get("model_name")
    result["threshold"] = metadata.get("phishing_threshold")

    try:
        features = extract_lexical_url_dataframe(pd.Series([str(url)]))
        probability = float(model.predict_proba(features)[0][1])
    except Exception:
        logger.exception("URL model inference failed")
        result["error"] = "URL model inference failed"
        return result

    result["available"] = True
    result["probability"] = probability
    is_phishing = probability >= result["threshold"]
    result["label"] = "phishing" if is_phishing else "legitimate"

    return result


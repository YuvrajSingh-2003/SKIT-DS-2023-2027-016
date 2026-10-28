"""Source-specific dataset preparation for the SMS task (Stage 1.3).

Two datasets, two roles:

* Mishra & Soni (Mendeley DOI 10.17632/f45bkkt8pr.1): training-eligible. Every
  row of a normalized text that carries conflicting labels is excluded; no label
  is chosen or changed. Same-label duplicates are reduced to one row.
* IMC 2025 (Agarwal et al., "Fishing for Smishing"): external evaluation only.
  Its GPT-4o-assigned scam_type values are mapped to evaluation labels with the
  documented rationale in IMC_SCAM_TYPE_TREATMENT. It must never be used for
  training, validation, threshold selection, feature selection or tuning.

This module reuses the frozen Stage 0 helpers normalize_text and
standardize_label from clean.py without modifying them. It writes no files.
Errors and accounting contain counts, category names and row positions, never
message text.
"""
import hashlib
import json
from pathlib import Path

import pandas as pd

from src.data.clean import (
    NEAR_DUPLICATE_THRESHOLD,
    find_near_label_conflicts,
    normalize_text,
    standardize_label,
)

MISHRA_SONI_SOURCE = "mishra_soni"
MISHRA_SONI_COLUMNS = ("LABEL", "TEXT")

IMC_SOURCE = "imc2025"
# Only these columns are read. 'language' is not personal data and is needed to
# restrict evaluation to English. Sender, phone, network and named-entity columns
# are never read.
IMC_ALLOWED_COLUMNS = ("text", "scam_type", "language")
EXTERNAL_EVALUATION_SPLIT = "external_evaluation_only"
EVALUATION_ONLY_SOURCES = frozenset({IMC_SOURCE})

LABEL_PREVIEW_CHARS = 20

# Evaluation treatment of each exact IMC scam_type string, with the evidence used.
# Definitions quoted from the paper's annotation prompt (Appendix D.2) and §5.
# (evaluation_label, status, rationale)
IMC_SCAM_TYPE_TREATMENT = {
    "banking": (
        "smishing", "included_smishing",
        "D.2: impersonates a bank or financial institution and asks to click a link, "
        "text back or call",
    ),
    "delivery": (
        "smishing", "included_smishing",
        "D.2 'Delivery/Parcel': impersonates a delivery company and asks to click a "
        "link, text back or call",
    ),
    "government": (
        "smishing", "included_smishing",
        "D.2: impersonates a government organization and asks to click a link, text "
        "back or call",
    ),
    "telecom": (
        "smishing", "included_smishing",
        "D.2: impersonates a mobile network operator and asks to click a link, text "
        "back or call",
    ),
    "hey mum/dad": (
        "smishing", "included_smishing",
        "D.2: addressed to mum/dad, asks to text back citing a broken phone or new "
        "number; §5 describes these as conversational scams that deceive users into "
        "sending funds",
    ),
    "wrong number": (
        None, "excluded_unresolved",
        "D.2 defines it as a text that 'looks like a normal greeting or asking about "
        "someone and/or to reply back'; the per-row criterion does not establish scam "
        "intent, so genuine mistaken texts cannot be ruled out",
    ),
    "spam": (
        "generic_spam", "separate_generic_spam",
        "D.2: 'illicit marketing message including casino, betting, random draws'; "
        "evaluated separately, never as smishing or legitimate",
    ),
    "others": (
        None, "excluded_unresolved",
        "D.2: 'does not fit' the other categories; §5.2 reports it mixes several scam "
        "types with OTP messages that may be harmless",
    ),
}


# ── shared checks ─────────────────────────────────────────────────────

def _blank(series: pd.Series) -> pd.Series:
    return series.isna() | series.astype(str).str.strip().eq("")


TRAINING_ELIGIBLE_SOURCES = frozenset({MISHRA_SONI_SOURCE})


def text_fingerprint(text) -> str:
    """SHA-256 of the normalized text. Identifies a message without storing it."""
    return hashlib.sha256(normalize_text(text).encode("utf-8")).hexdigest()


# SHA-256 of the verified IMC 2025 file (docs/datasets.md). A manifest built from any
# other file is refused.
IMC_SOURCE_SHA256 = "1bbd1e9e82c3ea023112207b80da268a5c4a07d2353c2b0898360ab037fa9a64"
MANIFEST_VERSION = 2
FINGERPRINT_METHOD = "sha256(normalize_text(text))"
_HEX64 = set("0123456789abcdef")


def _digest_of(fingerprints) -> str:
    return hashlib.sha256("\n".join(sorted(fingerprints)).encode("ascii")).hexdigest()


def write_evaluation_manifest(frame: pd.DataFrame, path: Path, source_sha256: str = IMC_SOURCE_SHA256) -> None:
    """Write the evaluation-only manifest: source, split, file checksum and fingerprints.

    Covers every row read from the evaluation source, whatever its eval_status, so
    no IMC text can enter training. Contains hashes only, never text.
    """
    fingerprints = sorted({text_fingerprint(t) for t in frame["text"]})
    manifest = {
        "manifest_version": MANIFEST_VERSION,
        "source": IMC_SOURCE,
        "split": EXTERNAL_EVALUATION_SPLIT,
        "source_file_sha256": source_sha256,
        "fingerprint_method": FINGERPRINT_METHOD,
        "fingerprint_count": len(fingerprints),
        "fingerprints_sha256": _digest_of(fingerprints),
        "fingerprints": fingerprints,
    }
    Path(path).write_text(json.dumps(manifest, indent=1), encoding="utf-8")


def load_evaluation_fingerprints(path: Path, expected_source_sha256: str = IMC_SOURCE_SHA256) -> frozenset:
    """Load and validate an evaluation manifest. Any problem refuses training.

    Checks: file exists; version, source, split and method are the expected
    values; source_file_sha256 matches the verified IMC file; every fingerprint
    is 64 lowercase hex characters; the count and the digest of the list match.
    """
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"Evaluation manifest {path} not found; training is refused")
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError(f"Evaluation manifest {path} is malformed; training is refused") from None

    def refuse(reason):
        return ValueError(f"Evaluation manifest {path} is malformed ({reason}); training is refused")

    if not isinstance(manifest, dict):
        raise refuse("not an object")
    expected = {
        "manifest_version": MANIFEST_VERSION,
        "source": IMC_SOURCE,
        "split": EXTERNAL_EVALUATION_SPLIT,
        "fingerprint_method": FINGERPRINT_METHOD,
        "source_file_sha256": expected_source_sha256,
    }
    for key, value in expected.items():
        if manifest.get(key) != value:
            raise refuse(f"{key} mismatch")
    fingerprints = manifest.get("fingerprints")
    if not isinstance(fingerprints, list) or not fingerprints:
        raise refuse("no fingerprints")
    if any(not isinstance(f, str) or len(f) != 64 or not set(f) <= _HEX64 for f in fingerprints):
        raise refuse("invalid fingerprint")
    if manifest.get("fingerprint_count") != len(fingerprints) or len(set(fingerprints)) != len(fingerprints):
        raise refuse("fingerprint count mismatch")
    if manifest.get("fingerprints_sha256") != _digest_of(fingerprints):
        raise refuse("fingerprint digest mismatch")
    return frozenset(fingerprints)


def assert_training_eligible(df: pd.DataFrame, evaluation_fingerprints=frozenset()) -> None:
    """Raise unless every row is provably training-eligible.

    Fails closed: a 'source' column is required and every value must be in
    TRAINING_ELIGIBLE_SOURCES. Any row marked evaluation-only, and any row whose
    text matches an evaluation fingerprint, is rejected, so evaluation data is
    caught even after its provenance columns were removed or rewritten.
    """
    if "split" in df.columns and df["split"].eq(EXTERNAL_EVALUATION_SPLIT).any():
        raise ValueError("Frame contains external-evaluation-only rows; it cannot be used for training or validation")
    if "source" not in df.columns:
        raise ValueError("Frame has no 'source' column; provenance cannot be verified, so training is refused")
    sources = set(df["source"].dropna())
    blocked = sorted(sources & EVALUATION_ONLY_SOURCES)
    if blocked:
        raise ValueError(f"Source(s) {blocked} are evaluation-only and cannot be used for training or validation")
    if df["source"].isna().any() or not sources <= TRAINING_ELIGIBLE_SOURCES:
        unknown = sorted(str(s)[:30] for s in sources - TRAINING_ELIGIBLE_SOURCES)
        raise ValueError(f"Rows with missing or non-approved source(s) {unknown}; training is refused")
    if evaluation_fingerprints and "text" in df.columns:
        matches = int(df["text"].map(text_fingerprint).isin(evaluation_fingerprints).sum())
        if matches:
            raise ValueError(f"{matches} row(s) match evaluation-only texts; training is refused")


# ── Mishra & Soni ─────────────────────────────────────────────────────

def load_mishra_soni(path: Path) -> pd.DataFrame:
    """Read only the LABEL and TEXT columns of the Mishra & Soni CSV, unchanged."""
    return pd.read_csv(path, usecols=list(MISHRA_SONI_COLUMNS), dtype=str, encoding="utf-8")


def prepare_mishra_soni(raw: pd.DataFrame) -> tuple:
    """Apply the approved conflict and duplicate policy.

    1. Reject missing or blank text or label (fail closed, counts only).
    2. Map labels case-insensitively with standardize_label; unknown or
       unresolved labels fail closed with the row position.
    3. Normalize text with normalize_text.
    4. Exclude every row whose normalized text carries more than one canonical
       label. No winning label is chosen and no row is relabelled.
    5. Among the remaining rows, keep one row per normalized text: the row with
       the lowest source_row after a stable sort on (text, label, source_row).

    Returns (prepared_frame, accounting). The frame has columns text, label,
    source and source_row (0-based row in the original CSV). The input is not
    modified.
    """
    absent = [c for c in MISHRA_SONI_COLUMNS if c not in raw.columns]
    if absent:
        raise ValueError(f"{MISHRA_SONI_SOURCE}: missing column(s) {absent}")

    text_missing = _blank(raw["TEXT"])
    label_missing = _blank(raw["LABEL"])
    if text_missing.any() or label_missing.any():
        raise ValueError(
            f"{MISHRA_SONI_SOURCE}: {int(text_missing.sum())} row(s) with missing or blank text "
            f"and {int(label_missing.sum())} row(s) with missing or blank label"
        )

    labels = []
    for position, value in enumerate(raw["LABEL"]):
        try:
            labels.append(standardize_label(value))
        except ValueError:
            preview = str(value)[:LABEL_PREVIEW_CHARS]
            raise ValueError(
                f"{MISHRA_SONI_SOURCE}: row {position}: label {preview!r} has no verified mapping"
            ) from None

    frame = pd.DataFrame({
        "text": [normalize_text(text) for text in raw["TEXT"]],
        "label": labels,
        "source": MISHRA_SONI_SOURCE,
        "source_row": range(len(raw)),
    })

    labels_per_text = frame.groupby("text")["label"].nunique()
    conflicting_texts = set(labels_per_text[labels_per_text > 1].index)
    in_conflict = frame["text"].isin(conflicting_texts)

    # Near-duplicate conflicts: among the remaining texts, any pair at similarity
    # >= NEAR_DUPLICATE_THRESHOLD with different labels. Every row of every text in
    # such a pair is excluded (by text, so overlapping pairs never double-count).
    remaining = frame[~in_conflict]
    representatives = remaining.drop_duplicates(subset=["text"]).reset_index(drop=True)
    near_pairs = find_near_label_conflicts(representatives["text"], representatives["label"])
    near_texts = set(representatives.loc[sorted({p for a, b, _ in near_pairs for p in (a, b)}), "text"])
    in_near_conflict = ~in_conflict & frame["text"].isin(near_texts)

    excluded = in_conflict | in_near_conflict
    kept = frame[~excluded].sort_values(["text", "label", "source_row"], kind="mergesort")
    deduplicated = kept.drop_duplicates(subset=["text"], keep="first").reset_index(drop=True)

    accounting = {
        "original_rows": len(frame),
        "original_rows_by_class": frame["label"].value_counts().sort_index().to_dict(),
        "conflicting_texts": len(conflicting_texts),
        "rows_affected_by_label_conflicts": int(in_conflict.sum()),
        "rows_excluded_for_label_conflicts": int(in_conflict.sum()),
        "rows_excluded_for_label_conflicts_by_class": (
            frame.loc[in_conflict, "label"].value_counts().sort_index().to_dict()
        ),
        "near_duplicate_threshold": NEAR_DUPLICATE_THRESHOLD,
        "near_duplicate_conflict_pairs": len(near_pairs),
        "near_duplicate_conflict_texts": len(near_texts),
        "rows_excluded_for_near_duplicate_conflicts": int(in_near_conflict.sum()),
        "rows_excluded_for_near_duplicate_conflicts_by_class": (
            frame.loc[in_near_conflict, "label"].value_counts().sort_index().to_dict()
        ),
        "same_label_duplicate_rows_removed": len(kept) - len(deduplicated),
        "final_rows": len(deduplicated),
        "final_rows_by_class": deduplicated["label"].value_counts().sort_index().to_dict(),
    }
    reconciled = (
        accounting["rows_excluded_for_label_conflicts"]
        + accounting["rows_excluded_for_near_duplicate_conflicts"]
        + accounting["same_label_duplicate_rows_removed"]
        + accounting["final_rows"]
    )
    if reconciled != accounting["original_rows"]:
        raise AssertionError(f"Row accounting does not reconcile: {reconciled} != {accounting['original_rows']}")

    return deduplicated, accounting


# ── IMC 2025 (external evaluation only) ───────────────────────────────

def load_imc_for_evaluation(path: Path) -> pd.DataFrame:
    """Read only text, scam_type and language. No other column is parsed."""
    return pd.read_csv(path, usecols=list(IMC_ALLOWED_COLUMNS), dtype=str, encoding="utf-8")


def map_imc_for_evaluation(raw: pd.DataFrame, english_only: bool = True) -> tuple:
    """Map IMC rows to evaluation labels without changing the source values.

    Every row gets an eval_status:
      excluded_non_english       language is not English (when english_only)
      excluded_missing_category  scam_type is missing
      excluded_unresolved        scam_type has no justified mapping
      included_smishing          counted in the primary smishing-recall set
      separate_generic_spam      reported separately from smishing
      excluded_label_conflict    same normalized text maps to different labels
      removed_duplicate          repeat of a kept text with the same label
    An unknown scam_type string fails closed.

    Returns (frame, accounting). The frame keeps source_scam_type exactly as in
    the file, and carries split = 'external_evaluation_only' on every row.
    """
    absent = [c for c in IMC_ALLOWED_COLUMNS if c not in raw.columns]
    if absent:
        raise ValueError(f"{IMC_SOURCE}: missing column(s) {absent}")
    extra = sorted(set(raw.columns) - set(IMC_ALLOWED_COLUMNS))
    if extra:
        raise ValueError(f"{IMC_SOURCE}: unexpected column(s) {extra}; load with load_imc_for_evaluation")

    text_missing = _blank(raw["text"])
    if text_missing.any():
        raise ValueError(f"{IMC_SOURCE}: {int(text_missing.sum())} row(s) with missing or blank text")

    known = set(IMC_SCAM_TYPE_TREATMENT)
    unknown = sorted({str(v)[:30] for v in raw["scam_type"].dropna() if v not in known})
    if unknown:
        raise ValueError(f"{IMC_SOURCE}: scam_type value(s) with no documented treatment: {unknown}")

    frame = pd.DataFrame({
        "text": [normalize_text(text) for text in raw["text"]],
        "source_scam_type": raw["scam_type"].to_numpy(),
        "source": IMC_SOURCE,
        "source_row": range(len(raw)),
        "split": EXTERNAL_EVALUATION_SPLIT,
    })
    eval_label = [None] * len(frame)
    status = [None] * len(frame)

    english = raw["language"].astype(str).str.strip().str.lower().eq("english").to_numpy()
    for i, scam_type in enumerate(frame["source_scam_type"]):
        if english_only and not english[i]:
            status[i] = "excluded_non_english"
        elif pd.isna(scam_type):
            status[i] = "excluded_missing_category"
        else:
            eval_label[i], status[i], _ = IMC_SCAM_TYPE_TREATMENT[scam_type]
    frame["eval_label"] = eval_label
    frame["eval_status"] = status

    # Among labelled rows, apply the same policy as for training data: exclude texts
    # with conflicting evaluation labels, keep one row per same-label text.
    labelled = frame["eval_label"].notna()
    labels_per_text = frame.loc[labelled].groupby("text")["eval_label"].nunique()
    conflicting = set(labels_per_text[labels_per_text > 1].index)
    conflict_rows = labelled & frame["text"].isin(conflicting)
    frame.loc[conflict_rows, "eval_status"] = "excluded_label_conflict"

    candidates = frame[labelled & ~conflict_rows].sort_values(["text", "eval_label", "source_row"], kind="mergesort")
    duplicate_rows = candidates.index[candidates.duplicated(subset=["text"], keep="first")]
    frame.loc[duplicate_rows, "eval_status"] = "removed_duplicate"
    frame.loc[conflict_rows | frame.index.isin(duplicate_rows), "eval_label"] = None

    counts = pd.crosstab(
        frame["source_scam_type"].fillna("<missing>"), frame["eval_status"]
    )
    accounting = {
        "rows_read": len(frame),
        "status_counts": frame["eval_status"].value_counts().sort_index().to_dict(),
        "counts_by_source_category": {
            category: {k: int(v) for k, v in row.items() if v} for category, row in counts.iterrows()
        },
        "primary_smishing_rows": int(frame["eval_status"].eq("included_smishing").sum()),
        "separate_generic_spam_rows": int(frame["eval_status"].eq("separate_generic_spam").sum()),
    }
    if sum(accounting["status_counts"].values()) != len(frame):
        raise AssertionError("IMC accounting does not reconcile")

    return frame, accounting

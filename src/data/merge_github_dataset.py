"""Merge the GitHub SMS dataset with the UCI smish dataset, label-safely.

Pipeline (each step fails safely; nothing is dropped silently):
  1. Keep English rows of the GitHub file (lang 'en' or 'english'). The number of
     rejected non-English rows is reported.
  2. Reject rows with missing or blank text or label in either source.
  3. Map every source label to a canonical label with clean.standardize_label.
     Unknown labels and unverified labels (phishing, 0, 1) stop the merge.
  4. Normalize text the same way as clean.py.
  5. Deduplicate with clean.deduplicate_labelled. Conflicting labels for
     identical or near-identical text stop the merge before anything is written.

Provenance: each output row keeps 'source' ('uci' or 'github') and 'source_row'
(its 0-based position within that source after the steps above). Message text
is never placed in an error message.
"""
import os
import sys
import tempfile
from pathlib import Path

import pandas as pd

# Ensure project root is on sys.path for direct script execution
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.data.clean import deduplicate_labelled, normalize_text, standardize_label
from src.data.load_data import load_raw

UCI_PATH = Path("data/raw/smish.csv")
GITHUB_RAW_PATH = Path("data/raw/github_sms_raw.csv")
OUTPUT_PATH = Path("data/raw/smish_combined.csv")

ENGLISH_LANGUAGE_CODES = {"en", "english"}
LABEL_PREVIEW_CHARS = 20
GITHUB_REQUIRED_COLUMNS = ("label", "text", "lang")
OUTPUT_COLUMNS = ["text", "label", "source", "source_row"]


def filter_english(df: pd.DataFrame) -> tuple:
    """Keep English rows. Returns (rows with label and text, rejected_count).

    Rows whose lang is not 'en' or 'english' are rejected and counted. A missing
    lang value counts as not English.
    """
    absent = [column for column in GITHUB_REQUIRED_COLUMNS if column not in df.columns]
    if absent:
        raise ValueError(f"GitHub source is missing column(s) {absent}")

    language = df["lang"].astype(str).str.strip().str.lower()
    is_english = language.isin(ENGLISH_LANGUAGE_CODES)
    kept = df.loc[is_english, ["label", "text"]].reset_index(drop=True)
    return kept, int((~is_english).sum())


def _check_no_missing(df: pd.DataFrame, source: str) -> None:
    """Refuse to continue when text or label is missing or blank. Counts only."""
    text_missing = df["text"].isna() | df["text"].astype(str).str.strip().eq("")
    label_missing = df["label"].isna() | df["label"].astype(str).str.strip().eq("")
    if text_missing.any() or label_missing.any():
        raise ValueError(
            f"{source}: {int(text_missing.sum())} row(s) with missing or blank text and "
            f"{int(label_missing.sum())} row(s) with missing or blank label. Nothing was merged."
        )


def canonicalize_source(df: pd.DataFrame, source: str) -> pd.DataFrame:
    """Return text (normalized), label (canonical), source and source_row.

    Raises ValueError for missing values, and for any label that has no verified
    mapping. The error names the source and the row position, never the text.
    """
    _check_no_missing(df, source)

    labels = []
    for position, raw_label in enumerate(df["label"]):
        try:
            labels.append(standardize_label(raw_label))
        except ValueError:
            # Show a short preview only: label cells should be categorical, but a
            # malformed cell must not leak arbitrary text into the error.
            preview = str(raw_label)[:LABEL_PREVIEW_CHARS]
            raise ValueError(
                f"{source}: row {position}: label {preview!r} has no verified mapping; "
                "nothing was merged"
            ) from None

    return pd.DataFrame({
        "text": [normalize_text(text) for text in df["text"]],
        "label": labels,
        "source": source,
        "source_row": range(len(df)),
    })


def merge_sources(uci: pd.DataFrame, github: pd.DataFrame) -> tuple:
    """Merge two raw sources (columns: text, label; GitHub already English-only).

    Returns (merged_frame, counts). The merged frame has columns text, label,
    source and source_row. Raises ValueError if any label conflicts.
    """
    left = canonicalize_source(uci, "uci")
    right = canonicalize_source(github, "github")
    combined = pd.concat([left, right], ignore_index=True)

    merged, dedupe_counts = deduplicate_labelled(combined)
    counts = {
        "uci_rows": len(left),
        "github_rows": len(right),
        "output_rows": len(merged),
        **dedupe_counts,
    }
    return merged[OUTPUT_COLUMNS], counts


def load_github(path: Path = GITHUB_RAW_PATH) -> pd.DataFrame:
    """Read the GitHub file and keep English rows. Prints the rejected count."""
    if not path.exists():
        raise FileNotFoundError(f"{path} not found.")

    df = pd.read_csv(path, low_memory=False)
    kept, rejected = filter_english(df)
    print(f"GitHub rows rejected as non-English: {rejected}")
    return kept


def _write_atomically(df: pd.DataFrame, path: Path) -> None:
    """Write df to path through a temporary file in the same directory."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            df.to_csv(handle, index=False)
        os.replace(temp_name, path)
    except BaseException:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise


def merge_datasets() -> pd.DataFrame:
    """Read both sources, merge them, and write OUTPUT_PATH.

    Not run during Stage 0.4. Any error stops before OUTPUT_PATH is written.
    """
    uci = load_raw(UCI_PATH)
    github = load_github(GITHUB_RAW_PATH)

    merged, counts = merge_sources(uci, github)
    _write_atomically(merged, OUTPUT_PATH)

    print(f"Row count from UCI source: {counts['uci_rows']}")
    print(f"Row count from GitHub source (English-only): {counts['github_rows']}")
    print(f"Exact duplicates removed: {counts['exact_removed']}")
    print(f"Near-duplicates removed: {counts['near_removed']}")
    print(f"Row count after merge: {counts['output_rows']}")
    print("Final label balance:")
    print(merged["label"].value_counts())
    print(f"Saved merged dataset to: {OUTPUT_PATH}")

    return merged


if __name__ == "__main__":
    merge_datasets()

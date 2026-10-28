"""Load the raw smish dataset and standardize column names."""
import logging

import pandas as pd
from pathlib import Path

logger = logging.getLogger(__name__)

RAW_PATH = Path("data/raw/smish.csv")

# How rows with a missing or blank text or label are handled.
#   "raise": refuse to load (default; nothing is dropped silently)
#   "drop":  drop them, logging the counts
MISSING_POLICIES = ("raise", "drop")


def load_raw(path: Path = RAW_PATH, missing: str = "raise") -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(
            f"{path} not found. Place your smish.csv into data/raw/ first."
        )
    df = pd.read_csv(path, encoding="utf-8-sig")

    # Strip BOM characters and whitespace from column names
    df.columns = [
        str(c).replace("\ufeff", "").replace("ï»¿", "").strip()
        for c in df.columns
    ]

    # Try to auto-detect text/label columns for common Kaggle SMS formats
    cols_lower = {c.lower(): c for c in df.columns}
    text_col = next((cols_lower[c] for c in ["text", "message", "v2", "sms"] if c in cols_lower), None)
    label_col = next((cols_lower[c] for c in ["label", "category", "v1", "class"] if c in cols_lower), None)

    if text_col is None or label_col is None:
        raise ValueError(
            f"Could not auto-detect text/label columns. Found columns: {list(df.columns)}. "
            f"Edit load_data.py to map them manually."
        )

    if missing not in MISSING_POLICIES:
        raise ValueError(f"missing must be one of {MISSING_POLICIES}, got {missing!r}")

    df = df[[text_col, label_col]].rename(columns={text_col: "text", label_col: "label"})

    # A value is missing if it is absent or blank after stripping whitespace.
    text_missing = df["text"].isna() | df["text"].astype(str).str.strip().eq("")
    label_missing = df["label"].isna() | df["label"].astype(str).str.strip().eq("")
    any_missing = text_missing | label_missing

    if any_missing.any():
        summary = (
            f"{int(any_missing.sum())} of {len(df)} rows have a missing or blank text "
            f"({int(text_missing.sum())}) or label ({int(label_missing.sum())})"
        )
        if missing == "raise":
            raise ValueError(f"{summary}. Pass missing='drop' to drop them explicitly.")
        logger.warning("Dropping rows: %s", summary)
        df = df[~any_missing]

    return df.reset_index(drop=True)


if __name__ == "__main__":
    data = load_raw()
    print(f"Loaded {len(data)} rows")
    print(data["label"].value_counts())
    print(data.head())

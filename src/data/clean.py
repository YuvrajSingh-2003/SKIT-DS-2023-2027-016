"""Clean the smish dataset: normalize text, dedupe, standardize labels.

Deduplication is label-safe. Identical or near-identical texts are removed only
when every row in the group has the same canonical label. Any disagreement
stops cleaning before output is written. No label is chosen by row order,
keyword heuristics, or a fixed priority.
"""
import re
from pathlib import Path

import numpy as np
import pandas as pd
from rapidfuzz import fuzz, process

from src.data.load_data import load_raw

PROCESSED_PATH = Path("data/processed/cleaned.csv")

# Similarity at or above this ratio counts as a near-duplicate (unchanged from before).
NEAR_DUPLICATE_THRESHOLD = 92
# Same-label greedy removal compares each row with this many most recently kept rows.
NEAR_DUPLICATE_WINDOW = 200
# Bounds memory when comparing large label groups.
CDIST_CHUNK_SIZE = 1000
# How many row positions to show in a conflict error.
MAX_REPORTED_ROWS = 5

# Canonical labels: legitimate messages, generic spam (NOT smishing), and smishing.
LABEL_MAP = {
    "ham": "legitimate",
    "spam": "generic_spam",
    "smishing": "smishing",
    "legitimate": "legitimate",
    "generic_spam": "generic_spam",
}

# Source labels whose meaning for SMS data is not verified. They are rejected
# rather than guessed, until a mapping is confirmed for the dataset they come from.
UNRESOLVED_LABELS = {"phishing", "0", "1"}


def normalize_text(text: str) -> str:
    text = str(text).lower().strip()
    text = re.sub(r"\s+", " ", text)
    return text


def standardize_label(label: str) -> str:
    """Return the canonical label: 'legitimate', 'generic_spam' or 'smishing'.

    Raises ValueError for source labels with no verified SMS mapping
    (UNRESOLVED_LABELS) and for any other unknown label, including None and
    misspellings.
    """
    key = str(label).strip().lower()

    if key in UNRESOLVED_LABELS:
        raise ValueError(
            f"Label {key!r} has no verified SMS mapping; add a confirmed mapping first"
        )
    if key not in LABEL_MAP:
        raise ValueError(f"Unknown label {key!r}")

    return LABEL_MAP[key]


def find_label_conflicts(df: pd.DataFrame) -> pd.DataFrame:
    """Return exact texts that occur with more than one canonical label.

    Input needs 'text' and 'label' columns. Output columns: text, labels (sorted),
    positions (row positions in df). Positions are identifiers, not message text.
    The set of conflicts does not depend on row order.
    """
    seen = {}
    for position, (text, label) in enumerate(zip(df["text"], df["label"])):
        entry = seen.setdefault(text, {"labels": set(), "positions": []})
        entry["labels"].add(label)
        entry["positions"].append(position)

    rows = [
        {"text": text, "labels": sorted(entry["labels"]), "positions": entry["positions"]}
        for text, entry in seen.items()
        if len(entry["labels"]) > 1
    ]
    return pd.DataFrame(rows, columns=["text", "labels", "positions"])


def find_near_label_conflicts(
    texts: pd.Series, labels: pd.Series, threshold: int = NEAR_DUPLICATE_THRESHOLD
) -> list:
    """Return every pair of rows with similarity >= threshold and different labels.

    All cross-label pairs are compared, not only the first match of each row.
    Returns a sorted list of (position_a, position_b, similarity) tuples, where
    position_a < position_b. Positions refer to the input order.
    """
    text_list = list(texts)
    positions_by_label = {}
    for position, label in enumerate(labels):
        positions_by_label.setdefault(label, []).append(position)

    label_names = sorted(positions_by_label)
    conflicts = []
    for i, label_a in enumerate(label_names):
        for label_b in label_names[i + 1:]:
            positions_a = positions_by_label[label_a]
            positions_b = positions_by_label[label_b]
            texts_b = [text_list[p] for p in positions_b]

            for start in range(0, len(positions_a), CDIST_CHUNK_SIZE):
                chunk = positions_a[start:start + CDIST_CHUNK_SIZE]
                scores = process.cdist(
                    [text_list[p] for p in chunk],
                    texts_b,
                    scorer=fuzz.ratio,
                    score_cutoff=threshold,
                )
                rows, cols = np.nonzero(scores >= threshold)
                for row, col in zip(rows, cols):
                    pair = tuple(sorted((chunk[row], positions_b[col])))
                    conflicts.append((pair[0], pair[1], float(scores[row, col])))

    return sorted(conflicts)


def near_duplicate_flags(texts: pd.Series, threshold: int = NEAR_DUPLICATE_THRESHOLD) -> pd.Series:
    """Flag rows that are near-duplicates of an earlier kept row (greedy, first kept).

    Labels are not checked here. Call this only after find_near_label_conflicts
    has confirmed that every near-duplicate pair shares a label.
    """
    kept = []
    flags = []
    for text in texts:
        is_dupe = any(
            fuzz.ratio(text, s) >= threshold for s in kept[-NEAR_DUPLICATE_WINDOW:]
        )
        flags.append(is_dupe)
        if not is_dupe:
            kept.append(text)
    return pd.Series(flags, index=texts.index, dtype=bool)


def near_duplicate_mask(texts: pd.Series, threshold: int = NEAR_DUPLICATE_THRESHOLD) -> pd.Series:
    """Backward-compatible name for near_duplicate_flags. Ignores labels."""
    return near_duplicate_flags(texts, threshold)


def _conflict_error(exact: pd.DataFrame, near_pairs: list) -> ValueError:
    """Build a conflict error from counts, label names and row positions only.

    Message text is never included.
    """
    lines = []
    if not exact.empty:
        lines.append(f"{len(exact)} identical text(s) carry conflicting labels:")
        for _, row in exact.head(MAX_REPORTED_ROWS).iterrows():
            positions = row["positions"][:MAX_REPORTED_ROWS]
            lines.append(f"  labels {row['labels']} at row positions {positions}")
    if near_pairs:
        lines.append(
            f"{len(near_pairs)} near-duplicate pair(s) (similarity >= {NEAR_DUPLICATE_THRESHOLD}) "
            "carry conflicting labels:"
        )
        for position_a, position_b, score in near_pairs[:MAX_REPORTED_ROWS]:
            lines.append(f"  row positions {position_a} and {position_b} (similarity {score:.1f})")
    lines.append("Nothing was written. Resolve these labels in the source data first.")
    return ValueError("\n".join(lines))


def deduplicate_labelled(df: pd.DataFrame) -> tuple:
    """Remove duplicate and near-duplicate rows, but only when their labels agree.

    df needs 'text' (already normalized) and 'label' (canonical) columns. Other
    columns are kept. Returns (deduplicated_frame, counts), where counts has
    exact_removed and near_removed.

    Raises ValueError, without any message text, when identical or
    near-identical texts carry different labels. Nothing is removed in that case.
    Output is sorted by (text, label), so it does not depend on input row order.
    """
    df = df.sort_values(["text", "label"], kind="mergesort").reset_index(drop=True)

    exact_conflicts = find_label_conflicts(df)
    if not exact_conflicts.empty:
        raise _conflict_error(exact_conflicts, [])

    before = len(df)
    df = df.drop_duplicates(subset=["text"], keep="first").reset_index(drop=True)
    exact_removed = before - len(df)

    # Every similar pair is checked before anything is removed. Exact duplicates
    # were removed above with their labels already equal, so this check is complete.
    near_pairs = find_near_label_conflicts(df["text"], df["label"])
    if near_pairs:
        raise _conflict_error(pd.DataFrame(columns=["text", "labels", "positions"]), near_pairs)

    flags = near_duplicate_flags(df["text"])
    df = df[~flags].reset_index(drop=True)

    return df, {"exact_removed": exact_removed, "near_removed": int(flags.sum())}


def clean():
    df = load_raw()
    df["text"] = df["text"].apply(normalize_text)
    df["label"] = df["label"].apply(standardize_label)

    df, counts = deduplicate_labelled(df)

    empty = int((df["text"].str.len() == 0).sum())
    if empty:
        raise ValueError(f"{empty} row(s) have empty text after normalization; nothing was written")

    PROCESSED_PATH.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(PROCESSED_PATH, index=False)

    print(f"Exact duplicates removed: {counts['exact_removed']}")
    print(f"Near-duplicates removed: {counts['near_removed']}")
    print(f"Final row count: {len(df)}")
    print(df["label"].value_counts())
    print(f"Saved to {PROCESSED_PATH}")


if __name__ == "__main__":
    clean()

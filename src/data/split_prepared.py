"""Group-aware train/validation/test split for prepared sources (Stage 1.6).

The frozen pipeline (clean.py -> categorize.py -> split.py) drops provenance at
clean(). This module splits the output of prepare_sources.prepare_mishra_soni:

1. Grouping. Every row is a node; two rows are connected when their normalized
   texts have rapidfuzz ratio >= 92 (clean.NEAR_DUPLICATE_THRESHOLD). All pairs
   are compared. Connected components (union-find) are indivisible groups, so
   A~B and B~C put A, B and C together even if A and C do not match.
2. Feasibility. If the largest group holds more rows than the smallest split's
   target (15% of rows by default), a defensible split is impossible and the
   split is refused.
3. Assignment (deterministic, seed 42 by default). Groups are shuffled with
   numpy's default_rng(seed), then stably sorted by size (largest first). Each
   group goes to the split with the largest remaining per-class need for the
   group's classes, measured against the 70/15/15 targets per class; ties go
   to train, then val, then test. Group integrity always wins over exact
   proportions.
4. Verification (verify_split). No group crosses splits; no cross-split pair at
   ratio >= 92; no normalized duplicate crosses splits; row counts sum; labels
   and provenance unchanged.

Provenance (source, source_row) and group_id are metadata. train_baseline builds
features from 'text' only. Writes nothing unless write_splits is called.
"""
from pathlib import Path

import numpy as np
import pandas as pd
from rapidfuzz import fuzz, process

from src.data.categorize import assign_category
from src.data.clean import NEAR_DUPLICATE_THRESHOLD, normalize_text
from src.data.prepare_sources import assert_training_eligible

SEED = 42
SPLIT_NAMES = ("train", "val", "test")
OUTPUT_COLUMNS = ["text", "label", "category", "source", "source_row", "group_id"]
CDIST_CHUNK_SIZE = 1000


# ── grouping ──────────────────────────────────────────────────────────

def near_duplicate_groups(texts, threshold: int = NEAR_DUPLICATE_THRESHOLD) -> np.ndarray:
    """Return a component id per text (ids are 0..k-1 in order of first row)."""
    normalized = [normalize_text(t) for t in texts]
    n = len(normalized)
    parent = list(range(n))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for start in range(0, n, CDIST_CHUNK_SIZE):
        chunk = normalized[start:start + CDIST_CHUNK_SIZE]
        scores = process.cdist(chunk, normalized, scorer=fuzz.ratio, score_cutoff=threshold)
        for row, col in zip(*np.nonzero(scores >= threshold)):
            a, b = find(start + int(row)), find(int(col))
            if a != b:
                parent[max(a, b)] = min(a, b)

    roots = [find(i) for i in range(n)]
    relabel = {}
    return np.array([relabel.setdefault(r, len(relabel)) for r in roots], dtype=int)


def audit_groups(labels: pd.Series, groups: np.ndarray) -> dict:
    """Aggregate statistics about the groups. No text is included."""
    frame = pd.DataFrame({"label": list(labels), "group": groups})
    sizes = frame.groupby("group").size()
    labels_per_group = frame.groupby("group")["label"].nunique()
    mixed = labels_per_group[labels_per_group > 1].index
    return {
        "rows": len(frame),
        "groups": int(sizes.size),
        "singleton_groups": int((sizes == 1).sum()),
        "size_distribution": {int(k): int(v) for k, v in sizes.value_counts().sort_index().items()},
        "largest_groups": [int(s) for s in sizes.sort_values(ascending=False).head(10)],
        "rows_in_multi_row_groups": int(sizes[sizes > 1].sum()),
        "mixed_label_groups": int(len(mixed)),
        "mixed_label_class_counts": frame[frame["group"].isin(mixed)]["label"].value_counts().to_dict(),
        "group_counts_by_class": (
            frame.drop_duplicates(["group", "label"])["label"].value_counts().to_dict()
        ),
    }


# ── assignment ────────────────────────────────────────────────────────

def _assign_groups(labels: pd.Series, groups: np.ndarray, fractions: dict, seed: int) -> dict:
    frame = pd.DataFrame({"label": list(labels), "group": groups})
    totals = frame["label"].value_counts()
    targets = {s: totals * f for s, f in fractions.items()}
    filled = {s: pd.Series(0.0, index=totals.index) for s in fractions}

    group_ids = np.unique(groups)
    rng = np.random.default_rng(seed)
    order = rng.permutation(group_ids)
    size = frame.groupby("group").size()
    order = sorted(order, key=lambda g: -size[g])  # stable: ties keep shuffled order

    composition = frame.groupby("group")["label"].value_counts().unstack(fill_value=0)
    assignment = {}
    for g in order:
        counts = composition.loc[g]
        counts = counts[counts > 0]

        def need(split):
            remaining = (targets[split][counts.index] - filled[split][counts.index]) / targets[split][counts.index]
            return float((remaining * counts).sum())

        best = max(fractions, key=lambda s: (need(s), -list(fractions).index(s)))
        assignment[g] = best
        filled[best] = filled[best].add(counts, fill_value=0)
    return assignment


def split_prepared(prepared: pd.DataFrame, seed: int = SEED,
                   validation_fraction: float = 0.15, test_fraction: float = 0.15) -> dict:
    """Return {'train', 'val', 'test'} frames, assigning whole groups to one split.

    Raises ValueError when the data is not training-eligible, repeats a
    normalized text, or contains a group too large for the smallest split.
    """
    assert_training_eligible(prepared)

    normalized = prepared["text"].map(normalize_text)
    if normalized.duplicated().any():
        raise ValueError(
            f"{int(normalized.duplicated().sum())} row(s) repeat a normalized text; "
            "prepare the source before splitting"
        )

    fractions = {"train": 1 - validation_fraction - test_fraction,
                 "val": validation_fraction, "test": test_fraction}
    groups = near_duplicate_groups(prepared["text"])
    sizes = pd.Series(groups).value_counts()
    smallest_target = min(fractions.values()) * len(prepared)
    if len(sizes) and sizes.iloc[0] > smallest_target:
        raise ValueError(
            f"Largest near-duplicate group has {int(sizes.iloc[0])} rows, more than the smallest "
            f"split target ({smallest_target:.0f} rows); a group-aware split is not feasible"
        )

    frame = prepared.copy()
    frame["category"] = [assign_category(t, l) for t, l in zip(frame["text"], frame["label"])]
    frame["group_id"] = groups
    assignment = _assign_groups(frame["label"], groups, fractions, seed)
    split_of = frame["group_id"].map(assignment)

    return {name: frame.loc[split_of == name, OUTPUT_COLUMNS].reset_index(drop=True)
            for name in SPLIT_NAMES}


# ── verification ──────────────────────────────────────────────────────

def cross_split_near_duplicates(splits: dict, threshold: int = None) -> dict:
    """Read-only report of near-duplicate pairs that cross split boundaries.

    Compares every pair of rows in different splits (normalized text, rapidfuzz
    ratio >= threshold, default 92). Returns counts and (split, row) ids only.
    """
    threshold = NEAR_DUPLICATE_THRESHOLD if threshold is None else threshold
    names = list(splits)
    pairs = []
    for i, first in enumerate(names):
        for second in names[i + 1:]:
            a, b = splits[first], splits[second]
            if a.empty or b.empty:
                continue
            scores = process.cdist([normalize_text(t) for t in a["text"]],
                                   [normalize_text(t) for t in b["text"]],
                                   scorer=fuzz.ratio, score_cutoff=threshold)
            for row, col in zip(*np.nonzero(scores >= threshold)):
                pairs.append({
                    "a": (first, int(row)), "b": (second, int(col)),
                    "same_label": a["label"].iloc[row] == b["label"].iloc[col],
                })
    rows = {p["a"] for p in pairs} | {p["b"] for p in pairs}
    by_splits = {}
    for p in pairs:
        key = f"{p['a'][0]}-{p['b'][0]}"
        by_splits[key] = by_splits.get(key, 0) + 1
    return {
        "threshold": threshold,
        "pairs": len(pairs),
        "distinct_rows": len(rows),
        "same_label_pairs": sum(p["same_label"] for p in pairs),
        "conflicting_label_pairs": sum(not p["same_label"] for p in pairs),
        "pairs_by_split_pair": by_splits,
        "pair_ids": [(p["a"], p["b"]) for p in pairs],
    }


def verify_split(prepared: pd.DataFrame, splits: dict) -> dict:
    """Independent checks. Raises AssertionError on the first failure; returns a report."""
    combined = pd.concat(splits.values(), ignore_index=True)
    if len(combined) != len(prepared):
        raise AssertionError(f"Row count {len(combined)} != prepared {len(prepared)}")

    group_splits = combined.assign(
        split=np.concatenate([[name] * len(part) for name, part in splits.items()])
    ).groupby("group_id")["split"].nunique()
    if (group_splits > 1).any():
        raise AssertionError(f"{int((group_splits > 1).sum())} group(s) appear in more than one split")

    seen = {}
    for name, part in splits.items():
        for text in part["text"].map(normalize_text):
            if seen.setdefault(text, name) != name:
                raise AssertionError("A normalized text appears in more than one split")

    near = cross_split_near_duplicates(splits)
    if near["pairs"]:
        raise AssertionError(f"{near['pairs']} near-duplicate pair(s) cross splits")

    original = prepared.set_index("source_row")[["text", "label", "source"]]
    after = combined.set_index("source_row")[["text", "label", "source"]].loc[original.index]
    if not original.equals(after):
        raise AssertionError("Labels, text or provenance changed during splitting")

    return {
        "rows": {name: len(part) for name, part in splits.items()},
        "class_counts": {name: part["label"].value_counts().to_dict() for name, part in splits.items()},
        "class_proportions": {
            name: {k: round(v, 4) for k, v in part["label"].value_counts(normalize=True).items()}
            for name, part in splits.items()
        },
        "groups_crossing_splits": 0,
        "near_duplicate_pairs_crossing_splits": 0,
        "normalized_duplicates_crossing_splits": 0,
    }


def write_splits(splits: dict, out_dir: Path) -> None:
    """Write train.csv, val.csv and test.csv, refusing to overwrite existing files."""
    out_dir = Path(out_dir)
    targets = {name: out_dir / f"{name}.csv" for name in splits}
    existing = [str(p) for p in targets.values() if p.exists()]
    if existing:
        raise FileExistsError(f"Refusing to overwrite {existing}")
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, path in targets.items():
        splits[name].to_csv(path, index=False)

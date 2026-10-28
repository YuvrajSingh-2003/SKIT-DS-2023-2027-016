"""Mandatory entry point for baseline training (Stage 1.4, hardened in Stage 1.5).

train_baseline.train_baseline() and `python -m src.training.train_baseline` both
route here. This wrapper:

1. Loads and validates the evaluation manifest (schema, IMC file checksum,
   fingerprint digest). Any problem refuses training.
2. Reads train.csv and val.csv ONCE and validates that snapshot: approved
   source on every row and no row matching an evaluation fingerprint.
3. Runs train_baseline on exactly that validated snapshot, by supplying it in
   place of train_baseline.load_data for the duration of the call. The files
   are not read again, so a file changed after validation cannot be used.

Run training only through this module:
    python -m src.training.guarded_training
"""
from contextlib import contextmanager
from pathlib import Path

import pandas as pd

from src.data.prepare_sources import assert_training_eligible, load_evaluation_fingerprints
from src.training import train_baseline as baseline

EVALUATION_MANIFEST = Path("data/incoming/imc2025/evaluation_manifest.json")


def load_verified_inputs(evaluation_manifest: Path = EVALUATION_MANIFEST) -> tuple:
    """Read train.csv and val.csv once and validate them. Returns the frames."""
    fingerprints = load_evaluation_fingerprints(evaluation_manifest)
    frames = []
    for name in ("train.csv", "val.csv"):
        frame = pd.read_csv(baseline.DATA_DIR / name)
        try:
            assert_training_eligible(frame, fingerprints)
        except ValueError as error:
            raise ValueError(f"{name}: {error}") from None
        frames.append(frame)
    return tuple(frames)


# Kept for callers from Stage 1.4.
def check_training_inputs(evaluation_manifest: Path = EVALUATION_MANIFEST) -> None:
    load_verified_inputs(evaluation_manifest)


@contextmanager
def _verified_snapshot(train: pd.DataFrame, val: pd.DataFrame):
    """Make train_baseline.load_data return the validated frames, then restore it."""
    original = baseline.load_data
    baseline.load_data = lambda: (train.copy(), val.copy())
    try:
        yield
    finally:
        baseline.load_data = original


def guarded_train_baseline(
    evaluation_manifest: Path = EVALUATION_MANIFEST,
    experiments_path: Path = baseline.EXPERIMENTS_PATH,
    overwrite: bool = False,
) -> None:
    # Protect existing results before any data is read (same rule as the trainer).
    if Path(experiments_path).exists() and not overwrite:
        raise FileExistsError(
            f"{experiments_path} already exists. Pass overwrite=True to replace it "
            "after a successful run, or a different experiments_path to keep it."
        )
    train, val = load_verified_inputs(evaluation_manifest)
    with _verified_snapshot(train, val):
        baseline._train_baseline_unguarded(experiments_path=experiments_path, overwrite=overwrite)


if __name__ == "__main__":
    guarded_train_baseline()

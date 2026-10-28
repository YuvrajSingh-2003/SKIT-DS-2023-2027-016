"""Regression tests for Stage 0.3: label-safe dedup, missing-text rejection, and
failure-safe experiment output.

Uses in-memory frames and temporary files only. No real model is fitted: the
estimators and cross-validation are replaced with fakes. No NLTK download,
network access, blockchain seeding or database access.
"""

import os
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

import src.data.clean as clean_mod
from src.data.categorize import assign_category
from src.training import train_baseline as tb


# ── Task 1: label-safe deduplication in clean() ───────────────────────

def _run_clean(monkeypatch, tmp_path, rows, name="cleaned.csv"):
    """Run clean() on in-memory rows, writing its output under tmp_path."""
    raw = pd.DataFrame(rows, columns=["label", "text"])
    monkeypatch.setattr(clean_mod, "load_raw", lambda: raw.copy())
    output = tmp_path / name
    monkeypatch.setattr(clean_mod, "PROCESSED_PATH", output)
    clean_mod.clean()
    return output


class TestCleanLabelSafety:

    def test_identical_text_with_same_label_is_deduplicated_and_counted(self, monkeypatch, tmp_path, capsys):
        output = _run_clean(monkeypatch, tmp_path, [
            ("smishing", "Win a prize now"),
            ("smishing", "win a prize now"),
            ("ham", "hello there"),
        ])

        result = pd.read_csv(output)
        assert len(result) == 2
        assert "Exact duplicates removed: 1" in capsys.readouterr().out

    def test_identical_text_with_conflicting_labels_raises_and_writes_nothing(self, monkeypatch, tmp_path):
        with pytest.raises(ValueError, match="conflicting labels"):
            _run_clean(monkeypatch, tmp_path, [
                ("spam", "win a prize now"),
                ("smishing", "WIN A PRIZE NOW"),
            ])

        assert not (tmp_path / "cleaned.csv").exists()

    def test_conflict_detection_does_not_depend_on_row_order(self, monkeypatch, tmp_path):
        forward = [("spam", "win a prize now"), ("smishing", "win a prize now"), ("ham", "hi")]

        with pytest.raises(ValueError, match="conflicting labels"):
            _run_clean(monkeypatch, tmp_path, forward)
        with pytest.raises(ValueError, match="conflicting labels"):
            _run_clean(monkeypatch, tmp_path, list(reversed(forward)), name="reversed.csv")

    def test_near_duplicate_with_same_label_is_removed(self, monkeypatch, tmp_path, capsys):
        output = _run_clean(monkeypatch, tmp_path, [
            ("smishing", "win a prize now"),
            ("smishing", "win a prize now!"),
        ])

        assert len(pd.read_csv(output)) == 1
        assert "Near-duplicates removed: 1" in capsys.readouterr().out

    def test_near_duplicate_with_conflicting_labels_raises(self, monkeypatch, tmp_path):
        with pytest.raises(ValueError, match="near-duplicate pair"):
            _run_clean(monkeypatch, tmp_path, [
                ("smishing", "win a prize now"),
                ("generic_spam", "win a prize now!"),
            ])

        assert not (tmp_path / "cleaned.csv").exists()

    def test_output_is_byte_identical_regardless_of_input_order(self, monkeypatch, tmp_path):
        rows = [
            ("ham", "hello there"),
            ("ham", "hello there!"),
            ("smishing", "win a prize now"),
            ("smishing", "win a prize now!"),
            ("spam", "free camera offer"),
        ]

        first = _run_clean(monkeypatch, tmp_path, rows, name="first.csv")
        second = _run_clean(monkeypatch, tmp_path, list(reversed(rows)), name="second.csv")

        assert first.read_bytes() == second.read_bytes()

    def test_find_label_conflicts_lists_only_texts_with_several_labels(self):
        df = pd.DataFrame({
            "text": ["a", "a", "b", "b"],
            "label": ["smishing", "generic_spam", "legitimate", "legitimate"],
        })

        conflicts = clean_mod.find_label_conflicts(df)

        assert conflicts["text"].tolist() == ["a"]
        assert conflicts["labels"].tolist()[0] == ["generic_spam", "smishing"]


# ── Task 2: missing text in assign_category ───────────────────────────

class TestAssignCategoryMissingText:

    @pytest.mark.parametrize("label", ["smishing", "legitimate", "generic_spam"])
    @pytest.mark.parametrize("bad_text", [None, float("nan"), "", "   ", "\t\n"])
    def test_missing_or_blank_text_is_rejected_for_every_label(self, label, bad_text):
        with pytest.raises(ValueError, match="Missing or blank text"):
            assign_category(bad_text, label)

    @pytest.mark.parametrize(
        "text, label, expected",
        [
            ("claim your prize now", "smishing", "prize_premium_scam"),
            ("verify your bank account", "smishing", "payment_scam"),
            ("hello there", "smishing", "other_scam"),
            ("hi friend", "legitimate", "benign"),
            ("win cash", "generic_spam", "generic_spam"),
        ],
    )
    def test_valid_inputs_keep_distinct_categories(self, text, label, expected):
        assert assign_category(text, label) == expected

    def test_unknown_label_with_valid_text_raises(self):
        with pytest.raises(ValueError, match="Unknown label"):
            assign_category("hello", "malicious")


# ── Task 3 and 4: failure-safe experiment output ──────────────────────

class TestAtomicWriteExperimentRows:

    def test_writes_new_file_and_leaves_no_temp_files(self, tmp_path):
        target = tmp_path / "experiments.csv"

        tb.write_experiment_rows([{"model": "a", "accuracy": 0.5}], target)

        assert pd.read_csv(target)["model"].tolist() == ["a"]
        assert sorted(p.name for p in tmp_path.iterdir()) == ["experiments.csv"]

    def test_replaces_existing_file_only_after_writing_succeeds(self, tmp_path):
        target = tmp_path / "experiments.csv"
        target.write_bytes(b"old,contents\n1,2\n")

        tb.write_experiment_rows([{"model": "new"}], target)

        assert pd.read_csv(target)["model"].tolist() == ["new"]

    def test_failure_at_replace_keeps_old_bytes_and_removes_temp(self, tmp_path, monkeypatch):
        target = tmp_path / "experiments.csv"
        original = b"old,contents\n1,2\n"
        target.write_bytes(original)

        def failing_replace(src, dst):
            raise OSError("simulated replace failure")

        monkeypatch.setattr(tb.os, "replace", failing_replace)

        with pytest.raises(OSError, match="simulated replace failure"):
            tb.write_experiment_rows([{"model": "new"}], target)

        assert target.read_bytes() == original
        assert sorted(p.name for p in tmp_path.iterdir()) == ["experiments.csv"]

    def test_failure_while_writing_keeps_old_bytes_and_removes_temp(self, tmp_path, monkeypatch):
        target = tmp_path / "experiments.csv"
        original = b"old,contents\n1,2\n"
        target.write_bytes(original)

        def failing_to_csv(self, *args, **kwargs):
            raise RuntimeError("simulated write failure")

        monkeypatch.setattr(pd.DataFrame, "to_csv", failing_to_csv)

        with pytest.raises(RuntimeError, match="simulated write failure"):
            tb.write_experiment_rows([{"model": "new"}], target)

        assert target.read_bytes() == original
        assert sorted(p.name for p in tmp_path.iterdir()) == ["experiments.csv"]


class _FakeModel:
    """Stand-in estimator: predicts the majority training category."""

    instances = 0
    fail_on_fit = False

    def __init__(self, *args, **kwargs):
        _FakeModel.instances += 1
        self.majority = None

    def fit(self, X, y):
        if _FakeModel.fail_on_fit:
            raise RuntimeError("simulated fit failure")
        self.majority = pd.Series(y).mode()[0]
        return self

    def predict(self, X):
        return np.array([self.majority] * X.shape[0], dtype=object)


def _valid_frames():
    train = pd.DataFrame({
        "text": ["hello there", "claim your prize now", "win cash", "hi friend"],
        "category": ["benign", "prize_premium_scam", "generic_spam", "benign"],
        "label": ["legitimate", "smishing", "generic_spam", "legitimate"],
    })
    val = pd.DataFrame({
        "text": ["see you soon", "claim the prize", "free cash"],
        "category": ["benign", "prize_premium_scam", "generic_spam"],
        "label": ["legitimate", "smishing", "generic_spam"],
    })
    return train, val


@pytest.fixture
def fake_training(monkeypatch):
    """Replace estimators, text preprocessing and CV so train_baseline runs fast."""
    _FakeModel.instances = 0
    _FakeModel.fail_on_fit = False
    monkeypatch.setattr(tb, "LogisticRegression", _FakeModel)
    monkeypatch.setattr(tb, "LinearSVC", _FakeModel)
    monkeypatch.setattr(tb, "preprocess_text", lambda text: text)
    monkeypatch.setattr(tb, "run_stratified_cv", lambda **kwargs: (0.5, 0.1, 0.4, 0.05))
    monkeypatch.setattr(tb, "load_data", lambda: _valid_frames())
    return _FakeModel


class TestTrainBaselineControlFlow:

    def test_success_replaces_existing_file_with_all_rows(self, fake_training, tmp_path):
        target = tmp_path / "experiments.csv"
        target.write_bytes(b"stale,content\n")

        tb._train_baseline_unguarded(experiments_path=target, overwrite=True)

        result = pd.read_csv(target)
        assert len(result) == 4  # 2 preprocessing variants x 2 models
        assert set(result["model"]) == {"logistic_regression", "linear_svc"}
        assert sorted(p.name for p in tmp_path.iterdir()) == ["experiments.csv"]

    def test_invalid_input_is_rejected_before_any_model_is_built(self, fake_training, monkeypatch, tmp_path):
        train, val = _valid_frames()
        val.loc[0, "category"] = "payment_scamm"
        monkeypatch.setattr(tb, "load_data", lambda: (train, val))
        target = tmp_path / "experiments.csv"
        target.write_bytes(b"keep,me\n")

        with pytest.raises(ValueError, match="unsupported category"):
            tb._train_baseline_unguarded(experiments_path=target, overwrite=True)

        assert fake_training.instances == 0
        assert target.read_bytes() == b"keep,me\n"

    def test_existing_file_is_protected_before_training_data_is_read(self, fake_training, monkeypatch, tmp_path):
        target = tmp_path / "experiments.csv"
        original = b"keep,me\n"
        target.write_bytes(original)
        reads = []
        monkeypatch.setattr(tb, "load_data", lambda: reads.append(1) or _valid_frames())

        with pytest.raises(FileExistsError):
            tb._train_baseline_unguarded(experiments_path=target)

        assert reads == []
        assert fake_training.instances == 0
        assert target.read_bytes() == original

    def test_failure_during_cv_keeps_existing_file_byte_identical(self, fake_training, monkeypatch, tmp_path):
        target = tmp_path / "experiments.csv"
        original = b"keep,me\n"
        target.write_bytes(original)

        def failing_cv(**kwargs):
            raise RuntimeError("simulated CV failure")

        monkeypatch.setattr(tb, "run_stratified_cv", failing_cv)

        with pytest.raises(RuntimeError, match="simulated CV failure"):
            tb._train_baseline_unguarded(experiments_path=target, overwrite=True)

        assert target.read_bytes() == original
        assert sorted(p.name for p in tmp_path.iterdir()) == ["experiments.csv"]

    def test_failure_during_fit_keeps_existing_file_byte_identical(self, fake_training, tmp_path):
        target = tmp_path / "experiments.csv"
        original = b"keep,me\n"
        target.write_bytes(original)
        fake_training.fail_on_fit = True

        with pytest.raises(RuntimeError, match="simulated fit failure"):
            tb._train_baseline_unguarded(experiments_path=target, overwrite=True)

        assert target.read_bytes() == original
        assert sorted(p.name for p in tmp_path.iterdir()) == ["experiments.csv"]

    def test_new_output_file_is_created_without_overwrite_flag(self, fake_training, tmp_path):
        target = tmp_path / "experiments.csv"

        tb._train_baseline_unguarded(experiments_path=target)

        assert len(pd.read_csv(target)) == 4


# ── Task 5: precision convention is visible in the result ─────────────

class TestPrecisionConventionIsVisible:

    def test_no_predicted_smishing_is_exposed_in_the_result(self):
        result = tb.binary_smishing_metrics(
            pd.Series(["payment_scam", "benign"]), ["benign", "benign"]
        )

        assert result["predicted_smishing_rows"] == 0
        assert result["precision"] == pytest.approx(0.0)

    def test_predicted_smishing_count_matches_predictions(self):
        result = tb.binary_smishing_metrics(
            pd.Series(["payment_scam", "benign", "generic_spam"]),
            ["payment_scam", "payment_scam", "payment_scam"],
        )

        # The generic-spam row is excluded from primary rows but its prediction
        # is not counted here: only primary rows contribute to the primary count.
        assert result["predicted_smishing_rows"] == 2

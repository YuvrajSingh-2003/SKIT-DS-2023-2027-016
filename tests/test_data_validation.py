"""Regression tests for data validation and training safety.

Covers loader handling of missing values, label/category validation before
fitting, evaluation populations, and protection of experiments.csv.

Uses temporary files and in-memory frames only. Nothing is trained: the data
loader and model classes are replaced with sentinels where needed. No network,
NLTK download, blockchain seeding or database access.
"""

import logging

import pandas as pd
import pytest

from src.data import load_data as load_data_module
from src.data.load_data import load_raw
from src.training import train_baseline as tb


# ── load_raw: missing labels and text ─────────────────────────────────

def _write_csv(tmp_path, body: str):
    path = tmp_path / "raw.csv"
    path.write_text("label,text\n" + body, encoding="utf-8")
    return path


class TestLoadRawMissingValues:

    def test_clean_file_loads_unchanged(self, tmp_path):
        path = _write_csv(tmp_path, "ham,hello\nspam,win money\n")

        df = load_raw(path)

        assert len(df) == 2

    def test_missing_label_raises_by_default_with_counts(self, tmp_path):
        path = _write_csv(tmp_path, "ham,hello\n,no label here\n")

        with pytest.raises(ValueError, match=r"1 of 2 rows.*label \(1\)"):
            load_raw(path)

    def test_missing_text_raises_by_default_with_counts(self, tmp_path):
        path = _write_csv(tmp_path, "ham,hello\nspam,\n")

        with pytest.raises(ValueError, match=r"1 of 2 rows.*text \(1\)"):
            load_raw(path)

    def test_blank_whitespace_text_counts_as_missing(self, tmp_path):
        path = _write_csv(tmp_path, "ham,hello\nspam,   \n")

        with pytest.raises(ValueError, match=r"text \(1\)"):
            load_raw(path)

    def test_drop_policy_removes_rows_and_logs_counts(self, tmp_path, caplog):
        path = _write_csv(tmp_path, "ham,hello\n,no label\nspam,\n")

        with caplog.at_level(logging.WARNING, logger="src.data.load_data"):
            df = load_raw(path, missing="drop")

        assert df["text"].tolist() == ["hello"]
        assert "2 of 3 rows" in caplog.text

    def test_unknown_missing_policy_is_rejected(self, tmp_path):
        path = _write_csv(tmp_path, "ham,hello\n")

        with pytest.raises(ValueError, match="missing must be one of"):
            load_raw(path, missing="ignore")


# ── validate_training_frame ───────────────────────────────────────────

def _frame(rows):
    return pd.DataFrame(rows, columns=["text", "category", "label"])


class TestValidateTrainingFrame:

    def test_valid_frame_passes(self):
        df = _frame([
            ("hello", "benign", "legitimate"),
            ("win cash", "generic_spam", "generic_spam"),
            ("claim prize", "prize_premium_scam", "smishing"),
        ])

        tb.validate_training_frame(df, "train")

    def test_frame_without_label_column_passes_on_category_checks(self):
        df = pd.DataFrame({"text": ["hello"], "category": ["benign"]})

        tb.validate_training_frame(df, "train")

    def test_missing_text_is_rejected_with_count(self):
        df = _frame([("hello", "benign", "legitimate"), ("", "benign", "legitimate")])

        with pytest.raises(ValueError, match="1 row.*missing or blank text"):
            tb.validate_training_frame(df, "train")

    def test_missing_category_is_rejected_with_count(self):
        df = _frame([("hello", None, "legitimate")])

        with pytest.raises(ValueError, match="1 row.*missing category"):
            tb.validate_training_frame(df, "train")

    def test_unsupported_category_is_rejected(self):
        df = _frame([("hello", "payment_scamm", "smishing")])

        with pytest.raises(ValueError, match="unsupported category.*payment_scamm"):
            tb.validate_training_frame(df, "train")

    def test_label_category_mismatch_is_rejected(self):
        df = _frame([("hello", "benign", "smishing")])

        with pytest.raises(ValueError, match="label does not match category"):
            tb.validate_training_frame(df, "train")

    def test_generic_spam_labelled_as_smishing_is_rejected(self):
        df = _frame([("win cash", "generic_spam", "smishing")])

        with pytest.raises(ValueError, match="label does not match category"):
            tb.validate_training_frame(df, "train")

    def test_missing_required_column_is_rejected(self):
        with pytest.raises(ValueError, match="missing required column"):
            tb.validate_training_frame(pd.DataFrame({"text": ["x"]}), "train")

    def test_category_label_map_covers_every_supported_category(self):
        assert set(tb.CATEGORY_TO_LABEL) == tb.SUPPORTED_CATEGORIES


# ── training fails before fitting on bad input ────────────────────────

class _FittingWasAttempted(AssertionError):
    pass


def _forbid_fitting(*args, **kwargs):
    raise _FittingWasAttempted("a model was constructed before validation passed")


class TestTrainingFailsBeforeFitting:

    def test_unsupported_category_stops_before_any_model_is_built(self, tmp_path, monkeypatch):
        bad = _frame([("hello", "payment_scamm", "smishing"), ("hi", "benign", "legitimate")])
        monkeypatch.setattr(tb, "load_data", lambda: (bad, bad))
        monkeypatch.setattr(tb, "LogisticRegression", _forbid_fitting)
        monkeypatch.setattr(tb, "LinearSVC", _forbid_fitting)
        experiments = tmp_path / "experiments.csv"

        with pytest.raises(ValueError, match="unsupported category"):
            tb._train_baseline_unguarded(experiments_path=experiments)

        assert not experiments.exists()

    def test_missing_text_stops_before_any_model_is_built(self, tmp_path, monkeypatch):
        bad = _frame([("", "benign", "legitimate")])
        monkeypatch.setattr(tb, "load_data", lambda: (bad, bad))
        monkeypatch.setattr(tb, "LogisticRegression", _forbid_fitting)
        experiments = tmp_path / "experiments.csv"

        with pytest.raises(ValueError, match="missing or blank text"):
            tb._train_baseline_unguarded(experiments_path=experiments)


# ── evaluation populations ────────────────────────────────────────────

class TestEvaluationPopulations:

    def test_primary_and_excluded_rows_add_up_to_all_rows(self):
        y_true = pd.Series(["payment_scam", "benign", "generic_spam", "generic_spam"])
        y_pred = ["payment_scam", "benign", "payment_scam", "benign"]

        result = tb.binary_smishing_metrics(y_true, y_pred)

        assert result["primary_rows"] + result["generic_spam_rows_excluded"] == len(y_true)
        assert result["generic_spam_rows_excluded"] == 2

    def test_generic_spam_flagged_count_and_rate_are_reported_separately(self):
        y_true = pd.Series(["generic_spam", "generic_spam", "benign"])
        y_pred = ["payment_scam", "benign", "benign"]

        result = tb.binary_smishing_metrics(y_true, y_pred)

        assert result["generic_spam_flagged_as_smishing"] == 1
        assert result["generic_spam_flagged_rate"] == pytest.approx(0.5)
        # The flagged generic spam does not appear in the primary precision.
        assert result["primary_rows"] == 1
        assert result["precision"] == pytest.approx(0.0)


# ── experiments.csv protection ────────────────────────────────────────

class TestExperimentsFileProtection:

    def test_existing_results_are_not_deleted_or_overwritten_by_default(self, tmp_path, monkeypatch):
        results = tmp_path / "experiments.csv"
        original = b"model,accuracy\nlinear_svc,0.97\n"
        results.write_bytes(original)
        monkeypatch.setattr(tb, "load_data", _forbid_fitting)

        with pytest.raises(FileExistsError, match="already exists"):
            tb._train_baseline_unguarded(experiments_path=results)

        assert results.read_bytes() == original

    def test_overwrite_true_keeps_existing_file_when_training_fails(self, tmp_path, monkeypatch):
        # Stage 0.3: overwrite=True no longer deletes the file up front. A failure
        # before the final atomic replacement leaves the old bytes intact.
        results = tmp_path / "experiments.csv"
        original = b"model,accuracy\n"
        results.write_bytes(original)

        class _Stop(Exception):
            pass

        def stop_after_check():
            raise _Stop()

        monkeypatch.setattr(tb, "load_data", stop_after_check)

        with pytest.raises(_Stop):
            tb._train_baseline_unguarded(experiments_path=results, overwrite=True)

        assert results.read_bytes() == original

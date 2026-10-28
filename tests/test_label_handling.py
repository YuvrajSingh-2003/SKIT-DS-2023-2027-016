"""Regression tests for label handling across clean, categorize and train_baseline.

Uses small in-memory fixtures only. Does not download NLTK data, access the
network, train a model, run blockchain seeding, or touch the database.
"""

import importlib

import pandas as pd
import pytest

from src.data.categorize import CATEGORY_KEYWORDS, assign_category
from src.data.clean import UNRESOLVED_LABELS, standardize_label
from src.training.train_baseline import (
    SMISHING_CATEGORIES,
    SUPPORTED_CATEGORIES,
    binary_smishing_metrics,
    to_binary_labels,
)


# ── standardize_label ─────────────────────────────────────────────────

class TestStandardizeLabel:

    @pytest.mark.parametrize(
        "raw, expected",
        [
            ("ham", "legitimate"),
            ("HAM", "legitimate"),
            (" spam ", "generic_spam"),
            ("Smishing", "smishing"),
            ("legitimate", "legitimate"),
            ("generic_spam", "generic_spam"),
        ],
    )
    def test_supported_labels_map_to_canonical_names(self, raw, expected):
        assert standardize_label(raw) == expected

    def test_spam_is_never_smishing(self):
        assert standardize_label("spam") == "generic_spam"
        assert standardize_label("spam") != "smishing"

    @pytest.mark.parametrize("raw", sorted(UNRESOLVED_LABELS))
    def test_unresolved_labels_are_rejected(self, raw):
        with pytest.raises(ValueError, match="no verified SMS mapping"):
            standardize_label(raw)

    @pytest.mark.parametrize(
        "raw",
        ["malicious", "benign", "smshing", "phishng", "", None, float("nan")],
    )
    def test_unknown_labels_missing_values_and_misspellings_are_rejected(self, raw):
        with pytest.raises(ValueError, match="Unknown label"):
            standardize_label(raw)


# ── assign_category ───────────────────────────────────────────────────

class TestAssignCategory:

    def test_legitimate_is_benign_even_with_scam_words(self):
        assert assign_category("claim your prize now", "legitimate") == "benign"

    def test_generic_spam_keeps_its_own_category_even_with_scam_words(self):
        assert assign_category("claim your prize now", "generic_spam") == "generic_spam"

    def test_smishing_with_prize_keywords_gets_prize_category(self):
        assert assign_category("claim your prize now", "smishing") == "prize_premium_scam"

    def test_smishing_with_payment_keywords_gets_payment_category(self):
        assert assign_category("verify your bank account", "smishing") == "payment_scam"

    def test_smishing_without_keywords_falls_back_to_other_scam(self):
        assert assign_category("hello there", "smishing") == "other_scam"

    @pytest.mark.parametrize("label", ["malicious", "benign", "spam", None, float("nan")])
    def test_unknown_labels_raise(self, label):
        with pytest.raises(ValueError, match="Unknown label"):
            assign_category("any text", label)

    def test_every_output_is_a_supported_category(self):
        samples = [
            ("claim your prize now", "smishing"),
            ("verify your bank account", "smishing"),
            ("hello there", "smishing"),
            ("free camera upgrade", "smishing"),
            ("hi friend", "legitimate"),
            ("win cash", "generic_spam"),
        ]
        categories = {assign_category(text, label) for text, label in samples}

        assert categories <= SUPPORTED_CATEGORIES


# ── category sets and consistency ─────────────────────────────────────

class TestCategorySets:

    def test_smishing_categories_match_categorize_keywords_plus_other(self):
        assert SMISHING_CATEGORIES == set(CATEGORY_KEYWORDS) | {"other_scam"}

    def test_supported_categories_are_smishing_plus_benign_and_generic_spam(self):
        assert SUPPORTED_CATEGORIES == SMISHING_CATEGORIES | {"benign", "generic_spam"}


# ── to_binary_labels ──────────────────────────────────────────────────

class TestToBinaryLabels:

    @pytest.mark.parametrize("category", sorted(SMISHING_CATEGORIES))
    def test_each_scam_category_becomes_smishing(self, category):
        assert to_binary_labels(pd.Series([category])).tolist() == ["smishing"]

    def test_benign_stays_benign(self):
        assert to_binary_labels(pd.Series(["benign"])).tolist() == ["benign"]

    def test_generic_spam_stays_generic_spam_and_is_not_smishing(self):
        assert to_binary_labels(pd.Series(["generic_spam"])).tolist() == ["generic_spam"]

    @pytest.mark.parametrize(
        "bad", ["prize_premium_scamm", "Benign", "malicious", "", "unknown"]
    )
    def test_misspellings_and_unknown_categories_raise(self, bad):
        with pytest.raises(ValueError, match="Unsupported category"):
            to_binary_labels(pd.Series(["benign", bad]))

    @pytest.mark.parametrize("missing", [None, float("nan")])
    def test_missing_values_raise(self, missing):
        with pytest.raises(ValueError, match="missing category"):
            to_binary_labels(pd.Series(["benign", missing]))

    def test_one_bad_value_rejects_the_whole_series(self):
        with pytest.raises(ValueError):
            to_binary_labels(pd.Series(["smishing", "benign", "typo_scam"]))


# ── binary_smishing_metrics ───────────────────────────────────────────

class TestBinarySmishingMetrics:

    def test_representative_example(self):
        y_true = pd.Series(["payment_scam", "prize_premium_scam", "benign", "generic_spam"])
        y_pred = ["payment_scam", "benign", "benign", "other_scam"]

        result = binary_smishing_metrics(y_true, y_pred)

        # generic_spam row is excluded from primary metrics: TP=1, FN=1, TN=1
        assert result["primary_rows"] == 3
        assert result["generic_spam_rows_excluded"] == 1
        assert result["precision"] == pytest.approx(1.0)
        assert result["recall"] == pytest.approx(0.5)
        assert result["f1"] == pytest.approx(2 / 3)

    def test_generic_spam_flagged_as_smishing_is_reported_not_counted_in_precision(self):
        y_true = pd.Series(["benign", "generic_spam", "payment_scam"])
        y_pred = ["benign", "other_scam", "payment_scam"]

        result = binary_smishing_metrics(y_true, y_pred)

        # The generic_spam row predicted as smishing does not lower precision.
        assert result["precision"] == pytest.approx(1.0)
        assert result["generic_spam_rows_excluded"] == 1
        assert result["generic_spam_flagged_as_smishing"] == 1
        assert result["generic_spam_flagged_rate"] == pytest.approx(1.0)

    def test_generic_spam_not_flagged_gives_zero_rate(self):
        y_true = pd.Series(["generic_spam", "generic_spam", "benign"])
        y_pred = ["benign", "generic_spam", "benign"]

        result = binary_smishing_metrics(y_true, y_pred)

        assert result["generic_spam_flagged_as_smishing"] == 0
        assert result["generic_spam_flagged_rate"] == pytest.approx(0.0)

    def test_no_generic_spam_rows_gives_no_rate(self):
        result = binary_smishing_metrics(
            pd.Series(["benign", "payment_scam"]), ["benign", "payment_scam"]
        )

        assert result["generic_spam_rows_excluded"] == 0
        assert result["generic_spam_flagged_rate"] is None

    def test_generic_spam_rows_never_enter_primary_denominators(self):
        y_true = pd.Series(["generic_spam", "generic_spam"])
        y_pred = ["payment_scam", "payment_scam"]

        result = binary_smishing_metrics(y_true, y_pred)

        assert result["primary_rows"] == 0
        assert result["precision"] is None
        assert result["recall"] is None
        assert result["f1"] is None
        assert result["generic_spam_flagged_rate"] == pytest.approx(1.0)

    def test_missed_smishing_predicted_as_generic_spam_is_a_false_negative(self):
        result = binary_smishing_metrics(
            pd.Series(["payment_scam", "benign"]), ["generic_spam", "benign"]
        )

        assert result["primary_rows"] == 2
        assert result["recall"] == pytest.approx(0.0)

    def test_unknown_truth_values_raise(self):
        with pytest.raises(ValueError, match="Unsupported category"):
            binary_smishing_metrics(pd.Series(["payment_scamm"]), ["payment_scam"])


# ── feature-module rename ─────────────────────────────────────────────

class TestTextFeatureModuleLayout:

    def test_text_features_module_is_importable(self):
        module = importlib.import_module("src.text_features")

        assert callable(module.extract_text_features)
        assert callable(module.extract_url_features)
        assert callable(module.preprocess_text)

    def test_url_feature_package_is_not_shadowed(self):
        module = importlib.import_module("src.features.url_lexical")

        assert callable(module.extract_lexical_url_features)

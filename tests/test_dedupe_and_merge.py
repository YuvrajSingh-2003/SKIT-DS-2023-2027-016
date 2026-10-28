"""Regression tests for Stage 0.4: all-candidate near-duplicate conflict checks,
label-safe merging of the GitHub and UCI sources, and privacy of error messages.

Uses in-memory frames and temporary files only. No network, no NLTK download,
no real dataset, no model training, no blockchain seeding, no database.
"""

import itertools
import os

import pandas as pd
import pytest

from src.data import clean as clean_mod
from src.data import merge_github_dataset as merge_mod
from src.data.clean import (
    NEAR_DUPLICATE_THRESHOLD,
    deduplicate_labelled,
    find_label_conflicts,
    find_near_label_conflicts,
    near_duplicate_flags,
)

# Synthetic strings (random letters) reproducing the Stage 0.3 verification case:
# a and b are 85 similar to each other, and the probe p is 92.5 similar to both.
TEXT_A = "ognlejzsfoasfxudbxenvjqygbctqsqrwnxiwkrd"
TEXT_B = "ogflejzyfoasfxgubxenvjqygbctqyqrwnxiwpro"
TEXT_P = "ognlejzsfoasfxudbxenvjqygbctqyqrwnxiwpro"
ALL_TEXTS = (TEXT_A, TEXT_B, TEXT_P)


def _frame(rows):
    """rows: (label, text) pairs in input order."""
    return pd.DataFrame([{"label": label, "text": text} for label, text in rows])


# ── Task 1: near-duplicate conflicts are checked against every candidate ──

class TestNearDuplicateConflictDetection:

    def test_threshold_is_unchanged(self):
        assert NEAR_DUPLICATE_THRESHOLD == 92

    def test_reproduced_three_row_conflict_is_detected(self):
        rows = [("smishing", TEXT_A), ("legitimate", TEXT_B), ("smishing", TEXT_P)]

        pairs = find_near_label_conflicts(
            pd.Series([text for _, text in rows]), pd.Series([label for label, _ in rows])
        )

        assert [(a, b) for a, b, _ in pairs] == [(1, 2)]

    def test_all_conflicting_candidates_are_reported_not_just_the_first(self):
        # The probe is generic_spam, so it conflicts with BOTH kept rows.
        rows = [("smishing", TEXT_A), ("legitimate", TEXT_B), ("generic_spam", TEXT_P)]

        pairs = find_near_label_conflicts(
            pd.Series([text for _, text in rows]), pd.Series([label for label, _ in rows])
        )

        assert [(a, b) for a, b, _ in pairs] == [(0, 2), (1, 2)]

    @pytest.mark.parametrize("order", list(itertools.permutations(range(3))))
    def test_three_row_conflict_raises_in_every_input_order(self, order):
        base = [("smishing", TEXT_A), ("legitimate", TEXT_B), ("smishing", TEXT_P)]
        rows = [base[i] for i in order]

        with pytest.raises(ValueError, match="near-duplicate pair"):
            deduplicate_labelled(_frame(rows))

    @pytest.mark.parametrize("order", list(itertools.permutations(range(3))))
    def test_same_label_near_duplicates_are_deterministic_in_every_order(self, order):
        base = [("smishing", TEXT_A), ("smishing", TEXT_B), ("smishing", TEXT_P)]
        rows = [base[i] for i in order]

        result, counts = deduplicate_labelled(_frame(rows))

        reference, _ = deduplicate_labelled(_frame(base))
        assert result.to_dict("list") == reference.to_dict("list")
        assert counts["near_removed"] == len(base) - len(result)

    def test_near_duplicate_flags_is_greedy_on_same_label_rows(self):
        flags = near_duplicate_flags(pd.Series([TEXT_A, TEXT_P]))

        assert flags.tolist() == [False, True]

    def test_nothing_is_removed_when_a_conflict_is_found(self):
        df = _frame([("smishing", TEXT_A), ("legitimate", TEXT_B), ("smishing", TEXT_P)])
        before = df.copy()

        with pytest.raises(ValueError):
            deduplicate_labelled(df)

        pd.testing.assert_frame_equal(df, before)


# ── Task 3: conflict errors never reveal message text ─────────────────

class TestConflictErrorPrivacy:

    def test_near_conflict_error_contains_positions_but_no_text(self):
        rows = [("smishing", TEXT_A), ("legitimate", TEXT_B), ("smishing", TEXT_P)]

        with pytest.raises(ValueError) as caught:
            deduplicate_labelled(_frame(rows))

        message = str(caught.value)
        assert "row positions" in message
        assert "Nothing was written" in message
        assert not any(text in message for text in ALL_TEXTS)

    def test_exact_conflict_error_contains_positions_but_no_text(self):
        # deduplicate_labelled expects normalized text, so the duplicates are identical here.
        rows = [("spam", "win a prize now"), ("smishing", "win a prize now")]

        with pytest.raises(ValueError) as caught:
            deduplicate_labelled(_frame(rows))

        message = str(caught.value)
        assert "row positions" in message
        assert "win a prize now" not in message

    def test_find_label_conflicts_records_positions_for_exact_text(self):
        df = _frame([("spam", "same"), ("smishing", "other"), ("smishing", "same")])

        conflicts = find_label_conflicts(df)

        assert conflicts["positions"].tolist() == [[0, 2]]


# ── Task 2: merger ────────────────────────────────────────────────────

class TestFilterEnglish:

    def test_keeps_english_and_counts_rejected_rows(self):
        raw = pd.DataFrame({
            "label": ["spam", "ham", "spam"],
            "text": ["one", "two", "three"],
            "lang": ["en", "fr", "English"],
        })

        kept, rejected = merge_mod.filter_english(raw)

        assert kept["text"].tolist() == ["one", "three"]
        assert rejected == 1

    def test_missing_language_counts_as_not_english(self):
        raw = pd.DataFrame({"label": ["spam"], "text": ["one"], "lang": [None]})

        kept, rejected = merge_mod.filter_english(raw)

        assert len(kept) == 0
        assert rejected == 1

    def test_missing_column_is_rejected(self):
        with pytest.raises(ValueError, match="missing column"):
            merge_mod.filter_english(pd.DataFrame({"label": ["spam"], "text": ["x"]}))


class TestCanonicalizeSource:

    def test_missing_text_is_rejected_with_counts_and_no_text(self):
        raw = pd.DataFrame({"label": ["ham", "ham"], "text": ["hello", None]})

        with pytest.raises(ValueError, match=r"github: .*1 row\(s\) with missing or blank text"):
            merge_mod.canonicalize_source(raw, "github")

    def test_blank_and_missing_labels_are_rejected(self):
        raw = pd.DataFrame({"label": ["ham", "  "], "text": ["hello", "world"]})

        with pytest.raises(ValueError, match="1 row\\(s\\) with missing or blank label"):
            merge_mod.canonicalize_source(raw, "uci")

    @pytest.mark.parametrize("label", ["phishing", "0", "1", "scam"])
    def test_unverified_or_unknown_labels_stop_the_merge(self, label):
        raw = pd.DataFrame({"label": ["ham", label], "text": ["hello", "world"]})

        with pytest.raises(ValueError, match=r"github: row 1: label .* has no verified mapping"):
            merge_mod.canonicalize_source(raw, "github")

    def test_long_unmapped_label_is_previewed_not_repeated_in_full(self):
        long_label = "x" * 200
        raw = pd.DataFrame({"label": [long_label], "text": ["hello"]})

        with pytest.raises(ValueError) as caught:
            merge_mod.canonicalize_source(raw, "github")

        assert long_label not in str(caught.value)
        assert "x" * merge_mod.LABEL_PREVIEW_CHARS in str(caught.value)

    def test_text_and_labels_are_normalized_and_provenance_is_kept(self):
        raw = pd.DataFrame({"label": ["Spam", "HAM"], "text": ["  Win  NOW ", "hi"]})

        out = merge_mod.canonicalize_source(raw, "github")

        assert out["text"].tolist() == ["win now", "hi"]
        assert out["label"].tolist() == ["generic_spam", "legitimate"]
        assert out["source"].tolist() == ["github", "github"]
        assert out["source_row"].tolist() == [0, 1]


class TestMergeSources:

    def test_identical_text_with_conflicting_labels_across_sources_raises(self):
        uci = pd.DataFrame({"label": ["spam"], "text": ["claim your prize"]})
        github = pd.DataFrame({"label": ["smishing"], "text": ["claim your prize"]})

        with pytest.raises(ValueError, match="conflicting labels") as caught:
            merge_mod.merge_sources(uci, github)

        assert "claim your prize" not in str(caught.value)

    def test_near_duplicate_with_conflicting_labels_across_sources_raises(self):
        # TEXT_A and TEXT_P are 92.5 similar (at the threshold); TEXT_A and TEXT_B are 85.
        uci = pd.DataFrame({"label": ["smishing"], "text": [TEXT_A]})
        github = pd.DataFrame({"label": ["legitimate"], "text": [TEXT_P]})

        with pytest.raises(ValueError, match="near-duplicate pair"):
            merge_mod.merge_sources(uci, github)

    def test_same_label_across_sources_is_merged_with_provenance(self):
        uci = pd.DataFrame({"label": ["ham", "spam"], "text": ["Hello there", "win a prize"]})
        github = pd.DataFrame({"label": ["ham"], "text": ["hello  there"]})

        merged, counts = merge_mod.merge_sources(uci, github)

        assert merged["text"].tolist() == ["hello there", "win a prize"]
        assert merged["label"].tolist() == ["legitimate", "generic_spam"]
        assert merged["source"].tolist() == ["uci", "uci"]
        assert list(merged.columns) == merge_mod.OUTPUT_COLUMNS
        assert counts["exact_removed"] == 1
        assert counts["uci_rows"] == 2 and counts["github_rows"] == 1

    def test_merge_does_not_depend_on_row_order_within_a_source(self):
        uci = pd.DataFrame({"label": ["ham", "spam", "smishing"],
                            "text": ["hello", "win money", "claim prize"]})
        github = pd.DataFrame({"label": ["spam"], "text": ["WIN MONEY"]})

        first, _ = merge_mod.merge_sources(uci, github)
        second, _ = merge_mod.merge_sources(uci.iloc[::-1].reset_index(drop=True), github)

        assert first["text"].tolist() == second["text"].tolist()
        assert first["label"].tolist() == second["label"].tolist()

    def test_merge_sources_writes_nothing_to_disk(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        uci = pd.DataFrame({"label": ["ham"], "text": ["hello"]})
        github = pd.DataFrame({"label": ["ham"], "text": ["hi"]})

        merge_mod.merge_sources(uci, github)

        assert list(tmp_path.iterdir()) == []


class TestLoadGithubAndAtomicWrite:

    def test_load_github_filters_english_and_reports_rejections(self, tmp_path, capsys):
        path = tmp_path / "github.csv"
        path.write_text("label,text,lang\nspam,one,en\nham,two,fr\n", encoding="utf-8")

        loaded = merge_mod.load_github(path)

        assert loaded["text"].tolist() == ["one"]
        assert "rejected as non-English: 1" in capsys.readouterr().out

    def test_failed_atomic_write_keeps_old_file_and_removes_temp(self, tmp_path, monkeypatch):
        target = tmp_path / "smish_combined.csv"
        target.write_bytes(b"old\n")

        def failing_replace(src, dst):
            raise OSError("simulated replace failure")

        monkeypatch.setattr(merge_mod.os, "replace", failing_replace)

        with pytest.raises(OSError):
            merge_mod._write_atomically(pd.DataFrame({"text": ["x"]}), target)

        assert target.read_bytes() == b"old\n"
        assert sorted(p.name for p in tmp_path.iterdir()) == ["smish_combined.csv"]

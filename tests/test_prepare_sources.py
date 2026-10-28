"""Tests for Stage 1.3 source preparation (src/data/prepare_sources.py).

Synthetic in-memory frames and temporary files only. No real dataset, network,
model training, database or blockchain access. No real message text.
"""

import hashlib
import itertools

import pandas as pd
import pytest

from src.data import prepare_sources as ps
from src.training.train_baseline import validate_training_frame

SECRET = "zz-private-message-zz"


def _mishra(rows):
    """rows: (LABEL, TEXT) pairs."""
    return pd.DataFrame(rows, columns=["LABEL", "TEXT"])


def _imc(rows):
    """rows: (text, scam_type, language) triples."""
    return pd.DataFrame(rows, columns=["text", "scam_type", "language"])


# ── Mishra & Soni: conflict exclusion and duplicates ──────────────────

class TestMishraSoniPreparation:

    def test_conflicting_texts_are_excluded_entirely(self):
        raw = _mishra([
            ("ham", "Hello there"),
            ("Smishing", "hello  there"),   # same normalized text, different label
            ("spam", "Win now"),
            ("spam", "win now"),            # same-label duplicate
            ("ham", "see you"),
        ])

        prepared, acc = ps.prepare_mishra_soni(raw)

        assert "hello there" not in set(prepared["text"])
        assert sorted(prepared["text"]) == ["see you", "win now"]
        assert acc["conflicting_texts"] == 1
        assert acc["rows_excluded_for_label_conflicts"] == 2
        assert acc["same_label_duplicate_rows_removed"] == 1
        assert acc["final_rows"] == 2
        assert acc["final_rows_by_class"] == {"generic_spam": 1, "legitimate": 1}

    def test_excluded_rows_can_exceed_conflicting_texts(self):
        raw = _mishra([("ham", "a b"), ("ham", "A B"), ("smishing", "a  b"), ("ham", "c")])

        _, acc = ps.prepare_mishra_soni(raw)

        assert acc["conflicting_texts"] == 1
        assert acc["rows_excluded_for_label_conflicts"] == 3
        assert acc["rows_excluded_for_label_conflicts_by_class"] == {"legitimate": 2, "smishing": 1}

    @pytest.mark.parametrize("order", list(itertools.permutations(range(4))))
    def test_same_label_duplicates_are_handled_deterministically(self, order):
        base = [("spam", "Win now"), ("spam", "win now"), ("ham", "hi"), ("smishing", "pay here")]
        raw = _mishra([base[i] for i in order])

        prepared, _ = ps.prepare_mishra_soni(raw)

        assert prepared[["text", "label"]].to_dict("list") == {
            "text": ["hi", "pay here", "win now"],
            "label": ["legitimate", "smishing", "generic_spam"],
        }
        # The kept duplicate is the one that came first in the file.
        positions = [i for i, (_, text) in enumerate(raw.itertuples(index=False)) if text.lower() == "win now"]
        kept = prepared.loc[prepared["text"] == "win now", "source_row"].item()
        assert kept == min(positions)

    @pytest.mark.parametrize(
        "raw_label, canonical",
        [("ham", "legitimate"), ("HAM", "legitimate"), ("Spam", "generic_spam"),
         ("spam", "generic_spam"), ("Smishing", "smishing"), ("SMISHING", "smishing")],
    )
    def test_case_insensitive_labels_map_to_canonical_classes(self, raw_label, canonical):
        prepared, _ = ps.prepare_mishra_soni(_mishra([(raw_label, "some text")]))

        assert prepared["label"].tolist() == [canonical]

    @pytest.mark.parametrize("bad", ["phishing", "0", "1", "scam", "malicious"])
    def test_unsupported_or_undocumented_labels_fail_closed(self, bad):
        with pytest.raises(ValueError, match="row 1: label .* has no verified mapping") as caught:
            ps.prepare_mishra_soni(_mishra([("ham", "ok"), (bad, SECRET)]))

        assert SECRET not in str(caught.value)

    def test_missing_text_or_label_fails_closed_without_text(self):
        with pytest.raises(ValueError, match="1 row\\(s\\) with missing or blank text and 1 row") as caught:
            ps.prepare_mishra_soni(_mishra([("ham", "  "), (None, SECRET)]))

        assert SECRET not in str(caught.value)

    @pytest.mark.parametrize("rows", [
        [("ham", "x"), ("spam", "x"), ("spam", "X"), ("smishing", "y"), ("smishing", "y"), ("ham", "z")],
        [("ham", "a")],
        [("ham", "a"), ("spam", "a")],
    ])
    def test_counts_reconcile_and_input_is_not_modified(self, rows):
        raw = _mishra(rows)
        before = raw.copy()

        prepared, acc = ps.prepare_mishra_soni(raw)

        assert (acc["rows_excluded_for_label_conflicts"] + acc["same_label_duplicate_rows_removed"]
                + acc["final_rows"]) == acc["original_rows"] == len(raw)
        assert sum(acc["final_rows_by_class"].values()) == len(prepared)
        pd.testing.assert_frame_equal(raw, before)

    def test_source_file_is_unchanged_and_only_needed_columns_are_read(self, tmp_path):
        path = tmp_path / "Dataset_5971.csv"
        path.write_text(
            "LABEL,TEXT,URL,EMAIL,PHONE\nham,hello,No,No,No\nSpam,win,yes,No,No\n", encoding="utf-8"
        )
        digest = hashlib.sha256(path.read_bytes()).hexdigest()

        raw = ps.load_mishra_soni(path)
        ps.prepare_mishra_soni(raw)

        assert list(raw.columns) == ["LABEL", "TEXT"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest

    def test_prepared_frame_is_training_eligible(self):
        prepared, _ = ps.prepare_mishra_soni(_mishra([("ham", "hello")]))

        ps.assert_training_eligible(prepared)


# ── IMC 2025: evaluation-only mapping ─────────────────────────────────

class TestImcMapping:

    def test_mapping_table_covers_exactly_the_observed_categories(self):
        assert set(ps.IMC_SCAM_TYPE_TREATMENT) == {
            "banking", "delivery", "government", "telecom",
            "hey mum/dad", "wrong number", "spam", "others",
        }
        for label, status, rationale in ps.IMC_SCAM_TYPE_TREATMENT.values():
            assert rationale

    def test_statuses_by_category_and_source_labels_preserved(self):
        raw = _imc([
            ("t1", "banking", "English"),
            ("t2", "delivery", "english"),
            ("t3", "government", "English"),
            ("t4", "telecom", "English"),
            ("t5", "hey mum/dad", "English"),
            ("t6", "wrong number", "English"),
            ("t7", "spam", "English"),
            ("t8", "others", "English"),
            ("t9", None, "English"),
            ("t10", "banking", "Spanish"),
        ])

        frame, acc = ps.map_imc_for_evaluation(raw)

        assert frame["source_scam_type"].tolist()[:8] == raw["scam_type"].tolist()[:8]
        assert pd.isna(frame["source_scam_type"].iloc[8])
        assert frame["eval_status"].tolist() == [
            "included_smishing", "included_smishing", "included_smishing", "included_smishing",
            "included_smishing", "excluded_unresolved", "separate_generic_spam",
            "excluded_unresolved", "excluded_missing_category", "excluded_non_english",
        ]
        assert acc["primary_smishing_rows"] == 5
        assert acc["separate_generic_spam_rows"] == 1
        assert sum(acc["status_counts"].values()) == len(raw)
        assert acc["counts_by_source_category"]["wrong number"] == {"excluded_unresolved": 1}

    def test_generic_spam_is_never_counted_as_smishing(self):
        frame, _ = ps.map_imc_for_evaluation(_imc([("t1", "spam", "English")]))

        assert frame["eval_label"].tolist() == ["generic_spam"]
        assert frame["eval_status"].tolist() == ["separate_generic_spam"]

    @pytest.mark.parametrize("category", ["Banking", "lottery", "Delivery/Parcel"])
    def test_unknown_or_differently_spelled_category_fails_closed(self, category):
        with pytest.raises(ValueError, match="no documented treatment"):
            ps.map_imc_for_evaluation(_imc([("t1", category, "English")]))

    def test_conflicts_excluded_and_duplicates_removed_in_evaluation_set(self):
        raw = _imc([
            ("same text", "banking", "English"),
            ("same text", "spam", "English"),     # conflicting evaluation labels
            ("Repeat", "delivery", "English"),
            ("repeat", "banking", "English"),     # same evaluation label: duplicate
        ])

        frame, acc = ps.map_imc_for_evaluation(raw)

        assert frame["eval_status"].tolist() == [
            "excluded_label_conflict", "excluded_label_conflict", "included_smishing", "removed_duplicate",
        ]
        assert frame["source_scam_type"].tolist() == ["banking", "spam", "delivery", "banking"]
        assert acc["primary_smishing_rows"] == 1

    def test_every_row_is_marked_evaluation_only(self):
        frame, _ = ps.map_imc_for_evaluation(_imc([("t1", "banking", "English")]))

        assert set(frame["split"]) == {ps.EXTERNAL_EVALUATION_SPLIT}
        assert set(frame["source"]) == {ps.IMC_SOURCE}


class TestImcIsolationAndPrivacy:

    def test_imc_frame_is_rejected_by_the_training_guard(self):
        frame, _ = ps.map_imc_for_evaluation(_imc([("t1", "banking", "English")]))

        with pytest.raises(ValueError, match="evaluation-only"):
            ps.assert_training_eligible(frame)

    def test_imc_source_is_rejected_even_without_split_column(self):
        df = pd.DataFrame({"text": ["t"], "label": ["smishing"], "source": ["imc2025"]})

        with pytest.raises(ValueError, match="evaluation-only"):
            ps.assert_training_eligible(df)

    def test_existing_training_validator_rejects_imc_frame(self):
        frame, _ = ps.map_imc_for_evaluation(_imc([("t1", "banking", "English")]))

        with pytest.raises(ValueError, match="missing required column"):
            validate_training_frame(frame, "train")

    def test_loader_reads_only_allowed_columns(self, tmp_path):
        fake_phone = "15550001234"
        path = tmp_path / "final_dataset_output.csv"
        header = ("time,sender_id,telephone_number_type,original_network_name,"
                  "original_network_country,text,translation,language,url_shortener,"
                  "named_entity,scam_type,lure_principles")
        row = (f"2024-01-01,phone number,{fake_phone},NetCo,GBR,{SECRET},,English,bit.ly,"
               "BankCo,banking,Authority")
        path.write_text(header + "\n" + row + "\n", encoding="utf-8")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()

        loaded = ps.load_imc_for_evaluation(path)

        assert sorted(loaded.columns) == sorted(ps.IMC_ALLOWED_COLUMNS)
        assert not loaded.astype(str).apply(lambda col: col.str.contains(fake_phone)).any().any()
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest

    def test_mapping_refuses_frames_with_extra_columns(self):
        raw = _imc([("t1", "banking", "English")])
        raw["telephone_number_type"] = ["MOBILE"]

        with pytest.raises(ValueError, match="unexpected column"):
            ps.map_imc_for_evaluation(raw)

    def test_errors_do_not_expose_message_text(self):
        with pytest.raises(ValueError) as missing:
            ps.map_imc_for_evaluation(_imc([("  ", "banking", "English"), (SECRET, "banking", "English")]))
        with pytest.raises(ValueError) as unknown:
            ps.map_imc_for_evaluation(_imc([(SECRET, "lottery", "English")]))

        assert SECRET not in str(missing.value)
        assert SECRET not in str(unknown.value)

    def test_accounting_contains_counts_not_text(self):
        _, acc = ps.map_imc_for_evaluation(_imc([(SECRET, "banking", "English")]))

        assert SECRET not in repr(acc)


# ── Stage 1.4: near-duplicate conflict exclusion ──────────────────────

# Synthetic random-letter strings: A~P and B~P are 92.5 similar; A~B is 85.
TEXT_A = "ognlejzsfoasfxudbxenvjqygbctqsqrwnxiwkrd"
TEXT_B = "ogflejzyfoasfxgubxenvjqygbctqyqrwnxiwpro"
TEXT_P = "ognlejzsfoasfxudbxenvjqygbctqyqrwnxiwpro"


class TestNearDuplicateConflictExclusion:

    def test_cross_label_near_duplicates_are_excluded_by_text(self):
        raw = _mishra([("smishing", TEXT_A), ("spam", TEXT_P), ("spam", TEXT_P.upper()), ("ham", "hi")])

        prepared, acc = ps.prepare_mishra_soni(raw)

        assert prepared["text"].tolist() == ["hi"]
        assert acc["near_duplicate_conflict_pairs"] == 1
        assert acc["near_duplicate_conflict_texts"] == 2
        assert acc["rows_excluded_for_near_duplicate_conflicts"] == 3   # duplicate row counted once
        assert acc["same_label_duplicate_rows_removed"] == 0

    def test_overlapping_pairs_never_double_count(self):
        raw = _mishra([("smishing", TEXT_A), ("ham", TEXT_B), ("spam", TEXT_P), ("ham", "hi")])

        _, acc = ps.prepare_mishra_soni(raw)

        assert acc["near_duplicate_conflict_pairs"] == 2
        assert acc["near_duplicate_conflict_texts"] == 3
        assert acc["rows_excluded_for_near_duplicate_conflicts"] == 3

    def test_same_label_near_duplicates_are_kept(self):
        prepared, acc = ps.prepare_mishra_soni(_mishra([("smishing", TEXT_A), ("smishing", TEXT_P)]))

        assert len(prepared) == 2
        assert acc["rows_excluded_for_near_duplicate_conflicts"] == 0

    def test_exact_near_and_duplicate_exclusions_reconcile(self):
        raw = _mishra([
            ("ham", "x"), ("spam", "x"),                    # exact conflict
            ("smishing", TEXT_A), ("spam", TEXT_P),          # near conflict
            ("ham", "y"), ("ham", "Y"),                      # same-label duplicate
        ])

        prepared, acc = ps.prepare_mishra_soni(raw)

        assert acc["rows_excluded_for_label_conflicts"] == 2
        assert acc["rows_excluded_for_near_duplicate_conflicts"] == 2
        assert acc["same_label_duplicate_rows_removed"] == 1
        assert acc["final_rows"] == len(prepared) == 1
        assert acc["original_rows"] == 2 + 2 + 1 + 1


# ── Stage 1.4: provenance guard and mandatory wrapper ─────────────────

def _imc_frame():
    frame, _ = ps.map_imc_for_evaluation(_imc([(SECRET, "banking", "English"), ("other eval text", "spam", "English")]))
    return frame


class TestTrainingGuard:

    def test_missing_source_column_fails_closed(self):
        with pytest.raises(ValueError, match="provenance cannot be verified"):
            ps.assert_training_eligible(pd.DataFrame({"text": ["a"], "label": ["smishing"]}))

    def test_unknown_or_missing_source_fails_closed(self):
        for source in ["somewhere_else", None]:
            df = pd.DataFrame({"text": ["a"], "source": [source]})
            with pytest.raises(ValueError, match="non-approved"):
                ps.assert_training_eligible(df)

    def test_imc_rows_rejected_after_provenance_is_stripped_and_text_transformed(self, tmp_path):
        manifest = tmp_path / "evaluation_manifest.json"
        ps.write_evaluation_manifest(_imc_frame(), manifest)
        fingerprints = ps.load_evaluation_fingerprints(manifest)
        laundered = pd.DataFrame({
            "text": [f"  {SECRET.upper()} ", "hello"],     # case and whitespace changed
            "category": ["payment_scam", "benign"],
            "source": ["mishra_soni", "mishra_soni"],      # provenance rewritten
        })

        with pytest.raises(ValueError, match="1 row\\(s\\) match evaluation-only texts") as caught:
            ps.assert_training_eligible(laundered, fingerprints)
        assert SECRET.lower() not in str(caught.value).lower()

    def test_prepared_mishra_soni_candidate_passes_with_fingerprints(self, tmp_path):
        manifest = tmp_path / "evaluation_manifest.json"
        ps.write_evaluation_manifest(_imc_frame(), manifest)
        prepared, _ = ps.prepare_mishra_soni(_mishra([("ham", "hello"), ("Smishing", "pay now")]))

        ps.assert_training_eligible(prepared, ps.load_evaluation_fingerprints(manifest))

    def test_manifest_contains_hashes_not_text(self, tmp_path):
        manifest = tmp_path / "evaluation_manifest.json"
        ps.write_evaluation_manifest(_imc_frame(), manifest)

        content = manifest.read_text()
        assert SECRET not in content and "other eval text" not in content

    def test_missing_or_malformed_manifest_fails_closed(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            ps.load_evaluation_fingerprints(tmp_path / "absent.json")
        bad = tmp_path / "bad.json"
        bad.write_text('{"split": "train", "fingerprints": []}')
        with pytest.raises(ValueError, match="malformed"):
            ps.load_evaluation_fingerprints(bad)


class TestGuardedTrainingWrapper:

    def _setup(self, tmp_path, monkeypatch, train_rows):
        from src.training import guarded_training as gt
        manifest = tmp_path / "evaluation_manifest.json"
        ps.write_evaluation_manifest(_imc_frame(), manifest)
        data_dir = tmp_path / "processed"
        data_dir.mkdir()
        pd.DataFrame(train_rows).to_csv(data_dir / "train.csv", index=False)
        pd.DataFrame({"text": ["see you"], "category": ["benign"], "source": ["mishra_soni"]}).to_csv(
            data_dir / "val.csv", index=False)
        monkeypatch.setattr(gt.baseline, "DATA_DIR", data_dir)
        calls = []
        monkeypatch.setattr(gt.baseline, "_train_baseline_unguarded", lambda **kw: calls.append(kw))
        return gt, manifest, calls

    def test_imc_text_in_training_file_stops_before_training(self, tmp_path, monkeypatch):
        gt, manifest, calls = self._setup(tmp_path, monkeypatch, {
            "text": [SECRET], "category": ["payment_scam"], "source": ["mishra_soni"]})

        with pytest.raises(ValueError, match="train.csv"):
            gt.guarded_train_baseline(evaluation_manifest=manifest, experiments_path=tmp_path / "out.csv")
        assert calls == []

    def test_file_without_source_column_stops_before_training(self, tmp_path, monkeypatch):
        gt, manifest, calls = self._setup(tmp_path, monkeypatch, {"text": ["hi"], "category": ["benign"]})

        with pytest.raises(ValueError, match="provenance"):
            gt.guarded_train_baseline(evaluation_manifest=manifest, experiments_path=tmp_path / "out.csv")
        assert calls == []

    def test_missing_manifest_stops_before_training(self, tmp_path, monkeypatch):
        gt, _, calls = self._setup(tmp_path, monkeypatch, {
            "text": ["hi"], "category": ["benign"], "source": ["mishra_soni"]})

        with pytest.raises(FileNotFoundError):
            gt.guarded_train_baseline(evaluation_manifest=tmp_path / "absent.json", experiments_path=tmp_path / "out.csv")
        assert calls == []

    def test_clean_mishra_soni_inputs_reach_training(self, tmp_path, monkeypatch):
        gt, manifest, calls = self._setup(tmp_path, monkeypatch, {
            "text": ["hi"], "category": ["benign"], "source": ["mishra_soni"]})

        gt.guarded_train_baseline(evaluation_manifest=manifest, experiments_path=tmp_path / "out.csv")

        assert len(calls) == 1

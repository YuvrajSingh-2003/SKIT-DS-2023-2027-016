"""Stage 1.5 tests: manifest validation, snapshot training, provenance through splits.

Synthetic data and temporary files only. No model is fitted (the trainer is
replaced with a fake), nothing is downloaded, no message text is printed.
"""

import inspect
import json

import pandas as pd
import pytest

from src.data import prepare_sources as ps
from src.data.clean import normalize_text
from src.data.split_prepared import split_prepared, write_splits
from src.training import guarded_training as gt
from src.training import train_baseline as baseline

SECRET = "zz-private-eval-message-zz"


def _manifest(tmp_path):
    frame, _ = ps.map_imc_for_evaluation(pd.DataFrame(
        {"text": [SECRET, "another eval text"], "scam_type": ["banking", "spam"], "language": ["English"] * 2}
    ))
    path = tmp_path / "evaluation_manifest.json"
    ps.write_evaluation_manifest(frame, path)
    return path


def _random_text(rng):
    return "".join(rng.choice("abcdefghijklmnopqrstuvwxyz ") for _ in range(40))


def _prepared(n_per_class=20):
    # Distinct random-letter texts: no two are near-duplicates, so every row is its own group.
    import random
    rng = random.Random(0)
    rows = []
    for _ in range(n_per_class):
        rows += [("ham", _random_text(rng)), ("spam", _random_text(rng)), ("smishing", _random_text(rng))]
    prepared, _ = ps.prepare_mishra_soni(pd.DataFrame(rows, columns=["LABEL", "TEXT"]))
    return prepared


# ── manifest schema and tamper detection ──────────────────────────────

class TestManifestValidation:

    def test_valid_manifest_loads(self, tmp_path):
        assert len(ps.load_evaluation_fingerprints(_manifest(tmp_path))) == 2

    @pytest.mark.parametrize("field, value", [
        ("manifest_version", 1),
        ("source", "mishra_soni"),
        ("split", "train"),
        ("fingerprint_method", "md5"),
        ("source_file_sha256", "0" * 64),
        ("fingerprint_count", 99),
        ("fingerprints_sha256", "f" * 64),
    ])
    def test_altered_field_is_refused(self, tmp_path, field, value):
        path = _manifest(tmp_path)
        data = json.loads(path.read_text())
        data[field] = value
        path.write_text(json.dumps(data))

        with pytest.raises(ValueError, match="malformed"):
            ps.load_evaluation_fingerprints(path)

    def test_removed_fingerprint_is_detected(self, tmp_path):
        path = _manifest(tmp_path)
        data = json.loads(path.read_text())
        data["fingerprints"] = data["fingerprints"][:1]
        data["fingerprint_count"] = 1
        path.write_text(json.dumps(data))

        with pytest.raises(ValueError, match="digest mismatch"):
            ps.load_evaluation_fingerprints(path)

    def test_invalid_fingerprint_and_bad_json_are_refused(self, tmp_path):
        path = _manifest(tmp_path)
        data = json.loads(path.read_text())
        data["fingerprints"][0] = "not-a-hash"
        path.write_text(json.dumps(data))
        with pytest.raises(ValueError, match="invalid fingerprint"):
            ps.load_evaluation_fingerprints(path)

        path.write_text("{not json")
        with pytest.raises(ValueError, match="malformed"):
            ps.load_evaluation_fingerprints(path)

    def test_manifest_holds_no_text(self, tmp_path):
        assert SECRET not in _manifest(tmp_path).read_text()


# ── guarded training runs on the validated snapshot ───────────────────

def _write_inputs(directory, train_rows):
    directory.mkdir(exist_ok=True)
    pd.DataFrame(train_rows).to_csv(directory / "train.csv", index=False)
    pd.DataFrame({"text": ["see you"], "category": ["benign"], "label": ["legitimate"],
                  "source": ["mishra_soni"]}).to_csv(directory / "val.csv", index=False)


class TestGuardedSnapshot:

    def _setup(self, tmp_path, monkeypatch, train_rows):
        data_dir = tmp_path / "processed"
        _write_inputs(data_dir, train_rows)
        monkeypatch.setattr(baseline, "DATA_DIR", data_dir)
        return data_dir, _manifest(tmp_path)

    def test_training_uses_validated_snapshot_not_a_later_file(self, tmp_path, monkeypatch):
        data_dir, manifest = self._setup(tmp_path, monkeypatch, {
            "text": ["hi there"], "category": ["benign"], "label": ["legitimate"], "source": ["mishra_soni"]})
        seen = []

        def fake_train(**kwargs):
            # Swap in evaluation text after validation; training must not see it.
            pd.DataFrame({"text": [SECRET], "category": ["payment_scam"], "label": ["smishing"],
                          "source": ["mishra_soni"]}).to_csv(data_dir / "train.csv", index=False)
            seen.append(baseline.load_data())

        original_loader = baseline.load_data
        monkeypatch.setattr(baseline, "_train_baseline_unguarded", fake_train)

        gt.guarded_train_baseline(evaluation_manifest=manifest, experiments_path=tmp_path / "out.csv")

        train, _ = seen[0]
        assert train["text"].tolist() == ["hi there"]
        assert baseline.load_data is original_loader

    @pytest.mark.parametrize("rows, message", [
        ({"text": ["hi"], "category": ["benign"]}, "provenance"),
        ({"text": ["hi"], "category": ["benign"], "source": ["somewhere"]}, "non-approved"),
        ({"text": ["hi"], "category": ["benign"], "source": ["imc2025"]}, "evaluation-only"),
        ({"text": [f" {SECRET.upper()} "], "category": ["benign"], "source": ["mishra_soni"]}, "evaluation-only texts"),
    ])
    def test_rejected_inputs_never_reach_training(self, tmp_path, monkeypatch, rows, message):
        _, manifest = self._setup(tmp_path, monkeypatch, rows)
        calls = []
        monkeypatch.setattr(baseline, "_train_baseline_unguarded", lambda **kw: calls.append(kw))

        with pytest.raises(ValueError, match=message) as caught:
            gt.guarded_train_baseline(evaluation_manifest=manifest, experiments_path=tmp_path / "out.csv")

        assert calls == []
        assert SECRET.lower() not in str(caught.value).lower()

    def test_malformed_manifest_never_reaches_training(self, tmp_path, monkeypatch):
        _, manifest = self._setup(tmp_path, monkeypatch, {
            "text": ["hi"], "category": ["benign"], "source": ["mishra_soni"]})
        data = json.loads(manifest.read_text())
        data["source_file_sha256"] = "0" * 64
        manifest.write_text(json.dumps(data))
        calls = []
        monkeypatch.setattr(baseline, "_train_baseline_unguarded", lambda **kw: calls.append(kw))

        with pytest.raises(ValueError, match="malformed"):
            gt.guarded_train_baseline(evaluation_manifest=manifest, experiments_path=tmp_path / "out.csv")
        assert calls == []


# ── provenance through splitting ──────────────────────────────────────

class TestSplitPrepared:

    def test_provenance_survives_and_texts_do_not_cross_splits(self):
        splits = split_prepared(_prepared())

        seen = set()
        for part in splits.values():
            assert set(part["source"]) == {"mishra_soni"}
            assert part["source_row"].notna().all()
            texts = set(part["text"].map(normalize_text))
            assert not texts & seen
            seen |= texts
        assert sum(len(p) for p in splits.values()) == 60

    def test_split_is_reproducible_with_the_seed(self):
        first = split_prepared(_prepared(), seed=7)
        second = split_prepared(_prepared(), seed=7)

        for name in first:
            pd.testing.assert_frame_equal(first[name], second[name])

    def test_normalized_duplicates_are_refused(self):
        prepared = _prepared()
        dup = prepared.iloc[[0]].copy()
        dup["text"] = "  " + dup["text"].str.upper() + " "
        with pytest.raises(ValueError, match="repeat a normalized text"):
            split_prepared(pd.concat([prepared, dup], ignore_index=True))

    def test_unapproved_source_cannot_be_split(self):
        prepared = _prepared()
        prepared["source"] = "imc2025"
        with pytest.raises(ValueError, match="evaluation-only"):
            split_prepared(prepared)

    def test_approved_splits_pass_the_full_guard(self, tmp_path):
        fingerprints = ps.load_evaluation_fingerprints(_manifest(tmp_path))
        for part in split_prepared(_prepared()).values():
            ps.assert_training_eligible(part, fingerprints)
            baseline.validate_training_frame(part, "split")

    def test_write_splits_refuses_to_overwrite(self, tmp_path):
        splits = split_prepared(_prepared())
        write_splits(splits, tmp_path)
        with pytest.raises(FileExistsError):
            write_splits(splits, tmp_path)

    def test_source_metadata_is_not_a_model_feature(self):
        # train_baseline builds features from 'text' only; it never reads provenance.
        code = inspect.getsource(baseline)
        assert "source_row" not in code
        assert '"source"' not in code and "'source'" not in code


# ── Stage 1.5 final: every entry point is guarded ─────────────────────

class TestEveryEntryPointIsGuarded:

    def test_direct_train_baseline_call_runs_the_guard(self, tmp_path, monkeypatch):
        data_dir = tmp_path / "processed"
        _write_inputs(data_dir, {"text": ["hi"], "category": ["benign"], "source": ["somewhere"]})
        monkeypatch.setattr(baseline, "DATA_DIR", data_dir)
        monkeypatch.setattr(gt, "EVALUATION_MANIFEST", _manifest(tmp_path))
        monkeypatch.setattr(gt.guarded_train_baseline, "__defaults__",
                            (_manifest(tmp_path), baseline.EXPERIMENTS_PATH, False))
        fitted = []
        monkeypatch.setattr(baseline, "_train_baseline_unguarded", lambda **kw: fitted.append(kw))

        with pytest.raises(ValueError, match="non-approved"):
            baseline.train_baseline(experiments_path=tmp_path / "out.csv")
        assert fitted == []

    def test_direct_call_without_manifest_is_refused(self, tmp_path, monkeypatch):
        data_dir = tmp_path / "processed"
        _write_inputs(data_dir, {"text": ["hi"], "category": ["benign"], "source": ["mishra_soni"]})
        monkeypatch.setattr(baseline, "DATA_DIR", data_dir)
        monkeypatch.setattr(gt.guarded_train_baseline, "__defaults__",
                            (tmp_path / "absent.json", baseline.EXPERIMENTS_PATH, False))
        fitted = []
        monkeypatch.setattr(baseline, "_train_baseline_unguarded", lambda **kw: fitted.append(kw))

        with pytest.raises(FileNotFoundError):
            baseline.train_baseline(experiments_path=tmp_path / "out.csv")
        assert fitted == []

    def test_direct_call_with_approved_data_reaches_training(self, tmp_path, monkeypatch):
        data_dir = tmp_path / "processed"
        _write_inputs(data_dir, {"text": ["hi"], "category": ["benign"], "source": ["mishra_soni"]})
        monkeypatch.setattr(baseline, "DATA_DIR", data_dir)
        monkeypatch.setattr(gt.guarded_train_baseline, "__defaults__",
                            (_manifest(tmp_path), baseline.EXPERIMENTS_PATH, False))
        fitted = []
        monkeypatch.setattr(baseline, "_train_baseline_unguarded", lambda **kw: fitted.append(kw))

        baseline.train_baseline(experiments_path=tmp_path / "out.csv")
        assert len(fitted) == 1

    def test_main_entry_point_calls_the_guarded_wrapper(self, monkeypatch):
        import runpy
        calls = []
        monkeypatch.setattr(gt, "guarded_train_baseline", lambda *a, **k: calls.append(1))

        runpy.run_module("src.training.train_baseline", run_name="__main__")

        assert calls == [1]

    def test_existing_output_is_protected_before_data_is_read(self, tmp_path, monkeypatch):
        out = tmp_path / "out.csv"
        out.write_text("keep\n")
        reads = []
        monkeypatch.setattr(gt, "load_verified_inputs", lambda *a: reads.append(1))

        with pytest.raises(FileExistsError):
            gt.guarded_train_baseline(evaluation_manifest=tmp_path / "x.json", experiments_path=out)
        assert reads == [] and out.read_text() == "keep\n"

    def test_private_implementation_is_not_public(self):
        assert "_train_baseline_unguarded" not in getattr(baseline, "__all__", [])
        assert baseline._train_baseline_unguarded.__name__.startswith("_")


class TestCrossSplitNearDuplicates:

    def test_reports_pairs_without_changing_splits(self):
        from src.data.split_prepared import cross_split_near_duplicates
        a = "ognlejzsfoasfxudbxenvjqygbctqsqrwnxiwkrd"
        p = "ognlejzsfoasfxudbxenvjqygbctqyqrwnxiwpro"
        splits = {
            "train": pd.DataFrame({"text": [a, "unrelated words here"], "label": ["smishing", "legitimate"]}),
            "val": pd.DataFrame({"text": [p], "label": ["smishing"]}),
            "test": pd.DataFrame({"text": [p], "label": ["generic_spam"]}),
        }
        before = {k: v.copy() for k, v in splits.items()}

        report = cross_split_near_duplicates(splits)

        assert report["threshold"] == 92
        assert report["pairs"] == 3            # train-val, train-test, val-test
        assert report["distinct_rows"] == 3
        assert report["same_label_pairs"] == 1
        assert report["conflicting_label_pairs"] == 2
        for k in splits:
            pd.testing.assert_frame_equal(splits[k], before[k])

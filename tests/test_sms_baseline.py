"""Stage 2 tests on synthetic data: metrics, group bootstrap, guarded training,
selection freeze, one-shot test evaluation and IMC ordering. No real data."""

import hashlib
import json
import random

import numpy as np
import pandas as pd
import pytest

from src.data import prepare_sources as ps
from src.data.split_prepared import split_prepared
from src.training import guarded_training as gt
from src.training import train_sms_baseline as sb

WORDS = {"legitimate": "meeting lunch home tonight", "generic_spam": "casino offer discount sale",
         "smishing": "account verify bank suspended"}


def _text(rng, label):
    noise = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz ") for _ in range(30))
    return f"{noise} {' '.join(rng.sample(WORDS[label].split(), 2))}"


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    rng = random.Random(3)
    rows = [(label, _text(rng, label)) for _ in range(40) for label in WORDS]
    prepared = pd.DataFrame({"text": [t for _, t in rows], "label": [l for l, _ in rows],
                             "source": "mishra_soni", "source_row": range(len(rows))})
    data_dir = tmp_path / "processed"
    data_dir.mkdir()
    shas = {}
    for name, part in split_prepared(prepared).items():
        part.to_csv(data_dir / f"{name}.csv", index=False)
        shas[name] = hashlib.sha256((data_dir / f"{name}.csv").read_bytes()).hexdigest()
    meta = tmp_path / "split_meta.json"
    meta.write_text(json.dumps({"source_csv_sha256": "x" * 64, "files_sha256": shas}))

    imc_file = tmp_path / "imc.csv"
    imc_file.write_text("text,scam_type,language\n" + "\n".join(
        f"{_text(rng, 'smishing')},banking,English" for _ in range(10)) + "\nwin casino now,spam,English\n")
    imc_frame, _ = ps.map_imc_for_evaluation(ps.load_imc_for_evaluation(imc_file))
    manifest = tmp_path / "manifest.json"
    ps.write_evaluation_manifest(imc_frame, manifest)

    monkeypatch.setattr(gt.baseline, "DATA_DIR", data_dir)
    return {"tmp": tmp_path, "data": data_dir, "meta": meta, "manifest": manifest, "imc": imc_file}


class TestMetrics:

    def test_values_and_smishing_false_positive_breakdown(self):
        y = ["legitimate", "legitimate", "generic_spam", "generic_spam", "smishing", "smishing"]
        p = ["legitimate", "smishing", "smishing", "generic_spam", "smishing", "legitimate"]

        m = sb.metrics(y, p)

        assert m["per_class"]["smishing"]["precision"] == pytest.approx(1 / 3)
        assert m["per_class"]["smishing"]["recall"] == pytest.approx(0.5)
        assert m["generic_spam_predicted_smishing"] == {"count": 1, "of": 2, "rate": 0.5}
        assert m["legitimate_predicted_smishing"] == {"count": 1, "of": 2, "rate": 0.5}
        assert m["confusion_matrix"]["labels"] == sb.CLASSES

    def test_undefined_precision_is_flagged(self):
        m = sb.metrics(["smishing", "legitimate"], ["legitimate", "legitimate"])

        assert set(m["undefined_precision"]) == {"generic_spam", "smishing"}
        assert m["per_class"]["smishing"]["precision"] == 0.0

    def test_group_bootstrap_is_deterministic_and_counts_groups(self):
        y = np.array(["smishing"] * 6 + ["legitimate"] * 4)
        p = np.array(["smishing", "legitimate"] * 5)
        g = np.array([0, 0, 1, 1, 2, 2, 3, 4, 5, 6])

        a, b = sb.group_bootstrap(y, p, g, replicates=200), sb.group_bootstrap(y, p, g, replicates=200)

        assert a == b and a["groups"] == 7


class TestTrainingRun:

    def test_train_writes_isolated_artifacts_and_reloads(self, workspace):
        run = sb.train(runs_dir=workspace["tmp"] / "runs", evaluation_manifest=workspace["manifest"],
                       split_metadata=workspace["meta"], run_name="r1")

        names = {p.name for p in run.iterdir()}
        assert {"config.json", "validation_candidates.json", "selection_frozen.json",
                "model.joblib", "checksums.sha256"} <= names
        assert len(json.loads((run / "validation_candidates.json").read_text())) == len(sb.CANDIDATES)
        assert "test.csv" not in json.dumps(json.loads((run / "config.json").read_text()))
        with pytest.raises(FileExistsError):
            sb.train(runs_dir=workspace["tmp"] / "runs", evaluation_manifest=workspace["manifest"],
                     split_metadata=workspace["meta"], run_name="r1")

    def test_training_never_reads_the_test_split(self, workspace, monkeypatch):
        (workspace["data"] / "test.csv").unlink()

        sb.train(runs_dir=workspace["tmp"] / "runs", evaluation_manifest=workspace["manifest"],
                 split_metadata=workspace["meta"], run_name="r2")

    def test_training_refuses_imc_text(self, workspace):
        train = pd.read_csv(workspace["data"] / "train.csv")
        imc_text = pd.read_csv(workspace["imc"])["text"].iloc[0]
        train.loc[0, "text"] = imc_text
        train.to_csv(workspace["data"] / "train.csv", index=False)

        with pytest.raises(ValueError, match="evaluation-only"):
            sb.train(runs_dir=workspace["tmp"] / "runs", evaluation_manifest=workspace["manifest"],
                     split_metadata=workspace["meta"], run_name="r3")
        assert not (workspace["tmp"] / "runs" / "r3").exists()

    def test_artifacts_contain_no_message_text(self, workspace):
        run = sb.train(runs_dir=workspace["tmp"] / "runs", evaluation_manifest=workspace["manifest"],
                       split_metadata=workspace["meta"], run_name="r4")
        texts = pd.read_csv(workspace["data"] / "train.csv")["text"].head(20)
        blob = "".join(p.read_text() for p in run.iterdir() if p.suffix in (".json", ".sha256"))
        assert not any(t in blob for t in texts)


class TestEvaluationOrder:

    def _run(self, workspace, name):
        return sb.train(runs_dir=workspace["tmp"] / "runs", evaluation_manifest=workspace["manifest"],
                        split_metadata=workspace["meta"], run_name=name)

    def test_test_requires_frozen_selection(self, workspace):
        empty = workspace["tmp"] / "runs" / "empty"
        empty.mkdir(parents=True)
        with pytest.raises(RuntimeError, match="not frozen"):
            sb.evaluate_test(empty, split_metadata=workspace["meta"], evaluation_manifest=workspace["manifest"])

    def test_test_runs_once_and_imc_waits_for_it(self, workspace):
        run = self._run(workspace, "r5")
        with pytest.raises(RuntimeError, match="locked test result"):
            sb.evaluate_imc(run, imc_path=workspace["imc"])

        result = sb.evaluate_test(run, split_metadata=workspace["meta"], evaluation_manifest=workspace["manifest"])
        assert result["rows"] == len(pd.read_csv(workspace["data"] / "test.csv"))
        assert "intervals" in result["uncertainty"]
        with pytest.raises(FileExistsError, match="already evaluated"):
            sb.evaluate_test(run, split_metadata=workspace["meta"], evaluation_manifest=workspace["manifest"])

        imc = sb.evaluate_imc(run, imc_path=workspace["imc"])
        assert imc["primary_smishing_recall"]["rows"] == 10
        assert imc["generic_spam_separate"]["rows"] == 1
        assert "not verified real-world performance" in imc["interpretation"]

    def test_tampered_test_file_or_model_is_refused(self, workspace):
        run = self._run(workspace, "r6")
        with open(workspace["data"] / "test.csv", "a") as handle:
            handle.write("\n")
        with pytest.raises(ValueError, match="checksum"):
            sb.evaluate_test(run, split_metadata=workspace["meta"], evaluation_manifest=workspace["manifest"])

        (run / "model.joblib").write_bytes(b"tampered")
        with pytest.raises(RuntimeError, match="does not match"):
            sb.evaluate_test(run, split_metadata=workspace["meta"], evaluation_manifest=workspace["manifest"])

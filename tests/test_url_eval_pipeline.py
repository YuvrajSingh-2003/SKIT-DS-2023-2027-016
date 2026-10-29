"""Offline URL evaluation-set pipeline (fixtures only; no network)."""

import hashlib
import json

import pandas as pd
import pytest

from src.data import url_eval_pipeline as pipe


def _source(tmp_path, name, lines, **overrides):
    path = tmp_path / name
    path.write_text("\n".join(lines) + "\n")
    meta = {
        "source_name": name, "label": "legitimate", "label_confidence": "popularity_proxy",
        "licence": "CC BY 4.0", "licence_verified": True, "source_url": "https://example.invalid/list",
        "retrieved_at": "2026-10-29T00:00:00+00:00", "retrieval_method": "manual download",
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    } | overrides
    (tmp_path / f"{name}.provenance.json").write_text(json.dumps(meta))
    return path


@pytest.fixture
def split(tmp_path):
    path = tmp_path / "train.csv"
    pd.DataFrame({"URL": ["https://www.trained.com", "http://phish.example/login"], "label": [1, 0]}).to_csv(path, index=False)
    return [path]


def test_missing_source_is_not_treated_as_downloaded(tmp_path):
    with pytest.raises(pipe.ProvenanceError, match="not present"):
        pipe.read_provenance(tmp_path / "tranco.csv")


def test_missing_sidecar_is_refused(tmp_path):
    (tmp_path / "list.txt").write_text("https://a.com/\n")
    with pytest.raises(pipe.ProvenanceError, match="sidecar"):
        pipe.read_provenance(tmp_path / "list.txt")


@pytest.mark.parametrize("override, message", [
    ({"licence_verified": False}, "licence not verified"),
    ({"label": "spam"}, "label must be"),
    ({"label_confidence": "trusted"}, "label_confidence"),
    ({"sha256": "0" * 64}, "checksum"),
])
def test_invalid_provenance_is_refused(tmp_path, override, message):
    path = _source(tmp_path, "list.txt", ["https://a.com/"], **override)
    with pytest.raises(pipe.ProvenanceError, match=message):
        pipe.read_provenance(path)


def test_tranco_style_lines_become_homepages(tmp_path):
    frame = pipe.ingest(_source(tmp_path, "top.csv", ["1,google.com", "2,example.org", "# c"]))
    assert frame["raw_url"].tolist() == ["https://google.com/", "https://example.org/"]
    assert set(frame["label_confidence"]) == {"popularity_proxy"}


def test_dedupe_by_canonical_url_and_drop_label_conflicts():
    frame = pd.DataFrame({
        "raw_url": ["HTTPS://A.com", "https://a.com/", "https://b.com/x", "https://b.com/x", "https://c.com/?b=2&a=1"],
        "label": ["legitimate", "legitimate", "legitimate", "phishing", "legitimate"],
    })
    out, report = pipe.canonicalize_and_dedupe(frame)
    assert sorted(out["canonical_url"]) == ["https://a.com/", "https://c.com/?a=1&b=2"]
    assert report == {"empty_after_canonicalization": 0, "label_conflict_urls_dropped": 1,
                      "exact_duplicates_dropped": 1}


def test_build_removes_training_overlap_and_writes_manifest(tmp_path, split):
    legit = _source(tmp_path, "legit.txt", ["https://trained.com/about", "https://fresh.org/docs?p=1"])
    phish = _source(tmp_path, "feed.txt", ["http://phish.example/login", "https://new-phish.xyz/"],
                    label="phishing", label_confidence="feed_reported")
    out = pipe.build([legit, phish], "20261029", root=tmp_path / "eval", splits=split)

    rows = pd.read_csv(out / "urls.csv")
    manifest = json.loads((out / "manifest.json").read_text())
    assert sorted(rows["canonical_url"]) == ["https://fresh.org/docs?p=1", "https://new-phish.xyz/"]
    assert manifest["usage"] == "evaluation_only"
    for source in manifest["sources"]:
        assert {"source_name", "licence", "source_url", "retrieved_at", "sha256", "file"} <= set(source)
    assert manifest["dedupe"]["key"] == "canonical_url"
    assert {"exact_duplicates_dropped", "label_conflict_urls_dropped"} <= set(manifest["dedupe"])
    assert manifest["training_overlap"]["url_overlap_dropped"] == 1
    assert manifest["training_overlap"]["host_overlap_dropped"] == 1  # trained.com via www-stripped host
    assert manifest["urls_sha256"] == hashlib.sha256((out / "urls.csv").read_bytes()).hexdigest()

    with pytest.raises(FileExistsError):
        pipe.build([legit], "20261029", root=tmp_path / "eval", splits=split)
    with pytest.raises(pipe.ProvenanceError, match="evaluation-only"):
        pipe.assert_not_evaluation_data(out / "urls.csv")


def test_missing_training_split_blocks_build(tmp_path):
    legit = _source(tmp_path, "legit.txt", ["https://fresh.org/"])
    with pytest.raises(pipe.ProvenanceError, match="overlap cannot be checked"):
        pipe.build([legit], "20261029", root=tmp_path / "eval", splits=[tmp_path / "nope.csv"])

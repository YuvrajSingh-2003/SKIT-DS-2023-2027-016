"""Offline pipeline for a representative, time-stamped URL evaluation set.

This module never fetches anything. It ingests URL lists that an operator has
already obtained under their source's terms and placed on disk, each with a
provenance sidecar (<file>.provenance.json). Sources without a valid sidecar
are refused, so an inaccessible or undocumented source cannot be mistaken for
downloaded data.

Steps:
    1. ingest     read each source + sidecar, verify the file checksum
    2. canonical  src.blockchain.canonicalize.canonicalize_url (unchanged)
    3. dedupe     exact canonical URL; label conflicts across sources dropped
    4. overlap    drop rows whose canonical URL or host appears in the
                  PhiUSIIL train/validation/test splits (reported, not silent)
    5. write      data/eval/url_eval_<YYYYMMDD>/urls.csv + manifest.json,
                  marked usage="evaluation_only"

Label confidence is recorded per row: a popularity list is NOT a safety
label, so legitimate rows from one carry "popularity_proxy".

    python -m src.data.url_eval_pipeline --sources a.txt b.txt --out-date 20261101
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import pandas as pd

from src.blockchain.canonicalize import canonicalize_url

EVAL_ROOT = Path("data/eval")
TRAINING_SPLITS = [Path("data/processed/url_splits") / name for name in
                   ("stratified_train.csv", "stratified_validation.csv", "stratified_test.csv")]
USAGE = "evaluation_only"

REQUIRED_PROVENANCE = {"source_name", "label", "label_confidence", "licence", "licence_verified",
                       "source_url", "retrieved_at", "retrieval_method", "sha256"}
LABELS = {"legitimate", "phishing"}
LABEL_CONFIDENCE = {
    "popularity_proxy",       # e.g. sampled from a top-sites list: popular, not verified safe
    "manually_reviewed",      # each URL checked by a person
    "feed_reported",          # listed by a phishing feed at retrieval time
    "feed_confirmed",         # feed entry with confirmed/verified status
}


class ProvenanceError(ValueError):
    """A source is missing, undocumented, or does not match its sidecar."""


def _sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read_provenance(source: Path) -> dict:
    sidecar = Path(f"{source}.provenance.json")
    if not Path(source).is_file():
        raise ProvenanceError(f"{source}: source file not present (not downloaded)")
    if not sidecar.is_file():
        raise ProvenanceError(f"{source}: missing provenance sidecar {sidecar.name}")
    meta = json.loads(sidecar.read_text(encoding="utf-8"))
    missing = REQUIRED_PROVENANCE - set(meta)
    if missing:
        raise ProvenanceError(f"{source}: provenance missing {sorted(missing)}")
    if meta["label"] not in LABELS:
        raise ProvenanceError(f"{source}: label must be one of {sorted(LABELS)}")
    if meta["label_confidence"] not in LABEL_CONFIDENCE:
        raise ProvenanceError(f"{source}: unknown label_confidence {meta['label_confidence']!r}")
    if meta["licence_verified"] is not True:
        raise ProvenanceError(f"{source}: licence not verified; not eligible")
    datetime.fromisoformat(meta["retrieved_at"])  # raises on a bad timestamp
    if meta["sha256"] != _sha256(source):
        raise ProvenanceError(f"{source}: file checksum does not match provenance sha256")
    return meta


def ingest(source: Path) -> pd.DataFrame:
    """One URL per line; blank lines and '#' comments are skipped. Tranco-style
    "rank,domain" lines become "https://<domain>/"."""
    meta = read_provenance(source)
    urls = []
    for line in Path(source).read_text(encoding="utf-8").splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        if "://" not in value and "," in value:
            value = f"https://{value.split(',')[-1].strip()}/"
        urls.append(value)
    frame = pd.DataFrame({"raw_url": urls})
    frame["label"] = meta["label"]
    frame["label_confidence"] = meta["label_confidence"]
    frame["source_name"] = meta["source_name"]
    frame["retrieved_at"] = meta["retrieved_at"]
    return frame


def host_key(canonical: str) -> str:
    host = (urlsplit(canonical).hostname or "").lower()
    return host[4:] if host.startswith("www.") else host


def canonicalize_and_dedupe(frame: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    frame = frame.copy()
    frame["canonical_url"] = frame["raw_url"].map(canonicalize_url)
    empty = frame["canonical_url"] == ""
    frame = frame[~empty]

    labels_per_url = frame.groupby("canonical_url")["label"].nunique()
    conflicts = set(labels_per_url[labels_per_url > 1].index)
    frame = frame[~frame["canonical_url"].isin(conflicts)]
    before = len(frame)
    frame = frame.drop_duplicates("canonical_url", keep="first").reset_index(drop=True)
    frame["host_key"] = frame["canonical_url"].map(host_key)
    return frame, {"empty_after_canonicalization": int(empty.sum()),
                   "label_conflict_urls_dropped": len(conflicts),
                   "exact_duplicates_dropped": before - len(frame)}


def training_keys(splits: list[Path] = TRAINING_SPLITS) -> tuple[set, set]:
    urls, hosts = set(), set()
    for path in splits:
        if not path.is_file():
            raise ProvenanceError(f"training split {path} not found; overlap cannot be checked")
        canonical = pd.read_csv(path, usecols=["URL"])["URL"].astype(str).map(canonicalize_url)
        urls.update(canonical)
        hosts.update(canonical.map(host_key))
    return urls, hosts


def remove_training_overlap(frame: pd.DataFrame, urls: set, hosts: set) -> tuple[pd.DataFrame, dict]:
    url_hit = frame["canonical_url"].isin(urls)
    host_hit = frame["host_key"].isin(hosts) & ~url_hit
    report = {"url_overlap_dropped": int(url_hit.sum()), "host_overlap_dropped": int(host_hit.sum()),
              "host_overlap_dropped_by_label": frame[host_hit]["label"].value_counts().to_dict()}
    return frame[~(url_hit | host_hit)].reset_index(drop=True), report


def build(sources: list[Path], out_date: str, root: Path = EVAL_ROOT,
          splits: list[Path] = TRAINING_SPLITS) -> Path:
    frames = [ingest(Path(s)) for s in sources]
    provenance = [read_provenance(Path(s)) | {"file": str(s)} for s in sources]
    frame, dedupe = canonicalize_and_dedupe(pd.concat(frames, ignore_index=True))
    frame, overlap = remove_training_overlap(frame, *training_keys(splits))

    out_dir = root / f"url_eval_{out_date}"
    if out_dir.exists():
        raise FileExistsError(f"{out_dir} exists; evaluation sets are immutable, choose a new date")
    out_dir.mkdir(parents=True)
    frame.to_csv(out_dir / "urls.csv", index=False)
    manifest = {
        "usage": USAGE,
        "rule": "never use for training, threshold selection or model selection",
        "built_at": datetime.now(timezone.utc).isoformat(),
        "sources": provenance,
        "canonicalization": "src.blockchain.canonicalize.canonicalize_url",
        "dedupe": dedupe | {"key": "canonical_url"},
        "training_overlap": overlap | {"splits": [str(p) for p in splits],
                                       "keys": "canonical URL, and host with leading www. removed"},
        "rows": len(frame),
        "rows_by_label": frame["label"].value_counts().to_dict(),
        "rows_by_label_confidence": frame["label_confidence"].value_counts().to_dict(),
        "urls_sha256": _sha256(out_dir / "urls.csv"),
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))
    return out_dir


def assert_not_evaluation_data(path: Path) -> None:
    """Training code calls this to refuse an evaluation-only file."""
    manifest = Path(path).parent / "manifest.json"
    if manifest.is_file() and json.loads(manifest.read_text()).get("usage") == USAGE:
        raise ProvenanceError(f"{path} is evaluation-only data")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sources", nargs="+", type=Path, required=True)
    parser.add_argument("--out-date", required=True, help="YYYYMMDD stamp for the evaluation set")
    args = parser.parse_args(argv)
    print(build(args.sources, args.out_date))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

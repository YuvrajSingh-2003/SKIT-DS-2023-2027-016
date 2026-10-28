"""Prepare a reviewable batch of threat hashes for the ThreatRegistry (no submission).

This module only computes hashes, applies documented eligibility rules, optionally
runs READ-ONLY registry lookups, and writes a manifest for human review. It never
signs, sends or queues a transaction; submission is a separate, approved step.

Hashes come from the existing pipeline (src/blockchain/hashing.py):
    URL      -> generate_url_hash      (canonicalize_url, prefix "url:",     Keccak-256)
    MESSAGE  -> generate_message_hash  (canonicalize_message, prefix "message:", Keccak-256)
so every hash equals what app/services/blockchain_checker.py queries.

The manifest holds hashes, provenance and proposed metadata only; never raw URLs
or message text.

    python -m src.blockchain.prepare_batch --out data/threat_registry/proposed_batch.json
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Optional

from src.blockchain.hashing import generate_message_hash, generate_url_hash

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = PROJECT_ROOT / "contracts" / "configs" / "contract_addresses.json"

# ThreatRegistry.ThreatType
THREAT_TYPE_MESSAGE = 0
THREAT_TYPE_URL = 1
TYPE_NAMES = {THREAT_TYPE_MESSAGE: "MESSAGE", THREAT_TYPE_URL: "URL"}

# Proposed on-chain metadata, matching the existing seeder convention
# (src/blockchain/seed_registry.py: verdict 1, confidence 100 for dataset-labelled threats).
PROPOSED_VERDICT = 1
PROPOSED_CONFIDENCE = 100

# Synthetic integration-test record (registered for testing; not a real threat).
SYNTHETIC_TEST_URL = "https://chainshield-test.invalid/registry-check"
SYNTHETIC_TEST_URL_HASH = "0xa8472757acafcc048ff051b4bd6e8e4b9cb903b39027d4ed8720fc5a2105c65e"

# A first batch is capped so it can be reviewed and costed; the rest is deferred.
DEFAULT_URL_BATCH_LIMIT = 250

VERIFIED = "source_verified"           # labelled malicious by a documented source
AUTOMATED = "source_reported_automated"  # automated feed, not human-verified


def _hash(value: str, threat_type: int) -> str:
    return generate_url_hash(value) if threat_type == THREAT_TYPE_URL else generate_message_hash(value)


def make_candidate(value: str, threat_type: int, *, source: str, source_record_id: str,
                   verification_status: str, evidence: str, retrieved_at: str,
                   license_ok: bool, is_synthetic: bool = False) -> dict:
    """Hash one input with the project pipeline. The raw value is NOT kept.

    Malformed inputs become an excluded candidate (hash None) instead of raising.
    The hash is computed twice and must match (determinism check).
    """
    entry = {
        "hash": None, "threat_type": TYPE_NAMES[threat_type], "threat_type_int": threat_type,
        "proposed_verdict": PROPOSED_VERDICT, "proposed_confidence": PROPOSED_CONFIDENCE,
        "source": source, "source_record_id": source_record_id,
        "verification_status": verification_status, "evidence": evidence,
        "retrieved_at": retrieved_at, "license_ok": license_ok, "is_synthetic": is_synthetic,
        "already_registered": None, "registry_status": None, "exclusion_reason": None,
    }
    try:
        first, second = _hash(value, threat_type), _hash(value, threat_type)
    except (ValueError, TypeError):
        entry["exclusion_reason"] = "malformed_input"
        return entry
    if first != second:
        entry["exclusion_reason"] = "nondeterministic_hash"
        return entry
    entry["hash"] = first
    if first == SYNTHETIC_TEST_URL_HASH:
        entry["is_synthetic"] = True
    return entry


def select_lowest_hash(urls: list, limit: int) -> list:
    """Original rule: the `limit` lowest hashes. Reproducible, but effectively random
    with respect to threat coverage (several URLs can share one domain)."""
    return sorted(urls, key=lambda e: e["hash"])[:limit]


def select_stratified(urls: list, limit: int) -> list:
    """At most one URL per domain, with TLD shares proportional to the source.

    Each TLD gets floor(limit * domains_in_tld / all_domains) slots; the remaining
    slots go to the largest fractional parts (ties by TLD name). Within a TLD and a
    domain the lowest hash wins, so the result does not depend on input order.
    Uses the in-memory `_group` (domain) and `tld` fields.
    """
    by_domain = {}
    for e in sorted(urls, key=lambda e: e["hash"]):
        by_domain.setdefault(e.get("_group") or e["hash"], e)
    by_tld = defaultdict(list)
    for rep in sorted(by_domain.values(), key=lambda e: e["hash"]):
        by_tld[e_tld(rep)].append(rep)
    total = len(by_domain)
    if total <= limit:
        return sorted(by_domain.values(), key=lambda e: e["hash"])
    shares = {t: limit * len(v) / total for t, v in by_tld.items()}
    quota = {t: int(x) for t, x in shares.items()}
    for t in sorted(shares, key=lambda t: (-(shares[t] - quota[t]), t))[:limit - sum(quota.values())]:
        quota[t] += 1
    return sorted((e for t, v in by_tld.items() for e in v[:quota[t]]), key=lambda e: e["hash"])


def e_tld(entry: dict) -> str:
    return (entry.get("tld") or "").lower()


SELECTORS = {"lowest-hash": select_lowest_hash, "stratified": select_stratified}


def apply_eligibility(candidates: Iterable[dict], url_batch_limit: int = DEFAULT_URL_BATCH_LIMIT,
                      selection: str = "lowest-hash") -> dict:
    """Split candidates into proposed / excluded / synthetic / deferred. Order-independent.

    Rules, first match wins:
      already excluded (malformed, test split, ...) -> excluded
      synthetic test record                          -> synthetic (never in a real batch)
      licence not cleared                            -> excluded "license_review_required"
      not source-verified                            -> excluded "not_source_verified"
      duplicate hash (keeps the earliest by source order) -> excluded "duplicate_hash"
      already registered (read-only lookup)          -> excluded "already_registered"
    Eligible URL entries not chosen by the selection rule (see SELECTORS) are
    deferred, not rejected.
    """
    proposed, excluded, synthetic, deferred = [], [], [], []
    seen = set()
    for entry in candidates:
        if entry["exclusion_reason"]:
            excluded.append(entry)
        elif entry["is_synthetic"]:
            synthetic.append(entry)
        elif not entry["license_ok"]:
            excluded.append({**entry, "exclusion_reason": "license_review_required"})
        elif entry["verification_status"] != VERIFIED:
            excluded.append({**entry, "exclusion_reason": "not_source_verified"})
        elif entry["hash"] in seen:
            excluded.append({**entry, "exclusion_reason": "duplicate_hash"})
        elif entry["already_registered"]:
            seen.add(entry["hash"])
            excluded.append({**entry, "exclusion_reason": "already_registered"})
        else:
            seen.add(entry["hash"])
            proposed.append(entry)

    urls = sorted((e for e in proposed if e["threat_type_int"] == THREAT_TYPE_URL), key=lambda e: e["hash"])
    messages = sorted((e for e in proposed if e["threat_type_int"] == THREAT_TYPE_MESSAGE), key=lambda e: e["hash"])
    chosen = SELECTORS[selection](urls, url_batch_limit)
    chosen_ids = {id(e) for e in chosen}
    deferred = [e for e in urls if id(e) not in chosen_ids]
    return {"proposed": messages + chosen, "excluded": excluded,
            "synthetic": synthetic, "deferred": deferred}


def check_registry(candidates: list, lookup: Optional[Callable[[str, int], str]]) -> dict:
    """Read-only registry check. lookup(hash, threat_type) returns a status string.

    'match_threat'/'match_non_threat' -> already_registered True; 'no_match' -> False;
    anything else (e.g. 'unavailable', no lookup) -> None (unknown).
    """
    if lookup is None:
        return {"performed": False, "reason": "no lookup configured"}
    statuses = {}
    for entry in candidates:
        if not entry["hash"]:
            continue
        status = lookup(entry["hash"], entry["threat_type_int"])
        entry["registry_status"] = status
        entry["already_registered"] = (True if status in ("match_threat", "match_non_threat")
                                       else False if status == "no_match" else None)
        statuses[status] = statuses.get(status, 0) + 1
    return {"performed": True, "statuses": statuses}


def read_only_lookup(hash_hex: str, threat_type: int) -> str:
    """Use the backend's read-only checker (view calls only; chain ID and contract verified)."""
    from app.services.blockchain_checker import _lookup_hash
    return _lookup_hash(hash_hex, threat_type)["status"]


# ── source loaders (raw values stay in memory only) ───────────────────

def phiusiil_candidates(path: Path, retrieved_at: str) -> list:
    """PhiUSIIL label 0 (phishing). CC BY 4.0; labelled by the dataset authors."""
    out = []
    with open(path, encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            if str(row.get("label", "")).strip() != "0":
                continue
            out.append(make_candidate(
                row["URL"], THREAT_TYPE_URL, source="PhiUSIIL (UCI 967, CC BY 4.0)",
                source_record_id=row.get("FILENAME") or "", verification_status=VERIFIED,
                evidence="Dataset label 0 = phishing (UCI page: 'label 0 to a phishing URL'); "
                         "historical (published 2024), current activity not checked",
                retrieved_at=retrieved_at, license_ok=True))
            out[-1]["_group"] = (row.get("Domain") or "").strip().lower()
            out[-1]["tld"] = (row.get("TLD") or "").strip().lower()
    return out


def openphish_candidates(path: Path, retrieved_at: str) -> list:
    """OpenPhish community feed snapshot. Automated detection; free tier is non-commercial
    and academic use forbids sharing with third parties, so publication needs review."""
    out = []
    for line_no, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        out.append(make_candidate(
            line.strip(), THREAT_TYPE_URL, source="OpenPhish community feed",
            source_record_id=f"{Path(path).name}:{line_no}", verification_status=AUTOMATED,
            evidence="Listed in the OpenPhish community feed at retrieval time",
            retrieved_at=retrieved_at, license_ok=False))
    return out


def mishra_soni_candidates(raw_csv: Path, splits_dir: Path, retrieved_at: str) -> list:
    """Smishing messages from the prepared Mishra & Soni data (conflicts already excluded).

    Hashes use the ORIGINAL message text (what a user would paste), located through
    source_row. Messages in the locked test split are excluded so the registry cannot
    contaminate a later system-level evaluation on that split.
    """
    with open(raw_csv, encoding="utf-8-sig", newline="") as handle:
        raw_rows = [(row["LABEL"], row["TEXT"]) for row in csv.DictReader(handle)]
    out = []
    for split in ("train", "val", "test"):
        with open(Path(splits_dir) / f"{split}.csv", encoding="utf-8", newline="") as handle:
            for row in csv.DictReader(handle):
                if row["label"] != "smishing" or row["source"] != "mishra_soni":
                    continue
                raw_label, raw_text = raw_rows[int(row["source_row"])]
                if raw_label.strip().lower() != "smishing":
                    raise ValueError(f"source_row {row['source_row']} does not map to a raw Smishing row")
                entry = make_candidate(
                    raw_text, THREAT_TYPE_MESSAGE,
                    source="Mishra & Soni SMS Phishing Dataset (Mendeley f45bkkt8pr v1, CC BY 4.0)",
                    source_record_id=f"row {row['source_row']}", verification_status=VERIFIED,
                    evidence="Source label 'Smishing'; kept after exact and near-duplicate "
                             "label-conflict exclusion (docs/datasets.md)",
                    retrieved_at=retrieved_at, license_ok=True)
                if split == "test" and not entry["exclusion_reason"]:
                    entry["exclusion_reason"] = "in_locked_test_split"
                out.append(entry)
    return out


def synthetic_candidate() -> dict:
    return make_candidate(
        SYNTHETIC_TEST_URL, THREAT_TYPE_URL, source="ChainShield synthetic integration test",
        source_record_id="synthetic-1", verification_status="synthetic_test_data",
        evidence="Registered on purpose for integration testing; not a real threat",
        retrieved_at="n/a", license_ok=True, is_synthetic=True)


# ── manifest ──────────────────────────────────────────────────────────

def _public(entry: dict) -> dict:
    """Drop in-memory-only fields (prefixed '_', e.g. the domain) before writing."""
    return {k: v for k, v in entry.items() if not k.startswith("_")}


def build_manifest(candidates: list, registry: dict, url_batch_limit: int, sources: dict,
                   selection: str = "lowest-hash", scope: str = "all") -> dict:
    result = apply_eligibility(candidates, url_batch_limit, selection)
    picked_urls = [e for e in result["proposed"] if e["threat_type_int"] == THREAT_TYPE_URL]
    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))["sepolia"]
    count = lambda items, t: sum(1 for e in items if e["threat_type_int"] == t)
    reasons = {}
    for e in result["excluded"]:
        reasons[e["exclusion_reason"]] = reasons.get(e["exclusion_reason"], 0) + 1
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "purpose": "Reviewable proposal only. Nothing in this file has been submitted on-chain.",
        "scope": scope,
        "network": {"chain_id": config["chainId"], "contract_address": config["contractAddress"]},
        "hashing": "src.blockchain.hashing: Keccak-256 of 'url:'+canonicalize_url(x) or "
                   "'message:'+canonicalize_message(x)",
        "url_selection": {"rule": selection, "limit": url_batch_limit,
                          "distinct_domains": len({e.get("_group") or e["hash"] for e in picked_urls}),
                          "distinct_tlds": len({e_tld(e) for e in picked_urls})},
        "label_basis": "Every proposed entry is labelled malicious by its source dataset at "
                       "collection time. None has been independently confirmed as a current, "
                       "live threat; PhiUSIIL URLs date from the 2024 dataset.",
        "proposed_metadata": {"verdict": PROPOSED_VERDICT, "confidence": PROPOSED_CONFIDENCE,
                              "threatType": {"URL": THREAT_TYPE_URL, "MESSAGE": THREAT_TYPE_MESSAGE}},
        "sources": sources,
        "registry_check": registry,
        "summary": {
            "candidates": len(candidates),
            "source_verified": sum(1 for e in candidates if e["verification_status"] == VERIFIED),
            "proposed_url": count(result["proposed"], THREAT_TYPE_URL),
            "proposed_message": count(result["proposed"], THREAT_TYPE_MESSAGE),
            "proposed_total": len(result["proposed"]),
            "deferred_url_eligible": len(result["deferred"]),
            "excluded_by_reason": reasons,
            "synthetic": len(result["synthetic"]),
            "already_registered_known": sum(1 for e in candidates if e["already_registered"] is True),
            "registry_status_unknown": sum(1 for e in candidates if e["hash"] and e["already_registered"] is None),
            "estimated_transactions": len(result["proposed"]),
            "estimated_gas": None,
            "estimated_gas_note": "Not computed: needs eth_estimateGas against the deployed contract "
                                  "(RPC) or a local EVM; neither is available.",
        },
        "proposed": [_public(e) for e in result["proposed"]],
        "excluded": [_public(e) for e in result["excluded"]],
        "synthetic": [_public(e) for e in result["synthetic"]],
        "deferred_hashes": [e["hash"] for e in result["deferred"]],
    }


RPC_ENV_VARS = ("SEPOLIA_RPC_URL", "WEB3_PROVIDER_URI")


def rpc_configured(env_file: Path = PROJECT_ROOT / ".env") -> bool:
    """True if an RPC endpoint is set in the environment or in the project .env
    (the same places the backend checker reads). Only the RPC keys are looked at;
    values are never printed."""
    if any(os.getenv(name, "").strip() for name in RPC_ENV_VARS):
        return True
    if Path(env_file).is_file():
        from dotenv import dotenv_values
        values = dotenv_values(env_file)
        return any((values.get(name) or "").strip() for name in RPC_ENV_VARS)
    return False


def check_manifest(manifest: dict, lookup: Callable[[str, int], str], *, delay: float = 0.25,
                   max_lookups: int = 1000, sleep: Callable[[float], None] = time.sleep) -> dict:
    """Read-only lookups for every proposed hash of an existing manifest.

    Bounded (max_lookups) and paced (delay seconds between calls). Returns a new
    report; the manifest itself is not modified.
    """
    proposed = manifest["proposed"]
    if len(proposed) > max_lookups:
        raise ValueError(f"{len(proposed)} lookups exceed max_lookups={max_lookups}")
    results, counts = [], {}
    for i, entry in enumerate(proposed):
        if i:
            sleep(delay)
        status = lookup(entry["hash"], entry["threat_type_int"])
        counts[status] = counts.get(status, 0) + 1
        results.append({"hash": entry["hash"], "threat_type": entry["threat_type"],
                        "registry_status": status,
                        "already_registered": (True if status in ("match_threat", "match_non_threat")
                                               else False if status == "no_match" else None)})
    known = {"match_threat", "match_non_threat", "no_match"}
    summary = {
        "existing_threat": counts.get("match_threat", 0),
        "existing_non_threat": counts.get("match_non_threat", 0),
        "new_candidates": counts.get("no_match", 0),
        "failed_or_unknown": sum(n for status, n in counts.items() if status not in known),
        "note": "'unavailable' means the lookup failed; it is NOT evidence that a hash is absent.",
    }
    return {"checked_at": datetime.now(timezone.utc).isoformat(), "summary": summary,
            "manifest_generated_at": manifest.get("generated_at"),
            "network": manifest.get("network"), "method": "threatExists/getThreat view calls only",
            "counts": counts, "results": results}


def write_manifest(manifest: dict, path: Path) -> None:
    path = Path(path)
    if path.exists():
        raise FileExistsError(f"Refusing to overwrite {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=1), encoding="utf-8")


def _sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main(argv: Optional[list] = None, env_file: Path = PROJECT_ROOT / ".env") -> int:
    """CLI entry point. env_file is where RPC settings are looked up (tests pass a temp path)."""
    parser = argparse.ArgumentParser(description="Prepare a threat-registry batch (no submission).")
    parser.add_argument("--out", required=True)
    parser.add_argument("--phiusiil", default=str(PROJECT_ROOT / "data/raw/PhiUSIIL_Phishing_URL_Dataset.csv"))
    parser.add_argument("--mishra-raw", default=str(PROJECT_ROOT / "data/incoming/mishra_soni/extracted/Dataset_5971.csv"))
    parser.add_argument("--splits-dir", default=str(PROJECT_ROOT / "data/processed"))
    parser.add_argument("--openphish", default=None, help="Optional OpenPhish snapshot (one URL per line)")
    parser.add_argument("--url-batch-limit", type=int, default=DEFAULT_URL_BATCH_LIMIT)
    parser.add_argument("--selection", choices=sorted(SELECTORS), default="lowest-hash")
    parser.add_argument("--registry-check", action="store_true", help="Run read-only registry lookups")
    parser.add_argument("--check-manifest", default=None,
                        help="Only run read-only lookups for this manifest's proposed hashes; write to --out")
    parser.add_argument("--delay", type=float, default=0.25, help="Seconds between lookups")
    only = parser.add_mutually_exclusive_group()
    only.add_argument("--urls-only", action="store_true", help="PhiUSIIL URLs only; SMS sources not needed")
    only.add_argument("--messages-only", action="store_true", help="Mishra & Soni smishing only; PhiUSIIL not needed")
    args = parser.parse_args(argv)

    if args.check_manifest:
        if Path(args.out).exists():
            raise FileExistsError(f"Refusing to overwrite {args.out}")
        if not rpc_configured(env_file):
            print("No RPC configured (SEPOLIA_RPC_URL / WEB3_PROVIDER_URI unset); no lookups performed.")
            return 2
        manifest = json.loads(Path(args.check_manifest).read_text(encoding="utf-8"))
        report = check_manifest(manifest, read_only_lookup, delay=args.delay)
        write_manifest(report, Path(args.out))
        print(json.dumps(report["counts"], indent=1))
        return 0

    scope = "urls" if args.urls_only else "messages" if args.messages_only else "all"
    use_urls, use_messages = scope in ("all", "urls"), scope in ("all", "messages")
    required = []
    if use_urls:
        required.append(Path(args.phiusiil))
    if use_messages:
        required += [Path(args.mishra_raw)] + [Path(args.splits_dir) / f"{s}.csv" for s in ("train", "val", "test")]
    if args.openphish and use_urls:
        required.append(Path(args.openphish))
    missing = [str(p) for p in required if not p.is_file()]
    if missing:
        print("Missing source files (nothing written):\n  " + "\n  ".join(missing))
        return 3

    now = datetime.now(timezone.utc).isoformat()
    candidates, sources = [], {}
    if use_messages:
        candidates += mishra_soni_candidates(Path(args.mishra_raw), Path(args.splits_dir), now)
        sources["mishra_soni"] = {
            "file": "Dataset_5971.csv", "file_sha256": _sha256(args.mishra_raw),
            "version": "Mendeley Data f45bkkt8pr, version 1", "license": "CC BY 4.0",
            "splits_sha256": {s: _sha256(Path(args.splits_dir) / f"{s}.csv") for s in ("train", "val", "test")},
            "selection": "all label-conflict-free smishing rows in train and val; test split excluded"}
    if use_urls:
        candidates = [synthetic_candidate()] + candidates
        candidates += phiusiil_candidates(Path(args.phiusiil), now)
        sources["phiusiil"] = {
            "file": Path(args.phiusiil).name, "file_sha256": _sha256(args.phiusiil),
            "version": "UCI Machine Learning Repository dataset 967", "license": "CC BY 4.0",
            "label_definition": "label 0 = phishing (dataset documentation)",
            "selection": f"{args.selection}, limit {args.url_batch_limit}"}
        sources["phishtank"] = {"used": False, "reason": "data feed rate-limited without an application key (HTTP 429)"}
        sources["urlhaus"] = {"used": False, "reason": "downloads and API require an abuse.ch Auth-Key (HTTP 410/401)"}
    if args.openphish and use_urls:
        candidates += openphish_candidates(Path(args.openphish), now)
        sources["openphish"] = {"file_sha256": _sha256(args.openphish),
                                "license": "non-commercial; academic users may not share with third parties"}

    registry = check_registry(candidates, read_only_lookup if args.registry_check else None)
    manifest = build_manifest(candidates, registry, args.url_batch_limit, sources, args.selection, scope)
    write_manifest(manifest, Path(args.out))
    print(json.dumps(manifest["summary"], indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

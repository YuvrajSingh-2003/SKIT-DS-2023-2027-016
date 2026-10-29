"""Dry-run planner for the licensed URL collection.

    python -m src.data.legit_sources.collect --source S1          # print the plan
    python -m src.data.legit_sources.collect --all

Collection is NOT implemented: `--execute` always refuses until a source's
status is `approved` in registry.py AND an approval record exists in
docs/legitimate_url_collection_plan.md. This module performs no network I/O.
"""

from __future__ import annotations

import argparse
import json
import sys

from src.data.legit_sources import registry

OUTPUT_ROOT = "data/incoming/legit_sources"   # gitignored


class NotApproved(RuntimeError):
    pass


def plan(source_id: str) -> dict:
    s = registry.get(source_id)
    out = {"source": s.id, "name": s.name, "side": s.side, "status": s.status, "licence": s.licence,
           "terms_url": s.terms_url, "terms_sha256": s.terms_sha256 or None, "label_basis": s.label_basis,
           "reason": s.reason or None, "dry_run": True, "network_io": False}
    if s.status in (registry.BLOCKED, registry.REJECTED):
        out["requests"] = []
        out["would_collect"] = False
        return out
    out.update({
        "would_collect": s.status == registry.APPROVED,
        "user_agent": registry.USER_AGENT, "min_interval_seconds": s.min_interval_seconds, "pinned": s.pinned or None,
        "requests": [{"method": r.method, "url": r.url.replace("{pinned}", s.pinned), "params": r.params, "note": r.note}
                     for r in s.requests],
        "raw_snapshot_dir": f"{OUTPUT_ROOT}/{s.id}/<UTC timestamp>/ (gitignored, checksummed)",
        "label_ceiling": "uncertain" if s.status == registry.POPULARITY else
                         ("verified_legitimate" if s.side == "legitimate" else "verified_phishing"),
    })
    return out


def execute(source_id: str) -> None:
    s = registry.get(source_id)
    raise NotApproved(f"{s.id} status is {s.status!r}: collection is not approved "
                      "(docs/legitimate_url_collection_plan.md, Phase 0)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--source")
    group.add_argument("--all", action="store_true")
    parser.add_argument("--execute", action="store_true", help="refused until approved")
    args = parser.parse_args(argv)
    ids = sorted(registry.SOURCES) if args.all else [args.source]
    if args.execute:
        try:
            for source_id in ids:
                execute(source_id)
        except NotApproved as error:
            print(f"REFUSED: {error}", file=sys.stderr)
            return 2
    print(json.dumps([plan(i) for i in ids], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

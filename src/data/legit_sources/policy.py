"""Labeling, privacy and provenance policy (docs/legitimate_url_collection_plan.md §3-§7).

Pure functions over URL strings: nothing here performs network access, and no
URL is ever fetched, resolved or visited.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from app.services.reputation_precheck import HOSTING_AND_SHARING_DOMAINS
from src.blockchain.canonicalize import canonicalize_url

VERIFIED_LEGITIMATE = "verified_legitimate"
VERIFIED_PHISHING = "verified_phishing"
UNCERTAIN = "uncertain"
LABELS = {VERIFIED_LEGITIMATE, VERIFIED_PHISHING, UNCERTAIN}
LABEL_BASES = {"first_party_registry", "first_party_enumeration", "publisher_declared", "popularity", "feed"}
FIRST_PARTY = {"first_party_registry", "first_party_enumeration", "publisher_declared"}

_SENSITIVE_KEY = re.compile(r"token|session|sid|auth|key|passw|email|e-mail|phone", re.I)
_EMAIL = re.compile(r"[^@/\s]+@[^@/\s]+\.[a-z]{2,}", re.I)

RECORD_FIELDS = [
    "url_raw", "url_canonical", "canonicalizer_version", "host", "registrable_domain", "psl_section",
    "psl_version", "scheme", "has_www", "is_root", "has_query", "has_port", "is_host_only", "label",
    "label_basis", "uncertain_reason", "source", "source_record_id", "source_snapshot", "terms_url",
    "terms_retrieved_at", "terms_sha256", "collected_at", "collector_version", "batch_id", "split",
]


# ── frozen Public Suffix List ─────────────────────────────────────────

@dataclass(frozen=True)
class PublicSuffixList:
    icann: frozenset
    private: frozenset
    sha256: str

    @classmethod
    def load(cls, path: Path, expected_sha256: str) -> "PublicSuffixList":
        data = Path(path).read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if digest != expected_sha256:
            raise ValueError(f"PSL checksum {digest} != frozen {expected_sha256}")
        icann, private = set(), set()
        section = icann
        for line in data.decode("utf-8").splitlines():
            line = line.strip()
            if "===BEGIN PRIVATE DOMAINS===" in line:
                section = private
            if line and not line.startswith("//"):
                section.add(line.split()[0].lower())
        return cls(frozenset(icann), frozenset(private), digest)

    def _suffix(self, labels: list[str], rules: frozenset) -> int:
        """Number of labels in the longest matching public suffix (PSL algorithm)."""
        best = 1
        for i in range(len(labels)):
            candidate = ".".join(labels[i:])
            wildcard = ".".join(["*"] + labels[i + 1:])
            if "!" + candidate in rules:
                return len(labels) - i - 1
            if candidate in rules or (i + 1 < len(labels) and wildcard in rules):
                best = max(best, len(labels) - i)
        return best

    def split(self, host: str) -> tuple[str, str]:
        """(registrable_domain under ICANN rules, section of the longest matching rule)."""
        labels = [l for l in host.lower().rstrip(".").split(".") if l]
        if not labels:
            return "", "none"
        icann_len = self._suffix(labels, self.icann)
        private_len = self._suffix(labels, self.private | self.icann)
        section = "private" if private_len > icann_len else "icann"
        n = icann_len + 1
        return (".".join(labels[-n:]) if len(labels) >= n else host.lower()), section


# ── shape, privacy, labels ────────────────────────────────────────────

def shape(url: str, host_only: bool = False) -> dict:
    parts = urlsplit(url if "://" in url else f"http://{url}")
    host = (parts.hostname or "").lower()
    return {"scheme": "" if host_only else parts.scheme.lower(), "has_www": host.startswith("www."),
            "is_root": parts.path in ("", "/") and not parts.query, "has_query": bool(parts.query),
            "has_port": parts.port is not None, "is_host_only": host_only, "host": host}


def privacy_exclusion(url: str) -> str | None:
    """Reason to EXCLUDE the URL (never redact), or None."""
    parts = urlsplit(url if "://" in url else f"http://{url}")
    if parts.username or parts.password or "@" in parts.netloc:
        return "userinfo"
    if _EMAIL.search(parts.path + "?" + parts.query):
        return "email_address"
    if any(_SENSITIVE_KEY.search(k) for k, _ in parse_qsl(parts.query, keep_blank_values=True)):
        return "sensitive_query_key"
    return None


def is_platform_host(host: str, psl_section: str) -> bool:
    return psl_section == "private" or any(host == d or host.endswith("." + d) for d in HOSTING_AND_SHARING_DOMAINS)


def assign_label(*, side: str, label_basis: str, url_declared_by_source: bool, host: str, psl_section: str,
                 conflicting: bool, platform_first_party: bool = False) -> tuple[str, str | None]:
    """Apply plan §3. Returns (label, uncertain_reason)."""
    if label_basis not in LABEL_BASES:
        raise ValueError(f"unknown label basis {label_basis!r}")
    if conflicting:
        return UNCERTAIN, "conflicting_sources"
    if side == "phishing":
        return (VERIFIED_PHISHING, None) if label_basis == "feed" else (UNCERTAIN, "unsupported_basis")
    if label_basis == "popularity":
        return UNCERTAIN, "popularity_only"
    if label_basis not in FIRST_PARTY:
        return UNCERTAIN, "unsupported_basis"
    if not url_declared_by_source:
        return UNCERTAIN, "host_evidence_does_not_verify_path"
    if is_platform_host(host, psl_section) and not platform_first_party:
        return UNCERTAIN, "user_content_platform"
    return VERIFIED_LEGITIMATE, None


def upgrade_allowed(old: str, new: str, new_evidence: bool) -> bool:
    """Labels are never upgraded without new recorded evidence (plan §3 rule 8)."""
    return old == new or new == UNCERTAIN or new_evidence


# ── records and batches ───────────────────────────────────────────────

def canonicalizer_version() -> str:
    try:
        return subprocess.run(["git", "hash-object", "src/blockchain/canonicalize.py"], capture_output=True,
                              text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return hashlib.sha1(Path("src/blockchain/canonicalize.py").read_bytes()).hexdigest()


def build_record(url: str, *, psl: PublicSuffixList, host_only: bool, **provenance) -> dict:
    s = shape(url, host_only)
    registrable, section = psl.split(s["host"])
    return {"url_raw": url, "url_canonical": canonicalize_url(url),
            "canonicalizer_version": provenance.pop("canonicalizer_version", None) or canonicalizer_version(),
            "host": s["host"], "registrable_domain": registrable, "psl_section": section, "psl_version": psl.sha256,
            **{k: s[k] for k in ("scheme", "has_www", "is_root", "has_query", "has_port", "is_host_only")},
            **provenance}


def validate_record(record: dict) -> list[str]:
    problems = [f"missing {f}" for f in RECORD_FIELDS if f not in record]
    if record.get("label") not in LABELS:
        problems.append(f"bad label {record.get('label')!r}")
    if record.get("label_basis") not in LABEL_BASES:
        problems.append(f"bad label_basis {record.get('label_basis')!r}")
    if record.get("label") == UNCERTAIN and not record.get("uncertain_reason"):
        problems.append("uncertain without reason")
    if record.get("label") == VERIFIED_LEGITIMATE and record.get("label_basis") not in FIRST_PARTY:
        problems.append("verified_legitimate requires first-party basis")
    if record.get("url_raw") and privacy_exclusion(record["url_raw"]):
        problems.append("privacy-excluded URL present")
    return problems


def batch_sha256(records: list[dict]) -> str:
    """Order-independent checksum of a batch (sorted canonical JSON lines)."""
    lines = sorted(json.dumps({k: r.get(k) for k in RECORD_FIELDS if k != "batch_id"}, sort_keys=True, default=str)
                   for r in records)
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()

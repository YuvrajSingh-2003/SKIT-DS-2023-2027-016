"""Experimental URL features v2: separate host, path/query and scheme blocks.

EXPERIMENT-ONLY. Production serving still uses src/features/url_lexical.py
(pinned); nothing here is imported by app/.

Design (docs/url_feature_investigation.md §5, docs/external_url_detection_review.md A1-A3):
- HOST block: computed from the canonical host only (scheme, userinfo, port,
  path, query, fragment, trailing dot and a leading "www." removed), so it is
  invariant to every non-host part of the URL (tested with a negative control).
- PATH block: path, query and fragment statistics.
- SCHEME block: is_https.

Every feature is label-independent: fixed word lists, no target-derived priors.
"""

from __future__ import annotations

import math
import re

import numpy as np
import pandas as pd

from src.data.url_features import SUSPICIOUS_KEYWORDS, URL_SHORTENERS
from app.services.reputation_precheck import HOSTING_AND_SHARING_DOMAINS
from src.training.train_url_multisource import MULTI_PART_SUFFIXES

FEATURE_SPEC_VERSION = "url_lexical_v2.0"

_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://")
_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_VOWELS = set("aeiou")
_CONSONANTS = set("abcdefghijklmnopqrstuvwxyz") - _VOWELS
_DIGITS = set("0123456789")
_FILE_EXT = re.compile(r"\.(php|html?|aspx?|jsp|cgi|exe|zip|js)$", re.I)

HOST_FEATURES = [
    "host_length", "host_labels", "host_subdomain_labels", "registrable_length", "max_label_length",
    "host_digits", "host_hyphens", "host_entropy", "registrable_entropy", "host_max_digit_run",
    "host_max_consonant_run", "host_vowel_ratio", "host_is_ip", "host_has_punycode", "tld_length",
    "host_keyword", "host_is_shortener", "host_platform_hosted",
]
PATH_FEATURES = [
    "path_length", "path_depth", "path_digits", "path_special", "path_percent_encoded",
    "path_has_file_extension", "path_keyword", "query_length", "query_params", "query_max_value_length",
    "has_fragment", "url_has_userinfo", "path_double_slash",
]
SCHEME_FEATURES = ["is_https"]
ALL_FEATURES = HOST_FEATURES + PATH_FEATURES + SCHEME_FEATURES


def split_url(raw: str) -> tuple[str, str, str, str]:
    """Return (scheme, canonical_host, path, query_and_fragment) by plain string surgery."""
    value = str(raw).strip()
    match = _SCHEME.match(value)
    scheme = match.group(0)[:-3].lower() if match else ""
    rest = value[match.end():] if match else value.removeprefix("//")
    cut = min([i for i in (rest.find("/"), rest.find("?"), rest.find("#")) if i != -1], default=len(rest))
    authority, tail = rest[:cut], rest[cut:]
    if "@" in authority:
        authority = authority.rsplit("@", 1)[1]
    if authority.startswith("["):
        authority = authority[1:authority.find("]")] if "]" in authority else authority[1:]
    elif ":" in authority:
        authority = authority.split(":", 1)[0]
    host = authority.lower().rstrip(".")
    host = host[4:] if host.startswith("www.") else host
    q = min([i for i in (tail.find("?"), tail.find("#")) if i != -1], default=len(tail))
    return scheme, host, tail[:q], tail[q:]


def _registrable(host: str) -> str:
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = pd.Series(list(text)).value_counts().to_numpy() / len(text)
    return float(-(counts * np.log2(counts)).sum())


def _max_run(text: str, members: set) -> int:
    best = current = 0
    for ch in text:
        current = current + 1 if ch in members else 0
        best = max(best, current)
    return best


def _keyword(text: str) -> int:
    lowered = text.lower()
    return int(any(re.search(rf"(?<![a-z]){re.escape(k)}(?![a-z])", lowered) for k in SUSPICIOUS_KEYWORDS))


def host_features(host: str) -> dict:
    labels = [l for l in host.split(".") if l] or [""]
    registrable = _registrable(host)
    reg_name = registrable.split(".")[0] if registrable else ""
    letters = sum(c.isalpha() for c in host)
    is_ip = bool(_IPV4.match(host)) or (":" in host)
    return {
        "host_length": len(host), "host_labels": len(labels),
        "host_subdomain_labels": max(len(labels) - len(registrable.split(".")), 0),
        "registrable_length": len(registrable), "max_label_length": max(len(l) for l in labels),
        "host_digits": sum(c in _DIGITS for c in host), "host_hyphens": host.count("-"),
        "host_entropy": _entropy(host), "registrable_entropy": _entropy(reg_name),
        "host_max_digit_run": _max_run(host, _DIGITS), "host_max_consonant_run": _max_run(host, _CONSONANTS),
        "host_vowel_ratio": (sum(c in _VOWELS for c in host) / letters) if letters else 0.0,
        "host_is_ip": int(is_ip), "host_has_punycode": int("xn--" in host),
        "tld_length": 0 if is_ip else len(labels[-1]), "host_keyword": _keyword(host),
        "host_is_shortener": int(any(host == d or host.endswith("." + d) for d in URL_SHORTENERS)),
        "host_platform_hosted": int(any(host.endswith("." + d) for d in HOSTING_AND_SHARING_DOMAINS)),
    }


def path_features(raw: str, path: str, query_fragment: str) -> dict:
    query, _, fragment = query_fragment.partition("#")
    query = query.removeprefix("?")
    params = [p for p in query.split("&") if p]
    authority = _SCHEME.sub("", str(raw).strip(), count=1).split("/", 1)[0]
    return {
        "path_length": len(path), "path_depth": len([s for s in path.split("/") if s]),
        "path_digits": sum(c in _DIGITS for c in path),
        "path_special": sum(not c.isalnum() and c != "/" for c in path),
        "path_percent_encoded": path.count("%") + query.count("%"),
        "path_has_file_extension": int(bool(_FILE_EXT.search(path))), "path_keyword": _keyword(path + "?" + query),
        "query_length": len(query), "query_params": len(params),
        "query_max_value_length": max((len(p.partition("=")[2]) for p in params), default=0),
        "has_fragment": int("#" in query_fragment), "url_has_userinfo": int("@" in authority),
        "path_double_slash": int("//" in path),
    }


def extract(raw: str) -> dict:
    scheme, host, path, query_fragment = split_url(raw)
    return {**host_features(host), **path_features(raw, path, query_fragment), "is_https": int(scheme == "https")}


def extract_dataframe(urls: pd.Series, columns: list[str] = ALL_FEATURES) -> pd.DataFrame:
    rows = [extract(u) for u in urls.astype(str)]
    return pd.DataFrame(rows, index=urls.index)[columns].astype(float)

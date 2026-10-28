"""Lexical URL features computed from the URL string alone.

These features are used by the URL inference model. Training and serving
both call `extract_lexical_url_features`, so the model sees identical inputs
in both places (no training-serving skew).

They deliberately avoid the PhiUSIIL dataset's precomputed columns that
depend on dataset-wide statistics or webpage fetches (for example
TLDLegitimateProb, URLCharProb, URLSimilarityIndex, LineOfCode, HasTitle),
because those cannot be recomputed for an arbitrary submitted URL.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

import pandas as pd

from src.data.url_features import (
    SUSPICIOUS_KEYWORDS,
    URL_SHORTENERS,
    calculate_url_depth,
)

LEXICAL_URL_FEATURES = [
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "TLDLength",
    "NoOfSubDomain",
    "NoOfLettersInURL",
    "LetterRatioInURL",
    "NoOfDegitsInURL",
    "DegitRatioInURL",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL",
    "SpacialCharRatioInURL",
    "HasObfuscation",
    "IsHTTPS",
    "IsURLShortener",
    "URLDepth",
    "HasSuspiciousKeyword",
]

_OBFUSCATION_CHARACTERS = ("%", "@", "\\")
_SPECIAL_CHARACTERS = set("!#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")


def _parse(url: str):
    """Parse a URL, adding a scheme when the input has none."""
    value = str(url).strip()
    parsed = urlparse(value)

    if not parsed.netloc:
        parsed = urlparse(f"http://{value}")

    return parsed


def _strip_root_slash(value: str) -> str:
    """Drop a trailing slash that only marks an empty path.

    The training data never has one ("https://example.com", not
    "https://example.com/"), so keeping it would change the features for the
    same site. Training and serving both use this function.
    """
    parsed = urlparse(value if "://" in value else f"http://{value}")

    if parsed.path == "/" and not parsed.query and not parsed.fragment:
        return value.rstrip("/")

    return value


def _is_ip_host(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return True


def extract_lexical_url_features(url: str) -> dict:
    """Compute the lexical feature vector for one URL string.

    Args:
        url: Raw URL string (with or without a scheme).

    Returns:
        Mapping from each name in LEXICAL_URL_FEATURES to a number.
    """
    value = _strip_root_slash(str(url).strip())
    parsed = _parse(value)

    hostname = (parsed.hostname or "").lower()
    labels = [label for label in hostname.split(".") if label]
    tld = labels[-1] if labels else ""
    url_length = len(value)

    letters = len(re.findall(r"[A-Za-z]", value))
    digits = len(re.findall(r"[0-9]", value))
    special = sum(1 for char in value if char in _SPECIAL_CHARACTERS)

    is_shortener = int(
        hostname in URL_SHORTENERS
        or any(hostname.endswith(f".{domain}") for domain in URL_SHORTENERS)
    )

    lowered = value.lower()
    has_keyword = int(
        any(
            re.search(rf"(?<![a-z]){re.escape(keyword)}(?![a-z])", lowered)
            for keyword in SUSPICIOUS_KEYWORDS
        )
    )

    return {
        "URLLength": url_length,
        "DomainLength": len(hostname),
        "IsDomainIP": int(_is_ip_host(hostname)),
        "TLDLength": len(tld),
        "NoOfSubDomain": max(len(labels) - 2, 0),
        "NoOfLettersInURL": letters,
        "LetterRatioInURL": letters / url_length if url_length else 0.0,
        "NoOfDegitsInURL": digits,
        "DegitRatioInURL": digits / url_length if url_length else 0.0,
        "NoOfEqualsInURL": value.count("="),
        "NoOfQMarkInURL": value.count("?"),
        "NoOfAmpersandInURL": value.count("&"),
        "NoOfOtherSpecialCharsInURL": special,
        "SpacialCharRatioInURL": special / url_length if url_length else 0.0,
        "HasObfuscation": int(
            any(char in value for char in _OBFUSCATION_CHARACTERS)
        ),
        "IsHTTPS": int(parsed.scheme.lower() == "https"),
        "IsURLShortener": is_shortener,
        "URLDepth": calculate_url_depth(value),
        "HasSuspiciousKeyword": has_keyword,
    }


def extract_lexical_url_dataframe(urls: pd.Series) -> pd.DataFrame:
    """Compute lexical features for a Series of URL strings, in order."""
    rows = [extract_lexical_url_features(url) for url in urls]

    return pd.DataFrame(rows, columns=LEXICAL_URL_FEATURES, index=urls.index)

"""Reputation pre-check prototype (disabled by default).

Purpose: reduce URL-model false positives on the bare homepages of
well-established domains. The URL model is known to flag almost any URL that
is not shaped like `https://www.<host>` (docs/url_shape_guard.md).

What it does when it applies: the scan route does not let the URL model's
*advisory* phishing label raise the risk level. It never sets a verdict:
- it never returns or implies SAFE (popularity is not a safety label);
- the blockchain registry is still consulted first and a registry threat
  still wins;
- heuristic findings still set the risk level as before.

It applies only when ALL of these hold, otherwise the URL continues through
the normal detection path unchanged:
- the pre-check is enabled (CHAINSHIELD_REPUTATION_PRECHECK=1) and a local
  list file is configured (CHAINSHIELD_REPUTATION_LIST);
- scheme is http/https, no userinfo, no explicit port, host is not an IP,
  host is ASCII and not punycode;
- the URL is a bare homepage: empty or "/" path, no query, no fragment
  (hosted phishing on popular sites lives in paths);
- the host is exactly a listed domain or "www." + a listed domain within the
  configured top N (other subdomains are excluded: user-controlled subdomains
  on popular platforms are a common phishing host);
- the domain is not a hosting/sharing platform or URL shortener.

The list file is local: one domain per line, or Tranco-style "rank,domain".
No network access happens here.
"""

from __future__ import annotations

import ipaddress
import os
import threading
from pathlib import Path
from urllib.parse import urlsplit

from src.data.url_features import URL_SHORTENERS

ENABLE_ENV = "CHAINSHIELD_REPUTATION_PRECHECK"
LIST_ENV = "CHAINSHIELD_REPUTATION_LIST"
TOP_N_ENV = "CHAINSHIELD_REPUTATION_TOP_N"
DEFAULT_TOP_N = 10000

# Apex domains where third parties publish content or redirects. Never eligible,
# even if a popularity list ranks them highly.
HOSTING_AND_SHARING_DOMAINS = frozenset({
    "github.io", "githubusercontent.com", "gitlab.io", "blogspot.com", "wordpress.com",
    "wixsite.com", "weebly.com", "webflow.io", "square.site", "framer.app", "framer.website",
    "carrd.co", "notion.site", "godaddysites.com", "myshopify.com", "linktr.ee",
    "sites.google.com", "docs.google.com", "drive.google.com", "forms.gle", "storage.googleapis.com",
    "firebaseapp.com", "web.app", "appspot.com", "herokuapp.com", "netlify.app", "vercel.app",
    "pages.dev", "workers.dev", "r2.dev", "glitch.me", "replit.app", "repl.co",
    "ngrok.io", "ngrok-free.app", "trycloudflare.com", "000webhostapp.com",
    "azurewebsites.net", "web.core.windows.net", "blob.core.windows.net", "sharepoint.com",
    "amazonaws.com", "cloudfront.net", "ipfs.io", "dweb.link", "translate.goog",
    "dropbox.com", "mediafire.com", "typeform.com", "jotform.com", "formstack.com",
})

NOT_APPLIED = "not_applied"
APPLIED = "applied"

_cache_lock = threading.Lock()
_cache: dict = {}


def is_enabled() -> bool:
    return os.environ.get(ENABLE_ENV) == "1"


def load_domain_list(path: Path, top_n: int) -> frozenset[str]:
    """Read the first top_n domains from a local list file."""
    domains = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            domain = value.split(",")[-1].strip().lower().rstrip(".")
            if domain:
                domains.append(domain)
            if len(domains) >= top_n:
                break
    return frozenset(domains)


def _configured_domains() -> frozenset[str] | None:
    path = os.environ.get(LIST_ENV)
    if not path or not Path(path).is_file():
        return None
    top_n = int(os.environ.get(TOP_N_ENV, DEFAULT_TOP_N))
    key = (path, Path(path).stat().st_mtime_ns, top_n)
    with _cache_lock:
        if key not in _cache:
            _cache.clear()
            _cache[key] = load_domain_list(Path(path), top_n)
        return _cache[key]


def _result(status: str, reason: str, domain: str | None = None) -> dict:
    return {"status": status, "applies": status == APPLIED, "reason": reason, "matched_domain": domain}


def evaluate(url: str, domains: frozenset[str] | None = None) -> dict:
    """Decide whether the pre-check applies to this URL. Never raises.

    `domains` overrides the configured list (offline experiments, tests);
    passing it also bypasses the enable flag.
    """
    if domains is None:
        if not is_enabled():
            return _result(NOT_APPLIED, "disabled")
        domains = _configured_domains()
        if domains is None:
            return _result(NOT_APPLIED, "no reputation list configured")

    try:
        parts = urlsplit(str(url).strip())
        host = (parts.hostname or "").lower().rstrip(".")
        port = parts.port
    except ValueError:
        return _result(NOT_APPLIED, "malformed URL")

    if parts.scheme.lower() not in {"http", "https"} or not host:
        return _result(NOT_APPLIED, "not an http(s) URL with a host")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        return _result(NOT_APPLIED, "URL contains userinfo")
    if port is not None:
        return _result(NOT_APPLIED, "explicit port")
    try:
        ipaddress.ip_address(host.strip("[]"))
        return _result(NOT_APPLIED, "IP address host")
    except ValueError:
        pass
    if not host.isascii() or any(label.startswith("xn--") for label in host.split(".")):
        return _result(NOT_APPLIED, "non-ASCII or punycode host")
    if parts.path not in {"", "/"} or parts.query or parts.fragment:
        return _result(NOT_APPLIED, "URL has a path, query or fragment")

    candidate = host[4:] if host.startswith("www.") else host
    if candidate in HOSTING_AND_SHARING_DOMAINS or candidate in URL_SHORTENERS:
        return _result(NOT_APPLIED, "hosting, sharing or shortener domain")
    if candidate not in domains:
        return _result(NOT_APPLIED, "domain not on the list (exact host or www. only)")

    return _result(APPLIED, "bare homepage of a listed domain", candidate)

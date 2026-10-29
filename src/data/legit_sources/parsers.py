"""Parsers from a source's response payload to (url, source_record_id, host_only, declared) tuples.

Pure functions over payloads that a collector would have fetched; they never
fetch anything themselves. `declared` is True when the source itself declares
that exact URL (or host, for host-only rows).
"""

from __future__ import annotations

import csv
import io
import xml.etree.ElementTree as ET


def wikidata_p856(payload: dict) -> list[tuple]:
    rows = []
    for b in payload.get("results", {}).get("bindings", []):
        url = b.get("url", {}).get("value", "")
        qid = b.get("item", {}).get("value", "").rsplit("/", 1)[-1]
        if url.startswith(("http://", "https://")):
            rows.append((url, qid, False, True))
    return rows


def dotgov_csv(text: str) -> list[tuple]:
    reader = csv.DictReader(io.StringIO(text))
    field = next((f for f in reader.fieldnames or [] if f.lower().replace(" ", "_") == "domain_name"), None)
    if field is None:
        raise ValueError("dotgov CSV has no 'Domain name' column")
    return [(r[field].strip().lower(), r[field].strip().lower(), True, True) for r in reader if r[field].strip()]


def govuk_sitemap(xml_text: str) -> list[tuple]:
    ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    root = ET.fromstring(xml_text)
    if root.tag.endswith("sitemapindex"):
        return []          # index of further sitemaps; the collector plans those separately
    return [(loc.text.strip(), loc.text.strip(), False, True) for loc in root.findall("sm:url/sm:loc", ns) if loc.text]


def datagov_package_search(payload: dict) -> list[tuple]:
    rows = []
    for pkg in payload.get("result", {}).get("results", []):
        if (pkg.get("organization") or {}).get("type", "").lower() not in {"", "federal government"}:
            continue
        for res in pkg.get("resources", []):
            url = (res.get("url") or "").strip()
            if url.startswith(("http://", "https://")):
                rows.append((url, f"{pkg.get('id')}/{res.get('id')}", False, True))
    return rows


PARSERS = {"S1": wikidata_p856, "S2": dotgov_csv, "S3": govuk_sitemap, "S4": datagov_package_search}

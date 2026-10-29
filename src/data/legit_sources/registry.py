"""Source registry for the licensed URL collection plan.

docs/legitimate_url_collection_plan.md is the authority; this module mirrors
its decisions so code cannot quietly use a source the plan does not allow.

Status values:
    awaiting_owner_approval  terms reviewed and look compatible; collection
                             still requires the owner's Phase 0 approval
    popularity_only          may only yield `uncertain` rows
    blocked                  terms unresolved or conflicting
    rejected                 not to be used
No source is `approved` yet, so no collection can run (see collect.py).
"""

from __future__ import annotations

from dataclasses import dataclass, field

USER_AGENT = ("ChainShield-URL-research/0.1 (research project; contact via "
              "https://github.com/YuvrajSingh-2003/SKIT-DS-2023-2027-016)")

AWAITING = "awaiting_owner_approval"
POPULARITY = "popularity_only"
BLOCKED = "blocked"
REJECTED = "rejected"
APPROVED = "approved"   # set only by a recorded owner approval; none yet


@dataclass(frozen=True)
class Request:
    method: str
    url: str
    params: dict = field(default_factory=dict)
    note: str = ""


@dataclass(frozen=True)
class Source:
    id: str
    name: str
    side: str                 # "legitimate" | "phishing"
    status: str
    licence: str
    terms_url: str
    label_basis: str          # first_party_registry | first_party_enumeration | publisher_declared | popularity | feed
    min_interval_seconds: float = 1.0
    pinned: str = ""          # commit / snapshot the plan pins
    terms_sha256: str = ""    # hash of a retrieved licence text, when one was captured
    requests: tuple = ()
    reason: str = ""


SOURCES: dict[str, Source] = {s.id: s for s in [
    Source("S1", "Wikidata P856 official websites", "legitimate", AWAITING, "CC0 1.0 (structured data)",
           "https://www.wikidata.org/wiki/Wikidata:Licensing", "first_party_registry", 2.0,
           requests=(Request("GET", "https://query.wikidata.org/sparql",
                             {"format": "json", "query": "SELECT ?item ?url WHERE { ?item wdt:P856 ?url } LIMIT 5000 OFFSET {offset}"},
                             "paged; dumps preferred for full runs (Wikimedia bot/API etiquette)"),)),
    Source("S2", "CISA .gov domain list", "legitimate", AWAITING, "CC0 1.0",
           "https://github.com/cisagov/dotgov-data", "first_party_registry", 1.0,
           pinned="b80a2cc9f1e07893d6df7203a39e199d81622603",
           terms_sha256="a2010f343487d3f7618affe54f789f5487602331c0a8d03f49e9a7c547cf0499",
           requests=(Request("GET", "https://raw.githubusercontent.com/cisagov/dotgov-data/{pinned}/current-full.csv"),)),
    Source("S3", "GOV.UK published pages", "legitimate", AWAITING, "Open Government Licence v3.0",
           "https://www.gov.uk/help/reuse-govuk-content", "first_party_enumeration", 1.0,
           requests=(Request("GET", "https://www.gov.uk/sitemap.xml", note="first-party enumeration; robots.txt respected"),)),
    Source("S4", "data.gov federal distribution URLs", "legitimate", AWAITING,
           "US federal works public domain (17 U.S.C. 105); catalog-metadata licence not stated",
           "https://resources.data.gov/open-licenses/", "publisher_declared", 1.0,
           requests=(Request("GET", "https://catalog.data.gov/api/3/action/package_search",
                             {"fq": 'organization_type:"Federal Government"', "rows": 1000, "start": "{start}"}),),
           reason="federal publishers only; verified only if the host is in S2"),
    Source("S5", "Chrome UX Report", "legitimate", POPULARITY, "CC BY 4.0",
           "https://developer.chrome.com/docs/crux/methodology", "popularity"),
    Source("S6", "Majestic Million", "legitimate", POPULARITY, "CC BY 3.0",
           "https://majestic.com/reports/majestic-million", "popularity"),
    Source("S7", "Common Crawl URL index", "legitimate", BLOCKED, "Common Crawl ToU (non-sublicensable; ML indemnification)",
           "https://commoncrawl.org/terms-of-use", "popularity", reason="owner/legal decision required"),
    Source("S8", "Wikimedia externallinks", "legitimate", BLOCKED, "unstated for metadata tables",
           "https://dumps.wikimedia.org/legal.html", "popularity"),
    Source("S10", "Tranco", "legitimate", BLOCKED, "no licence stated; CC BY-NC input",
           "https://tranco-list.eu/", "popularity"),
    Source("S11", "Cloudflare Radar", "legitimate", BLOCKED, "CC BY-NC 4.0", "https://radar.cloudflare.com/", "popularity"),
    Source("P1", "PhishTank", "phishing", BLOCKED, "FAQ: use OK; Cisco General Terms scope unclear",
           "https://phishtank.org/faq.php", "feed", reason="written permission requested before use"),
    Source("P2", "OpenPhish community feed", "phishing", BLOCKED, "personal/academic research only; no product use or redistribution",
           "https://openphish.com/terms.html", "feed"),
    Source("P3", "PhishStats", "phishing", BLOCKED, "non-transferable licence for security research; no redistribution",
           "https://phishstats.info/terms", "feed", reason="training/product use not addressed"),
    Source("P4", "Phishing.Database", "phishing", BLOCKED, "MIT list; upstream feeds undisclosed",
           "https://github.com/mitchellkrogza/Phishing.Database", "feed", reason="liveness tests, not verification"),
    Source("P5", "URLhaus", "phishing", REJECTED, "abuse.ch terms", "https://urlhaus.abuse.ch/api/", "feed",
           reason="tracks malware distribution, not phishing"),
    Source("P6", "APWG eCrime eXchange", "phishing", BLOCKED, "membership data-sharing agreement",
           "https://apwg.org/ecx/", "feed", reason="requires membership agreement"),
]}


def get(source_id: str) -> Source:
    if source_id not in SOURCES:
        raise KeyError(f"unknown source {source_id!r}; known: {sorted(SOURCES)}")
    return SOURCES[source_id]

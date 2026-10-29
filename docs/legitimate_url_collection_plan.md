# Licensed legitimate-URL collection plan (design; 2026-10-29)

**Status: design and source audit only.**
- Nothing has been collected, scraped or downloaded for this plan, apart from reading the
  terms pages cited below.
- No model training, production, threshold, acceptance-criteria, inference, SMS or blockchain change.

This is an engineering record, not legal advice. Wherever terms are ambiguous, the source is marked
**unresolved** or **blocked**, never "cleared".

**Problem being solved:** ChainShield lacks representative *legitimate* URLs with paths, queries,
`http`, and bare or `www` hosts. The evidence is in `docs/url_feature_investigation.md` §8: data
volume, not representation, is the binding limit. PhiUSIIL's legitimate class is 100%
`https://www.<host>`, and Hannousse 2021 adds only about 3k representative legitimate training URLs.

## 1. Source-by-source assessment

**How to read the columns:**
- **"Label basis"** is what the source can *support*:
  - *first-party*: the owner or registry declares the URL or host;
  - *publisher-declared*: a publisher lists a URL it serves;
  - *popularity*: traffic or link popularity only. **Not proof of legitimacy.**
- **"Coverage"** lists the URL shapes the source can contribute.
- All terms below were retrieved on 2026-10-29.

### 1a. Candidate sources

| # | Source | Terms (quoted / verified) | Automated collection, storage, training, project use | Attribution / redistribution / commercial | Stability and reproducibility | Label basis | Coverage |
|---|---|---|---|---|---|---|---|
| S1 | **Wikidata "official website" (P856)**, via the dumps or limited SPARQL | [Licensing](https://www.wikidata.org/wiki/Wikidata:Licensing): structured data "released into the public domain under Creative Commons Zero". [Terms of Use](https://foundation.wikimedia.org/wiki/Policy:Terms_of_Use) (effective 2023-06-07) §4/§12: no "abusive or disruptive" automated use; follow the user-agent, bot and API-etiquette policies | Collection via dumps (preferred) or throttled queries: yes. Storage and training: CC0 places no restriction. **The ToU does not mention ML** | None required for CC0 data; commercial use allowed; redistribution allowed | Dated dumps; record the dump date and file hash | **first-party-curated**: the URL is the entity's declared official site. Community-edited, so vandalism is possible → needs a cross-check | Bare and `www` hosts, `http` and `https`, mostly root, some paths (e.g. `/en/`) |
| S2 | **CISA `.gov` domain list** ([cisagov/dotgov-data](https://github.com/cisagov/dotgov-data)) | Repository licence **CC0-1.0**. LICENSE text not opened → confirm in Phase 1 | Yes (static files) | None (CC0) | Updated daily; pin a commit SHA | **registry**: registered `.gov` second-level domains. Note: "not all registered domains offer an online service" | **Host only** (second-level domains); no scheme, no path |
| S3 | **GOV.UK Content API** | [Reuse](https://www.gov.uk/help/reuse-govuk-content): content under **Open Government Licence v3.0** "except where otherwise stated". Scraping allowed if robots.txt is respected; rate-limited when excessive | Yes, via the Content API within its rate limits. We store URL strings and metadata only, no page bodies | OGL v3 requires attribution (full text to confirm in Phase 1); commercial reuse is part of OGL v3 | Live API; record retrieval timestamps and a hash of the snapshot | **first-party**: the publisher enumerates its own pages | `https://www.gov.uk/<paths>` with deep paths; **single host** → must be capped |
| S4 | **data.gov catalog (CKAN API)**, federal publishers only | [Open licenses](https://resources.data.gov/open-licenses/): federal employee works are US public domain (17 U.S.C. §105); CC0 recommended. **The licence of catalog metadata itself is not stated**, and the catalog includes non-federal publishers | Collection via the public API: likely permitted (not confirmed in a ToU). Storage and training: unresolved for catalog records | Unresolved | Live API; record dataset IDs and timestamps | **publisher-declared**: a distribution URL declared by the publisher. Treat as verified only when the host's registrable domain is in S2 (`.gov`) | Many agency hosts; **paths, queries (API endpoints), `http` and `https`** |
| S5 | **Chrome UX Report (CrUX)** | [Methodology](https://developer.chrome.com/docs/crux/methodology): "licensed under a Creative Commons Attribution 4.0 International License". Origins must be publicly discoverable and "sufficiently popular" | BigQuery (origin-level) or API: permitted under CC BY 4.0. Requires a Google account; BigQuery may cost money | Attribution required (CC BY 4.0); commercial use and redistribution permitted with attribution | Monthly releases; record the release ID | **popularity** (traffic) only | Origins: `http`/`https`, bare and `www`, ports. Page-level URLs have **query strings stripped** |
| S6 | **Majestic Million** | [Page](https://majestic.com/reports/majestic-million): "Creative Commons Attribution 3.0 Unported" | Download: yes | Attribution required (CC BY 3.0) | Daily; record the date and hash | **popularity** (referring subnets) | Hosts only |
| S7 | **Common Crawl URL index** | See `docs/dephides_licence_audit.md` §2: "non-sublicensable" licence; users must respect third-party terms; ML use listed under indemnification; "obtain the advice of legal counsel" | Collected under *our own* ToU acceptance: possible. **ML use places the risk on us** | Redistribution not addressed | Crawl IDs are stable | **none**: crawled ≠ legitimate; only popularity-seeded subsets are *popularity* | Full URLs: paths, queries, `http`, ports (the best shape coverage) |
| S8 | Wikimedia dumps: `externallinks` | [Dumps legal](https://dumps.wikimedia.org/legal.html): text is CC BY-SA 4.0/GFDL; **licence of metadata tables not stated** | Unresolved | Unresolved; share-alike risk | Dated dumps | **reputation-inferred** (linked from Wikipedia; spam links exist) | Very diverse full URLs |
| S9 | Wikipedia article URLs (page titles from dumps) | As S8 for titles; the URL strings are factual | Low risk; still unresolved | — | Dated dumps | **first-party** (Wikimedia's own pages) | `https://<lang>.wikipedia.org/wiki/…`, a few hosts → heavy concentration |
| S10 | Tranco | [tranco-list.eu](https://tranco-list.eu/): no licence for the list; inputs include **Cloudflare Radar CC BY-NC 4.0** | Unresolved | Unresolved; non-commercial input | Stable list IDs | **popularity** | Hosts only |
| S11 | Cloudflare Radar domain rankings | CC BY-NC 4.0 (per the Tranco page; not opened directly) | Non-commercial only | NC | — | **popularity** | Hosts only |
| S12 | Per-site sitemaps / crawling | Per-site terms; would require visiting sites | Not as a general strategy | — | Unstable | first-party (per site) | Paths and queries |
| S13 | Search-engine result scraping; personal browsing history | Search ToS generally prohibit scraping; history is personal data | No | — | — | — | — |

### 1b. Already-assessed datasets (for completeness)

| Dataset | Status | Reference |
|---|---|---|
| PhiUSIIL | Approved (CC BY 4.0); template caveat | `docs/datasets.md` |
| Hannousse & Yahiouche 2021 | Approved (CC BY 4.0); residual Yandex question | `docs/dephides_licence_audit.md` §4 |
| DEPHIDES | Blocked | `docs/dephides_licence_audit.md` |
| PhishVN v4 | Blocked pending clarification | `docs/external_dataset_adoption_audit.md` |
| LegitPhish v2 | Rejected | same |
| ISCX-URL2016 | Blocked (no licence stated; domain-only entries removed) | `docs/external_url_detection_review.md` |
| OpenPhish community snapshot | Restricted: academic or personal research only; no product use without written consent | `docs/external_dataset_adoption_audit.md` §2 |

## 2. Source decisions

| Decision | Sources | Condition |
|---|---|---|
| **Approved to design against (terms clear for our use)** | **S1** Wikidata P856 (CC0); **S2** CISA `.gov` (CC0); **S3** GOV.UK Content API (OGL v3) | Phase 0 owner approval. Confirm the S2 LICENSE file and the full OGL v3 text in Phase 1. Respect the Wikimedia and GOV.UK automated-access policies |
| **Approved with conditions** | **S4** data.gov, federal-publisher records only, and only distribution URLs whose host is in S2 | The catalog-metadata licence is not stated. Use federal records only (public domain), and record the publisher per row |
| **Approved as popularity-only (cannot yield "verified legitimate")** | **S5** CrUX (CC BY 4.0), **S6** Majestic (CC BY 3.0) | Used only as *uncertain* strata, or to choose which S1 entities to sample. Never trained on as legitimate without an approved protocol |
| **Blocked pending owner/legal decision** | **S7** Common Crawl, **S8** externallinks, **S10** Tranco, **S11** Cloudflare Radar, PhishVN, DEPHIDES | See the per-source reasons above |
| **Rejected** | **S12** general crawling, **S13**, LegitPhish | Visits sites or conflicts with terms; personal data; data defects |

**Gap the approved sources leave:**
- S1–S4 give bare and `www` hosts, `http`/`https`, root URLs, deep paths (S3, S4) and query strings
  (S4).
- They skew towards government and official sites (`.gov`, `gov.uk`). This is a **domain-type
  shortcut risk**; see §6.
- Commercial-site paths and queries at scale need **S7 (blocked)** or per-site agreements.

## 3. Verification and labeling policy

### Labels

| Label | Meaning | Allowed evidence |
|---|---|---|
| `verified_legitimate` | The exact URL, or for host-only rows the exact host, is declared by its owner or an authoritative registry, and no approved blocklist or feed conflicts | S1 (exact P856 URL), S2 (registry host), S3 (first-party page path), S4 (federal distribution URL on an S2 host) |
| `verified_phishing` | Confirmed phishing by an approved source with a documented verification method | PhiUSIIL/Hannousse phishing (existing, approved). **No new phishing source is approved in this plan** |
| `uncertain` | Popularity-only (S5, S6); conflicting sources; host-only evidence for a path URL; anything that fails a check below | — |

### Rules

1. **Popularity is never sufficient** for `verified_legitimate`.
2. **Ownership of a host does not verify other paths.** A row is verified only for the exact URL
   declared (S1), enumerated by the owner (S3), or declared by the publisher (S4). A P856 root URL does
   not verify any path on that host.
3. **Platform hosts are excluded from `verified_legitimate` unless first-party.** Hosts under
   user-content platforms (the frozen PSL private section, plus
   `reputation_precheck.HOSTING_AND_SHARING_DOMAINS`) are excluded unless the URL is the platform's own
   first-party page.
4. **Conflicts make a row `uncertain`, and are reported.** A conflict is a host or URL present in any
   approved phishing data, or the same canonical URL arriving from two sources with different labels.
5. **Cross-checks for S1:** P856 values edited within the last 30 days (by dump revision metadata),
   or entities with an active vandalism or deletion flag, are `uncertain`.
6. **Never fetch, resolve or visit collected URLs.** Collection uses only the official APIs and dump
   endpoints listed above. DNS, HTTP probes and screenshots are out of scope.
7. **`uncertain` rows are excluded from supervised training and from gated metrics.** They may be
   reported as a separate stratum. Any other use needs a separately approved protocol.
8. **Labels are never upgraded** after collection without new evidence recorded in provenance.

## 4. Schema and pipeline

### Record schema

One row per URL, Parquet, with a per-batch manifest.

| Field | Notes |
|---|---|
| `url_raw` | Exactly as received |
| `url_canonical` | `src.blockchain.canonicalize.canonicalize_url` |
| `canonicalizer_version` | Git blob SHA of `canonicalize.py` |
| `host`, `registrable_domain`, `psl_section` | From the frozen PSL (ICANN or private) |
| `psl_version` | SHA-256 of the frozen `public_suffix_list.dat` |
| `scheme`, `has_www`, `is_root`, `has_query`, `has_port`, `is_host_only` | Shape flags |
| `label` | `verified_legitimate` \| `verified_phishing` \| `uncertain` |
| `label_basis` | `first_party_registry` \| `first_party_enumeration` \| `publisher_declared` \| `popularity` \| `feed` |
| `uncertain_reason` | Nullable |
| `source`, `source_record_id` | e.g. S1 + the QID; S3 + the content_id |
| `source_snapshot` | Dump date, commit SHA or release ID |
| `terms_url`, `terms_retrieved_at`, `terms_sha256` | Hash of the saved terms-page text |
| `collected_at`, `collector_version` | — |
| `batch_id`, `batch_sha256` | Batch identity and checksum |
| `split` | — |

### Batch manifest

- Source, snapshot, row count, `batch_sha256`, and terms references.
- Exclusion counts by reason.
- The collector command line.
- **No credentials:** API keys come from the environment and are never recorded.

### Pipeline

```
fetch (per approved source; official API/dump only; descriptive User-Agent; throttled)
  → raw snapshot (gitignored, checksummed)
  → parse (url strings only; no page bodies)
  → privacy filter (§7)
  → canonicalize + shape flags + PSL grouping
  → label (policy §3) + conflict checks against approved phishing data
  → exact dedup (canonical URL) + near-duplicate check (MinHash on canonical URL, reported)
  → per-domain caps (§5)
  → group split (§6)
  → datasheet + manifest + checksums
```

**Location (proposed):** a `src/data/legit_sources/` collector per source, reusing
`src/data/url_eval_pipeline.py`. That module already enforces provenance sidecars, licence
verification, canonical dedup and training-overlap removal; the plan extends its sidecar fields to the
schema above.

## 5. Coverage targets and stopping criteria

**Shape cells:**
- bare root
- `www` root
- `http` (any path)
- non-root path, no query
- path with query
- explicit non-default port (expected rare in legitimate traffic; do not force it)
- host-only (S2)

**Sample size:**
- For a shape-specific FPR near the 5% gate, a Wilson 95% interval of about ±2 pp needs about
  **450–500 legitimate URLs per cell in *validation***.
- With a 70/15/15 split, that is about **3,300 per cell** in total.
- For the 5 main cells that is **~16k `verified_legitimate` URLs**.

**Domain diversity takes precedence over row count:**
- ≥ 2,000 registrable domains overall.
- ≥ 300 registrable domains per shape cell in validation.
- At most 5 URLs per registrable domain in training, and at most 2 per domain in validation and test.
- Single-host sources (S3 `gov.uk`, S9) are capped at 1% of each split.

**Stopping criteria.** Stop collecting when any of these holds:
1. Every main cell meets its validation size and domain-count targets.
2. Approved sources are exhausted under the caps. Record the shortfall per cell, and do not relax the
   caps to fill it.
3. The `uncertain` or conflict rate in a source exceeds 10%. Pause that source and review.
4. A shortcut check (§6.4) fails.

**Expected shortfall:** the "path with query" and commercial-site cells will likely remain short
without S7. That must be reported, not padded.

## 6. Evaluation and domain splitting

1. **Grouping:**
   - eTLD+1 from a **frozen** Public Suffix List snapshot (publicsuffix.org, MPL-2.0; record the
     SHA-256; keep the MPL header if committed).
   - Group on the ICANN section.
   - Private-section platforms become one group per platform suffix and are reported separately.
2. **Splits:**
   - `StratifiedGroupKFold` by eTLD+1 and label, seeded, 70/15/15.
   - **Leave-one-source-out**: one approved source (e.g. S4) is held out entirely as a source-shift
     test.
   - No per-row timestamps exist for most legitimate sources, so time-based splitting is unavailable.
     Record `collected_at` anyway.
3. **Leakage checks** (scripted, run before any experiment):
   - 0 shared eTLD+1 across splits;
   - 0 shared canonical URLs;
   - MinHash near-duplicate rate train→validation reported;
   - overlap with PhiUSIIL/Hannousse domains reported per split;
   - the existing PhiUSIIL/Hannousse locked test splits remain untouched.
4. **Shortcut checks** (a gate on the *dataset*, not the model). Within the combined new data, a
   single-feature classifier on each of scheme, `www`, root, query, port, TLD and source ID must not
   reach AUC ≥ 0.80 between labels. For example, if all new legitimate rows are `.gov`, TLD will fail
   this check, and then the source must be rebalanced or masked (cf. the L2 masking in
   `docs/url_feature_investigation.md`).
5. **Use in experiments:**
   - Only `verified_*` rows.
   - The **unchanged** `configs/url_candidate_acceptance.json`, with the new validation split added as
     an additional reported set.
   - The new test split stays locked until a candidate passes every validation gate.
   - The phishing side remains the existing approved data. The resulting **class-time and
     class-source mismatch** (new 2026 legitimate vs 2019–2024 phishing) must be reported, and
     source-masking arms run, as in L2.

## 7. Privacy, security and retention

- **Privacy:**
  - No page bodies, cookies or personal data are collected.
  - URLs with userinfo, e-mail addresses, or query keys matching
    `token|session|sid|auth|key|password|email|phone` are **excluded**, not redacted (redaction would
    alter shape statistics). Counts are recorded.
- **Security:**
  - Collected URLs are treated as untrusted strings and are never fetched or rendered.
  - Raw snapshots go to a gitignored directory and are parsed with `python -I`; no source-provided
    code is executed.
  - Collectors send a descriptive User-Agent, honour robots.txt and documented rate limits, and back
    off on 429.
- **Retention:**
  - Raw snapshots are kept locally with checksums until the experiment report is final.
  - Commit only derived rows whose licence permits redistribution: S1 and S2 (CC0), S3 (OGL, with an
    attribution file), and S4 federal records (public domain).
  - Popularity sources (S5/S6) are not committed; commit their IDs and checksums only.
  - Terms-page snapshots are stored as text with their hashes.

## 8. Implementation phases and checks

| Phase | Work | Exit check |
|---|---|---|
| **P0 approvals** (owner) | Approve S1–S4 and the S4 conditions; confirm the project's status (academic vs product) for the OpenPhish/NC questions; decide on S7 (Common Crawl) via legal or owner sign-off; optionally contact the PhishVN/DEPHIDES authors | Written decisions recorded in this file |
| **P1 foundations** (no collection) | Freeze the PSL (record hash); add the schema and provenance fields to `url_eval_pipeline`; write the privacy filter, shape flags and labeling-policy code; save terms-page snapshots; confirm the S2 LICENSE and full OGL v3 text | Unit tests: schema validation; privacy filter; host-only-does-not-verify-paths rule; platform exclusion; label never upgraded; PSL grouping; deterministic batch hash |
| **P2 collection** | Run S1 (dump), S2 (pinned commit), S3 (rate-limited API), S4 (federal and S2-host only) | Per-source manifests; exclusion counts; shape × label × source matrix; domain counts; collection stops per §5 |
| **P3 dataset QA** | Dedup, near-duplicates, conflicts, caps, grouped split, leakage and shortcut checks; datasheet | All §6.3 checks pass; §6.4 shortcut gate passes, or the remediation is documented |
| **P4 controlled experiment** | Re-run the existing arms (B0, c5–c8, H1/L1/L2) plus "+new legitimate" variants, validation only | Same acceptance file, unchanged; the new test split stays locked unless a candidate passes every gate |

**Reproducible checks to be implemented** (names are proposals):
- `python -m src.data.legit_sources.collect --source S1 --snapshot <dump-date>`
- `python -m src.data.legit_sources.qa --report reports/data/legit_qa.json`, which runs the leakage,
  shortcut, coverage and privacy checks
- `pytest tests/test_legit_sources.py`

## 9. Unresolved blockers

1. **S7 Common Crawl:** the main source for commercial-site paths and queries. It is blocked on the
   non-sublicensable, indemnifying ML terms. **Owner or legal decision needed.**
2. **S4 data.gov:** the catalog-metadata licence is not stated. The plan relies only on federal
   public-domain records; confirm with the owner.
3. **Project status:** academic or product. This determines whether OpenPhish (academic/personal
   only) and any NC-licensed input can be used at all.
4. **No approved new phishing source:** PhishTank's terms are unresolved, OpenPhish is restricted, and
   URLhaus is malware. Adding legitimate data alone creates class-time and class-source imbalance.
5. **Domain-type skew:** the approved sources skew towards government and official sites, so the
   §6.4 shortcut gate may fail and require rebalancing.
6. **Terms texts still to confirm in Phase 1:** the S2 LICENSE file contents and the full OGL v3 text.

## Sources consulted (2026-10-29)

- https://www.wikidata.org/wiki/Wikidata:Licensing
- https://foundation.wikimedia.org/wiki/Policy:Terms_of_Use
- https://dumps.wikimedia.org/legal.html
- https://github.com/cisagov/dotgov-data
- https://www.gov.uk/help/reuse-govuk-content
- https://resources.data.gov/open-licenses/
- https://developer.chrome.com/docs/crux/methodology
- https://majestic.com/reports/majestic-million
- https://tranco-list.eu/
- https://commoncrawl.org/terms-of-use (via `docs/dephides_licence_audit.md`)

## 10. Phase 0 record (2026-10-29)

### 10a. Licence texts confirmed

| Item | Result |
|---|---|
| S2 `cisagov/dotgov-data` LICENSE | **CC0 1.0 Universal** (full legal code). LICENSE SHA-256 `a2010f343487d3f7618affe54f789f5487602331c0a8d03f49e9a7c547cf0499`; repository pinned at commit `b80a2cc9f1e07893d6df7203a39e199d81622603` |
| S3 Open Government Licence v3.0 ([text](https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/)) | Free to "copy, publish, distribute and transmit" and "adapt"; **commercial exploitation permitted**. Attribution: "Contains public sector information licensed under the Open Government Licence v3.0" (or the provider's own statement). **Does not cover** personal data, third-party rights the provider cannot license, or logos/crests. Matches §7 (no personal data; URL strings only) |

### 10b. Phishing-source audit

A phishing source is needed so that new legitimate data is not paired only with 2019–2024 phishing.

| # | Source | Terms (retrieved 2026-10-29) | Label quality | Status |
|---|---|---|---|---|
| P1 | PhishTank | [FAQ](https://phishtank.org/faq.php): data is shared; commercial and non-commercial API use "is OK". The site's Terms link is the Cisco General Terms (§2.2: no sublicensing or derivative works of "Cisco Offers"; PhishTank not mentioned). Application key required | Community-verified (`verified` flag, per-row `submission_time`) | **Blocked: request written clarification** from PhishTank/Cisco covering storage, model training and non-redistribution |
| P2 | OpenPhish community | [Terms](https://openphish.com/terms.html): personal or academic research only; no "detection … product development"; no redistribution | Automated | **Blocked for training/product use**; existing snapshot stays report-only |
| P3 | PhishStats | [Terms](https://phishstats.info/terms) §10: "limited, non-exclusive, non-transferable, revocable license … for lawful security research, threat intelligence". §5: no redistribution of raw feeds without written permission. ML not mentioned. Anonymous access capped at 50/day | "Hybrid rule-based and ML" scoring; community submissions | **Blocked**: ask whether model training is within "security research … related purposes" |
| P4 | Phishing.Database (`mitchellkrogza`) | MIT (repository); **upstream feeds not disclosed** in the README | PyFunceble *liveness* (ACTIVE/INACTIVE), not phishing verification | **Blocked**: upstream unknown; liveness ≠ label |
| P5 | URLhaus | [API page](https://urlhaus.abuse.ch/api/): tracks malware distribution only, "(Phishing is not Malware)"; commercial users "may require a paid subscription" | — | **Rejected for phishing labels** |
| P6 | APWG eCrime eXchange | Membership and data-sharing agreement (not reviewed in detail) | Member-reported, curated | **Blocked**: requires membership; the cleanest route if eligible |
| — | PhiUSIIL, Hannousse 2021 | CC BY 4.0 | Feed-derived (2019–2024, 2020) | **Approved** (existing), but dated |

### 10c. Plan for appropriately licensed phishing examples

1. **Request written permission** (template text for the owner to send):
   - **PhishTank (Cisco):** P1. Ask for internal storage of the verified feed, model training and
     evaluation, no redistribution of raw rows, and attribution in reports.
   - **PhishStats:** P3. Same questions.
2. **Explore APWG eCX** academic or research membership (P6).
3. **Until one is granted:**
   - Phishing data stays the approved PhiUSIIL + Hannousse sets.
   - Any experiment adding new legitimate data must use source and time masking (as L2), leave-one-source-out
     evaluation, and report the class-time mismatch.
   - **No model may be promoted on the strength of new legitimate data alone.**
4. Whatever is granted, record its terms snapshot (URL, retrieval date, SHA-256) in `registry.py`
   and the provenance of every row.

### 10d. Decisions requested from the owner (none taken by the assistant)

| # | Decision | Recommendation |
|---|---|---|
| D1 | Approve S1–S3, and S4 under its conditions, for collection | Approve: CC0/OGL/public domain; first-party label basis |
| D2 | Project status: academic research or product | Needed for P2/P3 and any NC input |
| D3 | S7 Common Crawl | Legal or owner sign-off, or keep blocked |
| D4 | Send permission requests to PhishTank/Cisco and PhishStats; consider APWG | Yes |
| D5 | Confirm whether CC BY 4.0 from Hannousse's authors suffices for its Yandex-derived rows | Owner decision |

**Gating:** collection may start only after D1 is recorded here, *and* a cleared phishing source exists
(D4/D6) or the owner explicitly accepts the legitimate-only design with the mitigations in 10c.3.

### 10e. Collector implementation (dry-run only)

- **Code:**
  - `src/data/legit_sources/registry.py`: source statuses mirror this document; none is `approved`.
  - `policy.py`: frozen-PSL loader (checksum enforced, ICANN/private sections, wildcard/exception
    rules); shape flags; privacy exclusion; §3 labeling rules; record schema validation;
    order-independent batch SHA-256.
  - `parsers.py`: S1–S4 payload parsers (pure).
  - `collect.py`: dry-run planner. `--execute` always refuses (exit 2). No network I/O.
- **Commands:**
  - `python -m src.data.legit_sources.collect --all` prints the plans.
  - `python -m pytest -q tests/test_legit_sources.py` (40 tests, run with the network blocked at the
    socket level; synthetic fixtures only).
- **Still to do before any real run:**
  - freeze an actual PSL snapshot (MPL-2.0, record its hash);
  - implement the fetchers, behind the approval gate;
  - add the conflict check against approved phishing data;
  - add near-duplicate detection and the §6 split, leakage and shortcut gates.

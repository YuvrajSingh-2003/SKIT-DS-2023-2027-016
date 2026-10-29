# External dataset adoption audit: LegitPhish and PhishVN (2026-10-29)

**Scope:** whether either dataset can responsibly and technically address ChainShield's shortage of
representative legitimate URLs. Dataset audit only.
- No model was trained.
- No production, threshold, acceptance-criteria, inference, SMS or blockchain change.
- No external script, notebook or saved model was run or loaded.
- No dataset file is committed.
- No URL from either dataset was visited.

This is an engineering record, not legal advice.

## Recommendation

| Dataset | Recommendation | One-line reason |
|---|---|---|
| **LegitPhish** v2 | **REJECT** | 98.4% of its "legitimate" URLs are copied verbatim from PhiUSIIL (the dataset whose template caused our problem); its "phishing" class is URLhaus malware payloads; both classes carry strong shape shortcuts |
| **PhishVN** v4 (files v3.1.0) | **BLOCK PENDING CLARIFICATION** | Technically useful as a bare-domain benchmark, but upstream rights are materially unclear (see below) |

## 1. Comparison

| | LegitPhish | PhishVN |
|---|---|---|
| **Version inspected** | Mendeley [hx4m73v2sf v2](https://data.mendeley.com/datasets/hx4m73v2sf/2), DOI 10.17632/hx4m73v2sf.2, published 2025-05-22 | Mendeley [b97hxbxtpd v4](https://data.mendeley.com/datasets/b97hxbxtpd/4), DOI 10.17632/b97hxbxtpd.4, published 2026-08-18; archive `PhishVN_v3.1.0_open.zip` |
| **Paper** | Data in Brief, [10.1016/j.dib.2025.111972](https://doi.org/10.1016/j.dib.2025.111972) (not fetched; claims taken from the Mendeley description) | Data in Brief, [10.1016/j.dib.2026.113195](https://doi.org/10.1016/j.dib.2026.113195) (the Mendeley page says "under revision"; claims taken from the bundled datasheet) |
| **Files and SHA-256** (match the Mendeley API `sha256_hash`) | `url_features_extracted1.csv` (8,963,838 B) `8685e790…09dbcd` | `PhishVN_v3.1.0_open.zip` (5,813,309 B) `308351e9…d0ab5`; all 13 internal `MANIFEST.txt` entries verified (hash and size). `PhishVN_v3.0.0_results_bundle.zip` **not downloaded** (contains fitted estimators) |
| **Dataset licence (stated)** | CC BY 4.0 (Mendeley metadata) | CC BY 4.0 for data, MIT for code (`LICENSE`, `docs/datasheet.md`). The Mendeley CC BY 4.0 text itself notes "further permission may be required for any content … belonging to a third party" |
| **Rows** | 101,219 (63,678 phishing / 37,540 legitimate); 18 columns | 53,116 (36,706 phishing / 16,410 benign); gold+silver core 18,997, bronze 34,119 |
| **Upstream sources** | Claimed: phishing from "the URLHaus database … scraped from many sites"; legitimate "from reputable sources such as Wikipedia and Stack Overflow" | Phishing: NCSC "Tin Nhiem Mang" blacklist (gold/silver), ChongLuaDao snapshot via a GitHub mirror (bronze), OpenPhish community feed (bronze, 296). Benign: Tin Nhiem Mang trusted-org registry and directory, Tranco global sample, Tranco `.vn` slice (`docs/data_sources.md`) |
| **Label definition** | Binary `ClassLabel` (0 phishing / 1 legitimate); "manually verified" claimed | Inherited from sources. The datasheet states the positive label means "a domain listed by a Vietnamese anti-fraud" source, i.e. abuse, not only credential phishing |
| **Label-quality evidence** | None published | Two-annotator audit of 200 rows (κ 0.725). Source-label noise **12.1%** on positives (Wilson CI 7.1–20.0%; 11 of 12 bronze) and **4.0%** on benign (Tranco). Credential phishing is 42.5% of defensible positives |

## 2. Licence and provenance

### LegitPhish

- **Verified:** the dataset is CC BY 4.0 (Mendeley metadata).
- **Provenance problems** [measured by us]:
  - **36,955 of 37,540 (98.4%) legitimate URLs appear verbatim in PhiUSIIL's legitimate class**
    (after removing a trailing `/`). The description does not mention PhiUSIIL. PhiUSIIL is itself
    CC BY 4.0, so this is an undisclosed-derivation issue rather than a licence violation we can
    establish.
  - Only 204 legitimate rows are Wikipedia/Stack Overflow URLs, contradicting the description.
  - The phishing class comes from URLhaus, which tracks **malware distribution**, not phishing. PhishVN
    excludes URLhaus for this reason. Sampled rows are payloads such as `…/freebl3.dll`,
    `http://<ip>:45010/bin.sh`, `….exe`.
- **Unresolved:** URLhaus's own terms (not re-verified here). Moot given the rejection.

### PhishVN

**Verified:**
- The dataset authors license their compilation under CC BY 4.0.
- They document each upstream source, their legal basis (Vietnamese Decree 13/2023/ND-CP; PII
  redaction), and that the gated HTML/screenshot tier is research-only under a data-use agreement.
  We did not request or use the gated tier.

**Upstream rights:**

| Upstream | Rows | Terms found (retrieved 2026-10-29) | Status |
|---|---|---|---|
| NCSC "Tin Nhiem Mang" (blacklist + trusted-org registry) | 2,587 phishing (gold/silver) + 7,905 benign (`tinnhiem_web` 5,879, `tinnhiem_org` 2,026) | [tinnhiemmang.vn](https://tinnhiemmang.vn/): only "Copyright ©2020 NCA"; no reuse, scraping or redistribution terms visible | **Unresolved** |
| ChongLuaDao (via [elliotwutingfeng/ChongLuaDao-Phishing-Blocklist](https://github.com/elliotwutingfeng/ChongLuaDao-Phishing-Blocklist), snapshot 2024-05-16) | 33,823 phishing (bronze) | The mirror repository is **BSD-3-Clause** with an "AS IS" disclaimer; the terms of the original chongluadao.vn data were not found | **Unresolved** (mirror licence ≠ upstream data licence) |
| OpenPhish community feed | 296 phishing (bronze) | [openphish.com/terms](https://openphish.com/terms.html): use "solely for your personal use"; research use allowed only if it does not "support your organization's business operations"; **no commercial use including "detection, … product development"**; no "distribut[ion]" or "derivative works" without written consent | **Conflict:** redistribution in PhishVN and any product/detection use by us appear to require OpenPhish's written consent |
| Tranco (global + `.vn` slices) | 5,993 + 2,512 benign (silver) | [tranco-list.eu](https://tranco-list.eu/) states **no licence for the list itself**. Its inputs include Cisco Umbrella ("free of charge"), Majestic (CC BY 3.0), CrUX (CC BY-SA 4.0) and **Cloudflare Radar (CC BY-NC 4.0)** | **Unresolved:** a non-commercial input in the default list; no stated licence |

**Conclusion:**
- Our intended uses are research, model training, internal use, and committing derived artifacts or
  evaluation evidence.
- The authors' CC BY 4.0 grant cannot by itself clear content the authors did not own.
- Two of four upstream sources have no visible terms, one conflicts (OpenPhish), and one has no
  licence with a non-commercial input (Tranco).
- **Rights are materially unclear → BLOCK PENDING CLARIFICATION.**

**Separate finding about ChainShield itself:** our local OpenPhish snapshot
(`data/incoming/threat_feeds/`, never committed) has been used only to compute evaluation figures in
reports. Under OpenPhish's terms that is permissible only as academic/personal research that does not
support an organisation's business operations. Commercial or product use needs OpenPhish's written
consent. **Recommendation:** keep it uncommitted and report-only, and confirm the project's status
(academic) with the owner.

## 3. Coverage and label quality [measured by us]

Shape percentages are per label and source, computed on the inspected copy. "Root" = no path beyond
`/` and no query.

### LegitPhish

| Class | n | Has scheme | HTTPS | `www.` | Root | Query | Explicit port |
|---|---|---|---|---|---|---|---|
| legitimate | 37,540 | 100% | **100%** | **99.1%** | **98.6%** | 0.1% | 0% |
| phishing | 63,678 | 98.0% | 5.5% | 1.0% | 0.6% | 1.2% | **64.5%** |

- **Shortcuts:** HTTPS, `www.`, root and port each nearly separate the classes on their own. This is
  the PhiUSIIL template plus new artifacts.
- **Domains:**
  - Legitimate: 35,533 unique registrable domains.
  - Phishing: 22,143, concentrated (top 5 = 6.6%; e.g. one `.ro` domain 965 rows).
- **Hygiene:** 346 duplicate URLs, 0 label conflicts.
- **Missing metadata:** no dates, no source column, no split.

### PhishVN

| Label / source | n | Has scheme | HTTPS | `www.` | Root | Query |
|---|---|---|---|---|---|---|
| benign `tinnhiem_org` | 2,026 | 100% | 99.7% | 4.1% | 98.9% | 0% |
| benign `tinnhiem_web` | 5,879 | 0% | — | 0.1% | 100% | 0% |
| benign `tranco` | 5,993 | 0% | — | 0.1% | 100% | 0% |
| benign `tranco_vn` | 2,512 | 0% | — | 0% | 100% | 0% |
| phishing `tinnhiemmang` | 2,587 | 0% | — | 7.2% | 99.6% | 0% |
| phishing `chongluadao` | 33,823 | 0% | — | 49.6% | 100% | 0% |
| phishing `openphish` | 296 | 100% | 68.2% | 17.6% | 44.6% | 14.9% |

- **Coverage:** essentially a **bare-domain dataset** for both classes, with no paths and no `http`.
  - It offers ~16.4k bare-domain benign examples, exactly the shape behind ChainShield's
    `example.com` false positive.
  - It gives **no coverage of legitimate paths, queries or `http`**, which is the other half of our
    gap.
- **Shortcut risks:**
  - TLD: `.vn` is 61.6% of benign vs 2.6% of phishing, despite the authors' global-Tranco mitigation.
  - `www.`: ChongLuaDao phishing is 49.6% `www.` vs ~0% for most benign sources.
  - Scheme presence by source (only `tinnhiem_org` and OpenPhish rows carry a scheme).
  - Benign registrable domains are dominated by `gov.vn` / `edu.vn` under our two-label approximation.
    These are public suffixes, so a PSL-based grouping is required.
- **Language:** `vi` 46,827, mixed 6,289.
- **Dates:**
  - `collected_at` is **missing for 59.2%** of rows.
  - Benign 2021-04-01 to 2026-03-25; phishing 2020-02-08 to 2025-02-18 (the NCSC feed has been dormant
    since 2025-02-18 per the datasheet).
- **Hygiene:**
  - 0 duplicate URLs, 0 URL-level label conflicts.
  - 24 registrable domains carry both labels under our approximation, mostly shared platforms such as
    `weebly.com` and `blogspot.com`; the datasheet reports a site-level conflict review.
- **Label confidence:**
  - Gold and silver cover all benign rows (7,905 / 8,505) and 2,587 phishing rows.
  - Bronze covers 34,119 phishing rows, holding 11 of the 12 positive-label errors found in the
    authors' audit.
  - Popular-list (Tranco) benign rows are not individually verified; 2 of 50 audited were abusive.

## 4. Evaluation suitability (PhishVN; LegitPhish has no split)

- **Published split:** "group-aware temporal" 70/15/15 by registrable domain. Train 36,909, val 7,266,
  test 8,941.
- **Domain grouping:** our approximate domain overlap between splits is small (train–val 19,
  train–test 15, val–test 11 domains). The residual is consistent with the authors using a proper PSL.
- **Temporal separation is partial:**
  - Dated train rows run 2020-02-08 to 2025-01-02.
  - **Validation dates (2022-11-29 to 2023-03-29) lie inside the training period.**
  - Test runs 2023-02-07 to 2026-03-25.
  - 59% of rows are undated and hash-split.
- **Source leakage across splits:** the tier mix differs sharply.
  - Validation: gold 280 / silver 1,305 / bronze 5,681.
  - Test: gold 2,673 / silver 1,659 / bronze 4,609.
  - Validation and test therefore measure different source mixes.
- **Feature leakage:** the authors flag `is_https` as a collection artifact and exclude it.
- **Suitability, if rights were cleared:**
  - **Not suitable as primary training data:** bare-domain only, Vietnamese-specific TLD/brand
    distribution, abuse-not-phishing labels.
  - **Suitable as a limited, external, bare-domain FPR benchmark:** gold+silver benign only, bronze
    and OpenPhish excluded, PSL grouping, reported separately and never used for selection.
  - It cannot measure path, query or `http` false positives.

## 5. Overlap with ChainShield datasets [measured by us]

- **LegitPhish:**
  - 36,937 URL strings appear in PhiUSIIL or Hannousse.
  - 39.6% of rows share an approximate registrable domain with them.
  - 98.4% of its legitimate class is PhiUSIIL's legitimate class.
- **PhishVN:**
  - 6 URL strings appear in PhiUSIIL or Hannousse.
  - 16.3% of rows share an approximate registrable domain with them, inflated by shared platforms and
    public-suffix-like domains under the two-label approximation.

## 6. Proposed experiment (only if PhishVN is cleared; not started)

**E-VN:** external, evaluation-only bare-domain FPR check.
- **Data:** PhishVN gold+silver benign, minus any registrable domain present in ChainShield training
  data (PSL grouping), plus gold+silver phishing for recall.
- **Models scored:** B0 production, and existing candidates (c5–c8, H1/L1/L2) unchanged. No
  retraining, no threshold selection.
- **Report:**
  - bare-domain legitimate FPR with Wilson CIs, split by source stratum (`tinnhiem_*` vs `tranco*`)
    and by `.vn` vs non-`.vn`;
  - recall on NCSC gold+silver phishing.
- **Gates:** none (supplementary). Results must not influence model selection unless the acceptance
  criteria are formally amended.

**What would unblock it:**
1. Written confirmation from NCSC (or the PhishVN authors, with NCSC's permission) covering reuse of
   the registry and blacklist entries.
2. Confirmation of chongluadao.vn data terms, or excluding the bronze tier entirely (E-VN already does).
3. Excluding the 296 OpenPhish rows (E-VN already does).
4. A decision on Tranco-derived rows: either confirm acceptable use given its CC BY-NC input, or
   exclude the `tranco`/`tranco_vn` strata. That would leave only the 7,905 NCSC benign rows.

## 7. Reproduction (inspection only; files outside the repository)

```bash
D=$(mktemp -d); mkdir -p "$D/legitphish" "$D/phishvn"
api=https://data.mendeley.com/public-api/datasets
curl -s "$api/hx4m73v2sf?version=2" | python3 -I -m json.tool | less       # licence: CC BY 4.0
curl -s "$api/b97hxbxtpd?version=4" | python3 -I -m json.tool | less       # licence: CC BY 4.0
u=$(curl -s "$api/hx4m73v2sf/files?folder_id=root&version=2" | python3 -I -c "import json,sys;print(json.load(sys.stdin)[0]['content_details']['download_url'])")
curl -sL -o "$D/legitphish/url_features_extracted1.csv" "$u"
u=$(curl -s "$api/b97hxbxtpd/files?folder_id=root&version=4" | python3 -I -c "import json,sys;print([f for f in json.load(sys.stdin) if f['filename'].endswith('_open.zip')][0]['content_details']['download_url'])")
curl -sL -o "$D/phishvn/PhishVN_v3.1.0_open.zip" "$u"
sha256sum "$D"/legitphish/*.csv "$D"/phishvn/*.zip
# 8685e7901c3b4e73eb43c106cb166cc932dd14f76960a032c713c2c32f09dbcd  url_features_extracted1.csv
# 308351e9d0c0fca13a81f2f63524a7dee08ccba6c775848d125b3da5525d0ab5  PhishVN_v3.1.0_open.zip
(cd "$D/phishvn" && unzip -q PhishVN_v3.1.0_open.zip -d x)   # then verify x/MANIFEST.txt (13 entries)
```

The statistics in §§3–5 were computed with pandas over `URL`/`ClassLabel` (LegitPhish) and
`url`/`label`/`source`/`tier`/`split`/`collected_at` (PhishVN). Domains were grouped with
`src.training.train_url_multisource.registrable_domain`, a two-label approximation. The LegitPhish →
PhiUSIIL match compares `URL.rstrip("/")` with `data/raw/PhiUSIIL_Phishing_URL_Dataset.csv`
legitimate `URL`.

## Sources (retrieved 2026-10-29)

- https://data.mendeley.com/datasets/hx4m73v2sf/2 (API metadata and files)
- https://data.mendeley.com/datasets/b97hxbxtpd/4 (API metadata and files; bundled LICENSE, datasheet, data_sources)
- https://doi.org/10.1016/j.dib.2025.111972, https://doi.org/10.1016/j.dib.2026.113195 (cited; not fetched)
- https://openphish.com/terms.html
- https://tranco-list.eu/
- https://github.com/elliotwutingfeng/ChongLuaDao-Phishing-Blocklist (BSD-3-Clause)
- https://tinnhiemmang.vn/

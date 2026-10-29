# DEPHIDES dataset: licence and provenance audit (2026-10-29)

**Decision: experiment arm L2+D is BLOCKED** pending clarification or written permission. No
DEPHIDES data is used for training, evaluation, or committed to this repository.

**Scope:**
- The DEPHIDES dataset (Sahingoz, Buber, Kugu; GitHub `ebubekirbbr/dephides`, IEEE DataPort DOI
  10.21227/4098-8c60).
- Its upstream sources: Common Crawl (legitimate URLs) and PhishTank (phishing URLs).
- Any Yandex-derived material.

**Intended use being assessed:**
- training URL-model candidates;
- evaluating them;
- possibly committing derived data or trained artifacts to this repository.

All pages below were retrieved on 2026-10-29. Quotations are from those pages. This is an engineering
record, not legal advice.

## 1. Dataset-specific licence

| Source | What it says | Status |
|---|---|---|
| GitHub [ebubekirbbr/dephides](https://github.com/ebubekirbbr/dephides) `LICENSE` (commit `e66ef86`) | MIT License, "Copyright (c) 2023 ebubekirbbr" | Covers the repository. **The README does not say the MIT licence applies to the dataset** |
| Same README | "This data set has been shared so that one can use them in their own studies." No licence, no redistribution terms, no collection dates, no Common Crawl crawl IDs | Permissive *intent* for "their own studies"; **no explicit grant** for redistribution or commercial/production use |
| [IEEE DataPort, "Phishing Attack Dataset"](https://ieee-dataport.org/node/11847), DOI 10.21227/4098-8c60 (created 2023-10-26, updated 2025-05-03) | "This dataset requires an IEEE DataPort Subscription to access." No licence is stated; page footer "IEEE - All rights reserved." Citation formats provided | **No open licence shown** for the published dataset |
| Big dataset | Distributed via a Google Drive folder "on request" (README) | Access-controlled; not requested |

**Verified:**
- The code is MIT.
- The authors intend the data to be used in studies.
- A citation is expected (DataPort).

**Unresolved:**
- Whether the dataset itself is MIT, CC-licensed, or "all rights reserved".
- Whether commercial or production-model use is permitted.
- Whether derived subsets may be redistributed.

## 2. Common Crawl (legitimate URLs)

[Terms of Use](https://commoncrawl.org/terms-of-use), last updated 7 March 2024:

| Provision | Text (quoted) | Effect |
|---|---|---|
| §1 Licence | CC grants "a limited, non-assignable, non-transferable, non-sublicensable, non-exclusive, limited license" | Our use would be under our own licence; **a third party (DEPHIDES) cannot sublicense it to us** |
| §2 Third-party terms | Crawled Content "may be subject to separate terms of use or terms of service from the owners of such Crawled Content" | URLs remain subject to each site's terms |
| §3 Copyright | "YOU AGREE TO RESPECT THE COPYRIGHTS AND OTHER APPLICABLE RIGHTS OF THIRD PARTIES"; CC "strongly recommends that you obtain the advice of legal counsel before making any use" | — |
| §9(ii) Indemnification | lists "use of Crawled Content in connection with artificial intelligence, machine learning, or other similar technologies" as a source of user indemnification obligations | ML use is anticipated but places the risk on the user; **not an express grant** |
| Redistribution | Not expressly addressed | Unresolved |

**Verified:** access and use under the ToU is permitted; ML use is contemplated, with the user
indemnifying.

**Unresolved:**
- Whether URL strings (facts, likely low copyright risk) extracted by a third party and
  redistributed in DEPHIDES fall within our own ToU acceptance.
- Which crawl(s) were used (no crawl IDs are given), so the exact terms in force at collection are
  unknown.

## 3. PhishTank (phishing URLs)

| Source | What it says |
|---|---|
| [Developer info](https://phishtank.org/developer_info.php) | No licence named. Registration for an application key is required for automated downloads; rate limits; "descriptive User Agent" required |
| [FAQ](https://phishtank.org/faq.php) | "Do you share your phishing data?" "Yes, both on the website and via the API." API commercial and non-commercial use: "Yes, it is OK." "PhishTank is free to everyone, both the website and the data (via the API)." |
| Site footer "Terms of Use" → [Cisco General Terms](https://www.cisco.com/c/en/us/about/legal/cloud-and-software/end_user_license_agreement.html) | §2.1 licence "for Your direct benefit" and "non-transferable". §2.2(a) may not "transfer, sell, sublicense, monetize, or provide the functionality of any Software, Cloud Services, Subscription Offers, or Services to any third party". §2.2(d) may not "make derivative works of Cisco Offers". **PhishTank and threat data are not mentioned** |
| (`phishtank.org/terms_of_use.php` redirects to the home page) | — |

**Verified:** direct use of PhishTank data, including commercial use, is described as OK in the FAQ.

**Unresolved:**
- Whether the Cisco General Terms govern PhishTank *data*, and if so whether §2.2(a)/(d) restrict
  redistributing it or training on a third party's copy.
- Whether DEPHIDES's redistribution of PhishTank rows was permitted.

## 4. Yandex-derived material

- **DEPHIDES:** none found. The GitHub README and the IEEE DataPort page both list only PhishTank
  and Common Crawl.
- **Already in this repository, via Hannousse & Yahiouche 2021:**
  - Hannousse's legitimate URLs include "still active legitimate URLs provided by Sahingoz et al.
    [22]. Those legitimate URLs were originally collected from Yandex" (arXiv 2010.12847 §4.1).
  - The Hannousse dataset is published under **CC BY 4.0** by its authors (Mendeley), and that is the
    licence we rely on (`data/raw/hannousse_2021/SOURCE.md`).
  - **Unresolved (residual):** whether Yandex search-service terms placed restrictions on the original
    collection that survive the authors' CC BY 4.0 release. Hannousse's `dataset_B` has no per-row
    source column, so Yandex-derived rows cannot be isolated or removed.
  - Recommendation: the owner should decide whether CC BY 4.0 from the dataset authors is sufficient
    (our current assumption), or whether to seek confirmation from the authors.
  - This audit does **not** change the existing approval of Hannousse.

## 5. Decision

| Arm | Data | Status |
|---|---|---|
| B0, H1, L1, L2 | PhiUSIIL (CC BY 4.0) + Hannousse 2021 (CC BY 4.0) | **Proceed** (approved data) |
| L2+D | + DEPHIDES | **BLOCKED**: no dataset licence; upstream Common Crawl licence is non-sublicensable; PhishTank redistribution terms unresolved |
| N1 (char n-grams) | depends on L2+D outcome | Deferred |

**What would unblock L2+D** (any one path):
1. Written permission or an explicit licence from the DEPHIDES authors, covering ML training,
   evaluation and redistribution of derived artifacts. Their contacts are in the repository's
   `meta.txt` and on the IEEE DataPort page.
2. Re-collecting equivalent data ourselves under our own Common Crawl ToU acceptance, and PhishTank
   access with an application key. Then:
   - record crawl IDs and dates;
   - do **not** redistribute raw data;
   - commit only code, configs and checksums.
3. Legal or owner sign-off that the above terms permit internal training-only use without
   redistribution.

Until then: no DEPHIDES rows are committed, trained on, or evaluated against. The local inspection
clone was outside this repository and is not used by any pipeline.

## Sources (retrieved 2026-10-29)

- https://github.com/ebubekirbbr/dephides (README, LICENSE)
- https://ieee-dataport.org/node/11847
- https://commoncrawl.org/terms-of-use
- https://phishtank.org/developer_info.php
- https://phishtank.org/faq.php
- https://www.cisco.com/c/en/us/about/legal/cloud-and-software/end_user_license_agreement.html
- https://arxiv.org/abs/2010.12847 (Hannousse & Yahiouche, §4.1)

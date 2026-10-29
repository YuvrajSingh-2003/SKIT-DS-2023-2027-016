# Legitimate-URL data and time-stamped evaluation set — acquisition plan

## Status

**Nothing has been downloaded or crawled.**
- No top-sites list or legitimate-URL corpus exists in the repo.
- The only recent external URL data is `data/incoming/threat_feeds/openphish-community-20261028T152813Z.txt`:
  300 rows, phishing only, no provenance sidecar yet.
- The pipeline (`src/data/url_eval_pipeline.py`) is built and tested on fixtures. It refuses any
  source without a verified provenance sidecar.

## Why

- PhiUSIIL legitimate URLs are 100% `https://www.<host>` with no path.
- A model trained on them learns that template. See `docs/url_shape_guard.md`.

## Candidate sources (each needs a licence check before use)

| Source | Gives | Label confidence | Licence / terms to verify | Notes |
|---|---|---|---|---|
| Tranco list (tranco-list.eu) | ranked registrable domains | `popularity_proxy` | check current terms on the site; cite the list ID | Homepages only; popularity ≠ safety; has included malicious and hosting domains |
| Common Crawl URL index | real paths/queries on those domains | `popularity_proxy` when filtered by Tranco rank | Common Crawl terms of use | Offline index query; no site fetching. Gives varied scheme/www/path shapes |
| Manually reviewed sample | ground-truth legitimate | `manually_reviewed` | own work | Needed for any headline FPR claim; e.g. 500–1,000 URLs |
| OpenPhish community | recent phishing | `feed_reported` | community feed terms (check redistribution) | Time-stamped; already have one 300-row snapshot |
| PhishTank | verified phishing | `feed_confirmed` | requires account / API key; check terms | |
| URLhaus (abuse.ch) | malware URLs | not phishing; exclude or label separately | CC0 | Do not mix with phishing labels |

## Pipeline (implemented, offline)

1. **Provenance sidecar** `<file>.provenance.json`. Required fields:
   - `source_name`, `label`, `label_confidence`;
   - `licence` and `licence_verified: true`;
   - `source_url`, `retrieved_at` (ISO), `retrieval_method`, `sha256`.

   The pipeline refuses missing files, missing sidecars, unverified licences and checksum mismatches.
2. **Canonicalize** with `canonicalize_url`, used read-only. Tranco `rank,domain` lines become
   `https://<domain>/`.
3. **Dedupe** on the canonical URL. URLs labelled both ways across sources are dropped and counted.
4. **Training-overlap removal.** Drop rows whose canonical URL **or** host (with `www.` removed)
   appears in any PhiUSIIL split. Counts are reported in the manifest.
5. **Write** to `data/eval/url_eval_<YYYYMMDD>/urls.csv` with `manifest.json`.
   - The manifest sets `usage: evaluation_only`.
   - Sets are immutable: an existing date directory is refused.
   - Training code can call `assert_not_evaluation_data()`.

**Command:** `python -m src.data.url_eval_pipeline --sources <files…> --out-date YYYYMMDD`

## Sampling design (for the operator)

**Legitimate side:**
- Stratify by Tranco rank band (1–1k, 1k–10k, 10k–100k, 100k–1M).
- From the CC index, sample up to k URLs per domain to limit per-domain weight.
- Target shapes:
  - ~25% homepage, ~50% path, ~25% path+query;
  - ~30% non-`www`;
  - include `http` where the index records it.
- Exclude hosting/sharing apex domains (same list as `reputation_precheck.HOSTING_AND_SHARING_DOMAINS`)
  and anything present in a phishing feed at build time.

**Phishing side:**
- Feed snapshots retrieved within the same window, with `retrieved_at` recorded.
- Keep the evaluation window **after** the training data date, so the set is temporally out of sample.

**Splits:**
- Legitimate training data, after the licence check, goes in a separate directory with a group-by-host
  split.
- The evaluation set is never used for training, threshold or model selection.

## Label-confidence limits

- `popularity_proxy` rows can include compromised pages or user-hosted content. FPR measured on them is
  an *upper* bound on harm to genuinely legitimate pages, not a guarantee of safety.
- Headline figures should come from the `manually_reviewed` subset.
- Feed rows are point-in-time; many die quickly. Do not re-fetch them to "confirm".

## Permission needed

- Network retrieval of Tranco / Common Crawl index / feeds, plus a licence review by a person.
- Not done here, per project constraints.

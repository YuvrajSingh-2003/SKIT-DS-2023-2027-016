# Threat-registry batch: review report (2026-10-28)

Nothing has been submitted on-chain. All files here are proposals.

## Files
| File | Contents |
|---|---|
| `proposed_batch.json` | Original proposal (lowest-hash URL rule). Unchanged. |
| `proposed_batch_stratified.json` | Alternative: same 433 messages; 250 URLs, one per domain, TLD shares proportional to the source. |

Both were produced by `src/blockchain/prepare_batch.py` and contain hashes and provenance only (no URLs, domains or message text).

## URL selection
- **Original rule (`lowest-hash`):** every eligible PhiUSIIL phishing URL was hashed, deduplicated and sorted by hash, and the first 250 kept. Keccak output is uniform, so this is effectively a reproducible random sample. It has 249 domains (one domain appears twice) and 49 TLDs.
- **Available signals:** PhiUSIIL has no per-record timestamp, first-seen date, takedown status or verification time. Recency and source status therefore cannot be used. Domain and TLD are available, so diversity can be used.
- **Alternative rule (`stratified`):** one URL per domain; each TLD's share of the 250 is proportional to its share of the 85,290 phishing domains (e.g. `.com` 44%, `.app` 7%). The result has 250 domains and 52 TLDs, and 212 of its 250 URLs are also in the original. The difference is small because random sampling was already roughly proportional; the main gain is the one-per-domain guarantee.

## Field meanings (contracts/ThreatRegistry.sol, seed_registry.py)
- `threatType`: 0 = MESSAGE, 1 = URL (enum `ThreatType`).
- `verdict`: 0 = benign, 1 = threat. The backend reports `match_threat` only for verdict 1.
- `confidence`: uint16, 0–100 percentage. It is stored and displayed but is not used in any backend decision.
- The contract rejects zero hashes, duplicates (`DuplicateHash`), verdict > 1 and confidence > 100. Only the owner can submit, and records cannot be edited or removed.
- The existing seeder documents confidence 100 as "dataset-confirmed ground truth".

**Is confidence 100 appropriate?** It means that the source labelled the record malicious, not that the threat is current:
- Mishra & Soni smishing: a reasonable reading of 100 is "source label", since a message's content does not expire.
- PhiUSIIL URLs: these are 2024 historical records with no liveness check. Many domains may have been taken down or re-registered by legitimate owners, so 100 overstates current certainty.

The proposals keep 100 to match the existing convention and contract semantics. Choosing a lower value (or URL-only lower value) is a decision for the owner; it would need a documented meaning, since nothing in the contract defines one.

## Provenance
- `verification_status: source_verified` means the record is labelled malicious by a documented, licensed dataset. No entry has been independently confirmed as a current, live threat, and no URL was visited. The manifests say this in `label_basis`.
- OpenPhish (300 entries) is `source_reported_automated` and is excluded with `license_review_required` in both manifests.
- The synthetic test URL (`0xa847…c65e`) is listed under `synthetic` and is absent from both proposals.

## Effect of registration and recommended policy (second review)
- **Confidence has no effect on detection.** The backend (`app/services/blockchain_checker.py`) reads `confidence` and passes it through to the response. `/scan` and `/message/scan` decide only on `status`, which comes from `verdict`.
- **What `verdict = 1` does.** It yields `match_threat`: a URL scan becomes HIGH with decision `blockchain` and the model is not run, and a message scan becomes `smishing_registry_match` / HIGH.
- **Consequence for historical PhiUSIIL URLs.** Registering them as verdict 1 makes every future scan of the exact canonical URL HIGH, permanently. The contract has no update or removal function and rejects re-submission (`DuplicateHash`). A URL whose domain was later re-registered by a legitimate owner would be flagged forever. The risk is narrow, because only the exact canonical URL matches, not the domain.
- **No defined meaning for a lower confidence.** The contract only enforces 0–100. The seeder only ever uses 100 ("dataset-confirmed ground truth"). No code or document gives any other value a meaning. Choosing e.g. 70 would be an invented calibration, and the backend would ignore it anyway.
- **Recommended policy (owner decision):**
  1. Register verdict 1 only for records the owner accepts as permanent threats.
  2. Treat source-labelled smishing messages as eligible, since message content does not age.
  3. Do not register historical dataset-labelled URLs until each is confirmed current by a live, licensed feed (PhishTank or URLhaus with keys) at submission time. Otherwise submit the 433 messages only.
  4. If historical URLs are registered anyway, keep confidence 100 (the only documented value). Record the limitation in `docs/datasets.md` and in the manifest's `label_basis`, not through an undefined confidence value.
  5. A distinct on-chain meaning for "historical" versus "currently verified" would need a contract or ABI change, which is out of scope.

## RPC configuration
- The backend and this script read `SEPOLIA_RPC_URL` (or `WEB3_PROVIDER_URI`) from the environment or from the project `.env`. Here `.env` is absent and both variables are unset, so the check command exited with code 2 and performed no lookups.
- **Setup** (a read-only check needs only an RPC URL, never a private key):
  1. Get a Sepolia HTTPS endpoint from a provider you trust.
  2. In your own shell, run `export SEPOLIA_RPC_URL='<your endpoint>'`, or copy `.env.example` to `.env` and fill in only that line.
  3. Leave `SIGNER_PRIVATE_KEY` empty; it is not needed.

## Registry check
- `SEPOLIA_RPC_URL` and `WEB3_PROVIDER_URI` are unset. The check command exits with code 2 and performs no lookup, so no registry results exist.
- Command for when an RPC is configured. It makes view calls only (`threatExists` and `getThreat`) through the backend checker, which verifies chain ID 11155111 and the contract code. It makes at most 1,000 lookups, waits 0.25 s between them, and refuses to overwrite its output file:

  ```
  .venv/bin/python -m src.blockchain.prepare_batch \
      --check-manifest data/threat_registry/proposed_batch_stratified.json \
      --out data/threat_registry/registry_check_<date>.json --delay 0.25
  ```
  The output reports `existing_threat`, `existing_non_threat`, `new_candidates` and `failed_or_unknown` separately. An `unavailable` lookup is never counted as absent.

## Batching, transactions and gas
- The ABI has no batch function, only a single-hash `submitThreat`, so 683 entries need 683 transactions. Batching would require a new contract or a multicall-style owner contract; this would change the deployment and is out of scope.
- Gas was not estimated. A reliable figure needs `eth_estimateGas` against the deployed contract (RPC) or a local EVM, and neither is available. No price or cost is given.

## Final proposal for approval (third review)
Generated without OpenPhish. Hashes are identical to the stratified manifest above.

| File | SHA-256 | Writes (threatType) |
|---|---|---|
| `proposed_smishing.json` | `829f59551a4fe0bf02843aa57a345f72c45fdb4aad3caeb85870217220c4a6ae` | 433 (MESSAGE = 0) |
| `proposed_phishing_urls.json` | `70c8c564e6bb1487151a17ebd97dbd4d9782dc551998161cbe115936505325c8` | 250 (URL = 1) |
| `proposed_summary.json` | `407a44b6cfb7622f4f6340f05f349968ee9fee2b5df7eb2c9d3e208d06fbb178` | combined counts |

**Registry membership and gas:** not yet known. The preparing machine has no RPC. Run the read-only preflight on a machine with RPC:

```
.venv/bin/python -m src.blockchain.registry_preflight --manifest data/threat_registry/proposed_smishing.json --out data/threat_registry/preflight_smishing_<UTC>.json
.venv/bin/python -m src.blockchain.registry_preflight --manifest data/threat_registry/proposed_phishing_urls.json --out data/threat_registry/preflight_phishing_urls_<UTC>.json
```

The final write count is each file's `writes_needed`. Already-registered hashes must not be submitted, because the contract reverts on them with `DuplicateHash`.

## Files kept in git (2026-10-28)
- **Committed:** this review, `proposed_smishing.json` and `proposed_summary.json`.
- **Not committed, kept locally:**
  - `proposed_phishing_urls.json` (8 MB, mostly the list of 99,703 deferred hashes).
    Its reviewed SHA-256 is `70c8c564e6bb1487151a17ebd97dbd4d9782dc551998161cbe115936505325c8` (table above).
  - The superseded `proposed_batch.json` and `proposed_batch_stratified.json`.
- **Regenerating the URL manifest** (with the same PhiUSIIL file, SHA-256 `8e7e0331…aed2ff9a`):

  ```
  .venv/bin/python -m src.blockchain.prepare_batch --urls-only --selection stratified \
      --out data/threat_registry/proposed_phishing_urls_<date>.json
  ```

  It yields the same 250 proposed hashes, but a new `generated_at` and therefore a new file
  checksum. A regenerated file is a new artifact and needs fresh review and approval before
  any write.

## Final smishing batch (prepared 2026-10-29; NOT submitted)

| Artifact | SHA-256 | Entries |
|---|---|---|
| `proposed_smishing_reviewed_20261029.json` | `119cf3c8da096e7c043da3281ec337129d4832e3538116cbc8db877a9112e04a` | 425 (8 validation rows excluded where the model disagreed) |
| `proposed_smishing_final_20261029.json` | `00d49ac9c3deb7db8b5ed5961d7bed21676a03f9683c0eea4714a6384a9805e3` | **421** (4 more excluded: no link, phone or call-to-action, and no independent evidence) |

Both are derived from `proposed_smishing.json` (`829f5955…`), with entries copied verbatim.
Every final hash was re-derived from its raw row. Locked-test-split rows are excluded, and
there are no URL entries. The exclusions are conservative; they are not findings that those
messages are benign.

**Read-only preflight** (`preflight_smishing_final_20261028T195556Z.json`, SHA-256 `f698ca58…1eda59`):
- 421 confirmed misses, 0 existing entries, 0 failures.
- Chain 11155111; contract `0x62bFA47Fe851545365b152B746475925100CEc96`; owner
  `0x74faB8279d61BEC35D9e95B72FAE96ee550B07cd`; `threatCount` 7.
- Estimated gas: about 260,000 per write, 109,493,994 in total.

**Approved by the owner on 2026-10-29: these 421 writes.** They were not submitted on the
preparing machine, because the owner's signing key was not configured there. To submit:

```
.venv/bin/python -m src.blockchain.submit_reviewed_batch \
  --manifest data/threat_registry/proposed_smishing_final_20261029.json \
  --log data/threat_registry/submission_log_<UTC>.jsonl --submit
```

The URL manifest preflight (`preflight_phishing_urls_20261028T192909Z.json`) shows 250 misses.
The URL batch remains on HOLD and is not authorized.

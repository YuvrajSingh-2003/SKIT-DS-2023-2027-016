"""Submit the owner-approved, reviewed smishing batch to the ThreatRegistry.

Accepts ONLY the finalized artifact pinned below (path given on the command line,
content checked against the pinned SHA-256). Without --submit it performs every
check read-only and writes nothing to the chain.

Checks before any write:
  * manifest SHA-256 and candidate count equal the pinned, approved values;
  * every entry is MESSAGE / verdict 1 / confidence 100, hashes are unique, and each
    hash is re-derived from its raw source row with src.blockchain.hashing;
  * no locked-test-split row is present;
  * chain ID, contract address, deployed code and contract owner are as pinned;
  * (submit mode) the signer is the owner and has no pending transactions;
  * an explicit typed confirmation showing chain, contract, artifact, checksum and
    the exact number of writes.

During submission, one transaction at a time:
  * threatExists is rechecked immediately before each write; registered hashes are
    skipped (never resubmitted);
  * the script stops at the first failed, reverted or uncertain transaction and
    never retries one whose outcome is unknown;
  * every step is appended to a JSONL log (transaction hash, candidate hash,
    receipt block, gas used, outcome). Keys and RPC URLs are never logged.

    python -m src.blockchain.submit_reviewed_batch \
        --manifest data/threat_registry/proposed_smishing_final_20261029.json \
        --log data/threat_registry/submission_log_<UTC>.jsonl            # checks only
    ... add --submit to write (requires SIGNER_PRIVATE_KEY in the environment or .env)
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ABI_PATH = PROJECT_ROOT / "contracts" / "abi" / "ThreatRegistry.json"
RAW_CSV = PROJECT_ROOT / "data" / "incoming" / "mishra_soni" / "extracted" / "Dataset_5971.csv"
TEST_SPLIT = PROJECT_ROOT / "data" / "processed" / "test.csv"

# Approved scope (owner review, 2026-10-29). Changing any of these needs fresh approval.
EXPECTED_MANIFEST_SHA256 = "00d49ac9c3deb7db8b5ed5961d7bed21676a03f9683c0eea4714a6384a9805e3"
EXPECTED_COUNT = 421
CHAIN_ID = 11155111
CONTRACT_ADDRESS = "0x62bFA47Fe851545365b152B746475925100CEc96"
EXPECTED_OWNER = "0x74faB8279d61BEC35D9e95B72FAE96ee550B07cd"
THREAT_TYPE_MESSAGE, VERDICT, CONFIDENCE = 0, 1, 100
RECEIPT_TIMEOUT_S = 180


class SubmissionError(RuntimeError):
    """A check failed; nothing further is attempted."""


def _sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_and_verify_manifest(path: Path, *, expected_sha256: Optional[str] = None,
                             expected_count: Optional[int] = None, raw_csv: Optional[Path] = None,
                             test_split: Optional[Path] = None) -> list:
    """Return the proposed entries after every offline check, or raise SubmissionError."""
    from src.blockchain.hashing import generate_message_hash

    expected_sha256 = expected_sha256 or EXPECTED_MANIFEST_SHA256
    expected_count = expected_count or EXPECTED_COUNT
    raw_csv, test_split = raw_csv or RAW_CSV, test_split or TEST_SPLIT

    actual = _sha256(path)
    if actual != expected_sha256:
        raise SubmissionError(f"manifest SHA-256 {actual} does not match the approved {expected_sha256}")
    manifest = json.loads(Path(path).read_text(encoding="utf-8"))
    entries = manifest["proposed"]
    if len(entries) != expected_count:
        raise SubmissionError(f"manifest has {len(entries)} entries, approved count is {expected_count}")
    if manifest["network"]["chain_id"] != CHAIN_ID or manifest["network"]["contract_address"].lower() != CONTRACT_ADDRESS.lower():
        raise SubmissionError("manifest network differs from the pinned chain/contract")
    if len({e["hash"] for e in entries}) != len(entries):
        raise SubmissionError("duplicate hashes in manifest")

    with open(raw_csv, encoding="utf-8-sig", newline="") as handle:
        raw = list(csv.DictReader(handle))
    with open(test_split, encoding="utf-8", newline="") as handle:
        test_rows = {int(r["source_row"]) for r in csv.DictReader(handle)}
    for e in entries:
        if (e["threat_type_int"], e["proposed_verdict"], e["proposed_confidence"]) != (THREAT_TYPE_MESSAGE, VERDICT, CONFIDENCE):
            raise SubmissionError(f"{e['source_record_id']}: unexpected type/verdict/confidence")
        if not re.fullmatch(r"0x[0-9a-f]{64}", e["hash"]):
            raise SubmissionError(f"{e['source_record_id']}: malformed hash")
        row = int(e["source_record_id"].split()[1])
        if row in test_rows:
            raise SubmissionError(f"{e['source_record_id']}: locked test-split row")
        if raw[row]["LABEL"].strip().lower() != "smishing" or generate_message_hash(raw[row]["TEXT"]) != e["hash"]:
            raise SubmissionError(f"{e['source_record_id']}: hash does not re-derive from its source row")
    return entries


def verify_chain(w3, contract) -> str:
    """Pinned network checks. Returns the owner address."""
    if w3.eth.chain_id != CHAIN_ID:
        raise SubmissionError(f"connected chain {w3.eth.chain_id} is not {CHAIN_ID}")
    if contract.address.lower() != CONTRACT_ADDRESS.lower():
        raise SubmissionError("contract address differs from the pinned address")
    if not w3.eth.get_code(contract.address):
        raise SubmissionError("no contract code at the pinned address")
    owner = contract.functions.owner().call()
    if owner.lower() != EXPECTED_OWNER.lower():
        raise SubmissionError(f"contract owner {owner} is not the expected owner")
    return owner


def verify_signer(w3, signer_address: str, owner: str) -> None:
    if signer_address.lower() != owner.lower():
        raise SubmissionError("signer is not the contract owner")
    if w3.eth.get_transaction_count(signer_address, "pending") != w3.eth.get_transaction_count(signer_address, "latest"):
        raise SubmissionError("signer has pending transactions; resolve them before submitting")


def _key(entry) -> bytes:
    return bytes.fromhex(entry["hash"][2:])


def plan(entries: list, contract) -> dict:
    """Split entries into to-write and already-registered (read-only). Conflicting entries stop."""
    to_write, already = [], []
    for e in entries:
        if contract.functions.threatExists(_key(e)).call():
            t = contract.functions.getThreat(_key(e)).call()
            if (int(t[0]), int(t[1])) != (THREAT_TYPE_MESSAGE, VERDICT):
                raise SubmissionError(f"{e['hash']} is registered with a different type/verdict; review needed")
            already.append(e)
        else:
            to_write.append(e)
    return {"to_write": to_write, "already_registered": already}


class _Log:
    def __init__(self, path: Path):
        self._f = open(path, "x", encoding="utf-8")   # never overwrite a log

    def write(self, **record) -> None:
        record["at"] = datetime.now(timezone.utc).isoformat()
        self._f.write(json.dumps(record) + "\n")
        self._f.flush()

    def close(self) -> None:
        self._f.close()


def _safe_error(error: Exception) -> str:
    """Exception class plus a message with anything URL-like removed."""
    message = re.sub(r"https?://\S+", "<url>", str(error))[:200]
    return f"{type(error).__name__}: {message}"


def _receipt_timeout_errors() -> tuple:
    try:
        from web3.exceptions import TimeExhausted   # raised by wait_for_transaction_receipt
        return (TimeoutError, TimeExhausted)
    except ImportError:
        return (TimeoutError,)


def submit(entries: list, w3, contract, account, log: _Log, *, receipt_timeout: int = RECEIPT_TIMEOUT_S,
           timeout_errors: Optional[tuple] = None) -> dict:
    """Write entries one at a time. Stops at the first failure or uncertainty."""
    timeout_errors = timeout_errors or _receipt_timeout_errors()
    done, skipped = [], []
    for i, e in enumerate(entries):
        remaining = len(entries) - i
        if contract.functions.threatExists(_key(e)).call():
            skipped.append(e["hash"]); log.write(event="skipped_already_registered", hash=e["hash"])
            continue
        try:
            tx = contract.functions.submitThreat(_key(e), THREAT_TYPE_MESSAGE, VERDICT, CONFIDENCE).build_transaction({
                "from": account.address, "chainId": CHAIN_ID,
                "nonce": w3.eth.get_transaction_count(account.address, "pending")})
            signed = account.sign_transaction(tx)
            tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        except Exception as error:
            log.write(event="send_failed", hash=e["hash"], error=_safe_error(error))
            return {"stopped": "send_failed", "completed": done, "skipped": skipped, "remaining": remaining}
        tx_hex = tx_hash.hex() if hasattr(tx_hash, "hex") else str(tx_hash)
        log.write(event="sent", hash=e["hash"], tx=tx_hex)
        try:
            receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=receipt_timeout)
        except timeout_errors:
            state = contract.functions.threatExists(_key(e)).call()
            log.write(event="uncertain_no_receipt", hash=e["hash"], tx=tx_hex, registered_now=bool(state))
            return {"stopped": "uncertain", "completed": done, "skipped": skipped, "remaining": remaining,
                    "uncertain_tx": tx_hex, "registered_now": bool(state)}
        if receipt["status"] != 1:
            log.write(event="reverted", hash=e["hash"], tx=tx_hex, block=receipt.get("blockNumber"))
            return {"stopped": "reverted", "completed": done, "skipped": skipped, "remaining": remaining}
        if not contract.functions.threatExists(_key(e)).call():
            log.write(event="mined_but_not_registered", hash=e["hash"], tx=tx_hex)
            return {"stopped": "state_mismatch", "completed": done, "skipped": skipped, "remaining": remaining}
        done.append(e["hash"])
        log.write(event="confirmed", hash=e["hash"], tx=tx_hex, block=receipt.get("blockNumber"), gas_used=receipt.get("gasUsed"))
    return {"stopped": None, "completed": done, "skipped": skipped, "remaining": 0}


def confirmation_text(manifest: Path, checksum: str, writes: int) -> str:
    return (f"Chain: Sepolia ({CHAIN_ID})\nContract: {CONTRACT_ADDRESS}\nArtifact: {manifest}\n"
            f"SHA-256: {checksum}\nWrites: {writes}\n"
            f"Type exactly 'SUBMIT {writes} TO {CONTRACT_ADDRESS}' to proceed: ")


def _rpc_url() -> Optional[str]:
    for name in ("SEPOLIA_RPC_URL", "WEB3_PROVIDER_URI"):
        if os.getenv(name, "").strip():
            return os.environ[name].strip()
    env = PROJECT_ROOT / ".env"
    if env.is_file():
        from dotenv import dotenv_values
        values = dotenv_values(env)
        for name in ("SEPOLIA_RPC_URL", "WEB3_PROVIDER_URI"):
            if (values.get(name) or "").strip():
                return values[name].strip()
    return None


def _load_signer():
    """Owner key from SIGNER_PRIVATE_KEY (environment or .env). Never printed or logged."""
    from eth_account import Account
    key = os.getenv("SIGNER_PRIVATE_KEY", "").strip()
    if not key and (PROJECT_ROOT / ".env").is_file():
        from dotenv import dotenv_values
        key = (dotenv_values(PROJECT_ROOT / ".env").get("SIGNER_PRIVATE_KEY") or "").strip()
    if not key:
        raise SubmissionError("SIGNER_PRIVATE_KEY is not set (environment or .env)")
    account = Account.from_key(key)
    del key
    return account


def main(argv: Optional[list] = None, *, w3_factory: Optional[Callable] = None,
         signer_factory: Callable = _load_signer, prompt: Callable[[str], str] = input) -> int:
    parser = argparse.ArgumentParser(description="Submit the approved reviewed smishing batch (checks only unless --submit).")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--log", required=True, help="new JSONL log file (refuses to overwrite)")
    parser.add_argument("--submit", action="store_true", help="actually write (requires typed confirmation)")
    args = parser.parse_args(argv)

    if Path(args.log).exists():
        print(f"Refusing to overwrite {args.log}"); return 2
    try:
        entries = load_and_verify_manifest(Path(args.manifest))
        rpc = _rpc_url()
        if not rpc:
            raise SubmissionError("no RPC configured (SEPOLIA_RPC_URL / WEB3_PROVIDER_URI)")
        if w3_factory is None:
            from web3 import Web3
            w3_factory = lambda url: Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 30}))
        w3 = w3_factory(rpc)
        abi = json.loads(ABI_PATH.read_text(encoding="utf-8"))
        abi = abi["abi"] if isinstance(abi, dict) else abi
        contract = w3.eth.contract(address=w3.to_checksum_address(CONTRACT_ADDRESS), abi=abi)
        owner = verify_chain(w3, contract)
        p = plan(entries, contract)
        summary = {"manifest": args.manifest, "sha256": EXPECTED_MANIFEST_SHA256, "candidates": len(entries),
                   "already_registered": len(p["already_registered"]), "writes": len(p["to_write"]), "owner": owner}
        print(json.dumps(summary, indent=1))
        if not args.submit:
            print("Checks passed. Read-only run: nothing was signed or sent.")
            return 0
        account = signer_factory()
        verify_signer(w3, account.address, owner)
        answer = prompt(confirmation_text(Path(args.manifest), EXPECTED_MANIFEST_SHA256, len(p["to_write"])))
        if answer.strip() != f"SUBMIT {len(p['to_write'])} TO {CONTRACT_ADDRESS}":
            print("Confirmation did not match. Nothing was sent."); return 3
    except SubmissionError as error:
        print(f"Stopped before any write: {error}"); return 4

    log = _Log(Path(args.log))
    log.write(event="start", **summary)
    try:
        result = submit(p["to_write"], w3, contract, account, log)
    finally:
        log.close()
    print(json.dumps({k: (len(v) if isinstance(v, list) else v) for k, v in result.items()}, indent=1))
    return 0 if result["stopped"] is None else 5


if __name__ == "__main__":
    raise SystemExit(main())

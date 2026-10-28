
"""Read-only lookups against the ThreatRegistry contract.

Only Keccak-256 hashes of canonicalized inputs (src/blockchain/hashing.py) are
sent to the chain, and only through view calls. Nothing is ever written.

Every result carries a status:
  match_threat      the hash is registered with verdict 1 (threat)
  match_non_threat  the hash is registered with a non-threat verdict
  no_match          the registry was reachable and the hash is not registered
                    (not evidence of safety)
  unavailable       RPC, network identity, contract or call could not be verified
"""

import json
import logging
import os
from pathlib import Path

from dotenv import load_dotenv
from web3 import Web3

from src.blockchain.hashing import generate_message_hash, generate_url_hash

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[2]

load_dotenv(PROJECT_ROOT / ".env")

CONFIG_PATH = PROJECT_ROOT / "contracts" / "configs" / "contract_addresses.json"
ABI_PATH = PROJECT_ROOT / "contracts" / "abi" / "ThreatRegistry.json"

# ThreatRegistry.ThreatType enum values.
THREAT_TYPE_MESSAGE = 0
THREAT_TYPE_URL = 1

STATUS_MATCH_THREAT = "match_threat"
STATUS_MATCH_NON_THREAT = "match_non_threat"
STATUS_NO_MATCH = "no_match"
STATUS_UNAVAILABLE = "unavailable"


def _empty_result() -> dict:
    return {
        "status": STATUS_UNAVAILABLE,
        "available": False,
        "found": False,
        "verdict": None,
        "threat_type": None,
        "confidence": None,
        "error": None,
    }


def _lookup_hash(url_hash: str, expected_threat_type: int) -> dict:
    """View-call lookup of one 0x-prefixed bytes32 hash. Fails closed."""
    result = _empty_result()

    try:
        rpc_url = (
            os.getenv("SEPOLIA_RPC_URL")
            or os.getenv("WEB3_PROVIDER_URI")
        )

        if not rpc_url:
            result["error"] = "RPC endpoint is not configured"
            return result

        with open(CONFIG_PATH, encoding="utf-8") as file:
            config = json.load(file)

        with open(ABI_PATH, encoding="utf-8") as file:
            abi = json.load(file)

        network_config = config["sepolia"]
        contract_address = Web3.to_checksum_address(
            network_config["contractAddress"]
        )

        web3 = Web3(
            Web3.HTTPProvider(
                rpc_url,
                request_kwargs={"timeout": 10},
            )
        )

        if not web3.is_connected():
            result["error"] = "Could not connect to Sepolia RPC"
            return result

        if web3.eth.chain_id != network_config["chainId"]:
            result["error"] = "Connected network does not match Sepolia"
            return result

        if not web3.eth.get_code(contract_address):
            result["error"] = "ThreatRegistry contract is not deployed"
            return result

        contract = web3.eth.contract(
            address=contract_address,
            abi=abi,
        )

        hash_bytes = bytes.fromhex(url_hash[2:])

        exists = contract.functions.threatExists(hash_bytes).call()

        if not exists:
            result["available"] = True
            result["status"] = STATUS_NO_MATCH
            return result

        threat = contract.functions.getThreat(hash_bytes).call()

        if int(threat[0]) != expected_threat_type:
            # Domain-separated hashes should never cross types; treat as unverifiable.
            result["error"] = "Registry entry has an unexpected threat type"
            return result

        result["available"] = True
        result["found"] = True
        result["threat_type"] = int(threat[0])
        result["verdict"] = int(threat[1])
        result["confidence"] = int(threat[2])
        result["status"] = (
            STATUS_MATCH_THREAT if result["verdict"] == 1 else STATUS_MATCH_NON_THREAT
        )

        return result

    except Exception:
        logger.warning("Blockchain lookup failed.")
        result = _empty_result()
        result["error"] = "Blockchain lookup failed"
        return result


def check_blockchain_threat(url: str) -> dict:
    """Check a URL against the blockchain registry using read-only calls."""
    try:
        url_hash = generate_url_hash(url)
    except ValueError:
        result = _empty_result()
        result["error"] = "URL could not be canonicalized for lookup"
        return result
    return _lookup_hash(url_hash, THREAT_TYPE_URL)


def check_message_threat(message: str) -> dict:
    """Check a message's canonical hash against the registry (read-only).

    The message itself never leaves this process; only its Keccak-256 hash is
    used in a view call.
    """
    try:
        message_hash = generate_message_hash(message)
    except ValueError:
        result = _empty_result()
        result["error"] = "Message could not be canonicalized for lookup"
        return result
    return _lookup_hash(message_hash, THREAT_TYPE_MESSAGE)

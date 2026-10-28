"""Read-only Sepolia preflight for a proposed threat-registry manifest.

For every proposed hash this checks registry membership with view calls and,
for hashes not yet registered, asks the node for a gas estimate of the write
(eth_estimateGas, simulated from the contract owner's address). Nothing is
signed or broadcast; no private key is read or needed.

    python -m src.blockchain.registry_preflight \
        --manifest data/threat_registry/proposed_smishing.json \
        --out data/threat_registry/preflight_smishing_<UTC>.json

The RPC URL comes from SEPOLIA_RPC_URL / WEB3_PROVIDER_URI (environment or the
project .env) and is never printed or written.
"""
from __future__ import annotations

import argparse
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = PROJECT_ROOT / "contracts" / "configs" / "contract_addresses.json"
ABI_PATH = PROJECT_ROOT / "contracts" / "abi" / "ThreatRegistry.json"
RPC_ENV_VARS = ("SEPOLIA_RPC_URL", "WEB3_PROVIDER_URI")


class PreflightError(RuntimeError):
    """The network or contract could not be verified; no per-hash results."""


def rpc_url(env_file: Path = PROJECT_ROOT / ".env") -> Optional[str]:
    """RPC URL from the environment or the .env file (only the RPC keys are read)."""
    for name in RPC_ENV_VARS:
        if os.getenv(name, "").strip():
            return os.getenv(name).strip()
    if Path(env_file).is_file():
        from dotenv import dotenv_values
        values = dotenv_values(env_file)
        for name in RPC_ENV_VARS:
            if (values.get(name) or "").strip():
                return values[name].strip()
    return None


def _status(threat: tuple, expected_type: int) -> str:
    if int(threat[0]) != expected_type:
        return "error_type_mismatch"
    return "match_threat" if int(threat[1]) == 1 else "match_non_threat"


def preflight(manifest: dict, web3, *, config: dict, abi: list, max_hashes: int = 1000,
              delay: float = 0.1, sleep: Callable[[float], None] = time.sleep) -> dict:
    """Run the read-only checks with a connected Web3 instance. Raises PreflightError."""
    proposed = manifest["proposed"]
    if len(proposed) > max_hashes:
        raise PreflightError(f"{len(proposed)} hashes exceed max_hashes={max_hashes}")
    if web3.eth.chain_id != config["chainId"]:
        raise PreflightError("Connected network does not match the configured chain ID")
    if manifest.get("network", {}).get("contract_address", "").lower() != config["contractAddress"].lower():
        raise PreflightError("Manifest contract address differs from the repository configuration")
    address = web3.to_checksum_address(config["contractAddress"])
    if not web3.eth.get_code(address):
        raise PreflightError("No contract code at the configured address")
    contract = web3.eth.contract(address=address, abi=abi)
    owner = contract.functions.owner().call()
    count_before = contract.functions.threatCount().call()

    results, counts, gas_values = [], {}, []
    for i, entry in enumerate(proposed):
        if i:
            sleep(delay)
        item = {"hash": entry["hash"], "threat_type": entry["threat_type"], "gas_estimate": None, "error": None}
        try:
            key = bytes.fromhex(entry["hash"][2:])
            if contract.functions.threatExists(key).call():
                item["registry_status"] = _status(contract.functions.getThreat(key).call(),
                                                  entry["threat_type_int"])
            else:
                item["registry_status"] = "no_match"
                # Gas estimate only (eth_estimateGas simulation); never transacted here.
                write = contract.get_function_by_name("submitThreat")
                item["gas_estimate"] = write(key, entry["threat_type_int"], entry["proposed_verdict"],
                                             entry["proposed_confidence"]).estimate_gas({"from": owner})
                gas_values.append(item["gas_estimate"])
        except Exception as error:  # one failed hash never becomes "absent"
            item.setdefault("registry_status", "unavailable")
            item["error"] = type(error).__name__
        counts[item["registry_status"]] = counts.get(item["registry_status"], 0) + 1
        results.append(item)

    gas_price = web3.eth.gas_price
    total_gas = sum(gas_values)
    estimated_all = len(gas_values) == counts.get("no_match", 0)
    return {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "manifest_generated_at": manifest.get("generated_at"),
        "manifest_scope": manifest.get("scope"),
        "network": {"chain_id": config["chainId"], "contract_address": address},
        "contract_owner": owner,
        "threat_count_at_check": count_before,
        "method": "view calls (threatExists, getThreat, owner, threatCount) and eth_estimateGas; nothing signed or sent",
        "summary": {
            "proposed": len(proposed),
            "existing_threat": counts.get("match_threat", 0),
            "existing_non_threat": counts.get("match_non_threat", 0),
            "new_candidates": counts.get("no_match", 0),
            "failed_or_unknown": sum(n for s, n in counts.items()
                                     if s not in ("match_threat", "match_non_threat", "no_match")),
            "writes_needed": counts.get("no_match", 0),
            "gas_estimated_for_all_new": estimated_all,
            "total_gas_estimate": total_gas if estimated_all else None,
            "max_gas_single": max(gas_values) if gas_values else None,
            "gas_price_wei_at_check": gas_price,
            "indicative_cost_eth": (total_gas * gas_price / 10**18) if estimated_all else None,
            "note": "Indicative only: gas price changes between blocks. 'unavailable' is not 'absent'.",
        },
        "results": results,
    }


def main(argv: Optional[list] = None, env_file: Path = PROJECT_ROOT / ".env",
         web3_factory: Optional[Callable[[str], object]] = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only registry preflight (no transactions).")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--delay", type=float, default=0.1)
    args = parser.parse_args(argv)

    out = Path(args.out)
    if out.exists():
        raise FileExistsError(f"Refusing to overwrite {out}")
    url = rpc_url(env_file)
    if not url:
        print("No RPC configured (SEPOLIA_RPC_URL / WEB3_PROVIDER_URI unset); nothing checked.")
        return 2
    if web3_factory is None:
        from web3 import Web3
        web3_factory = lambda u: Web3(Web3.HTTPProvider(u, request_kwargs={"timeout": 15}))
    web3 = web3_factory(url)

    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))["sepolia"]
    abi = json.loads(ABI_PATH.read_text(encoding="utf-8"))
    abi = abi["abi"] if isinstance(abi, dict) else abi
    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    try:
        report = preflight(manifest, web3, config=config, abi=abi, delay=args.delay)
    except PreflightError as error:
        print(f"Preflight stopped: {error}")
        return 4
    except Exception as error:
        print(f"Preflight stopped: could not reach or read the network ({type(error).__name__})")
        return 4
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=1), encoding="utf-8")
    print(json.dumps(report["summary"], indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

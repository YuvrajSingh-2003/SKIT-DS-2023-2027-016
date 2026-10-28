"""Registry lookups through the real Web3 HTTP stack against a local fake JSON-RPC.

The fake node (in-process, random localhost port) answers eth_chainId, eth_getCode
and eth_call for threatExists/getThreat, so app/services/blockchain_checker.py runs
unmodified. No real network, no keys, no transactions.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from eth_abi import decode, encode
from eth_utils import keccak

from app.services import blockchain_checker as bc
from src.blockchain.hashing import generate_message_hash, generate_url_hash

THREAT_URL = "https://chainshield-test.invalid/registry-check"
BENIGN_URL = "https://registered-benign.invalid/"
CONFUSED_URL = "https://type-confused.invalid/"
THREAT_MESSAGE = "ChainShield synthetic registry test message"

REGISTRY = {
    generate_url_hash(THREAT_URL): (1, 1, 100),
    generate_url_hash(BENIGN_URL): (1, 0, 100),
    generate_url_hash(CONFUSED_URL): (0, 1, 100),     # stored as MESSAGE: must not match a URL lookup
    generate_message_hash(THREAT_MESSAGE): (0, 1, 100),
}
SELECTORS = {keccak(text=s)[:4].hex(): s for s in ("threatExists(bytes32)", "getThreat(bytes32)")}


def _handler(chain_id, code):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _result(self, request):
            method = request["method"]
            if method == "eth_chainId":
                return hex(chain_id)
            if method == "web3_clientVersion":
                return "fake/1"
            if method == "eth_getCode":
                return code
            if method == "eth_call":
                data = request["params"][0]["data"]
                name = SELECTORS[data[2:10]]
                key = "0x" + decode(["bytes32"], bytes.fromhex(data[10:]))[0].hex()
                if name.startswith("threatExists"):
                    return "0x" + encode(["bool"], [key in REGISTRY]).hex()
                t, v, c = REGISTRY[key]
                return "0x" + encode(["uint8", "uint8", "uint16", "uint64", "address"],
                                     [t, v, c, 1, "0x" + "00" * 19 + "aa"]).hex()
            raise KeyError(method)

        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            requests = request if isinstance(request, list) else [request]
            replies = []
            for r in requests:
                try:
                    replies.append({"jsonrpc": "2.0", "id": r["id"], "result": self._result(r)})
                except KeyError as missing:
                    replies.append({"jsonrpc": "2.0", "id": r["id"],
                                    "error": {"code": -32601, "message": str(missing)}})
            body = json.dumps(replies if isinstance(request, list) else replies[0]).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    return Handler


@pytest.fixture
def fake_node(monkeypatch):
    servers = []

    def start(chain_id=11155111, code="0x6080"):
        server = HTTPServer(("127.0.0.1", 0), _handler(chain_id, code))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        monkeypatch.delenv("WEB3_PROVIDER_URI", raising=False)
        monkeypatch.setenv("SEPOLIA_RPC_URL", f"http://127.0.0.1:{server.server_port}")
    yield start
    for server in servers:
        server.shutdown()


def test_registry_hit_non_threat_miss_and_type_mismatch(fake_node):
    fake_node()
    assert bc.check_blockchain_threat(THREAT_URL)["status"] == "match_threat"
    assert bc.check_blockchain_threat(BENIGN_URL)["status"] == "match_non_threat"
    assert bc.check_blockchain_threat("https://not-registered.invalid/")["status"] == "no_match"
    confused = bc.check_blockchain_threat(CONFUSED_URL)
    assert confused["status"] == "unavailable" and confused["found"] is False
    assert bc.check_message_threat(THREAT_MESSAGE)["status"] == "match_threat"
    assert bc.check_message_threat("See you at 6")["status"] == "no_match"


def test_wrong_chain_is_unavailable(fake_node):
    fake_node(chain_id=1)
    result = bc.check_blockchain_threat(THREAT_URL)
    assert result["status"] == "unavailable" and "Sepolia" in result["error"]


def test_missing_contract_code_is_unavailable(fake_node):
    fake_node(code="0x")
    assert bc.check_blockchain_threat(THREAT_URL)["status"] == "unavailable"


def test_unreachable_node_is_unavailable(monkeypatch):
    server = HTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
    port = server.server_port
    server.server_close()                       # nothing listens on this port now
    monkeypatch.delenv("WEB3_PROVIDER_URI", raising=False)
    monkeypatch.setenv("SEPOLIA_RPC_URL", f"http://127.0.0.1:{port}")
    result = bc.check_blockchain_threat(THREAT_URL)
    assert result["status"] == "unavailable" and result["available"] is False


def test_url_route_never_safe_when_registry_unreachable(monkeypatch):
    from app.routes import scan as scan_route
    monkeypatch.delenv("SEPOLIA_RPC_URL", raising=False)
    monkeypatch.delenv("WEB3_PROVIDER_URI", raising=False)
    monkeypatch.setattr(scan_route, "predict_phishing", lambda url: {
        "available": True, "probability": 0.01, "label": "legitimate", "model_name": "m", "error": None})
    result = scan_route._build_scan_result("https://www.example.org")
    assert result["blockchain_status"] == "unavailable"
    assert result["risk_level"] == "UNKNOWN"

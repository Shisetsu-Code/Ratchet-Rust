"""Exercise the actual desktop console protocol without opening a window."""
import json
import ipaddress
import os
from pathlib import Path
import sys
import urllib.parse
import urllib.request
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools" / "owner_setup"))
import owner_console

class LocalTestEdge(urllib.request.BaseHandler):
    """Model the parent's trusted edge address only on its local test server."""

    def __init__(self, origin: str, address: str) -> None:
        parsed = urllib.parse.urlsplit(origin)
        if parsed.scheme not in ("http", "https") or parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
            raise ValueError("Synthetic edge addresses require a local contract server")
        if ipaddress.ip_address(address) not in ipaddress.ip_network("2001:db8::/32"):
            raise ValueError("Contract edge address must use the documentation range")
        self.origin = (parsed.scheme, parsed.hostname, parsed.port)
        self.address = address

    def http_request(self, request: urllib.request.Request) -> urllib.request.Request:
        parsed = urllib.parse.urlsplit(request.full_url)
        if (parsed.scheme, parsed.hostname, parsed.port) != self.origin:
            raise ValueError("Synthetic edge headers must stay on the local contract server")
        request.add_unredirected_header("CF-Connecting-IP", self.address)
        return request

    https_request = http_request


def main() -> None:
    origin = os.environ["RATCHET_TEST_BASE"]
    edge = LocalTestEdge(origin, os.environ["RATCHET_TEST_EDGE_ADDRESS"])
    original_build_opener = urllib.request.build_opener
    # Keep the real console protocol, signatures, encryption and response checks.
    # Only the local test transport supplies the edge address that Miniflare
    # otherwise collapses to localhost for every independent contract file.
    with patch("urllib.request.build_opener", side_effect=lambda *handlers: original_build_opener(edge, *handlers)):
        result = owner_console.signed_operation(
            origin, Path(os.environ["RATCHET_TEST_OWNER_FILE"]),
            os.environ["RATCHET_TEST_OWNER_PASSWORD"], {"type": "accounts.list", "limit": 100},
        )
    assert isinstance(result.get("accounts"), list)
    print(json.dumps({"native_console_verified": True, "accounts": len(result["accounts"]), "edge_address": edge.address}))


if __name__ == "__main__":
    main()

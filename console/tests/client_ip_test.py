#!/usr/bin/env python3
"""Unit test: client_ip() trusts CloudFront-Viewer-Address only from CONSOLE_TRUSTED_PROXY_CIDRS.
Run: python3 console/tests/client_ip_test.py   (no dependencies; FastAPI is stubbed)."""
import os
import sys
import types

os.environ["CONSOLE_TRUSTED_PROXY_CIDRS"] = "10.40.0.0/16"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.modules.setdefault("fastapi", types.SimpleNamespace(HTTPException=Exception, Request=object))
from app import auth  # noqa: E402  (after the environment and the stub are in place)


def req(peer: str, headers: dict) -> types.SimpleNamespace:
    return types.SimpleNamespace(client=types.SimpleNamespace(host=peer), headers=headers)


CASES = [
    (req("10.40.3.9", {"cloudfront-viewer-address": "198.51.100.94:51122"}), "198.51.100.94"),
    (req("10.40.3.9", {"cloudfront-viewer-address": "2001:db8::7:51122"}), "2001:db8::7"),
    (req("10.40.3.9", {}), "10.40.3.9"),                                          # health checks
    (req("10.40.3.9", {"cloudfront-viewer-address": "junk"}), "10.40.3.9"),
    (req("203.0.113.5", {"cloudfront-viewer-address": "192.0.2.1:1"}), "203.0.113.5"),   # spoof from outside the VPC
]
bad = [(r.client.host, r.headers, auth.client_ip(r), want) for r, want in CASES if auth.client_ip(r) != want]
print("client_ip: all cases ok" if not bad else f"client_ip FAILED: {bad}")
sys.exit(1 if bad else 0)

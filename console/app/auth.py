"""Login, sessions, source-IP allowlist and CSRF defence for the Guardrail Console.

- Password hashes use stdlib scrypt, stored as  scrypt:<n>:<r>:<p>:<salt_hex>:<hash_hex>
  (no '$' characters, so the value is safe inside a bash-sourced .env).
- Sessions are random server-side tokens (in memory: a restart signs everyone out).
- Cookie: Secure, HttpOnly, SameSite=Strict. Mutations also need the X-Console header.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import secrets
import threading
import time

from fastapi import HTTPException, Request

SESSION_TTL = int(os.environ.get("CONSOLE_SESSION_TTL", 8 * 3600))
COOKIE = "gc_session"
_ALLOW = [ipaddress.ip_network(c.strip()) for c in
          os.environ.get("CONSOLE_ALLOW_CIDRS", "127.0.0.0/8").split(",") if c.strip()]
# Behind CloudFront (AWS deployment): the TCP peer is the internal load balancer, and the real
# viewer is in CloudFront-Viewer-Address ("ip:port"). That header is trusted ONLY when the peer is
# in one of these networks (the VPC); the load balancer itself only forwards requests that carry
# CloudFront's secret origin header. Empty (the default) = direct connections, no header trusted.
_TRUSTED_PROXIES = [ipaddress.ip_network(c.strip()) for c in
                    os.environ.get("CONSOLE_TRUSTED_PROXY_CIDRS", "").split(",") if c.strip()]
VIEWER_HEADER = "cloudfront-viewer-address"

_sessions: dict[str, tuple[str, float]] = {}
_failures: dict[str, list[float]] = {}
_lock = threading.Lock()
MAX_FAILURES, FAIL_WINDOW = 5, 300


def hash_password(password: str, n: int = 2 ** 14, r: int = 8, p: int = 1) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=32)
    return f"scrypt:{n}:{r}:{p}:{salt.hex()}:{dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt, want = stored.split(":")
        if algo != "scrypt":
            return False
        dk = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt),
                            n=int(n), r=int(r), p=int(p), dklen=32)
        return hmac.compare_digest(dk.hex(), want)
    except (ValueError, TypeError):
        return False


def client_ip(request: Request) -> str:
    peer = request.client.host if request.client else ""
    if not _TRUSTED_PROXIES:
        return peer          # direct connections: X-Forwarded-For and friends are NOT trusted
    try:
        from_proxy = any(ipaddress.ip_address(peer) in net for net in _TRUSTED_PROXIES)
    except ValueError:
        from_proxy = False
    viewer = request.headers.get(VIEWER_HEADER, "")
    if from_proxy and viewer:
        host = viewer.rsplit(":", 1)[0].strip("[]")   # "203.0.113.7:4711" or "2001:db8::1:4711"
        try:
            return str(ipaddress.ip_address(host))
        except ValueError:
            return peer
    return peer


def check_source(request: Request) -> None:
    try:
        ip = ipaddress.ip_address(client_ip(request))
    except ValueError:
        raise HTTPException(403, "Source not allowed") from None
    if not any(ip in net for net in _ALLOW):
        raise HTTPException(403, "Source not allowed") from None


def login(request: Request, username: str, password: str) -> str:
    ip = client_ip(request)
    now = time.time()
    with _lock:
        recent = [t for t in _failures.get(ip, []) if now - t < FAIL_WINDOW]
        _failures[ip] = recent
        if len(recent) >= MAX_FAILURES:
            raise HTTPException(429, "Too many failed sign-ins. Try again in a few minutes.")
    want_user = os.environ.get("CONSOLE_USER", "")
    want_hash = os.environ.get("CONSOLE_PASSWORD_HASH", "")
    ok = bool(want_user and want_hash) and hmac.compare_digest(username, want_user) \
        and verify_password(password, want_hash)
    if not ok:
        with _lock:
            _failures.setdefault(ip, []).append(now)
        raise HTTPException(401, "Wrong username or password")
    token = secrets.token_urlsafe(32)
    with _lock:
        _failures.pop(ip, None)
        _sessions[token] = (username, now + SESSION_TTL)
    return token


def logout(token: str | None) -> None:
    if token:
        with _lock:
            _sessions.pop(token, None)


def current_user(request: Request) -> str:
    token = request.cookies.get(COOKIE)
    with _lock:
        entry = _sessions.get(token or "")
        if not entry or entry[1] < time.time():
            _sessions.pop(token or "", None)
            raise HTTPException(401, "Sign in required")
        return entry[0]


def require_csrf(request: Request) -> None:
    """Defence in depth on top of SameSite=Strict: custom header + same-origin check."""
    if request.headers.get("x-console") != "1":
        raise HTTPException(403, "Missing X-Console header")
    origin = request.headers.get("origin")
    if origin and origin.split("://", 1)[-1] != request.headers.get("host", ""):
        raise HTTPException(403, "Cross-origin request refused")

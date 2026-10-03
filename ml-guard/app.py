"""ML guard: second guardrail layer for the Kiro gateway (Amazon Bedrock Guardrails ApplyGuardrail).

Called by the APISIX inference guard (policy/inference-guard.lua) only after the regex rules
passed, and by the console's prompt tester. Internal only: no published port, and requests are
accepted only from the APISIX and console containers' fixed addresses on the Docker network.

POST /check  {"text": "..."}  ->  {"action": "block"|"allow", "policies": ["pii:NAME", ...],
                                   "mask": ["<matched text>", ...], "latency_ms": 480}
GET  /info                    ->  {"provider": "bedrock", "guardrail_id": ..., "version": ...}

"mask" carries the detected PII spans so the caller can mask them in its own audit log; it is
returned only to the two trusted callers and never logged here.
"""
from __future__ import annotations

import json
import logging
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import boto3
from botocore.config import Config

GUARDRAIL_ID = os.environ.get("BEDROCK_GUARDRAIL_ID", "").strip()   # empty = layer not configured
GUARDRAIL_VERSION = os.environ.get("BEDROCK_GUARDRAIL_VERSION", "1")
REGION = os.environ.get("AWS_REGION", "us-east-1")
MAX_CHARS = int(os.environ.get("ML_GUARD_MAX_CHARS", "8000"))       # cost cap: 1 text unit = 1,000 chars
ALLOWED = set(os.environ.get("ML_GUARD_ALLOWED_IPS", "172.30.0.10,172.30.0.20").split(","))
MAX_BODY = 1024 * 1024

log = logging.getLogger("ml-guard")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
# Short timeouts: the gateway enforces its own deadline; don't pile up threads behind a slow call.
client = boto3.client("bedrock-runtime", region_name=REGION,
                      config=Config(connect_timeout=2, read_timeout=5, retries={"max_attempts": 1}))


def check(text: str) -> dict:
    t0 = time.perf_counter()
    r = client.apply_guardrail(guardrailIdentifier=GUARDRAIL_ID, guardrailVersion=GUARDRAIL_VERSION,
                               source="INPUT", content=[{"text": {"text": text[:MAX_CHARS]}}])
    ms = round((time.perf_counter() - t0) * 1000)
    policies, mask = [], []
    for a in r.get("assessments", []):
        for t in (a.get("topicPolicy") or {}).get("topics", []):
            if t.get("action") == "BLOCKED":
                policies.append(f"topic:{t.get('name')}")
        for f in (a.get("contentPolicy") or {}).get("filters", []):
            if f.get("action") == "BLOCKED":
                policies.append(f"content:{f.get('type')}")
        sip = a.get("sensitiveInformationPolicy") or {}
        for e in sip.get("piiEntities", []):
            if e.get("action") in ("BLOCKED", "ANONYMIZED"):
                policies.append(f"pii:{e.get('type')}")
                if e.get("match"):
                    mask.append(e["match"])
        for e in sip.get("regexes", []):
            if e.get("action") in ("BLOCKED", "ANONYMIZED"):
                policies.append(f"regex:{e.get('name')}")
                if e.get("match"):
                    mask.append(e["match"])
    blocked = r.get("action") == "GUARDRAIL_INTERVENED"
    return {"action": "block" if blocked else "allow", "policies": sorted(set(policies)),
            "mask": sorted(set(mask), key=len, reverse=True), "latency_ms": ms,
            "chars_checked": min(len(text), MAX_CHARS)}


class Handler(BaseHTTPRequestHandler):
    server_version = "ml-guard"
    sys_version = ""

    def _send(self, code: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _trusted(self) -> bool:
        if self.client_address[0] in ALLOWED:
            return True
        self._send(403, {"error": "forbidden"})
        return False

    def do_GET(self):
        if not self._trusted():
            return
        if self.path == "/info":
            return self._send(200, {"provider": "bedrock", "guardrail_id": GUARDRAIL_ID,
                                    "version": GUARDRAIL_VERSION, "region": REGION,
                                    "max_chars": MAX_CHARS})
        if self.path == "/healthz":
            return self._send(200, {"ok": True})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._trusted():
            return
        if self.path != "/check":
            return self._send(404, {"error": "not found"})
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0 or n > MAX_BODY:
            return self._send(413, {"error": "body too large or empty"})
        try:
            text = json.loads(self.rfile.read(n)).get("text")
        except (ValueError, AttributeError):
            return self._send(400, {"error": "invalid json"})
        if not isinstance(text, str) or not text.strip():
            return self._send(200, {"action": "allow", "policies": [], "mask": [], "latency_ms": 0,
                                    "chars_checked": 0})
        if not GUARDRAIL_ID:                                     # caller applies its fail mode
            return self._send(503, {"error": "BEDROCK_GUARDRAIL_ID is not set"})
        try:
            out = check(text)
        except Exception as e:                                   # caller decides fail-open/closed
            log.warning("ApplyGuardrail failed: %s", type(e).__name__)
            return self._send(502, {"error": f"bedrock: {type(e).__name__}"})
        # Log the verdict only, never the text or the matches.
        log.info("check action=%s policies=%s chars=%d ms=%d", out["action"], ",".join(out["policies"]),
                 out["chars_checked"], out["latency_ms"])
        self._send(200, out)

    def log_message(self, *_):            # suppress the default per-request access log
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()

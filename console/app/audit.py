"""Read the APISIX audit log (JSON lines written by file-logger) for search and stats.

The log volume is mounted read-only. Only the tail of the file is scanned (TAIL_BYTES) so a
large log cannot stall the console; production would query the SIEM / OpenSearch instead.
"""
from __future__ import annotations

import json
import os
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import rules

LOG = Path(os.environ.get("AUDIT_LOG", "/audit/kiro-audit.log"))
TAIL_BYTES = int(os.environ.get("AUDIT_TAIL_BYTES", 32 * 1024 * 1024))
KIRO_HOST_PREFIXES = ("runtime.", "q.", "management.")
OP_LABELS = {
    "AmazonCodeWhispererStreamingService.GenerateAssistantResponse": "Chat",
    "AmazonCodeWhispererService.SendTelemetryEvent": "Telemetry",
    "KiroControlPlaneBearerService.ListAvailableModels": "List models",
    "AmazonCodeWhispererService.GetProfile": "Get profile",
}


def _f(v) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


# Defence in depth: the gateway already masks rule matches before writing the audit log, but
# lines written before masking existed (or with LOG_FULL_BODY) may still hold raw matches.
# Re-mask on read with the CURRENT rules so the portal never displays them either way.
_mask_cache: tuple[float, list[re.Pattern]] = (-1.0, [])


def _maskers() -> list[re.Pattern]:
    global _mask_cache
    try:
        mtime = rules.FILE.stat().st_mtime
    except OSError:
        return _mask_cache[1]
    if mtime != _mask_cache[0]:
        pats = []
        for r in rules.load()[0].get("rules", []):
            try:   # PCRE and Python re agree on the syntax these rules use; skip any that don't
                pats.append(re.compile(r["pattern"], re.I if r.get("case_insensitive") else 0))
            except re.error:
                pass
        _mask_cache = (mtime, pats)
    return _mask_cache[1]


def mask_text(text: str) -> str:
    for p in _maskers():
        text = p.sub(lambda m: rules.mask(m.group(0)), text)
    return text


def normalise(e: dict) -> dict | None:
    uri, host = e.get("uri") or "", e.get("host") or ""
    if uri.startswith("/__mock/"):
        return None                                   # internal mock LLM hop
    if uri.startswith("/v1/"):
        path = "ai"
    elif host.startswith(KIRO_HOST_PREFIXES):
        path = "kiro"
    else:
        return None
    status = int(e.get("status") or 0)
    policy = e.get("policy") or ""
    rule = e.get("rule") or ""
    if policy == "blocked" or (path == "ai" and status == 400):
        result = "blocked"
        rule = rule or ("prompt-guard" if path == "ai" else "")
    elif status == 429:
        result = "rate_limited"
    elif status >= 500 or status == 0:
        result = "error"
    else:
        result = "allowed"
    op = e.get("op") or ""
    return {
        "ts": e.get("ts"), "path": path, "host": host,
        "op": OP_LABELS.get(op, op.split(".")[-1] if op else
                            ("Chat" if path == "ai" or host.startswith("runtime.") else "-")),
        "status": status, "result": result, "rule": rule,
        "user": e.get("consumer") or e.get("user") or "anonymous",
        "prompt": mask_text(e.get("prompt") or ""),
        "latency_ms": round((_f(e.get("req_time")) or 0) * 1000),
        "model": e.get("llm_model") or "",
        "tokens": int(_f(e.get("prompt_tokens")) or 0) + int(_f(e.get("completion_tokens")) or 0),
        # runtime.* only serves inference, so count it as chat even without an X-Amz-Target header.
        "is_chat": path == "ai" or host.startswith("runtime.") or op.endswith("GenerateAssistantResponse"),
    }


def read_events() -> list[dict]:
    if not LOG.exists():
        return []
    with LOG.open("rb") as fh:
        size = fh.seek(0, os.SEEK_END)
        fh.seek(max(0, size - TAIL_BYTES))
        if size > TAIL_BYTES:
            fh.readline()                               # drop partial first line
        lines = fh.read().splitlines()
    out = []
    for line in lines:
        try:
            ev = normalise(json.loads(line))
        except (ValueError, TypeError, AttributeError):
            continue
        if ev:
            out.append(ev)
    return out


def _ts(ev: dict) -> datetime | None:
    try:
        return datetime.fromisoformat(ev["ts"])
    except (KeyError, TypeError, ValueError):
        return None


def search(q: str = "", result: str = "", path: str = "", chat_only: bool = True,
           hours: float = 24, limit: int = 200) -> list[dict]:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    ql = q.lower()
    out = []
    for ev in reversed(read_events()):                  # newest first
        t = _ts(ev)
        if t and t < cutoff:
            break
        if chat_only and not ev["is_chat"]:
            continue
        if result and ev["result"] != result:
            continue
        if path and ev["path"] != path:
            continue
        if ql and ql not in f'{ev["prompt"]} {ev["user"]} {ev["rule"]} {ev["op"]}'.lower():
            continue
        out.append(ev)
        if len(out) >= limit:
            break
    return out


def _pct(values: list[int], p: float) -> int | None:
    if not values:
        return None
    s = sorted(values)
    return s[min(len(s) - 1, int(round(p / 100 * (len(s) - 1))))]


def stats(hours: float = 24) -> dict:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    evs = [e for e in read_events() if e["is_chat"] and (t := _ts(e)) and t >= cutoff]
    by_rule, by_user = Counter(), Counter()
    buckets: dict[str, Counter] = defaultdict(Counter)
    lat = {"kiro": [], "ai": []}
    for e in evs:
        t = _ts(e)
        key = t.strftime("%Y-%m-%dT%H:00") if hours <= 48 else t.strftime("%Y-%m-%d")
        buckets[key][e["result"]] += 1
        if e["result"] == "blocked":
            by_rule[e["rule"] or "unknown"] += 1
            by_user[e["user"]] += 1
        elif e["result"] == "allowed" and e["status"] == 200:   # completed model calls only
            lat[e["path"]].append(e["latency_ms"])
    return {
        "hours": hours,
        "requests": len(evs),
        "blocked": sum(1 for e in evs if e["result"] == "blocked"),
        "rate_limited": sum(1 for e in evs if e["result"] == "rate_limited"),
        "users": len({e["user"] for e in evs}),
        "by_rule": by_rule.most_common(10),
        "blocked_by_user": by_user.most_common(10),
        "timeline": [{"bucket": k, **v} for k, v in sorted(buckets.items())],
        "latency_ms": {p: {"p50": _pct(v, 50), "p95": _pct(v, 95), "n": len(v)} for p, v in lat.items()},
        "tokens": sum(e["tokens"] for e in evs),
    }

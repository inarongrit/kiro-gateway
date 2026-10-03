"""Observability API for the portal: server-side queries to Prometheus, Loki and Tempo.

The browser never sends PromQL / LogQL / TraceQL. Every query is a fixed template here and the
only caller-controlled inputs are a window (hours, validated) and, for traces, a hex trace id or
a small enum filter, so this cannot be used to read arbitrary data from the backends.
"""
from __future__ import annotations

import base64
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

PROM = os.environ.get("PROMETHEUS_URL", "http://prometheus:9090")
LOKI = os.environ.get("LOKI_URL", "http://loki:3100")
TEMPO = os.environ.get("TEMPO_URL", "http://tempo:3200")

KIRO_CHAT_ROUTE = "runtime.us-east-1.kiro.dev"
ROUTE_LABELS = {
    "runtime.us-east-1.kiro.dev": "Kiro chat",
    "q.us-east-1.amazonaws.com": "Kiro API",
    "management.us-east-1.kiro.dev": "Kiro account",
    "ai-chat": "AI route",
    "ai-mock-llm": "Mock LLM (internal)",
}
TRACE_ID = re.compile(r"^[0-9a-f]{16,32}$")


class BackendError(Exception):
    """A monitoring backend is unreachable or returned an error."""


def _get(url: str, timeout: float = 8) -> dict:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise LookupError("not found") from e
        raise BackendError(f"{urllib.parse.urlsplit(url).hostname} returned HTTP {e.code}") from e
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise BackendError(f"{urllib.parse.urlsplit(url).hostname} unreachable") from e


def _window(hours: float) -> tuple[float, float, int]:
    """(start, end, step seconds) giving ~60-120 points for any window."""
    end = time.time()
    start = end - hours * 3600
    step = max(60, int(hours * 3600 / 96) // 60 * 60)
    return start, end, step


def _rng(hours: float) -> str:
    return f"{max(1, int(hours * 60))}m"


# ---- Prometheus ---------------------------------------------------------------------------
def _prom_range(expr: str, hours: float) -> list[dict]:
    start, end, step = _window(hours)
    q = urllib.parse.urlencode({"query": expr, "start": start, "end": end, "step": step})
    return _get(f"{PROM}/api/v1/query_range?{q}")["data"]["result"]


def _prom_instant(expr: str) -> list[dict]:
    q = urllib.parse.urlencode({"query": expr})
    return _get(f"{PROM}/api/v1/query?{q}")["data"]["result"]


def _num(v: str) -> float | None:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return None if f != f or f in (float("inf"), float("-inf")) else f  # drop NaN / Inf


def _scalar(expr: str) -> float | None:
    r = _prom_instant(expr)
    return _num(r[0]["value"][1]) if r else None


def _pivot(results: list[dict], label: str, scale: float = 1.0, rename: dict | None = None,
           digits: int = 3) -> tuple[list[dict], list[str]]:
    """Prometheus matrix -> [{t: epoch_ms, <series>: value}] rows + series names (chart-ready)."""
    rows: dict[int, dict] = {}
    names: list[str] = []
    for s in results:
        raw = s["metric"].get(label, "") or "other"
        name = (rename or {}).get(raw, raw)
        if name not in names:
            names.append(name)
        for ts, v in s["values"]:
            n = _num(v)
            row = rows.setdefault(int(float(ts) * 1000), {"t": int(float(ts) * 1000)})
            if n is not None:
                row[name] = round(row.get(name, 0) + n * scale, digits)
    out = [rows[k] for k in sorted(rows)]
    for row in out:  # every row carries every series so stacked charts line up
        for n in names:
            row.setdefault(n, 0)
    return out, names


def _parallel(**jobs):
    with ThreadPoolExecutor(max_workers=len(jobs)) as ex:
        futs = {k: ex.submit(f) for k, f in jobs.items()}
        return {k: f.result() for k, f in futs.items()}


def traffic(hours: float) -> dict:
    r = _rng(hours)
    res = _parallel(
        # route!="" drops unrouted hits (e.g. the portal's own data-plane health probe -> 404)
        total=lambda: _scalar(f'round(sum(increase(apisix_http_status{{route!=""}}[{r}])))'),
        errors_5xx=lambda: _scalar(
            f'round(sum(increase(apisix_http_status{{code=~"5..",route!=""}}[{r}])) or vector(0))'),
        blocked_403=lambda: _scalar(
            f'round(sum(increase(apisix_http_status{{code="403",route="{KIRO_CHAT_ROUTE}"}}[{r}])) or vector(0))'),
        limited_429=lambda: _scalar(
            f'round(sum(increase(apisix_http_status{{code="429",route!=""}}[{r}])) or vector(0))'),
        by_route=lambda: _prom_range('sum by (route) (rate(apisix_http_status{route!=""}[5m])) * 60', hours),
        by_code=lambda: _prom_range('sum by (code) (rate(apisix_http_status{route!=""}[5m])) * 60', hours),
        route_totals=lambda: _prom_instant(f'round(sum by (route) (increase(apisix_http_status{{route!=""}}[{r}])))'),
        code_totals=lambda: _prom_instant(f'round(sum by (code) (increase(apisix_http_status{{route!=""}}[{r}])))'),
        bandwidth=lambda: _prom_range("sum by (type) (rate(apisix_bandwidth[5m]))", hours),
    )
    by_route, routes = _pivot(res["by_route"], "route", rename=ROUTE_LABELS)
    by_code, codes = _pivot(res["by_code"], "code")
    bw, bw_types = _pivot(res["bandwidth"], "type", digits=0)
    return {
        "hours": hours,
        "totals": {k: res[k] for k in ("total", "errors_5xx", "blocked_403", "limited_429")},
        "per_minute_by_route": {"series": routes, "rows": by_route},
        "per_minute_by_code": {"series": sorted(codes), "rows": by_code},
        "bandwidth_bytes_per_s": {"series": bw_types, "rows": bw},
        "routes": sorted(({"route": ROUTE_LABELS.get(m["metric"].get("route"), m["metric"].get("route")),
                           "id": m["metric"].get("route"), "requests": _num(m["value"][1]) or 0}
                          for m in res["route_totals"]), key=lambda x: -x["requests"]),
        "codes": sorted(({"code": m["metric"].get("code"), "requests": _num(m["value"][1]) or 0}
                         for m in res["code_totals"]), key=lambda x: x["code"] or ""),
    }


def latency(hours: float) -> dict:
    r = _rng(hours)
    q = "histogram_quantile({p}, sum by (le{by}) (rate(apisix_http_latency_bucket{{{sel}}}[{w}])))"
    chat = f'type="request",route="{KIRO_CHAT_ROUTE}"'
    res = _parallel(
        chat_p50=lambda: _scalar(q.format(p=0.5, by="", sel=chat, w=r)),
        chat_p95=lambda: _scalar(q.format(p=0.95, by="", sel=chat, w=r)),
        overhead_p50=lambda: _scalar(q.format(p=0.5, by="", sel='type="apisix"', w=r)),
        overhead_p95=lambda: _scalar(q.format(p=0.95, by="", sel='type="apisix"', w=r)),
        upstream_p95=lambda: _scalar(q.format(p=0.95, by="", sel='type="upstream"', w=r)),
        p50_route=lambda: _prom_range(q.format(p=0.5, by=", route", sel='type="request",route!=""', w="15m"), hours),
        p95_route=lambda: _prom_range(q.format(p=0.95, by=", route", sel='type="request",route!=""', w="15m"), hours),
        split=lambda: _prom_range(q.format(p=0.95, by=", type", sel='type=~"upstream|apisix"', w="15m"), hours),
        table=lambda: _prom_instant(q.format(p=0.95, by=", route", sel='type="request",route!=""', w=r)),
        table50=lambda: _prom_instant(q.format(p=0.5, by=", route", sel='type="request",route!=""', w=r)),
        counts=lambda: _prom_instant(f'round(sum by (route) (increase(apisix_http_latency_count{{type="request",route!=""}}[{r}])))'),
    )
    p50, s50 = _pivot(res["p50_route"], "route", rename=ROUTE_LABELS, digits=1)
    p95, s95 = _pivot(res["p95_route"], "route", rename=ROUTE_LABELS, digits=1)
    split, ss = _pivot(res["split"], "type", rename={"upstream": "Upstream (Kiro / AWS)", "apisix": "Gateway"},
                       digits=1)
    by = {}
    for key in ("table50", "table", "counts"):
        for m in res[key]:
            rid = m["metric"].get("route")
            by.setdefault(rid, {"id": rid, "route": ROUTE_LABELS.get(rid, rid)})[
                {"table50": "p50", "table": "p95", "counts": "requests"}[key]] = _num(m["value"][1])
    return {
        "hours": hours,
        "kiro_chat_ms": {"p50": res["chat_p50"], "p95": res["chat_p95"]},
        "gateway_overhead_ms": {"p50": res["overhead_p50"], "p95": res["overhead_p95"]},
        "upstream_p95_ms": res["upstream_p95"],
        "p50_by_route": {"series": s50, "rows": p50},
        "p95_by_route": {"series": s95, "rows": p95},
        "p95_gateway_vs_upstream": {"series": ss, "rows": split},
        "routes": sorted(by.values(), key=lambda x: -(x.get("requests") or 0)),
    }


# ---- Loki ---------------------------------------------------------------------------------
def _loki_range(expr: str, hours: float) -> list[dict]:
    start, end, step = _window(hours)
    step = max(step, 300)
    q = urllib.parse.urlencode({"query": expr, "start": int(start * 1e9), "end": int(end * 1e9), "step": step})
    return _get(f"{LOKI}/loki/api/v1/query_range?{q}")["data"]["result"]


def _loki_instant(expr: str) -> list[dict]:
    q = urllib.parse.urlencode({"query": expr, "time": int(time.time() * 1e9)})
    return _get(f"{LOKI}/loki/api/v1/query?{q}")["data"]["result"]


def usage(hours: float) -> dict:
    r = _rng(hours)
    chat = 'kind="chat"'
    _s, _e, step = _window(hours)
    bucket = f"{max(step, 300) // 60}m"
    res = _parallel(
        by_path=lambda: _loki_range(f"sum by (path) (count_over_time({{{chat}}}[{bucket}]))", hours),
        per_user=lambda: _loki_instant(f"sum by (user, path) (count_over_time({{{chat}}} | json [{r}]))"),
        blocked_user=lambda: _loki_instant(
            f'sum by (user) (count_over_time({{{chat}, result="blocked"}} | json [{r}]))'),
        tokens=lambda: _prom_instant(
            f"sum by (consumer, llm_model) (increase(apisix_llm_prompt_tokens[{r}]))"),
        tokens_c=lambda: _prom_instant(
            f"sum by (consumer, llm_model) (increase(apisix_llm_completion_tokens[{r}]))"),
        tokens_t=lambda: _prom_range(
            "sum (increase(apisix_llm_prompt_tokens[15m])) + sum (increase(apisix_llm_completion_tokens[15m]))",
            hours),
    )
    by_path, paths = _pivot(res["by_path"], "path", rename={"kiro": "Kiro", "ai": "AI route"}, digits=0)
    blocked = {m["metric"].get("user", ""): int(float(m["value"][1])) for m in res["blocked_user"]}
    users: dict[str, dict] = {}
    for m in res["per_user"]:
        u = m["metric"].get("user") or "unknown"
        row = users.setdefault(u, {"user": u, "kiro": 0, "ai": 0, "blocked": blocked.get(u, 0)})
        row[m["metric"].get("path", "kiro")] = row.get(m["metric"].get("path", "kiro"), 0) + int(float(m["value"][1]))
    for row in users.values():
        row["total"] = row["kiro"] + row["ai"]
    tok: dict[tuple, dict] = {}
    for key, field in (("tokens", "prompt"), ("tokens_c", "completion")):
        for m in res[key]:
            k = (m["metric"].get("consumer", ""), m["metric"].get("llm_model", ""))
            tok.setdefault(k, {"consumer": k[0], "model": k[1], "prompt": 0, "completion": 0})[field] = round(
                _num(m["value"][1]) or 0)
    tok_rows, _ = _pivot([{"metric": {"k": "tokens"}, "values": s["values"]} for s in res["tokens_t"]], "k", digits=0)
    return {
        "hours": hours,
        "chats_by_path": {"series": paths, "rows": by_path},
        "kiro_chats": sum(u["kiro"] for u in users.values()),
        "ai_calls": sum(u["ai"] for u in users.values()),
        "active_users": len(users),
        "users": sorted(users.values(), key=lambda x: -x["total"])[:50],
        "ai_tokens": sum(t["prompt"] + t["completion"] for t in tok.values()),
        "tokens_by_consumer": sorted(tok.values(), key=lambda x: -(x["prompt"] + x["completion"])),
        "tokens_over_time": tok_rows,
    }


# ---- Tempo --------------------------------------------------------------------------------
_SEL = " | select(span.http.status_code, span.net.host.name, span.http.method)"
TRACE_FILTERS = {
    "chat": '{resource.service.name="kiro-gateway" && span.net.host.name != "apisix" && name =~ "POST.*" && nestedSetParent < 0}' + _SEL,
    "all": '{resource.service.name="kiro-gateway" && span.net.host.name != "apisix" && nestedSetParent < 0}' + _SEL,
    "slow": '{resource.service.name="kiro-gateway" && span.net.host.name != "apisix" && nestedSetParent < 0 && duration > 1s}' + _SEL,
    "errors": '{resource.service.name="kiro-gateway" && span.net.host.name != "apisix" && span.http.status_code >= 400}' + _SEL,
}


def _attrs(lst) -> dict:
    out = {}
    for a in lst or []:
        v = a.get("value", {})
        out[a["key"]] = next(iter(v.values()), None) if v else None
    return out


def traces(hours: float, kind: str, limit: int) -> dict:
    end = int(time.time())
    q = urllib.parse.urlencode({"q": TRACE_FILTERS[kind], "limit": limit, "start": int(end - hours * 3600),
                                "end": end, "spss": 1})
    data = _get(f"{TEMPO}/api/search?{q}")
    out = []
    for t in data.get("traces", []):
        span = ((t.get("spanSet") or {}).get("spans") or [{}])[0]
        a = _attrs(span.get("attributes"))
        code = a.get("http.status_code")
        out.append({"trace_id": t["traceID"].rjust(32, "0"), "name": t.get("rootTraceName", ""),
                    "start_ms": int(int(t.get("startTimeUnixNano", 0)) / 1e6),
                    "duration_ms": t.get("durationMs", 0),
                    "host": a.get("net.host.name") or "", "method": a.get("http.method") or "",
                    "status": int(code) if str(code or "").isdigit() else None})
    out.sort(key=lambda x: -x["start_ms"])
    return {"hours": hours, "kind": kind, "traces": out}


def _hex(b64: str) -> str:
    return base64.b64decode(b64).hex() if b64 else ""


def trace(trace_id: str) -> dict:
    if not TRACE_ID.match(trace_id):
        raise ValueError("invalid trace id")
    data = _get(f"{TEMPO}/api/v2/traces/{trace_id}")
    spans = []
    for rs in data.get("trace", {}).get("resourceSpans", []):
        for ss in rs.get("scopeSpans", []):
            for s in ss.get("spans", []):
                spans.append({
                    "id": _hex(s.get("spanId", "")), "parent": _hex(s.get("parentSpanId", "")),
                    "name": s.get("name", ""), "kind": s.get("kind", "").replace("SPAN_KIND_", "").lower(),
                    "start_ns": int(s.get("startTimeUnixNano", 0)), "end_ns": int(s.get("endTimeUnixNano", 0)),
                    "status": (s.get("status") or {}).get("code", "").replace("STATUS_CODE_", "").lower(),
                    "attributes": {k: v for k, v in _attrs(s.get("attributes")).items()
                                   if not re.search(r"auth|token|cookie|key", k, re.I)},
                })
    if not spans:
        raise LookupError("not found")
    t0 = min(s["start_ns"] for s in spans)
    t1 = max(s["end_ns"] for s in spans)
    for s in spans:
        s["offset_ms"] = round((s.pop("start_ns") - t0) / 1e6, 3)
        s["duration_ms"] = round((s.pop("end_ns") - t0) / 1e6 - s["offset_ms"], 3)
    spans.sort(key=lambda s: s["offset_ms"])
    root = next((s for s in spans if not s["parent"] or s["parent"] not in {x["id"] for x in spans}), spans[0])
    return {"trace_id": trace_id, "duration_ms": round((t1 - t0) / 1e6, 3), "root": root["name"],
            "attributes": root["attributes"], "spans": spans}

#!/usr/bin/env python3
"""Generate the Kiro Gateway Grafana dashboards (dashboards are code; run after editing).

    python3 monitoring/grafana/build_dashboards.py

Writes monitoring/grafana/dashboards/*.json, which Grafana provisions read-only.
Data: Prometheus (APISIX metrics), Loki (audit log via OTel Collector), Tempo (traces).
Loki labels: path (kiro|ai), result (allowed|blocked|rate_limited|error), rule, kind (chat|background).
Structured metadata: user, trace_id, op, status_code.
"""
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent / "dashboards"
PROM = {"type": "prometheus", "uid": "prometheus"}
LOKI = {"type": "loki", "uid": "loki"}
TEMPO = {"type": "tempo", "uid": "tempo"}
CHAT = 'kind="chat"'
_id = 0


def nid():
    global _id
    _id += 1
    return _id


def target(ds, expr, legend="", instant=False, ref="A", **kw):
    t = {"datasource": ds, "refId": ref, "expr": expr, "legendFormat": legend}
    if ds is LOKI:
        t["queryType"] = "instant" if instant else "range"
    elif instant:
        t["instant"], t["range"] = True, False
    t.update(kw)
    return t


def panel(kind, title, x, y, w, h, targets, desc="", unit=None, options=None, field=None, ds=PROM):
    p = {"id": nid(), "type": kind, "title": title, "description": desc, "datasource": ds,
         "gridPos": {"x": x, "y": y, "w": w, "h": h}, "targets": targets,
         "fieldConfig": {"defaults": dict(field or {}), "overrides": []}, "options": options or {}}
    if unit:
        p["fieldConfig"]["defaults"]["unit"] = unit
    return p


def stat(title, x, y, expr, ds=PROM, unit=None, color="blue", desc="", w=6, thresholds=False):
    field = {"color": {"mode": "thresholds"}, "thresholds": {"mode": "absolute", "steps": [
        {"color": "green", "value": None}, {"color": color, "value": 1}]}} if thresholds else \
        {"color": {"mode": "fixed", "fixedColor": color}}
    return panel("stat", title, x, y, w, 4, [target(ds, expr, instant=True)], desc, unit, ds=ds,
                 options={"reduceOptions": {"calcs": ["lastNotNull"]}, "colorMode": "background",
                          "graphMode": "none", "textMode": "value"},
                 field=field)


def ts(title, x, y, w, h, targets, ds=PROM, unit=None, desc="", stack=False, bars=False):
    custom = {"drawStyle": "bars" if bars else "line", "fillOpacity": 60 if bars else 15,
              "lineWidth": 1 if bars else 2, "showPoints": "never",
              "stacking": {"mode": "normal" if stack else "none"}}
    p = panel("timeseries", title, x, y, w, h, targets, desc, unit, ds=ds,
              options={"legend": {"displayMode": "list", "placement": "bottom"},
                       "tooltip": {"mode": "multi"}}, field={"custom": custom})
    # Same colours everywhere: allowed green, blocked red, rate limited orange, errors purple.
    p["fieldConfig"]["overrides"] = [
        {"matcher": {"id": "byName", "options": n},
         "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": c}}]}
        for n, c in (("allowed", "green"), ("blocked", "red"), ("rate_limited", "orange"), ("error", "purple"))]
    return p


# Kiro wraps the user's text in injected context; show only the user's words in log panels.
USER_TEXT = ('{{ regexReplaceAll "\\\\s*--- USER MESSAGE END ---[\\\\s\\\\S]*$" '
             '(regexReplaceAll "^[\\\\s\\\\S]*--- USER MESSAGE BEGIN ---\\\\s*" .prompt "") "" }}')


def bars(title, x, y, w, h, expr, label, ds=LOKI, desc="", color="red"):
    return panel("barchart", title, x, y, w, h, [target(ds, expr, legend="{{%s}}" % label, instant=True)],
                 desc, ds=ds, field={"color": {"mode": "fixed", "fixedColor": color}},
                 options={"orientation": "horizontal", "xField": label, "showValue": "always",
                          "legend": {"showLegend": False}, "barWidth": 0.7})


def table(title, x, y, w, h, targets, ds, desc="", options=None, value_name="Count"):
    p = panel("table", title, x, y, w, h, targets, desc, ds=ds, options=options or {"showHeader": True})
    if ds is TEMPO:     # hide the raw span sub-table column; the Trace ID link opens the full trace
        p["transformations"] = [{"id": "organize", "options": {"excludeByName": {"nested": True}}}]
    else:   # instant series -> one row per label set, value column renamed, sorted descending
        p["transformations"] = [
            {"id": "merge", "options": {}},
            {"id": "organize", "options": {"excludeByName": {"Time": True},
                                           "renameByName": {"Value #A": value_name, "Value": value_name}}},
            {"id": "sortBy", "options": {"sort": [{"field": value_name, "desc": True}]}}]
    return p


def logs(title, x, y, w, h, expr, desc=""):
    return panel("logs", title, x, y, w, h, [target(LOKI, expr)], desc, ds=LOKI,
                 options={"showTime": True, "wrapLogMessage": True, "enableLogDetails": True,
                          "sortOrder": "Descending", "dedupStrategy": "none"})


def text(title, x, y, w, h, md):
    return {"id": nid(), "type": "text", "title": title, "gridPos": {"x": x, "y": y, "w": w, "h": h},
            "options": {"mode": "markdown", "content": md}}


def dashboard(uid, title, panels, desc, variables=(), refresh="30s", time_from="now-24h"):
    return {"uid": uid, "title": title, "description": desc, "tags": ["kiro-gateway"],
            "timezone": "browser", "schemaVersion": 39, "editable": False, "refresh": refresh,
            "time": {"from": time_from, "to": "now"}, "panels": panels,
            "templating": {"list": list(variables)},
            "links": [{"title": "Kiro Gateway", "type": "dashboards", "tags": ["kiro-gateway"], "asDropdown": True},
                      {"title": "Guardrail Console", "type": "link", "url": "/", "targetBlank": False}]}


def var_loki_label(name, label, query_filter=CHAT):
    return {"name": name, "label": name.title(), "type": "query", "datasource": LOKI, "refresh": 2,
            "query": {"label": label, "stream": "{%s}" % query_filter, "type": 1},
            "includeAll": True, "multi": True, "allValue": ".+", "current": {"text": "All", "value": "$__all"}}


def var_text(name, label):
    return {"name": name, "label": label, "type": "textbox", "query": "", "current": {"text": "", "value": ""}}


# ---------------------------------------------------------------- 1. Gateway overview
def gateway():
    req = 'sum by (route) (rate(apisix_http_status{route!=""}[$__rate_interval]))'
    p = [
        stat("Requests (range)", 0, 0, "round(sum(increase(apisix_http_status[$__range])))", color="blue"),
        stat("5xx errors (range)", 6, 0, 'round(sum(increase(apisix_http_status{code=~"5.."}[$__range])) or vector(0))', color="red", thresholds=True),
        stat("Kiro chat p95 latency", 12, 0,
             'histogram_quantile(0.95, sum by (le) (rate(apisix_http_latency_bucket{type="request",route="runtime.us-east-1.kiro.dev"}[$__range])))',
             unit="ms", color="purple", desc="End-to-end Kiro inference latency at the gateway, 95th percentile."),
        stat("Gateway overhead p95", 18, 0,
             'histogram_quantile(0.95, sum by (le) (rate(apisix_http_latency_bucket{type="apisix"}[$__range])))',
             unit="ms", color="green", desc="Time APISIX itself adds (guardrails, routing), excluding upstream."),
        ts("Request rate by route", 0, 4, 12, 8, [target(PROM, req, "{{route}}")], unit="reqps"),
        ts("Responses by status code", 12, 4, 12, 8,
           [target(PROM, 'sum by (code) (rate(apisix_http_status[$__rate_interval]))', "{{code}}")],
           unit="reqps", stack=True, desc="403 on runtime.* = guardrail block; 429 = rate limited; 499 = client closed (Kiro telemetry)."),
        ts("Latency p50 / p95 by route (request)", 0, 12, 12, 8, [
            target(PROM, 'histogram_quantile(0.50, sum by (le, route) (rate(apisix_http_latency_bucket{type="request",route!=""}[$__rate_interval])))', "p50 {{route}}", ref="A"),
            target(PROM, 'histogram_quantile(0.95, sum by (le, route) (rate(apisix_http_latency_bucket{type="request",route!=""}[$__rate_interval])))', "p95 {{route}}", ref="B")],
           unit="ms"),
        ts("Upstream vs gateway latency (p95)", 12, 12, 12, 8, [
            target(PROM, 'histogram_quantile(0.95, sum by (le, type) (rate(apisix_http_latency_bucket{type=~"upstream|apisix"}[$__rate_interval])))', "{{type}}")],
           unit="ms", desc="upstream = Kiro/AWS backend; apisix = time spent in the gateway."),
        ts("Bandwidth", 0, 20, 24, 7, [
            target(PROM, 'sum by (type) (rate(apisix_bandwidth[$__rate_interval]))', "{{type}}")], unit="Bps"),
    ]
    return dashboard("kiro-gateway-overview", "1 · Gateway overview", p,
                     "Traffic, errors, latency and bandwidth for all routes (Prometheus).", time_from="now-3h")


# ---------------------------------------------------------------- 2. Guardrails
def guardrails():
    blocked = '{%s, result="blocked"}' % CHAT
    p = [
        stat("Chats checked", 0, 0, 'sum(count_over_time({%s}[$__range]))' % CHAT, LOKI, color="blue"),
        stat("Blocked", 6, 0, 'sum(count_over_time(%s[$__range])) or vector(0)' % blocked, LOKI, color="red"),
        stat("PII / secret blocks", 12, 0,
             'sum(count_over_time({%s, result="blocked", rule=~"pii-.*|secret-.*|aws-.*|bedrock:pii:.*|bedrock:regex:.*"}[$__range])) or vector(0)' % CHAT,
             LOKI, color="orange", desc="Blocks by the PII and secret rules (email, ID, card, phone, SSN, keys) and by Bedrock Guardrails PII detection (names, addresses, ...)."),
        stat("Block rate", 18, 0,
             'sum(count_over_time(%s[$__range])) / sum(count_over_time({%s}[$__range]))' % (blocked, CHAT),
             LOKI, unit="percentunit", color="purple"),
        ts("Allowed vs blocked over time", 0, 4, 14, 8,
           [target(LOKI, 'sum by (result) (count_over_time({%s}[$__auto]))' % CHAT, "{{result}}")],
           LOKI, bars=True, stack=True),
        bars("Blocks by rule", 14, 4, 10, 8, 'sum by (rule) (count_over_time(%s[$__range]))' % blocked, "rule"),
        bars("Blocks by path", 0, 12, 7, 6, 'sum by (path) (count_over_time(%s[$__range]))' % blocked, "path",
             color="orange", desc="kiro = Kiro CLI/IDE; ai = /v1/chat/completions"),
        bars("Users with most blocks", 7, 12, 17, 6,
             'topk(10, sum by (user) (count_over_time(%s[$__range])))' % blocked, "user", color="purple",
             desc="Kiro users are a hash of their token (rotates on refresh); AI route users are consumer names."),
        logs("Recent blocked prompts", 0, 18, 24, 12,
             '%s | json | line_format `[{{.rule}}] {{.user}} · %s`' % (blocked, USER_TEXT),
             "Kiro prompts (only the user's words). AI route prompts are not stored. Expand a line for trace_id → Tempo."),
    ]
    return dashboard("kiro-gateway-guardrails", "2 · Guardrails", p,
                     "What the guardrail rules allowed and blocked (Loki, from the APISIX audit log).")


# ---------------------------------------------------------------- 3. Usage
def usage():
    p = [
        stat("Kiro chats", 0, 0, 'sum(count_over_time({path="kiro", %s}[$__range]))' % CHAT, LOKI, color="blue"),
        stat("AI route calls", 6, 0, 'sum(count_over_time({path="ai", %s}[$__range]))' % CHAT, LOKI, color="green"),
        stat("Active users", 12, 0, 'count(sum by (user) (count_over_time({%s}[$__range])))' % CHAT, LOKI, color="purple"),
        stat("AI tokens", 18, 0,
             'sum(increase(apisix_llm_prompt_tokens[$__range])) + sum(increase(apisix_llm_completion_tokens[$__range]))',
             color="orange", desc="Prompt + completion tokens on the OpenAI-compatible route. Kiro traffic has no token data."),
        ts("Chats over time by path", 0, 4, 12, 8,
           [target(LOKI, 'sum by (path) (count_over_time({%s}[$__auto]))' % CHAT, "{{path}}")], LOKI, bars=True, stack=True),
        ts("AI tokens over time by consumer", 12, 4, 12, 8, [
            target(PROM, 'sum by (consumer) (increase(apisix_llm_prompt_tokens[$__rate_interval]))', "prompt {{consumer}}", ref="A"),
            target(PROM, 'sum by (consumer) (increase(apisix_llm_completion_tokens[$__rate_interval]))', "completion {{consumer}}", ref="B")],
           unit="short"),
        table("Chats per user", 0, 12, 12, 10,
              [target(LOKI, 'sum by (user) (count_over_time({%s}[$__range]))' % CHAT, "{{user}}", instant=True)], LOKI,
              value_name="Chats"),
        table("AI tokens per consumer and model", 12, 12, 12, 10, [
            target(PROM, 'sum by (consumer, llm_model) (increase(apisix_llm_prompt_tokens[$__range]) + increase(apisix_llm_completion_tokens[$__range]))',
                   "{{consumer}} · {{llm_model}}", instant=True, format="table")], PROM, value_name="Tokens"),
    ]
    return dashboard("kiro-gateway-usage", "3 · Usage", p, "Who uses Kiro and the AI route, and how much.")


# ---------------------------------------------------------------- 4. Logs & traces
def logs_traces():
    sel = '{kind=~"$kind", path=~"$path", result=~"$result", rule=~"$rule"}'
    p = [
        text("How to use", 0, 0, 24, 3,
             "Filter with the variables above, or type text into **Search** (matches prompt, user, rule). "
             "Expand a log line and click **Open trace** to see the request in Tempo. "
             "Traces → logs works the other way from the trace view."),
        ts("Matching events", 0, 3, 24, 6,
           [target(LOKI, 'sum by (result) (count_over_time(%s |= "$search" [$__auto]))' % sel, "{{result}}")],
           LOKI, bars=True, stack=True),
        logs("Audit log", 0, 9, 24, 14,
             '%s |= "$search" | json | line_format `{{.status}} {{.host}}{{.uri}} [{{.rule}}] {{.user}} · %s`' % (sel, USER_TEXT)),
        table("Recent traces (Tempo)", 0, 23, 24, 9, [{
            "datasource": TEMPO, "refId": "A", "queryType": "traceql", "limit": 50,
            "query": '{resource.service.name="kiro-gateway" && name =~ "POST.*"}'}], TEMPO,
            desc="Chat/API requests (POST). Click a Trace ID to open the span breakdown (access phase, upstream, response streaming)."),
    ]
    vars_ = [
        var_loki_label("path", "path", 'kind=~".+"'), var_loki_label("result", "result", 'kind=~".+"'),
        var_loki_label("rule", "rule", 'kind=~".+"'), var_loki_label("kind", "kind", 'kind=~".+"'),
        var_text("search", "Search"),
    ]
    vars_[3]["current"] = {"text": "chat", "value": "chat"}
    return dashboard("kiro-gateway-logs", "4 · Logs & traces", p, "Search the audit log and jump to traces.",
                     variables=vars_, refresh="10s", time_from="now-6h")


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    for d in (gateway(), guardrails(), usage(), logs_traces()):
        path = OUT / f"{d['uid']}.json"
        path.write_text(json.dumps(d, indent=2) + "\n")
        print(f"wrote {path.relative_to(OUT.parent.parent.parent)}  ({len(d['panels'])} panels)")

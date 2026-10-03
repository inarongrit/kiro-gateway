#!/usr/bin/env python3
"""End-to-end monitoring check: fresh traffic -> Prometheus, Loki, Tempo, Grafana panels.

    python3 monitoring/tests/monitoring_check.py

Sends tagged kiro-cli prompts (allowed, demo block, PII) and AI route calls, then verifies that
every signal shows THOSE requests (not just older history), and that every Grafana panel returns
data for the last 15 minutes. Exit code = number of failures.
"""
import glob, http.cookiejar, json, os, random, ssl, subprocess, sys, time, urllib.parse, urllib.request
from pathlib import Path

GW = Path(__file__).resolve().parents[2]
os.chdir(GW)
B, CA = "https://127.0.0.1:9180", str(GW / "pki/ca.crt")
TAG = f"mon-{random.randint(10000, 99999)}"
fails = 0


def ok(cond, msg):
    global fails
    print(("PASS  " if cond else "FAIL  ") + msg)
    fails += 0 if cond else 1


def sh(cmd, **kw):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, **kw)


def internal(url):  # query a service on the Docker network (none have published ports)
    r = sh(f"docker run --rm --network kiro-gateway_gw curlimages/curl:8.10.1 -s -H 'Accept: application/json' {json.dumps(url)}")
    return json.loads(r.stdout or "null")


# ---- 1. traffic ----------------------------------------------------------------------------
t0 = time.time()
scratch = os.environ.get("KIROCREW_SCRATCH") or os.environ.get("TMPDIR") or "/tmp"
prompts = {"allowed": f"Reply with exactly: OK {TAG}",
           "demo-keyword": f"{TAG} KIRO-GATEWAY-BLOCK-DEMO",
           "pii-email": f"{TAG} send it to somchai.j@example.co.th",
           "pii-credit-card": f"{TAG} my card is 4111 1111 1111 1111"}
for name, p in prompts.items():
    r = sh(f"{GW}/scripts/kiro-via-gateway run kiro-cli chat --no-interactive --trust-tools= {json.dumps(p)}", cwd=scratch)
    out = (r.stdout + r.stderr).strip().splitlines()[-1:] or [""]
    expect_block = name != "allowed"
    ok(("Blocked by organization" in out[0]) == expect_block, f"kiro-cli {name}: {'blocked' if expect_block else 'allowed'} ({out[0][:70]})")
for p in (f"hello {TAG}", f"{TAG} key AKIAABCDEFGHIJKLMNOP"):
    sh(f"{GW}/scripts/ai-demo.sh {json.dumps(p)}")
print(f"traffic sent (tag {TAG}); waiting for ingestion...")
time.sleep(25)

# ---- 2. Loki: our tagged lines, labelled, with trace ids ------------------------------------
q = urllib.parse.urlencode({"query": '{kind="chat"} |= "%s"' % TAG, "start": f"{int(t0 - 5)}000000000", "limit": 50})
res = internal(f"http://loki:3100/loki/api/v1/query_range?{q}")
streams = res["data"]["result"] if res else []
seen = {(s["stream"].get("result"), s["stream"].get("rule")) for s in streams for _ in s["values"]}
for want in [("allowed", "none"), ("blocked", "demo-keyword"), ("blocked", "pii-email"), ("blocked", "pii-credit-card")]:
    ok(want in seen, f"Loki has tagged Kiro chat result={want[0]} rule={want[1]}")
traces = [s["stream"].get("trace_id") for s in streams if s["stream"].get("path") == "kiro"]
ok(len(traces) >= 4 and all(t and len(t) == 32 for t in traces), f"Loki lines carry trace_id ({len(traces)} Kiro lines)")
prompts_in_loki = " ".join(v[1] for s in streams for v in s["values"])
for raw, what in (("4111 1111 1111 1111", "card number"), ("somchai.j@example.co.th", "email address")):
    ok(raw not in prompts_in_loki, f"Loki does NOT contain the blocked {what} in clear text (masked by the guard)")
ok("41***************11" in prompts_in_loki, "Loki keeps the masked preview of the blocked card number")

# ---- 3. Tempo: the trace behind each tagged line exists -------------------------------------
found = 0
for tid in traces:
    t = internal(f"http://tempo:3200/api/traces/{tid}")
    spans = [sp for b in (t or {}).get("batches", []) for ss in b.get("scopeSpans", []) for sp in ss.get("spans", [])]
    found += bool(spans)
ok(found == len(traces) and found > 0, f"Tempo has the trace for every tagged Kiro line ({found}/{len(traces)})")

# ---- 4. Prometheus: counters moved during the test ------------------------------------------
def prom(expr, at=None):
    q = {"query": expr, **({"time": f"{at:.3f}"} if at else {})}
    r = internal("http://prometheus:9090/api/v1/query?" + urllib.parse.urlencode(q))
    return float(r["data"]["result"][0]["value"][1]) if r and r["data"]["result"] else 0.0
def grew(counter):
    # Counter value now minus before the test. Unlike increase(), this also counts a series that
    # did not exist yet when the test started (first scrape of a fresh stack starts at its value).
    return prom(f"sum({counter})") - prom(f"sum({counter})", at=t0 - 1)
time.sleep(16)   # one more scrape interval so the last requests are in
ok(grew('apisix_http_status{route="runtime.us-east-1.kiro.dev",code="403"}') >= 2.5,
   "Prometheus: Kiro 403 (blocks) counted during the test")
ok(grew('apisix_http_status{route="runtime.us-east-1.kiro.dev",code="200"}') >= 0.9,
   "Prometheus: Kiro 200 (allowed chat) counted during the test")
ok(grew("apisix_llm_completion_tokens") > 0, "Prometheus: AI route tokens counted during the test")

# ---- 5. Grafana: every panel returns data for the last 15 minutes, via the console ----------
ctx = ssl.create_default_context(cafile=CA)
op = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def api(path, body=None):
    r = urllib.request.Request(B + path, data=json.dumps(body).encode() if body is not None else None,
                               headers={"Content-Type": "application/json", "X-Console": "1"})
    with op.open(r, timeout=60) as x:
        return json.loads(x.read() or b"null")
api("/api/login", {"username": "admin", "password": (GW / "pki/console-initial-password").read_text().strip()})
now = int(time.time() * 1000); frm = now - 15 * 60 * 1000
subst = {"$__rate_interval": "1m", "$__range": "15m", "$__auto": "1m", "$search": "", "$path": ".+",
         "$result": ".+", "$rule": ".+", "$kind": "chat"}
for f in sorted(glob.glob("monitoring/grafana/dashboards/*.json")):
    d = json.load(open(f))
    for p in d["panels"]:
        for t in p.get("targets", []):
            q = dict(t, intervalMs=15000, maxDataPoints=300)
            if "expr" in q:
                for k, v in subst.items():
                    q["expr"] = q["expr"].replace(k, v)
            r = list(api("/grafana/api/ds/query", {"from": str(frm), "to": str(now), "queries": [q]})["results"].values())[0]
            rows = sum(len((fr.get("data", {}).get("values") or [[]])[0]) for fr in r.get("frames", []))
            ok(not r.get("error") and rows > 0, f"Grafana [{d['title']}] {p['title']} ({rows} points, last 15 min)"
               + (f" error={r['error'][:80]}" if r.get("error") else ""))

print(f"\n{'ALL MONITORING CHECKS PASSED' if fails == 0 else f'{fails} MONITORING CHECK(S) FAILED'}")
sys.exit(fails)

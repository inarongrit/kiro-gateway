"""Guardrail Console API. Served over HTTPS by uvicorn; see console/Dockerfile."""
from __future__ import annotations

import os
import ssl
import urllib.request
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from . import audit, auth, observe, rules

app = FastAPI(title="Guardrail Console", docs_url=None, redoc_url=None, openapi_url=None)
WEB = Path(__file__).resolve().parent.parent / "web"


@app.middleware("http")
async def guard(request: Request, call_next):
    try:
        auth.check_source(request)                     # IP allowlist on every request
    except HTTPException as e:
        return JSONResponse({"detail": e.detail}, status_code=e.status_code)
    resp: Response = await call_next(request)
    if request.url.path.startswith(("/ui", "/grafana")):
        # APISIX dashboard (React + antd + Monaco) and Grafana need inline styles/scripts and blob: workers.
        csp = ("default-src 'self'; img-src 'self' data: blob:; font-src 'self' data:; "
               "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval' blob:; "
               "worker-src 'self' blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'")
    else:
        csp = ("default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
               "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
    resp.headers["Content-Security-Policy"] = csp
    resp.headers.update({
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
    })
    if not request.url.path.startswith(("/ui/assets/", "/grafana/public/")):
        resp.headers.setdefault("Cache-Control", "no-store")
    return resp


def user(request: Request) -> str:
    return auth.current_user(request)


def mutating(request: Request) -> str:
    auth.require_csrf(request)
    return auth.current_user(request)


# ---- auth -------------------------------------------------------------------------------
class LoginIn(BaseModel):
    username: str = Field(max_length=100)
    password: str = Field(max_length=500)


@app.post("/api/login")
def login(body: LoginIn, request: Request, response: Response):
    auth.require_csrf(request)
    token = auth.login(request, body.username, body.password)
    response.set_cookie(auth.COOKIE, token, max_age=auth.SESSION_TTL, secure=True,
                        httponly=True, samesite="strict", path="/")
    return {"user": body.username}


@app.post("/api/logout")
def logout(request: Request, response: Response, _: str = Depends(mutating)):
    auth.logout(request.cookies.get(auth.COOKIE))
    response.delete_cookie(auth.COOKIE, path="/")
    return {"ok": True}


@app.get("/api/me")
def me(u: str = Depends(user)):
    return {"user": u}


@app.get("/api/health")
def health():
    return {"ok": True}


# ---- rules ------------------------------------------------------------------------------
class SaveIn(rules.Config):
    base_version: str


@app.get("/api/guardrails")
def get_guardrails(_: str = Depends(user)):
    data, ver = rules.load()
    return {"config": data, "version": ver}


@app.put("/api/guardrails")
def put_guardrails(body: SaveIn, request: Request, u: str = Depends(mutating)):
    cfg = rules.Config(**body.model_dump(exclude={"base_version"}))
    try:
        data, ver, commit = rules.save(cfg, body.base_version, u, auth.client_ip(request))
    except rules.ConflictError as e:
        raise HTTPException(409, str(e)) from e
    except rules.ValidationFailed as e:
        raise HTTPException(422, str(e)) from e
    except rules.ApplyFailed as e:
        raise HTTPException(502, f"Gateway rejected the change, nothing was saved. {e}") from e
    return {"config": data, "version": ver, "commit": commit}


class CheckIn(BaseModel):
    pattern: str = Field(min_length=1, max_length=1000)


@app.post("/api/check-pattern")
def check_pattern(body: CheckIn, _: str = Depends(mutating)):
    err = rules.pcre_error(body.pattern)
    return {"valid": err is None, "error": err}


class TestIn(BaseModel):
    text: str = Field(min_length=1, max_length=20000)
    path: Literal["kiro", "ai"] = "kiro"


@app.post("/api/test-prompt")
def test_prompt(body: TestIn, _: str = Depends(mutating)):
    data, _v = rules.load()
    return rules.test_prompt(data, body.text, body.path)


@app.get("/api/history")
def history(_: str = Depends(user)):
    return {"changes": rules.history()}


# ---- audit ------------------------------------------------------------------------------
@app.get("/api/events")
def events(_: str = Depends(user), q: str = Query("", max_length=200),
           result: Literal["", "allowed", "blocked", "rate_limited", "error"] = "",
           path: Literal["", "kiro", "ai"] = "", hours: float = Query(24, gt=0, le=24 * 31),
           all_ops: bool = False, limit: int = Query(200, ge=1, le=1000)):
    return {"events": audit.search(q, result, path, not all_ops, hours, limit)}


@app.get("/api/stats")
def stats(_: str = Depends(user), hours: float = Query(24, gt=0, le=24 * 31)):
    data, _v = rules.load()
    g = data["guardrails"]
    s = audit.stats(hours)
    s["protections_on"] = sum(1 for v in g.values() if v["enabled"])
    s["protections_total"] = len(g)
    s["rules_enabled"] = sum(1 for r in data["rules"] if r["enabled"])
    return s


@app.get("/api/status")
def status(_: str = Depends(user)):
    """Gateway health as seen from the console: data plane up + Admin API reachable."""
    ctx = ssl.create_default_context(cafile=os.environ.get("GW_CA", "/etc/kiro-gateway/ca.crt"))
    out = {}
    for name, url, kw in (
        ("data_plane", "http://apisix:9080/", {}),
        ("admin_api", os.environ.get("APISIX_ADMIN_URL", "https://apisix:9180") + "/apisix/admin/routes",
         {"context": ctx}),
    ):
        req = urllib.request.Request(url, headers={"X-API-KEY": os.environ.get("APISIX_ADMIN_KEY", "")}
                                     if name == "admin_api" else {})
        try:
            with urllib.request.urlopen(req, timeout=3, **kw) as r:
                out[name] = r.status < 500
        except urllib.error.HTTPError as e:
            out[name] = e.code == 404 if name == "data_plane" else False
        except Exception:
            out[name] = False
    return {"healthy": all(out.values()), **out}


# ---- observability (Prometheus / Loki / Tempo, fixed server-side queries) -----------------
def _obs(fn, *a):
    try:
        return fn(*a)
    except observe.BackendError as e:
        raise HTTPException(503, f"Monitoring backend unavailable: {e}") from e
    except LookupError:
        raise HTTPException(404, "Not found (it may have aged out of retention)") from None
    except ValueError as e:
        raise HTTPException(422, str(e)) from e


Hours = Query(24, gt=0, le=24 * 15)  # Prometheus retention is 15 days


@app.get("/api/obs/traffic")
def obs_traffic(_: str = Depends(user), hours: float = Hours):
    return _obs(observe.traffic, hours)


@app.get("/api/obs/latency")
def obs_latency(_: str = Depends(user), hours: float = Hours):
    return _obs(observe.latency, hours)


@app.get("/api/obs/usage")
def obs_usage(_: str = Depends(user), hours: float = Hours):
    return _obs(observe.usage, hours)


@app.get("/api/obs/traces")
def obs_traces(_: str = Depends(user), hours: float = Query(1, gt=0, le=24 * 7),
               kind: Literal["chat", "all", "slow", "errors"] = "chat", limit: int = Query(50, ge=1, le=200)):
    return _obs(observe.traces, hours, kind, limit)


@app.get("/api/obs/traces/{trace_id}")
def obs_trace(trace_id: str, _: str = Depends(user)):
    return _obs(observe.trace, trace_id.lower())


# ---- APISIX dashboard + Admin API behind the console login ------------------------------
# The embedded APISIX dashboard (/ui/) and the Admin API it calls (/apisix/admin/) are proxied
# to APISIX inside the Docker network, so the Admin API is never exposed on its own. A console
# session is required; the dashboard still asks for the APISIX admin key on top of that.
ADMIN_UPSTREAM = os.environ.get("APISIX_ADMIN_URL", "https://apisix:9180")
_PROXY_CTX = ssl.create_default_context(cafile=os.environ.get("GW_CA", "/etc/kiro-gateway/ca.crt"))
_FWD_REQ = ("x-api-key", "content-type", "accept", "accept-language", "if-none-match", "if-modified-since")
_FWD_RESP = ("content-type", "cache-control", "etag", "last-modified", "location")
# CONSOLE_ADMIN_KEY_FROM_SESSION=0 restores the old behaviour (browser must also supply the key).
ADMIN_KEY_FROM_SESSION = os.environ.get("CONSOLE_ADMIN_KEY_FROM_SESSION", "1") == "1"


def _same_origin(request: Request) -> bool:
    origin = request.headers.get("origin")
    if origin:
        return origin.split("://", 1)[-1] == request.headers.get("host", "")
    return request.headers.get("sec-fetch-site", "same-origin") in ("same-origin", "none")


def _upstream(method: str, path: str, query: str, headers: dict, body: bytes, base: str = None):
    url = f"{base or ADMIN_UPSTREAM}{path}" + (f"?{query}" if query else "")
    req = urllib.request.Request(url, data=body or None, method=method, headers=headers)

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):            # hand redirects back to the browser
            return None
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=_PROXY_CTX), NoRedirect)
    try:
        with opener.open(req, timeout=60) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


# ---- Grafana behind the console login ---------------------------------------------------
# Grafana runs with auth.proxy and trusts X-WEBAUTH-USER only from this container's IP.
# The browser's own cookies and any client-sent X-WEBAUTH-* header are never forwarded.
GRAFANA_UPSTREAM = os.environ.get("GRAFANA_URL", "http://grafana:3000")
_GF_FWD_REQ = _FWD_REQ + ("x-grafana-org-id", "x-grafana-device-id", "x-dashboard-uid", "x-datasource-uid",
                          "x-panel-id", "x-plugin-id", "x-query-group-id", "x-grafana-nocache", "x-cache-skip")


@app.api_route("/grafana", methods=["GET"])
@app.api_route("/grafana/{rest:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def grafana_proxy(request: Request, rest: str = ""):
    try:
        u = auth.current_user(request)
    except HTTPException:
        if request.method == "GET" and "text/html" in request.headers.get("accept", ""):
            return Response(status_code=302, headers={"Location": "/?next=grafana"})
        raise
    if request.method != "GET" and not _same_origin(request):
        raise HTTPException(403, "Cross-origin request refused")
    headers = {k: v for k, v in request.headers.items() if k.lower() in _GF_FWD_REQ}
    headers["X-WEBAUTH-USER"] = u
    path = request.url.path if request.url.path != "/grafana" else "/grafana/"
    status, rh, data = await run_in_threadpool(_upstream, request.method, path, request.url.query,
                                               headers, await request.body(), GRAFANA_UPSTREAM)
    out = {k: v for k, v in rh.items() if k.lower() in _FWD_RESP}
    loc = out.get("Location") or out.get("location")
    if loc and "://" in loc:                             # Grafana builds absolute URLs from its own host
        out.pop("Location", None)
        out.pop("location", None)
        out["Location"] = "/" + loc.split("://", 1)[1].split("/", 1)[-1]
    return Response(content=data, status_code=status, headers=out)


@app.api_route("/ui", methods=["GET"])
@app.api_route("/ui/{rest:path}", methods=["GET"])
@app.api_route("/apisix/admin/{rest:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def apisix_proxy(request: Request, rest: str = ""):
    is_ui = request.url.path.startswith("/ui")
    try:
        auth.current_user(request)
    except HTTPException:
        if is_ui:                                        # page load: send them to sign in first
            return Response(status_code=302, headers={"Location": "/?next=ui"})
        raise
    if is_ui and DASHBOARD_DIST:
        return _serve_dashboard(request.url.path)
    if request.method != "GET" and not _same_origin(request):
        raise HTTPException(403, "Cross-origin request refused")
    headers = {k: v for k, v in request.headers.items() if k.lower() in _FWD_REQ}   # never the cookie
    if ADMIN_KEY_FROM_SESSION:
        # One sign-in for the whole portal: the signed-in console user acts with the gateway's
        # admin key, which stays server-side. Any key the browser sends is ignored.
        headers = {k: v for k, v in headers.items() if k.lower() != "x-api-key"}
        headers["X-API-KEY"] = os.environ.get("APISIX_ADMIN_KEY", "")
    body = await request.body()
    status, rh, data = await run_in_threadpool(_upstream, request.method, request.url.path,
                                               request.url.query, headers, body)
    out = {k: v for k, v in rh.items() if k.lower() in _FWD_RESP}
    return Response(content=data, status_code=status, headers=out)


# The forked APISIX dashboard build (dashboard/dist, mounted read-only). When present it is served
# for /ui/ instead of APISIX's bundled copy; the Admin API above is still proxied to APISIX.
_dist = Path(os.environ.get("DASHBOARD_DIST", "/dashboard"))
DASHBOARD_DIST = _dist.resolve() if (_dist / "index.html").is_file() else None


def _serve_dashboard(url_path: str) -> Response:
    if url_path in ("/ui", "/ui/"):
        rel = "index.html"
    else:
        rel = url_path[len("/ui/"):]
    target = (DASHBOARD_DIST / rel).resolve()
    if DASHBOARD_DIST not in target.parents and target != DASHBOARD_DIST:
        raise HTTPException(404, "Not found")              # path traversal guard
    if not target.is_file():
        if rel.startswith("assets/"):
            raise HTTPException(404, "Not found")          # missing asset: real 404, not the SPA shell
        target = DASHBOARD_DIST / "index.html"             # client-side route (e.g. /ui/routes)
    resp = FileResponse(target)
    resp.headers["Cache-Control"] = ("public, max-age=31536000, immutable" if rel.startswith("assets/")
                                     else "no-store")      # hashed assets cache; the shell never does
    resp.headers["X-Dashboard-Source"] = "fork"
    return resp


# ---- static UI --------------------------------------------------------------------------
if (WEB / "static").is_dir():
    app.mount("/static", StaticFiles(directory=WEB / "static"), name="static")


@app.get("/")
def index():
    page = WEB / "index.html"
    if not page.exists():
        return JSONResponse({"detail": "UI not built yet (Stage 4)"}, status_code=503)
    return FileResponse(page)

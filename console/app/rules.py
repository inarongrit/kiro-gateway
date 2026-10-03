"""Read/validate/apply/commit the live guardrail rules ($KGW_DATA_DIR/guardrails.json).

Save flow (serialised by a lock, optimistic concurrency via a content hash):
  validate -> write file -> scripts/build-policy.sh (re-validates, regenerates policy objects into
  $KGW_DATA_DIR/generated) -> scripts/apply.sh (policy kinds only) -> git commit in $KGW_DATA_DIR.
Any failure restores the previous file and regenerated objects, so the gateway and the rule
history never diverge. The code repo is never written (the console mounts it read-only).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import threading
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, field_validator

GW = Path(os.environ.get("GW_DIR", "/gw"))
# Live rules + their change history live in the data dir (its own git repo), not the code repo.
DATA = Path(os.environ.get("KGW_DATA_DIR", str(GW / "data")))
FILE = DATA / "guardrails.json"
DEFAULT_FILE = GW / "config" / "guardrails.default.json"
APPLY_KINDS = "plugin_configs global_rules routes"   # never touches ssls (keys are not mounted)
_lock = threading.Lock()


class Rule(BaseModel):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")
    label: str = Field(min_length=1, max_length=80)
    description: str = Field(default="", max_length=300)
    pattern: str = Field(min_length=1, max_length=1000)
    case_insensitive: bool = False
    applies_to: list[Literal["kiro", "ai"]] = Field(min_length=1)
    enabled: bool = True

    @field_validator("pattern")
    @classmethod
    def no_placeholder(cls, v: str) -> str:
        if "${" in v or "]==]" in v:
            raise ValueError("pattern may not contain '${' or ']==]'")
        return v


class Toggle(BaseModel):
    enabled: bool


class RateLimit(Toggle):
    requests: int = Field(ge=1, le=100000)
    window_seconds: int = Field(ge=1, le=86400)


class TokenBudget(Toggle):
    tokens: int = Field(ge=1, le=100_000_000)
    window_seconds: int = Field(ge=1, le=86400 * 31)


class MLGuard(Toggle):
    """Second layer (Amazon Bedrock Guardrails via the ml-guard service), Kiro path only."""
    timeout_ms: int = Field(default=1500, ge=200, le=10000)
    fail_mode: Literal["open", "closed"] = "open"   # what to do if Bedrock is slow or unavailable


class Guardrails(BaseModel):
    kiro_prompt_guard: Toggle
    kiro_rate_limit: RateLimit
    ai_prompt_guard: Toggle
    ai_token_budget: TokenBudget
    kiro_ml_guard: MLGuard = MLGuard(enabled=False)


class Config(BaseModel):
    block_message: str = Field(min_length=1, max_length=300)
    rules: list[Rule] = Field(max_length=200)
    guardrails: Guardrails

    @field_validator("rules")
    @classmethod
    def unique_ids(cls, v: list[Rule]) -> list[Rule]:
        ids = [r.id for r in v]
        if len(ids) != len(set(ids)):
            raise ValueError("rule ids must be unique")
        return v


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    env = {**os.environ, "HOME": "/tmp", "APPLY_KINDS": APPLY_KINDS, "KGW_DATA_DIR": str(DATA)}
    return subprocess.run(cmd, cwd=GW, env=env, capture_output=True, text=True, timeout=120, **kw)


def pcre_error(pattern: str) -> str | None:
    """Syntax-check with PCRE (grep -P), the same engine family the gateway uses.
    Returns a plain-English message (the backend tool name is not shown to users)."""
    p = _run(["grep", "-qP", "--", pattern], input="")
    if p.returncode in (0, 1):
        return None
    detail = (p.stderr.strip().splitlines() or [""])[0].removeprefix("grep: ").strip()
    return "That is not a valid regular expression" + (f" ({detail})" if detail else "") + "."


def pcre_search(pattern: str, text: str) -> str | None:
    """Return the matched substring, or None. -z: treat the whole prompt as one record."""
    p = _run(["grep", "-oPz", "-m1", "--", pattern], input=text)
    return p.stdout.split("\0")[0] if p.returncode == 0 else None


def _git(*args: str, **kw) -> subprocess.CompletedProcess:
    """git in the data dir (rule history), never in the code repo."""
    return subprocess.run(["git", "-C", str(DATA), "-c", f"safe.directory={DATA}", *args],
                          env={**os.environ, "HOME": "/tmp"}, capture_output=True, text=True, timeout=30, **kw)


def ensure_data() -> None:
    """First start: seed the live rules from the tracked defaults and start their history."""
    DATA.mkdir(parents=True, exist_ok=True)
    if not FILE.exists():
        FILE.write_bytes(DEFAULT_FILE.read_bytes())
    if not (DATA / ".git").exists():
        _git("init", "-q", "-b", "main")
        (DATA / ".gitignore").write_text("generated/\n")
        _git("add", "--", "guardrails.json", ".gitignore")
        _git("-c", "user.name=Kiro Gateway", "-c", "user.email=kiro-gateway@localhost",
             "commit", "-q", "-m", "guardrails: initial rules from config/guardrails.default.json")


def load() -> tuple[dict, str]:
    ensure_data()
    raw = FILE.read_bytes()
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def _restore(old: bytes) -> None:
    FILE.write_bytes(old)
    _run(["scripts/build-policy.sh"])
    _run(["scripts/apply.sh"])


def save(new: Config, base_version: str, user: str, ip: str) -> tuple[dict, str, str]:
    with _lock:
        old = FILE.read_bytes()
        if hashlib.sha256(old).hexdigest() != base_version:
            raise ConflictError("Someone else changed the rules. Reload and try again.")
        for r in new.rules:
            if err := pcre_error(r.pattern):
                raise ValidationFailed(f"Rule '{r.label}': {err}")
        current = json.loads(old)
        merged = {"_doc": current.get("_doc", ""), "version": current.get("version", 1),
                  **new.model_dump()}
        FILE.write_text(json.dumps(merged, indent=2, ensure_ascii=False) + "\n")
        for step in (["scripts/build-policy.sh"], ["scripts/apply.sh"]):
            p = _run(step)
            if p.returncode != 0:
                _restore(old)
                raise ApplyFailed(f"{step[0]} failed: {(p.stderr or p.stdout).strip()[-400:]}")
        summary = describe_change(json.loads(old), merged)
        msg = f"guardrails: {summary}\n\nChanged via Guardrail Console by {user} from {ip}"
        _git("add", "--", "guardrails.json")
        c = _git("-c", f"user.name=Guardrail Console ({user})", "-c", "user.email=guardrail-console@localhost",
                 "commit", "-q", "-m", msg, "--", "guardrails.json")
        commit = _git("rev-parse", "--short", "HEAD").stdout.strip() if c.returncode == 0 else ""
        data, ver = load()
        return data, ver, commit or "(nothing to commit)"


def describe_change(old: dict, new: dict) -> str:
    o = {r["id"]: r for r in old.get("rules", [])}
    n = {r["id"]: r for r in new.get("rules", [])}
    parts = [f"added '{n[i]['label']}'" for i in n.keys() - o.keys()]
    parts += [f"removed '{o[i]['label']}'" for i in o.keys() - n.keys()]
    for i in n.keys() & o.keys():
        if n[i] != o[i]:
            if n[i]["enabled"] != o[i]["enabled"] and {**n[i], "enabled": 0} == {**o[i], "enabled": 0}:
                parts.append(f"{'enabled' if n[i]['enabled'] else 'disabled'} '{n[i]['label']}'")
            else:
                parts.append(f"edited '{n[i]['label']}'")
    for k, v in new.get("guardrails", {}).items():
        if v != old.get("guardrails", {}).get(k):
            parts.append(f"changed {k}")
    if new.get("block_message") != old.get("block_message"):
        parts.append("changed block message")
    return ", ".join(sorted(parts)) or "no effective change"


def history(limit: int = 20) -> list[dict]:
    ensure_data()
    p = _git("log", f"-n{limit}", "--format=%h%x1f%an%x1f%aI%x1f%s", "--", "guardrails.json")
    out = []
    for line in p.stdout.splitlines():
        h, an, at, s = line.split("\x1f")
        out.append({"commit": h, "author": an, "time": at, "summary": s})
    return out


def test_prompt(cfg: dict, text: str, path: str) -> dict:
    """Dry-run the live rules. Returns masked previews and UTF-16 offsets (for highlighting in
    the browser's own copy of the text), never the raw matched secret."""
    g = cfg["guardrails"]
    guard_on = g["kiro_prompt_guard" if path == "kiro" else "ai_prompt_guard"]["enabled"]
    # The Kiro guard normalises before matching; ai-prompt-guard (a stock plugin) does not.
    subject = normalise(text) if path == "kiro" else text
    checked = []
    for r in cfg["rules"]:
        if not r["enabled"] or path not in r["applies_to"]:
            continue
        pat = ("(?i)" if r.get("case_insensitive") else "") + r["pattern"]
        m = pcre_search(pat, subject)
        hit = {"id": r["id"], "label": r["label"], "matched": m is not None}
        if m is not None:
            hit["preview"] = mask(m)
            if subject == text and (i := text.find(m)) >= 0:
                hit["start"] = _utf16_len(text[:i])
                hit["length"] = _utf16_len(m)
        checked.append(hit)
    hits = [c for c in checked if c["matched"]]
    ml = _ml_layer(g, subject, text) if path == "kiro" else {"enabled": False}
    hits += ml.pop("hits", [])
    return {"path": path, "guard_enabled": guard_on, "would_block": bool(guard_on and hits),
            "normalised": subject != text, "rules_checked": len(checked), "matches": hits, "ml": ml}


ML_URL = os.environ.get("ML_GUARD_URL", "http://172.30.0.40:8080")
_USER_MSG = re.compile(r"--- USER MESSAGE BEGIN ---\n(.*)\n--- USER MESSAGE END ---", re.S)


def _user_text(text: str) -> str:
    """Mirror of user_text() in policy/inference-guard.lua: only the user's words go to Bedrock."""
    m = _USER_MSG.search(text)
    return m.group(1) if m else text


def _ml_layer(g: dict, subject: str, text: str) -> dict:
    """Second layer, exactly as the gateway runs it: only when enabled. The tester always calls it
    (even if a regex already matched) so the admin sees what each layer thinks."""
    cfg = g.get("kiro_ml_guard") or {}
    if not cfg.get("enabled"):
        return {"enabled": False}
    subject = _user_text(subject)
    import urllib.request
    req = urllib.request.Request(f"{ML_URL}/check", data=json.dumps({"text": subject}).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=cfg.get("timeout_ms", 1500) / 1000) as r:
            res = json.load(r)
    except Exception as e:
        return {"enabled": True, "available": False, "fail_mode": cfg.get("fail_mode", "open"),
                "error": type(e).__name__, "hits": [] if cfg.get("fail_mode", "open") == "open" else
                [{"id": "ml-unavailable", "label": "Second layer unavailable (fail closed)",
                  "matched": True, "layer": "ml"}]}
    hits = []
    if res.get("action") == "block":
        spans = res.get("mask") or []
        for pol in res.get("policies") or ["policy"]:
            hits.append({"id": f"bedrock:{pol}", "label": f"Bedrock Guardrails: {pol}", "matched": True,
                         "layer": "ml"})
        for i, span in enumerate(spans):        # previews + offsets for highlighting, never raw text
            h = hits[min(i, len(hits) - 1)] if hits else None
            if h is not None and "preview" not in h:
                h["preview"] = mask(span)
                if subject == text and (k := text.find(span)) >= 0:
                    h["start"], h["length"] = _utf16_len(text[:k]), _utf16_len(span)
    return {"enabled": True, "available": True, "action": res.get("action"),
            "policies": res.get("policies", []), "latency_ms": res.get("latency_ms"), "hits": hits}


# Mirrors policy/inference-guard.lua normalise(): full-width ASCII and Thai digits to ASCII,
# ideographic space to space, zero-width characters removed.
_NORMALISE = {**{cp: cp - 0xFEE0 for cp in range(0xFF01, 0xFF5F)},
              **{0x0E50 + d: 0x30 + d for d in range(10)},
              0x3000: 0x20, 0x200B: None, 0x200C: None, 0x200D: None, 0x2060: None, 0xFEFF: None}


def normalise(text: str) -> str:
    return text.translate(_NORMALISE)


def mask(s: str) -> str:
    """Same shape as the gateway's audit-log mask: 'so****th', short or non-ASCII ends -> stars."""
    if len(s) >= 8 and s[:2].isascii() and s[-2:].isascii():
        return s[:2] + "*" * (len(s) - 4) + s[-2:]
    return "*" * len(s)


def _utf16_len(s: str) -> int:
    return len(s.encode("utf-16-le")) // 2


class ConflictError(Exception): ...
class ValidationFailed(Exception): ...
class ApplyFailed(Exception): ...

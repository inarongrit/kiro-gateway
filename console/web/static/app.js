"use strict";
// Guardrail Console UI. No framework, no build step. All text goes through textContent (no innerHTML
// with data), so prompts from the audit log can never inject markup.
const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
const clone = (o) => JSON.parse(JSON.stringify(o));
const GUARDS = {
  kiro_prompt_guard: { name: "Kiro prompt check", help: "Apply the block rules to Kiro chat prompts." },
  kiro_rate_limit:   { name: "Kiro rate limit", help: "Chat requests allowed per user.", fields: [["requests", "requests"], ["window_seconds", "seconds"]] },
  ai_prompt_guard:   { name: "AI route prompt check", help: "Apply the block rules to /v1/chat/completions." },
  ai_token_budget:   { name: "AI route token budget", help: "Model tokens allowed per user.", fields: [["tokens", "tokens"], ["window_seconds", "seconds"]] },
};
const RESULT_TXT = { blocked: "Blocked", allowed: "Allowed", rate_limited: "Rate limited", error: "Error" };
let saved = null, version = null, draft = null, editing = null, timers = [];
const openRows = new Set();

// ---- API ----------------------------------------------------------------------------------
async function api(method, path, body) {
  const opts = { method, headers: {}, credentials: "same-origin" };
  if (method !== "GET") { opts.headers["X-Console"] = "1"; opts.headers["Content-Type"] = "application/json"; }
  if (body !== undefined) opts.body = JSON.stringify(body);
  const r = await fetch(path, opts);
  let data = null; try { data = await r.json(); } catch (_) { /* empty body */ }
  if (r.status === 401 && path !== "/api/login") { showLogin(); throw new Error("signed out"); }
  if (!r.ok) {
    const d = data && data.detail;
    const msg = Array.isArray(d) ? d.map((x) => `${(x.loc || []).slice(-2).join(".")}: ${x.msg}`).join("; ") : (d || `HTTP ${r.status}`);
    const err = new Error(msg); err.status = r.status; throw err;
  }
  return data;
}
function toast(msg, kind = "ok", ms = 4500) {
  const t = $("toast"); t.textContent = msg; t.className = `toast ${kind}`;
  clearTimeout(toast._t); toast._t = setTimeout(() => t.classList.add("hidden"), ms);
}

// ---- sign in ------------------------------------------------------------------------------
function showLogin() {
  timers.forEach(clearInterval); timers = [];
  $("app").classList.add("hidden"); $("savebar").classList.add("hidden"); $("login").classList.remove("hidden");
  $("loginForm").username.focus();
}
$("loginForm").addEventListener("submit", async (ev) => {
  ev.preventDefault(); $("loginErr").textContent = "";
  const f = ev.target;
  try {
    await api("POST", "/api/login", { username: f.username.value, password: f.password.value }); f.password.value = "";
    const next = new URLSearchParams(location.search).get("next");
    if (next === "ui") { location.href = "/ui/"; return; }
    if (next === "grafana") { location.href = "/grafana/"; return; }
    start();
  }
  catch (e) { $("loginErr").textContent = e.message; }
});
$("logout").addEventListener("click", async () => {
  if (isDirty() && !confirm("You have unsaved changes. Sign out anyway?")) return;
  try { await api("POST", "/api/logout"); } catch (_) {}
  showLogin();
});

// ---- rules + protections (draft editing) --------------------------------------------------
function isDirty() { return draft && saved && JSON.stringify(draft) !== JSON.stringify(stripMeta(saved)); }
function stripMeta(c) { const { _doc, version: _v, ...rest } = c; return rest; }
function changeCount() {
  if (!isDirty()) return 0;
  const s = stripMeta(saved); let n = 0;
  const sm = new Map(s.rules.map((r) => [r.id, JSON.stringify(r)])), dm = new Map(draft.rules.map((r) => [r.id, JSON.stringify(r)]));
  for (const [id, v] of dm) if (sm.get(id) !== v) n++;
  for (const id of sm.keys()) if (!dm.has(id)) n++;
  for (const k of Object.keys(draft.guardrails)) if (JSON.stringify(draft.guardrails[k]) !== JSON.stringify(s.guardrails[k])) n++;
  if (draft.block_message !== s.block_message) n++;
  return n;
}
function refreshDirty() {
  const n = changeCount();
  $("savebar").classList.toggle("hidden", n === 0);
  $("dirtyTxt").textContent = `${n} unsaved change${n === 1 ? "" : "s"}`;
  renderKpiProt();
}
function sw(on, label, onChange) {
  const b = el("button", "sw"); b.type = "button"; b.setAttribute("role", "switch");
  b.setAttribute("aria-checked", String(!!on)); b.setAttribute("aria-label", label);
  b.addEventListener("click", () => { const v = b.getAttribute("aria-checked") !== "true"; b.setAttribute("aria-checked", String(v)); onChange(v); });
  return b;
}
function renderRules() {
  const box = $("rules"); box.replaceChildren();
  const s = new Map(stripMeta(saved).rules.map((r) => [r.id, JSON.stringify(r)]));
  if (!draft.rules.length) box.append(el("div", "mu", "No rules yet. Add one to start blocking."));
  for (const r of draft.rules) {
    const row = el("div", "rule" + (r.enabled ? "" : " off"));
    row.append(sw(r.enabled, `Switch rule ${r.label}`, (v) => { r.enabled = v; renderRules(); refreshDirty(); }));
    const mid = el("div", "grow");
    const title = el("div"); title.append(el("b", null, r.label));
    for (const p of r.applies_to) { title.append(" "); title.append(el("span", "tag k", p === "kiro" ? "Kiro" : "AI route")); }
    if (r.case_insensitive) { title.append(" "); title.append(el("span", "tag", "any case")); }
    if (s.get(r.id) !== JSON.stringify(r)) { title.append(" "); title.append(el("span", "dirty-dot", s.has(r.id) ? "● edited" : "● new")); }
    mid.append(title);
    if (r.description) mid.append(el("div", "mu small", r.description));
    mid.append(el("div", "mono mu pat", r.pattern));
    row.append(mid);
    const hits = el("div", "right small mu", hitText(r.id));
    const edit = el("button", "btn sm", "Edit"); edit.type = "button"; edit.addEventListener("click", () => openRule(r));
    const right = el("div", "stack right"); right.append(edit, hits);
    row.append(right);
    box.append(row);
  }
}
let ruleHits = {};
function hitText(id) { const n = ruleHits[id] || 0; return n ? `${n} hit${n === 1 ? "" : "s"}` : "no hits"; }
function renderGuards() {
  const box = $("guards"); box.replaceChildren();
  for (const [key, meta] of Object.entries(GUARDS)) {
    const g = draft.guardrails[key]; if (!g) continue;
    const row = el("div", "row wrap");
    row.append(sw(g.enabled, meta.name, (v) => { g.enabled = v; refreshDirty(); }));
    const t = el("div", "grow"); t.append(el("b", null, meta.name)); t.append(el("div", "mu small", meta.help)); row.append(t);
    for (const [field, unit] of meta.fields || []) {
      const lab = el("label", "row mu small");
      const inp = el("input", "in num"); inp.type = "number"; inp.min = "1"; inp.value = g[field]; inp.setAttribute("aria-label", `${meta.name} ${unit}`);
      inp.addEventListener("input", () => { const v = parseInt(inp.value, 10); inp.classList.toggle("bad", !(v >= 1)); if (v >= 1) { g[field] = v; refreshDirty(); } });
      lab.append(inp, el("span", null, unit)); row.append(lab);
    }
    box.append(row);
  }
  $("blockMsg").value = draft.block_message;
}
$("blockMsg").addEventListener("input", (e) => { draft.block_message = e.target.value; refreshDirty(); });

// ---- rule dialog --------------------------------------------------------------------------
const slug = (s) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 63) || "rule";
function uniqueId(base) { let id = base, i = 2; while (draft.rules.some((r) => r.id === id)) id = `${base}-${i++}`; return id; }
function openRule(rule) {
  editing = rule; const f = $("ruleForm");
  $("dlgTitle").textContent = rule ? "Edit rule" : "Add rule";
  f.label.value = rule ? rule.label : ""; f.description.value = rule ? rule.description || "" : "";
  f.pattern.value = rule ? rule.pattern : ""; f.case_insensitive.checked = rule ? !!rule.case_insensitive : false;
  f.kiro.checked = rule ? rule.applies_to.includes("kiro") : true; f.ai.checked = rule ? rule.applies_to.includes("ai") : true;
  f.enabled.checked = rule ? rule.enabled : true;
  $("ruleId").textContent = rule ? rule.id : "(from name)"; $("delRule").classList.toggle("hidden", !rule);
  $("dlgErr").textContent = ""; $("patMsg").textContent = "Plain words work too. Use \\d for a digit, [A-Z] for a capital letter.";
  $("patMsg").className = "small mu"; f.pattern.classList.remove("bad");
  $("ruleDlg").showModal(); f.label.focus();
}
let patTimer = null, patValid = true;
$("ruleForm").pattern.addEventListener("input", (e) => {
  clearTimeout(patTimer); const v = e.target.value;
  patTimer = setTimeout(async () => {
    if (!v) return;
    try {
      const r = await api("POST", "/api/check-pattern", { pattern: v });
      patValid = r.valid; e.target.classList.toggle("bad", !r.valid);
      $("patMsg").textContent = r.valid ? "✓ Valid pattern" : `✗ ${r.error}`; $("patMsg").className = r.valid ? "small mu" : "small err";
    } catch (_) {}
  }, 350);
});
$("ruleForm").label.addEventListener("input", (e) => { if (!editing) $("ruleId").textContent = uniqueId(slug(e.target.value)); });
$("dlgCancel").addEventListener("click", () => $("ruleDlg").close());
$("delRule").addEventListener("click", () => {
  if (!editing || !confirm(`Delete rule "${editing.label}"? It is removed when you press Save & apply.`)) return;
  draft.rules = draft.rules.filter((r) => r !== editing); $("ruleDlg").close(); renderRules(); refreshDirty();
});
$("ruleForm").addEventListener("submit", async (ev) => {
  ev.preventDefault(); const f = ev.target;
  const applies = [f.kiro.checked && "kiro", f.ai.checked && "ai"].filter(Boolean);
  if (!f.label.value.trim()) return ($("dlgErr").textContent = "Give the rule a name.");
  if (!f.pattern.value) return ($("dlgErr").textContent = "Enter a pattern.");
  if (!applies.length) return ($("dlgErr").textContent = "Choose at least one place the rule applies to.");
  try { const r = await api("POST", "/api/check-pattern", { pattern: f.pattern.value }); if (!r.valid) return ($("dlgErr").textContent = `Pattern is not valid: ${r.error}`); }
  catch (e) { return ($("dlgErr").textContent = e.message); }
  const rule = { id: editing ? editing.id : uniqueId(slug(f.label.value)), label: f.label.value.trim(), description: f.description.value.trim(),
    pattern: f.pattern.value, case_insensitive: f.case_insensitive.checked, applies_to: applies, enabled: f.enabled.checked };
  if (editing) Object.assign(editing, rule); else draft.rules.push(rule);
  $("ruleDlg").close(); renderRules(); refreshDirty();
});
$("addRule").addEventListener("click", () => openRule(null));

// ---- save ---------------------------------------------------------------------------------
$("discard").addEventListener("click", () => { draft = clone(stripMeta(saved)); renderRules(); renderGuards(); refreshDirty(); });
$("save").addEventListener("click", async () => {
  const b = $("save"); b.disabled = true; b.textContent = "Applying…";
  try {
    const r = await api("PUT", "/api/guardrails", { ...draft, base_version: version });
    saved = r.config; version = r.version; draft = clone(stripMeta(saved));
    renderRules(); renderGuards(); refreshDirty(); loadHistory();
    toast(`Saved and live on the gateway. Recorded as ${r.commit}.`);
  } catch (e) {
    if (e.status === 409) toast("Someone else changed the rules. Press Discard to load their version, then redo your change.", "err", 9000);
    else toast(`Not saved: ${e.message}`, "err", 9000);
  } finally { b.disabled = false; b.textContent = "Save & apply"; }
});
window.addEventListener("beforeunload", (e) => { if (isDirty()) { e.preventDefault(); e.returnValue = ""; } });

// ---- prompt tester ------------------------------------------------------------------------
$("tBtn").addEventListener("click", async () => {
  const text = $("tText").value, res = $("tRes");
  if (!text.trim()) return $("tText").focus();
  try {
    const r = await api("POST", "/api/test-prompt", { text, path: $("tPath").value });
    res.replaceChildren(); res.classList.remove("hidden");
    const where = r.path === "kiro" ? "Kiro chat" : "the AI route";
    if (r.would_block) {
      res.className = "result block";
      res.append(el("b", null, `⛔ Would be blocked in ${where}`));
      for (const m of r.matches) { const d = el("div", "small"); d.append(`Rule “${m.label}” matched `); d.append(el("span", "mono", m.preview || "")); res.append(d); }
    } else if (r.matches.length && !r.guard_enabled) {
      res.className = "result warn"; res.append(el("b", null, `⚠ Matches a rule, but the prompt check for ${where} is switched off`));
    } else {
      res.className = "result allow"; res.append(el("b", null, `✓ Would be allowed in ${where}`));
      res.append(el("div", "small", `Checked against ${r.rules_checked} active rule${r.rules_checked === 1 ? "" : "s"}.`));
    }
    if (isDirty()) res.append(el("div", "small mu", "Your unsaved changes are not included until you press Save & apply."));
  } catch (e) { toast(e.message, "err"); }
});

// ---- live activity, stats, history, health -----------------------------------------------
function fmtTime(ts) { const d = new Date(ts); return isNaN(d) ? ts : d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }); }
async function loadEvents() {
  const p = new URLSearchParams({ hours: $("hours").value, q: $("eQ").value, result: $("eRes").value, path: $("ePath").value, limit: "150" });
  if ($("eAll").checked) p.set("all_ops", "true");
  const { events } = await api("GET", `/api/events?${p}`);
  const box = $("events"); box.replaceChildren(); $("evCount").textContent = `${events.length} shown`;
  if (!events.length) box.append(el("div", "mu small", "Nothing matches yet. Use Kiro through the gateway and activity appears here."));
  for (const e of events) {
    const key = `${e.ts}|${e.user}|${e.op}|${e.status}`;
    const row = el("div", "ev" + (openRows.has(key) ? " open" : "")); row.tabIndex = 0;
    const head = el("div", "row");
    head.append(el("span", "mono mu", fmtTime(e.ts)), el("span", `tag ${e.result}`, RESULT_TXT[e.result] || e.result));
    head.append(el("span", null, `${e.path === "kiro" ? "Kiro" : "AI route"} · ${e.op}`), el("span", "mono mu small", e.user));
    head.append(el("span", "grow"));
    if (e.rule) head.append(el("span", "small", ruleLabel(e.rule)));
    head.append(el("span", "mu small", `${e.latency_ms} ms`));
    row.append(head);
    const full = e.prompt || (e.path === "ai" ? "(AI route prompts are not stored)" : "(no prompt)");
    const short = userText(full);
    const p = el("div", "p small", openRows.has(key) ? full : short);
    row.append(p);
    const toggle = () => { row.classList.toggle("open"); openRows.has(key) ? openRows.delete(key) : openRows.add(key); p.textContent = openRows.has(key) ? full : short; };
    row.addEventListener("click", toggle); row.addEventListener("keydown", (k) => { if (k.key === "Enter" || k.key === " ") { k.preventDefault(); toggle(); } });
    box.append(row);
  }
}
// Kiro wraps the user's text in injected context blocks; show just the user's words in the list.
function userText(s) {
  const m = /--- USER MESSAGE BEGIN ---\s*([\s\S]*?)\s*(--- USER MESSAGE END ---|$)/.exec(s);
  return m && m[1] ? m[1] : s;
}
function ruleLabel(id) {
  const r = saved && saved.rules.find((x) => x.id === id);
  if (r) return r.label;
  return { "prompt-guard": "AI prompt check", unknown: "Earlier block (rule not recorded)" }[id] || id;
}
function bars(box, pairs) {
  box.replaceChildren(); if (!pairs.length) return box.append(el("div", "mu small", "No blocks in this window."));
  const max = Math.max(...pairs.map((p) => p[1]));
  for (const [name, n] of pairs) {
    const b = el("div", "b"); const tr = el("div", "track"); const fi = el("div", "fill"); fi.style.width = `${Math.max(3, (n / max) * 100)}%`;
    tr.append(fi); b.append(el("span", "lbl small", name), tr, el("span", "small", String(n))); box.append(b);
  }
}
let lastStats = null;
async function loadStats() {
  const s = await api("GET", `/api/stats?hours=${$("hours").value}`); lastStats = s;
  $("kReq").textContent = s.requests; $("kBlk").textContent = s.blocked; $("kUsr").textContent = s.users;
  const l = s.latency_ms.kiro; $("kLat").textContent = l.n ? `${(l.p50 / 1000).toFixed(1)}s / ${(l.p95 / 1000).toFixed(1)}s` : "–";
  ruleHits = Object.fromEntries(s.by_rule); if (draft) renderRules();
  bars($("byRule"), s.by_rule.map(([id, n]) => [ruleLabel(id), n])); bars($("byUser"), s.blocked_by_user);
  const tl = $("timeline"); tl.replaceChildren(); const max = Math.max(1, ...s.timeline.map((t) => (t.allowed || 0) + (t.blocked || 0)));
  for (const t of s.timeline) {
    const col = el("div", "col"); col.title = `${t.bucket}: ${t.allowed || 0} allowed, ${t.blocked || 0} blocked`;
    const a = el("div", "a"); a.style.height = `${((t.allowed || 0) / max) * 70}px`; const x = el("div", "x"); x.style.height = `${((t.blocked || 0) / max) * 70}px`;
    col.append(a, x); tl.append(col);
  }
  if (!s.timeline.length) tl.append(el("div", "mu small", "No traffic in this window."));
  renderKpiProt();
}
function renderKpiProt() {
  if (!draft) return; const g = Object.values(stripMeta(saved).guardrails);
  $("kProt").textContent = `${g.filter((x) => x.enabled).length} / ${g.length}`;
}
async function loadHistory() {
  const { changes } = await api("GET", "/api/history"); const ul = $("history"); ul.replaceChildren();
  if (!changes.length) ul.append(el("li", null, "No changes recorded yet."));
  for (const c of changes.slice(0, 8)) {
    const li = el("li"); li.append(el("span", "mono", c.commit), ` ${new Date(c.time).toLocaleString()} · `, el("b", null, c.summary.replace(/^guardrails: /, "")), ` · ${c.author}`); ul.append(li);
  }
}
async function loadHealth() {
  try { const h = await api("GET", "/api/status"); $("healthDot").className = `dot ${h.healthy ? "ok" : "bad"}`; $("healthTxt").textContent = h.healthy ? "gateway healthy" : "gateway problem"; }
  catch (_) { $("healthDot").className = "dot bad"; $("healthTxt").textContent = "gateway unreachable"; }
}
const safe = (fn) => () => fn().catch((e) => { if (e.message !== "signed out") console.warn(e); });
let qTimer = null;
$("eQ").addEventListener("input", () => { clearTimeout(qTimer); qTimer = setTimeout(safe(loadEvents), 300); });
["eRes", "ePath", "eAll"].forEach((id) => $(id).addEventListener("change", safe(loadEvents)));
$("hours").addEventListener("change", () => { safe(loadEvents)(); safe(loadStats)(); });

// ---- boot ---------------------------------------------------------------------------------
async function start() {
  const me = await api("GET", "/api/me"); $("me").textContent = me.user;
  const g = await api("GET", "/api/guardrails"); saved = g.config; version = g.version; draft = clone(stripMeta(saved));
  $("login").classList.add("hidden"); $("app").classList.remove("hidden");
  renderRules(); renderGuards(); refreshDirty();
  await Promise.all([loadEvents(), loadStats(), loadHistory(), loadHealth()].map((p) => p.catch(() => {})));
  timers.forEach(clearInterval);
  timers = [setInterval(safe(loadEvents), 5000), setInterval(safe(loadStats), 15000), setInterval(safe(loadHealth), 15000)];
}
start().catch(() => showLogin());

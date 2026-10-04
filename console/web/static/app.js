"use strict";
// Sign-in page. After a successful sign-in (or if already signed in) go to ?next= : the portal
// (default) or Grafana. Only these two fixed targets are allowed, so ?next= cannot redirect off-site.
const TARGETS = { ui: "/ui/", grafana: "/grafana/" };
const target = TARGETS[new URLSearchParams(location.search).get("next")] || TARGETS.ui;
const $ = (id) => document.getElementById(id);

fetch("/api/me", { credentials: "same-origin" })
  .then((r) => { if (r.ok) location.replace(target); else $("loginForm").username.focus(); })
  .catch(() => $("loginForm").username.focus());

$("loginForm").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("loginErr").textContent = "";
  const f = ev.target;
  try {
    const r = await fetch("/api/login", {
      method: "POST", credentials: "same-origin",
      headers: { "X-Console": "1", "Content-Type": "application/json" },
      body: JSON.stringify({ username: f.username.value, password: f.password.value }),
    });
    f.password.value = "";
    if (r.ok) { location.replace(target); return; }
    const data = await r.json().catch(() => null);
    $("loginErr").textContent = (data && typeof data.detail === "string") ? data.detail : `Sign-in failed (HTTP ${r.status})`;
  } catch (e) {
    $("loginErr").textContent = "Gateway unreachable. Try again.";
  }
});

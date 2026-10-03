# Kiro Gateway — guardrails, audit and monitoring for Kiro (Squid + Apache APISIX)

Central control and content inspection for Kiro traffic, plus an OpenAI-compatible AI Gateway.
**Test/demo only**: uses a self-signed test CA and binds everything to `127.0.0.1`.

```
kiro-cli ──HTTPS_PROXY──▶ Squid :3128 ──(Kiro hosts only, via squid/hosts)──▶ APISIX :443 ──TLS──▶ real Kiro/AWS endpoint
                            └──(everything else: plain CONNECT tunnel, not decrypted)──▶ internet
apps ──apikey──▶ APISIX :9080 /v1/chat/completions ──ai-proxy──▶ OpenAI (or local mock LLM)
```

| Component | Role |
|---|---|
| Squid | Thin CONNECT tier. Never decrypts. Picks which hosts go to APISIX via its own `hosts_file`. |
| APISIX | Terminates TLS for listed Kiro hosts, applies policy, re-encrypts to the real endpoint (upstream certs verified). |
| etcd | APISIX config store. Not exposed to the host. |

## Quick start

```bash
cd kiro-gateway
scripts/init.sh                       # once: .env secrets, test CA + certs, data/ (idempotent)
docker compose up -d
scripts/apply.sh                      # push config/ + policy/ to APISIX (idempotent)

source scripts/kiro-via-gateway on    # this shell -> gateway (fails safe if proxy is down)
kiro-cli chat
source scripts/kiro-via-gateway off   # back to direct, prior env values restored

scripts/kiro-via-gateway run kiro-cli chat   # one-off, shell untouched
scripts/kiro-via-gateway status
scripts/ai-demo.sh                    # AI Gateway smoke test
scripts/verify.sh                     # full end-to-end check (stack, interception, block, AI route, kiro on/off)
```

`.env` (git-ignored, 0600) holds `APISIX_ADMIN_KEY`, `AI_GW_DEMO_KEY`, `AI_GW_MOCK_TOKEN`, and optional
`OPENAI_API_KEY` (set it and re-run `scripts/apply.sh` to use OpenAI instead of the mock LLM).

## What is enforced

| Where | Policy |
|---|---|
| All intercepted hosts (`global_rules/kiro-audit`) | Audit log (allowlisted fields — no request headers, so tokens never logged). Per-user key = SHA-256 of bearer token (12 hex). |
| `runtime.*.kiro.dev` — inference (`kiro-inference`) | Blocks the current prompt on `KIRO-GATEWAY-BLOCK-DEMO` or an AWS access key ID (`AKIA…`) → 403 shown in Kiro. 30 req/min per user. No response buffering. |
| `q.*`, `management.*` (`kiro-observe`) | Log only. |
| `telemetry.*`, `client-telemetry.*`, `cognito-identity.*` | Not intercepted (tunneled). |
| `/v1/chat/completions` (`ai-chat`) | `key-auth` per user, `ai-prompt-guard` (same deny rules), 20k tokens/h per user, provider key held by the gateway. |

Intercepted Kiro hosts (found by observing kiro-cli 2.27.0): `runtime.us-east-1.kiro.dev` (inference,
`GenerateAssistantResponse`), `q.us-east-1.amazonaws.com`, `management.us-east-1.kiro.dev`.

## Operations

```bash
# Intercept another host (cert + upstream + route + Squid override), then apply
scripts/intercept-host.sh <hostname> && scripts/apply.sh && docker compose restart squid

# Change policy: edit policy/*.lua or scripts/build-policy.sh, then
scripts/apply.sh

# Logs
docker compose exec apisix tail -f /usr/local/apisix/logs/kiro-audit.log | jq .
docker compose exec squid  tail -f /var/log/squid/access.log
LOG_FULL_BODY=1 scripts/apply.sh      # debug: also log raw request bodies (contains code/history!)

# Read-only Admin API without exposing the key
scripts/admin.sh GET routes
```

`config/` is the source of truth (git). `pki/` (CA key, leaf keys, generated SSL objects) and `.env` are
git-ignored. `apply.sh` refuses to push any object with an unresolved `${VAR}`. It does not delete
objects removed from `config/` — use `scripts/admin.sh DELETE <kind>/<id>`.

## Rollback

| Scope | Command | Reversible |
|---|---|---|
| One shell | `source scripts/kiro-via-gateway off` | yes |
| Stop interception, keep proxy | Empty `squid/hosts` (keep the comment lines), `docker compose restart squid` | yes |
| Stop the stack | `docker compose down` | yes (config kept in etcd volume) |
| Full teardown | `docker compose down -v` | **no** — deletes etcd data and audit logs; re-run `apply.sh` to rebuild |

Nothing outside this directory is modified: no `/etc/hosts`, no system trust store, no Kiro settings.

## Guardrail Console (web UI)

`https://<host>:9180/`: one page to manage block rules and watch Kiro / AI route traffic. It is the
**only public port**: the APISIX dashboard is at `https://<host>:9180/ui/` behind the same sign-in, and
the APISIX Admin API is reachable only from inside Docker (and from the host at `127.0.0.1:9181`).
Screens: `console/docs/*.png`.

- **Sign in**: `admin`, password in `pki/console-initial-password` (0600). Change it with
  `scripts/console-passwd.sh admin --stdin` then `docker compose up -d console`.
- **Test a prompt**: checks text against the saved rules; nothing is sent to Kiro or a model.
- **Block rules / Protections**: edits stay local until **Save & apply**, which validates, applies to the
  live gateway and commits `config/guardrails.json` to git as `Guardrail Console (<user>)`.
- **Live activity / Blocks and traffic / Recent rule changes**: read from the audit log and git history.

Rules live only in `config/guardrails.json` (shared by the Kiro guard and `ai-prompt-guard`), so editing
the file and running `scripts/apply.sh` is equivalent to using the console.

Security: HTTPS (test CA), IP allowlist (`CONSOLE_ALLOW_CIDRS` in `docker-compose.yml`), scrypt password
hash in `.env`, Secure/HttpOnly/SameSite=Strict session, `X-Console` header + origin check on changes,
strict CSP, 5 failed sign-ins → 5 min lockout. The container sees only the public CA cert from `pki/`
and applies policy objects only (never certificates). Remote access needs one security group rule:
TCP 9180 from your network.

Tests: `console/tests/api_test.sh` (API) and
`NODE_PATH=$(npm root -g) node console/tests/ui_e2e.js add|remove` (browser, needs Playwright).

## Monitoring (Grafana + Prometheus + Loki + OpenTelemetry)

`https://<host>:9180/grafana/` (or **Monitoring ↗** in the console header), behind the console sign-in:
the console checks your session and passes your username to Grafana (auth proxy, trusted only from the
console container). Grafana, Prometheus, Loki, Tempo and the OTel Collector have **no published ports**.

| Dashboard | Shows | Source |
|---|---|---|
| 1 · Gateway overview | request rate, status codes, latency p50/p95, upstream vs gateway time, bandwidth | Prometheus (`prometheus` plugin) |
| 2 · Guardrails | allowed vs blocked, blocks by rule / path / user, recent blocked prompts | Loki (audit log) |
| 3 · Usage | Kiro chats and AI route calls per user, AI tokens per consumer/model | Loki + Prometheus |
| 4 · Logs & traces | searchable audit log (path/result/rule/kind + text), recent traces | Loki + Tempo |

Pipeline: APISIX `prometheus` → Prometheus (15d); APISIX `opentelemetry` → OTel Collector → Tempo (15d);
audit log file → OTel Collector (`file_log` + `transform`) → Loki (15d; labels `path,result,rule,kind`,
`user`/`trace_id` as structured metadata). Log lines link to traces (Loki derived field `trace_id`).
Dashboards are code: edit `monitoring/grafana/build_dashboards.py`, run it, Grafana reloads in ~30 s.
End-to-end check (fresh tagged traffic -> Prometheus, Loki, Tempo, every Grafana panel):
`python3 monitoring/tests/monitoring_check.py`. Screenshots: `monitoring/docs/`.

## Known limits (PoC)

### Second guardrail layer: Amazon Bedrock Guardrails

Kiro chats that pass the regex rules go to `ml-guard` (a small container, `ml-guard/`), which calls
Bedrock `ApplyGuardrail` with guardrail `kiro-gateway-poc` **version 3** (us-east-1, Standard tier,
definition in `guardrail-eval/bedrock-guardrail.json`, id/version in `ml-guard/guardrail.env`). It blocks
personal data (name, address, email, phone, card, SSN, IBAN, password, AWS keys, Thai ID) and a
"data exfiltration" denied topic. Switch, timeout (default 1.5 s) and fail mode (default **open**: if
Bedrock is slow or down, the regex verdict stands) are on the portal Rules page. Bedrock-detected spans
are masked in the audit log like regex matches; audit rules read `bedrock:pii:NAME` etc. Only the user's
message is sent to Bedrock (Kiro's own `--- CONTEXT ENTRY ---` wrapper is stripped); the regex rules
still check the full content. Prompts go to Bedrock in your account (cross-Region inference stays in
the US geography).

**Prompt-attack (injection/jailbreak) detection is OFF** since v3. With it on (v1), Bedrock blocked
normal coding-assistant prompts at every strength including LOW: `Reply with exactly: AFTER_OK
FINAL-E2E-9558`, `Reply with exactly: OK KML1`, and (not deterministically) `You are a helpful assistant
that writes pytest unit tests...`. Trade-off: most injection attempts now pass the gateway (2 of 5 in
the test set are still blocked, by the PII/topic checks). The model's own safety training is the
remaining defence. v3 also tightened the exfiltration topic definition, which in v2 blocked
`Respond only with valid JSON, no prose, no markdown fences.`

Measured on `guardrail-eval/testset.jsonl` (48 fake Thai + English prompts, 23 should block, 25 should
pass):

| Layer | Precision | Recall | False blocks | Misses |
|---|---|---|---|---|
| Regex rules alone | 0.89 | 0.35 | 1 | 15 |
| Regex + Bedrock v1 (with prompt attack; first 40 prompts) | 0.96 | 1.00 | 1 | 0 |
| **Regex + Bedrock v3 (current)** | **0.95** | **0.87** | 1 | 3 (all prompt attacks) |

The one false block is a 16-digit build number read as a card number. Bedrock adds ~0.5 s per Kiro
chat (p50 ~450-500 ms, p95 ~560-660 ms from this server); ~US$0.25 per 1,000 short prompts (PII +
topic). Results: `guardrail-eval/results-bedrock.json` (v1), `guardrail-eval/results-bedrock-v3.json`.
Thai: the denied-topic filter lists Thai as supported; the PII filter does not list Thai but caught the
Thai name/address cases; Thai-digit IDs are caught by the regex layer.

Strands Decider 2B was also evaluated (`guardrail-eval/decider-notes.md`) and **not** wired in: on this
CPU-only host it needs ~9.5 GB RAM and ~8 s per prompt, and recall was 0.61 at threshold 0.5 (0 at 0.9).
Usable only for offline review, or inline on a GPU host.

### Other limits

- **Identity**: all Kiro traffic arrives from Squid's IP, so users are keyed by a token hash that changes
  on token refresh. Needs a real identity source for production (see below).
- **Inspection covers the current prompt only** (`conversationState.currentMessage.userInputMessage.content`).
  It includes context Kiro injects. History is not re-scanned, so one blocked turn does not poison a session.
- **Blocking, not rewriting**: modifying bodies or streamed responses is out of scope. Model responses are
  not inspected.
- **Privacy of stored prompts**: the guard masks every rule match before the prompt is written to the
  audit log (`so*****th`, `41*****11`), so Loki, the Grafana log panels and the portal never hold the raw
  secret; the prompt tester returns only masked previews. Text that no rule matches (source code, names,
  addresses) is still stored for allowed and blocked prompts. Build with `PROMPT_LOG=off`
  (`PROMPT_LOG=off ./scripts/apply.sh`) to store no prompt text at all, only verdict + rule.
  `LOG_FULL_BODY=1` logs raw bodies and bypasses masking: debugging only.
- **Evasion**: before matching, the Kiro guard maps full-width ASCII and Thai digits to ASCII and removes
  zero-width characters. Spelled-out tricks (`name [at] example.com`) and splitting a secret across turns
  or files are not caught by the regex rules (the Bedrock layer below catches some of them). The AI route's
  stock `ai-prompt-guard` does not normalise.
- **Fail-closed**: a Kiro inference request whose body cannot be read is blocked (rule `uninspectable`).
- **One sign-in**: the console injects the APISIX admin key server-side for signed-in users, so the
  Gateway pages need no separate key. Set `CONSOLE_ADMIN_KEY_FROM_SESSION=0` to require the key again.
- **Upstream TLS trust** is pinned per upstream (`config/upstreams/_trust.json`: Amazon Root CA 1–4,
  Starfield G2) because APISIX does not apply its global trust store when `tls.verify` is set. If AWS
  changes roots, update that file.
- **Endpoints are region/version specific** (`us-east-1`, kiro-cli 2.27.0). Re-run discovery after upgrades:
  run kiro-cli via the proxy with an empty `squid/hosts` and read the Squid log.
- Verified with `SSL_CERT_FILE`; not verified whether kiro-cli reads the OS trust store (matters for MDM).

## Org-wide rollout path (same architecture, no redesign)

1. **PKI** — replace the test CA with an internal intermediate CA. Issue leaf certs for the Kiro hosts
   from it (or cert-manager on Kubernetes). Push the root to clients via MDM.
2. **Clients** — MDM sets `HTTPS_PROXY`/`NO_PROXY` (or a PAC file) and the CA. If kiro-cli turns out to
   ignore the OS store, also push `SSL_CERT_FILE`. Alternative without a proxy: Kiro's endpoint settings
   (`api.codewhisperer.service`, `api.q.service`, …) pointed at APISIX — validate first.
3. **Proxy tier** — Squid behind an internal TCP load balancer (NLB), ≥2 nodes across AZs. It is stateless;
   `squid.conf` + `hosts` ship as config. If you already have a secure web gateway (Zscaler, Netskope, …),
   have it forward the Kiro hosts to APISIX instead and drop Squid.
4. **APISIX** — deploy with the official Helm chart (`apisix/apisix`) on EKS/Kubernetes: data plane
   behind an internal LB with HPA, 3-node etcd (or decoupled control plane / standalone YAML mode from
   a ConfigMap). The same `config/` objects apply unchanged via `scripts/apply.sh` or ADC in CI.
5. **Enforcement** — egress firewall / security groups: only the proxy tier may reach the Kiro hosts on
   443. Otherwise users can bypass the gateway by unsetting `HTTPS_PROXY`.
6. **Identity** — Squid proxy auth (Kerberos/SSO) or mTLS client certs, passed to APISIX for real per-user
   attribution; AI Gateway consumers via `openid-connect` instead of static keys.
7. **Inspection** — replace the demo Lua rules with `forward-auth` to a central DLP service, shared by the
   Kiro and AI Gateway routes. Decide fail-open vs fail-closed.
8. **Logs & data handling** — ship audit logs (`kafka-logger`/`http-logger`/`elasticsearch-logger`) to the
   SIEM/S3 with retention. Prompts contain source code: get privacy/legal sign-off first.
9. **Limits** — switch `limit-count`/`ai-rate-limiting` to `policy: redis` so limits are shared across replicas.
10. **AI providers** — `ai-proxy` also supports `bedrock` (SigV4), `anthropic`, `azure-openai`, `gemini`.

Also check Kiro's built-in admin controls (e.g. prompt logging, if available on your plan) — they may
cover the logging requirement without interception.

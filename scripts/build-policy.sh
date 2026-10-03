#!/usr/bin/env bash
# Build APISIX policy objects from policy/*.lua + the live rules file into $KGW_DATA_DIR/generated/.
# Called by apply.sh and the console; safe to run on its own. Tracked config/ is never written.
set -euo pipefail
cd "$(dirname "$0")/.."
# Runtime state lives outside the code repo (git-ignored data/ by default):
#   $DATA/guardrails.json  the live rules, edited by the console (its own git history in $DATA)
#   $DATA/generated/       APISIX objects derived from it (rebuilt on every change, never edited)
DATA=${KGW_DATA_DIR:-data}
GEN="$DATA/generated"
mkdir -p "$GEN/global_rules" "$GEN/plugin_configs" "$GEN/routes" "$GEN/consumers"
[[ -f "$DATA/guardrails.json" ]] || { cp config/guardrails.default.json "$DATA/guardrails.json"; echo "seeded $DATA/guardrails.json from config/guardrails.default.json"; }
# Full request bodies hold the entire conversation + tool context (tens of KB, often code).
# Default: log only the current prompt (policy/inference-guard.lua). Set LOG_FULL_BODY=1 to
# also log the raw body (capped at LOG_MAX_BODY) for debugging.
LOG_MAX_BODY=${LOG_MAX_BODY:-65536}
# Prompt text in the audit log (and so in Loki and the portal): "masked" (default) keeps the
# prompt with every rule match masked; "off" logs no prompt text at all, only the verdict + rule.
# LOG_FULL_BODY=1 is a debugging aid that logs the RAW body and bypasses masking -- never in prod.
PROMPT_LOG=${PROMPT_LOG:-masked}
[[ "$PROMPT_LOG" == masked || "$PROMPT_LOG" == off ]] || { echo "PROMPT_LOG must be masked|off" >&2; exit 1; }
BODY_VAR='"-"'; [[ "${LOG_FULL_BODY:-0}" == 1 ]] && BODY_VAR='"$request_body"'

# ---------------------------------------------------------------------------
# Guardrail rules: $DATA/guardrails.json is the single source of truth for both the Kiro
# inference guard and the AI route's ai-prompt-guard. Validate before generating anything,
# so a bad edit can never reach the gateway.
# ---------------------------------------------------------------------------
G="$DATA/guardrails.json"
jq -e '
  (.rules | type == "array") and
  ([.rules[].id] | length == (unique | length)) and
  all(.rules[]; (.id | type == "string" and test("^[a-z0-9][a-z0-9-]{0,62}$"))
                and (.label | type == "string" and length > 0)
                and (.pattern | type == "string" and length > 0 and (contains("${") | not))
                and (.enabled | type == "boolean")
                and ((.case_insensitive // false) | type == "boolean")
                and (.applies_to | type == "array" and length > 0 and all(.[]; . == "kiro" or . == "ai")))
  and (.block_message | type == "string" and length > 0)
  and all(.guardrails[]; .enabled | type == "boolean")
  and ((.guardrails.kiro_ml_guard.fail_mode // "open") | . == "open" or . == "closed")
  and (.guardrails.kiro_rate_limit.requests > 0) and (.guardrails.kiro_rate_limit.window_seconds > 0)
  and (.guardrails.ai_token_budget.tokens > 0) and (.guardrails.ai_token_budget.window_seconds > 0)
' "$G" >/dev/null || { echo "invalid $G (schema check failed)" >&2; exit 1; }
# Regex syntax check with PCRE (same engine family as nginx/ngx.re).
while IFS= read -r p; do
  rc=0; printf '' | grep -qP -- "$p" 2>/dev/null || rc=$?
  [[ $rc -le 1 ]] || { echo "invalid regex in $G: $p" >&2; exit 1; }
done < <(jq -r '.rules[].pattern' "$G")
# Effective pattern per rule: (?i) prefix for case-insensitive rules (works in ngx.re and ai-prompt-guard).
rules_for() { jq -c --arg path "$1" '[.rules[] | select(.enabled and (.applies_to | index($path)))
  | {id, label: .label, pattern: ((if .case_insensitive then "(?i)" else "" end) + .pattern)}]' "$G"; }
# ml: second layer (ml-guard -> Bedrock Guardrails), called only when the regex rules pass.
KIRO_CFG=$(jq -c --argjson r "$(rules_for kiro)" \
  '{guard: .guardrails.kiro_prompt_guard.enabled, message: .block_message, rules: $r,
    ml: (.guardrails.kiro_ml_guard // {enabled: false} | {enabled, timeout_ms: (.timeout_ms // 1500),
         fail_mode: (.fail_mode // "open")})}' "$G")
[[ "$KIRO_CFG" != *']==]'* ]] || { echo "guardrails.json must not contain ]==]" >&2; exit 1; }
AI_DENY=$(rules_for ai | jq -c '[.[].pattern]')
gr() { jq -c ".guardrails.$1" "$G"; }

# Global rule: identity + audit log for every intercepted request.
# The log_format is an ALLOWLIST: no request headers are logged, so Authorization, cookies,
# and SigV4/x-amz-security-token never reach the audit log.
jq -n --rawfile ident policy/identity.lua --argjson maxb "$LOG_MAX_BODY" --argjson bodyvar "$BODY_VAR" '{
  plugins: {
    "serverless-pre-function": { phase: "access", functions: [$ident] },
    "prometheus": { prefer_name: true },
    "opentelemetry": { sampler: { name: "always_on" } },
    "file-logger": {
      path: "logs/kiro-audit.log",
      max_req_body_bytes: $maxb,
      log_format: {
        ts: "$time_iso8601", host: "$host", method: "$request_method", uri: "$uri",
        trace_id: "$opentelemetry_trace_id",
        op: "$http_x_amz_target", status: "$status", upstream_status: "$upstream_status",
        user: "$kiro_user", policy: "$kiro_policy", rule: "$kiro_rule", ua: "$http_user_agent",
        req_bytes: "$request_length", resp_bytes: "$body_bytes_sent",
        req_time: "$request_time", upstream_time: "$upstream_response_time",
        consumer: "$consumer_name", llm_model: "$llm_model", prompt_tokens: "$llm_prompt_tokens",
        completion_tokens: "$llm_completion_tokens",
        prompt: "$kiro_prompt", req_body_bytes: "$kiro_body_bytes",
        ml: "$kiro_ml", ml_ms: "$kiro_ml_ms",
        req_body: $bodyvar
      }
    }
  }
}' > "$GEN/global_rules/kiro-audit.json"

# Shared by all Kiro routes: never buffer streamed (event-stream) responses.
jq -n '{ desc: "Kiro control/telemetry hosts: observe only",
  plugins: { "proxy-buffering": { disable_proxy_buffering: true } } }' \
  > "$GEN/plugin_configs/kiro-observe.json"

# Inference: observe + content guard (rules from guardrails.json) + optional per-user rate limit.
jq -n --rawfile guard policy/inference-guard.lua --arg cfg "$KIRO_CFG" --arg plm "$PROMPT_LOG" --argjson rl "$(gr kiro_rate_limit)" '{
  desc: "Kiro inference: content guard + per-user rate limit (generated from the live rules (data/guardrails.json))",
  plugins: ({
    "proxy-buffering": { disable_proxy_buffering: true },
    "serverless-pre-function": { phase: "access",
      functions: [ $guard | split("__GUARDRAILS_JSON__") | join($cfg)
                          | split("__PROMPT_LOG_MODE__") | join($plm) ] }
  } + (if $rl.enabled then { "limit-count": {
      count: $rl.requests, time_window: $rl.window_seconds, key_type: "var", key: "kiro_user",
      rejected_code: 429, rejected_msg: "Rate limited by organization AI gateway",
      policy: "local", show_limit_quota_header: true } } else {} end))
}' > "$GEN/plugin_configs/kiro-inference.json"

# Intercepted-host routes (tracked, hand-written) must point at the policy that matches their host:
# runtime.* (inference) -> kiro-inference, every other Kiro host -> kiro-observe. Check, don't rewrite.
for f in config/routes/*.json; do
  [[ -e "$f" ]] || continue
  host=$(jq -r '.hosts[0] // empty' "$f")
  [[ -n "$host" ]] || continue
  pc=kiro-observe; [[ "$host" == runtime.* ]] && pc=kiro-inference
  [[ $(jq -r '.plugin_config_id // empty' "$f") == "$pc" ]] \
    || { echo "$f: plugin_config_id must be \"$pc\" for host $host" >&2; exit 1; }
done
echo "policy built"

# ---------------------------------------------------------------------------
# AI Gateway (OpenAI-compatible) -- POST http://<gw>:9080/v1/chat/completions
#   - clients authenticate to the GATEWAY with a per-user key (key-auth consumer);
#     the provider key stays on the gateway and is never handed to users.
#   - ai-prompt-guard: deny rules from the live rules (data/guardrails.json) (applies_to "ai").
#   - ai-rate-limiting: per-consumer token budget (guardrails.ai_token_budget).
#   - provider: OpenAI when OPENAI_API_KEY is set in .env, otherwise a local mock LLM
#     so the pipeline is demoable with no external key.
# Secrets are left as ${VAR} placeholders here; apply.sh substitutes them from .env.
# ---------------------------------------------------------------------------
if [[ -n "${OPENAI_API_KEY:-}" ]]; then
  PROVIDER=$(jq -n '{provider: "openai",
    auth: {header: {Authorization: "Bearer ${OPENAI_API_KEY}"}},
    options: {model: "gpt-4o-mini"}}')
  MODE=openai
else
  PROVIDER=$(jq -n '{provider: "openai-compatible",
    auth: {header: {Authorization: "Bearer ${AI_GW_MOCK_TOKEN}"}},
    options: {model: "mock-llm"},
    override: {endpoint: "http://127.0.0.1:9080/__mock/v1/chat/completions"}}')
  MODE=mock
fi

jq -n --argjson p "$PROVIDER" --argjson deny "$AI_DENY" \
      --argjson pg "$(gr ai_prompt_guard)" --argjson tb "$(gr ai_token_budget)" '{
  name: "ai-chat", desc: "OpenAI-compatible AI Gateway route (guardrails from the live rules (data/guardrails.json))",
  uri: "/v1/chat/completions", methods: ["POST"],
  plugins: ({
    "key-auth": {},
    "ai-proxy": ($p + { logging: { summaries: true, payloads: false }, timeout: 60000 })
  }
  + (if $pg.enabled and ($deny | length) > 0
       then { "ai-prompt-guard": { deny_patterns: $deny, match_all_roles: false } } else {} end)
  + (if $tb.enabled then { "ai-rate-limiting": { limit: $tb.tokens, time_window: $tb.window_seconds,
       limit_strategy: "total_tokens", rejected_code: 429, rejected_msg: "Token budget exceeded" } } else {} end))
}' > "$GEN/routes/ai-chat.json"

# Mock LLM: OpenAI-shaped response. Only matches requests carrying the gateway-internal mock
# token (sent by ai-proxy); anything else gets 404. (ip-restriction is not usable here: Docker's
# port proxy makes host traffic look local.)
jq -n '{
  name: "ai-mock-llm", desc: "Local mock LLM for keyless demos (internal token only)",
  uri: "/__mock/v1/chat/completions", methods: ["POST"],
  vars: [["http_authorization", "==", "Bearer ${AI_GW_MOCK_TOKEN}"]],
  plugins: {
    "mocking": { content_type: "application/json", response_status: 200,
      response_example: "{\"id\":\"chatcmpl-mock\",\"object\":\"chat.completion\",\"model\":\"mock-llm\",\"choices\":[{\"index\":0,\"message\":{\"role\":\"assistant\",\"content\":\"MOCK_OK: the AI Gateway forwarded your prompt.\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":12,\"completion_tokens\":9,\"total_tokens\":21}}" }
  }
}' > "$GEN/routes/ai-mock-llm.json"

# Demo consumer (one per user in production, or federate via openid-connect).
jq -n '{ username: "demo_user", desc: "Demo AI Gateway user",
  plugins: { "key-auth": { key: "${AI_GW_DEMO_KEY}" } } }' > "$GEN/consumers/demo_user.json"
echo "ai-gateway provider: $MODE"

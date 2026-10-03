#!/usr/bin/env bash
# AI Gateway demo/smoke test. Loads the demo consumer key from .env (never printed).
# Usage: scripts/ai-demo.sh            -> run all checks
#        scripts/ai-demo.sh "prompt"   -> send one prompt and print the reply
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; source ./.env; set +a
GW=${AI_GW_URL:-http://127.0.0.1:9080}

chat() {  # chat <prompt> [extra curl args...]
  local p=$1; shift
  curl -sS -w '\n%{http_code}' "$GW/v1/chat/completions" -H 'Content-Type: application/json' "$@" \
    -d "$(jq -n --arg p "$p" '{messages: [{role: "user", content: $p}]}')"
}

if [[ $# -gt 0 ]]; then
  chat "$1" -H "apikey: $AI_GW_DEMO_KEY" | sed '$d' | jq -r '.choices[0].message.content // .'
  exit 0
fi

check() {  # check <label> <expected-code> <output>
  local code=${3##*$'\n'} body=${3%$'\n'*}
  local ok=FAIL; [[ "$code" == "$2" ]] && ok=PASS
  printf '%-4s %-38s expect=%s got=%s  %s\n' "$ok" "$1" "$2" "$code" "$(echo "$body" | head -c 110 | tr '\n' ' ')"
}
check "no gateway key"              401 "$(chat 'hello')"
check "wrong gateway key"           401 "$(chat 'hello' -H 'apikey: wrong')"
check "allowed prompt"              200 "$(chat 'Say hello' -H "apikey: $AI_GW_DEMO_KEY")"
check "deny: demo keyword"          400 "$(chat 'please KIRO-GATEWAY-BLOCK-DEMO' -H "apikey: $AI_GW_DEMO_KEY")"
check "deny: AWS access key id"     400 "$(chat 'my key AKIAABCDEFGHIJKLMNOP' -H "apikey: $AI_GW_DEMO_KEY")"
check "mock LLM not reachable from outside" 404 "$(curl -sS -w '\n%{http_code}' -X POST "$GW/__mock/v1/chat/completions" -d '{}')"
echo "--- token budget headers (allowed request)"
curl -sS -D - -o /dev/null "$GW/v1/chat/completions" -H 'Content-Type: application/json' -H "apikey: $AI_GW_DEMO_KEY" \
  -d '{"messages":[{"role":"user","content":"hi"}]}' | grep -iE '^x-ai-ratelimit|^x-ratelimit' || echo "(no quota headers)"

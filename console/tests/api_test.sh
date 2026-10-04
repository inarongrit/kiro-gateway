#!/usr/bin/env bash
# Guardrail Console API tests (run on the gateway host). Reads the console password from
# pki/console-initial-password (never printed). Leaves rules exactly as it found them.
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1
B=${CONSOLE_URL:-https://127.0.0.1:9180}
CA=pki/ca.crt; J=$(mktemp -d); trap 'rm -rf "$J"' EXIT
fails=0; ok() { printf 'PASS  %s\n' "$*"; }; no() { printf 'FAIL  %s\n' "$*"; fails=$((fails+1)); }
expect() { [[ "$2" == "$3" ]] && ok "$1 ($3)" || no "$1 (expected $2, got $3)"; }
c()  { curl -sS --cacert $CA -b "$J/c" -c "$J/c" -o "$J/out" -w '%{http_code}' "$@"; }
cm() { c -H 'X-Console: 1' -H 'Content-Type: application/json' "$@"; }
body() { cat "$J/out"; }

expect "health (no login needed)"            200 "$(c $B/api/health)"
expect "rules need login"                     401 "$(c $B/api/guardrails)"
expect "login without X-Console header"       403 "$(c -H 'Content-Type: application/json' -d '{"username":"admin","password":"x"}' $B/api/login)"
expect "wrong password"                       401 "$(cm -d '{"username":"admin","password":"wrong"}' $B/api/login)"
pw=$(cat pki/console-initial-password)
expect "correct login"                        200 "$(cm -d "$(jq -n --arg p "$pw" '{username:"admin",password:$p}')" $B/api/login)"
grep -q 'gc_session' "$J/c" && grep -qi 'TRUE.*gc_session' "$J/c" && ok "session cookie is Secure" || no "session cookie flags"
expect "status"                               200 "$(c $B/api/status)"; jq -c . "$J/out"
expect "get rules"                            200 "$(c $B/api/guardrails)"
cp "$J/out" "$J/orig.json"; ver=$(jq -r .version "$J/orig.json")

expect "cross-origin mutation refused"        403 "$(cm -H 'Origin: https://evil.example' -d '{"pattern":"a"}' $B/api/check-pattern)"
expect "pattern check: invalid"               200 "$(cm -d '{"pattern":"AKIA[0-9"}' $B/api/check-pattern)"; [[ $(jq .valid "$J/out") == false ]] && ok "invalid regex reported" || no "invalid regex not reported"
expect "prompt tester"                        200 "$(cm -d '{"text":"my key AKIAABCDEFGHIJKLMNOP","path":"kiro"}' $B/api/test-prompt)"
[[ $(jq -r '.would_block' "$J/out") == true && $(jq -r '.matches[0].id' "$J/out") == aws-access-key-id ]] && ok "tester: AKIA blocked by aws-access-key-id" || no "tester: $(body)"
grep -q 'AKIAABCDEFGHIJKLMNOP' "$J/out" && no "tester echoes the raw secret" || ok "tester returns only a masked preview ($(jq -r '.matches[0].preview' "$J/out"))"
cm -d '{"text":"key ＡＫＩＡＡＢＣＤＥＦＧＨＩＪＫＬＭＮＯＰ","path":"kiro"}' $B/api/test-prompt >/dev/null
[[ $(jq -r '.would_block' "$J/out") == true && $(jq -r '.normalised' "$J/out") == true ]] && ok "tester: full-width AWS key normalised and blocked" || no "tester full-width: $(body)"
cm -d '{"text":"hello world","path":"ai"}' $B/api/test-prompt >/dev/null; [[ $(jq .would_block "$J/out") == false ]] && ok "tester: clean prompt allowed" || no "tester clean: $(body)"
if [[ $(c $B/api/guardrails >/dev/null; jq -r '.config.guardrails.kiro_ml_guard.enabled // false' "$J/out") == true ]]; then
  cm -d '{"text":"Write a welcome letter to John Michael Carter, 742 Evergreen Terrace, Springfield, IL 62704","path":"kiro"}' $B/api/test-prompt >/dev/null
  [[ $(jq -r '.would_block' "$J/out") == true && $(jq -r '.ml.action' "$J/out") == block && $(jq -r '[.matches[] | select(.layer == "ml")] | length' "$J/out") -gt 0 ]] \
    && ok "tester: Bedrock layer blocks a name + address the regex rules miss ($(jq -r '.ml.policies | join(",")' "$J/out"), $(jq -r '.ml.latency_ms' "$J/out") ms)" || no "tester ml: $(body)"
  grep -q 'John Michael Carter\|Evergreen Terrace' "$J/out" && no "tester echoes Bedrock-detected PII" || ok "tester returns only masked previews for Bedrock matches"
fi

save() { jq --arg v "$1" '.config + {base_version: $v} | del(._doc, .version)' "$2" > "$J/put.json"; cm -X PUT --data-binary @"$J/put.json" $B/api/guardrails; }
jq '.config.rules += [{"id":"api-test","label":"API test rule","pattern":"api-test-zz[0-9]+","applies_to":["kiro","ai"],"enabled":true}]' "$J/orig.json" > "$J/new.json"
expect "stale version refused"                409 "$(save deadbeef "$J/new.json")"
jq '.config.rules += [{"id":"bad","label":"bad","pattern":"(unclosed","applies_to":["kiro"],"enabled":true}]' "$J/orig.json" > "$J/bad.json"
expect "invalid regex refused on save"        422 "$(save "$ver" "$J/bad.json")"
jq '.config.rules += [{"id":"BAD ID","label":"x","pattern":"x","applies_to":["kiro"],"enabled":true}]' "$J/orig.json" > "$J/bad2.json"
expect "invalid rule id refused"              422 "$(save "$ver" "$J/bad2.json")"
expect "add rule (apply + commit)"            200 "$(save "$ver" "$J/new.json")"; echo "      commit: $(jq -r .commit "$J/out")"
ver2=$(jq -r .version "$J/out")
grep -q 'api-test-zz' data/generated/plugin_configs/kiro-inference.json && grep -q 'api-test-zz' data/generated/routes/ai-chat.json \
  && ok "rule reached generated Kiro + AI policy" || no "rule missing from generated policy"
code=$(curl -s -o /dev/null -w '%{http_code}' --cacert $CA -x http://127.0.0.1:3128 -X POST -H 'Content-Type: application/x-amz-json-1.0' \
  -d '{"conversationState":{"currentMessage":{"userInputMessage":{"content":"x api-test-zz42"}}}}' https://runtime.us-east-1.kiro.dev/)
expect "live gateway blocks the new rule (Kiro path)" 403 "$code"
git -C data log -1 --format='%an | %s' -- guardrails.json | grep -q "Guardrail Console (admin) | guardrails: added 'API test rule'" \
  && ok "git commit records who + what" || no "commit: $(git -C data log -1 --format='%an | %s')"
expect "history"                              200 "$(c $B/api/history)"; jq -r '.changes[0].summary' "$J/out" | sed 's/^/      /'
expect "restore original rules"               200 "$(save "$ver2" "$J/orig.json")"
grep -q 'api-test-zz' data/generated/plugin_configs/kiro-inference.json && no "test rule still present" || ok "test rule removed"
expect "events"                               200 "$(c "$B/api/events?hours=24&limit=5")"; jq -c '.events[0] | {ts,path,result,rule,user,op,latency_ms}' "$J/out"
expect "stats"                                200 "$(c "$B/api/stats?hours=24")"; jq -c '{requests,blocked,users,by_rule,latency_ms,protections_on}' "$J/out"
expect "obs traffic"                          200 "$(c "$B/api/obs/traffic?hours=24")"; jq -c '.totals' "$J/out"
jq -e '(.codes | type == "array") and (.per_minute_by_route.rows | type == "array")' "$J/out" >/dev/null && ok "obs traffic shape" || no "obs traffic shape"
expect "obs latency"                          200 "$(c "$B/api/obs/latency?hours=24")"; jq -c '{kiro_chat_ms,gateway_overhead_ms}' "$J/out"
expect "obs usage"                            200 "$(c "$B/api/obs/usage?hours=24")"; jq -c '{kiro_chats,ai_calls,active_users,ai_tokens}' "$J/out"
expect "obs traces"                           200 "$(c "$B/api/obs/traces?hours=24&kind=chat&limit=5")"
tid=$(jq -r '.traces[0].trace_id // empty' "$J/out")
for _ in 1 2 3 4 5 6; do   # Tempo search lags ingest by ~10-20 s on a freshly started stack
  [[ -n "$tid" ]] && break
  sleep 5; c "$B/api/obs/traces?hours=24&kind=chat&limit=5" >/dev/null; tid=$(jq -r '.traces[0].trace_id // empty' "$J/out")
done
[[ -n "$tid" ]] && expect "obs trace detail"  200 "$(c "$B/api/obs/traces/$tid")" || no "no traces in last 24h"
expect "obs trace id is validated"            422 "$(c "$B/api/obs/traces/not-hex")"
expect "obs window is bounded"                422 "$(c "$B/api/obs/traffic?hours=99999")"
expect "obs rejects unknown trace filter"     422 "$(c "$B/api/obs/traces?kind=raw")"
expect "logout"                               200 "$(cm -X POST $B/api/logout)"
expect "rules need login again"               401 "$(c $B/api/guardrails)"
expect "obs needs login"                      401 "$(c "$B/api/obs/traffic")"
echo; [[ $fails -eq 0 ]] && echo "ALL CONSOLE API CHECKS PASSED" || echo "$fails CONSOLE CHECK(S) FAILED"; exit $fails

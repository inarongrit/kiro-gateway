#!/usr/bin/env bash
# End-to-end verification of the Kiro gateway PoC. Re-runnable; prints PASS/FAIL per check.
# Requires: stack up, kiro-cli logged in. Secrets are loaded internally and never printed.
set -uo pipefail
cd "$(dirname "$0")/.."
GW_DIR=$PWD; PROXY=http://127.0.0.1:3128; CA=pki/ca.crt; TOGGLE=scripts/kiro-via-gateway
SCRATCH=${KIROCREW_SCRATCH:-${TMPDIR:-/tmp}}; fails=0
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; fails=$((fails+1)); }
expect() { [[ "$2" == "$3" ]] && pass "$1 ($3)" || fail "$1 (expected $2, got $3)"; }
audit() { docker compose exec -T apisix cat /usr/local/apisix/logs/kiro-audit.log 2>/dev/null; }
squid_lines() {  # Kiro-host entries only (the toggle's own health probe hits aws.amazon.com)
  docker compose exec -T squid cat /var/log/squid/access.log 2>/dev/null | grep -cE 'kiro\.dev:443|q\.us-east-1\.amazonaws\.com:443'; }
strip() { sed 's/\x1b\[[0-9;]*[mGKH]//g' | tr '\n' ' '; }
kiro() { (cd "$SCRATCH" && timeout 150 "$@" kiro-cli chat --no-interactive --trust-tools= "Reply with exactly: PROXY_OK" 2>&1 | strip); }

echo "== 1. stack"
for s in etcd apisix squid; do
  st=$(docker compose ps --format '{{.Service}} {{.State}}' | awk -v s=$s '$1==s{print $2}')
  expect "container $s" running "${st:-missing}"
done
pub=$(docker compose ps --format '{{.Ports}}' | tr ',' '\n' | grep -- '->' | grep -v '127.0.0.1:' | grep -vcE '0\.0\.0\.0:9180->9200')
expect "nothing public except the Guardrail Console (9180)" 0 "$pub"

echo "== 2. tunneled host (not intercepted: verifies with public CAs only)"
expect "aws.amazon.com via proxy, default trust" 200 "$(curl -s -o /dev/null -w '%{http_code}' -x $PROXY https://aws.amazon.com/)"

echo "== 3. intercepted Kiro host"
H=runtime.us-east-1.kiro.dev
curl -s -o /dev/null -x $PROXY https://$H/; expect "$H without test CA is rejected (curl exit 60)" 60 "$?"
issuer=$(curl -sv -o /dev/null --cacert $CA -x $PROXY https://$H/ 2>&1 | sed -n 's/^\*  *issuer: //p' | head -1)
[[ "$issuer" == *"Kiro Gateway Test CA"* ]] && pass "$H served by gateway cert" || fail "$H issuer: $issuer"
expect "$H via gateway == direct status" "$(curl -s -o /dev/null -w '%{http_code}' https://$H/)" \
  "$(curl -s -o /dev/null -w '%{http_code}' --cacert $CA -x $PROXY https://$H/)"

echo "== 4. blocked prompt (raw request, no credentials needed: policy runs before upstream)"
body='{"conversationState":{"currentMessage":{"userInputMessage":{"content":"hello KIRO-GATEWAY-BLOCK-DEMO"}}}}'
expect "demo keyword on inference host" 403 "$(curl -s -o /dev/null -w '%{http_code}' --cacert $CA -x $PROXY -X POST \
  -H 'Content-Type: application/x-amz-json-1.0' -H 'X-Amz-Target: AmazonCodeWhispererStreamingService.GenerateAssistantResponse' \
  -d "$body" https://$H/)"
since4=$(date -u +%Y-%m-%dT%H:%M:%S)
akia='{"conversationState":{"currentMessage":{"userInputMessage":{"content":"key AKIAABCDEFGHIJKLMNOP"}}}}'
expect "AWS access key ID on inference host" 403 "$(curl -s -o /dev/null -w '%{http_code}' --cacert $CA -x $PROXY -X POST \
  -H 'Content-Type: application/x-amz-json-1.0' -d "$akia" https://$H/)"
clean='{"conversationState":{"currentMessage":{"userInputMessage":{"content":"hello world"}}}}'
code=$(curl -s -o /dev/null -w '%{http_code}' --cacert $CA -x $PROXY -X POST -H 'Content-Type: application/x-amz-json-1.0' -d "$clean" https://$H/)
[[ "$code" != 403 ]] && pass "clean prompt not blocked by gateway ($code from upstream)" || fail "clean prompt blocked (403)"
sleep 1
expect "audit log names the matched rule" aws-access-key-id \
  "$(audit | jq -r --arg s "$since4" 'select(.policy=="blocked" and (.ts|.[0:19]) >= $s) | .rule' | tail -1)"
badpat=$(docker compose logs --since "${since4}Z" apisix 2>&1 | grep -c "bad pattern in rule")
expect "no rule pattern errors in gateway log" 0 "$badpat"
if [[ $(jq -r '.guardrails.kiro_ml_guard.enabled // false' data/guardrails.json) == true ]]; then
  since5=$(date -u +%Y-%m-%dT%H:%M:%S)
  pii='{"conversationState":{"currentMessage":{"userInputMessage":{"content":"Write a welcome letter to John Michael Carter, 742 Evergreen Terrace, Springfield, IL 62704"}}}}'
  expect "Bedrock layer blocks name + address (regex rules miss it)" 403 "$(curl -s -o /dev/null -w '%{http_code}' --cacert $CA -x $PROXY -X POST \
    -H 'Content-Type: application/x-amz-json-1.0' -d "$pii" https://$H/)"
  sleep 1
  last=$(audit | jq -c --arg s "$since5" 'select(.policy=="blocked" and (.ts|.[0:19]) >= $s)' | tail -1)
  [[ $(jq -r '.rule' <<<"$last") == bedrock:pii:* ]] && pass "audit log names the Bedrock policy ($(jq -r '.rule + ", " + .ml_ms + " ms"' <<<"$last"))" \
    || fail "Bedrock block not in audit log: ${last:0:200}"
  grep -q 'John Michael Carter\|Evergreen Terrace' <<<"$last" && fail "Bedrock-detected PII stored in clear text" \
    || pass "Bedrock-detected PII masked in the audit log"
fi

echo "== 5. AI Gateway route"
out=$(scripts/ai-demo.sh); echo "$out" | sed 's/^/      /' | cut -c1-100
n=$(grep -c '^FAIL' <<<"$out"); expect "ai-demo.sh failures" 0 "$n"

echo "== 6. kiro-cli via gateway (toggle 'run') + audit log"
since=$(date -u +%Y-%m-%dT%H:%M:%S)
r=$(kiro "$GW_DIR/$TOGGLE" run); [[ "$r" == *PROXY_OK* ]] && pass "kiro-cli via gateway answered" || fail "kiro-cli via gateway: ${r: -200}"
sleep 1
entry=$(audit | jq -c --arg s "$since" 'select(.host=="runtime.us-east-1.kiro.dev" and .op=="AmazonCodeWhispererStreamingService.GenerateAssistantResponse" and (.ts|.[0:19]) >= $s)' | tail -1)
[[ -n "$entry" ]] && pass "inference request in audit log: $(jq -r '"status=\(.status) policy=\(.policy) user=\(.user) prompt_chars=\(.prompt|length)"' <<<"$entry")" \
                  || fail "no inference entry in audit log since $since"
leaks=$(audit | grep -ciE 'bearer |"authorization"|x-amz-security-token|aws_secret')
expect "credential strings in audit log" 0 "$leaks"

echo "== 7. toggle off -> direct"
before=$(squid_lines)
r=$(cd "$SCRATCH" && bash -c "source '$GW_DIR/$TOGGLE' on >/dev/null && source '$GW_DIR/$TOGGLE' off >/dev/null && \
     [[ -z \${HTTPS_PROXY:-} ]] && timeout 150 kiro-cli chat --no-interactive --trust-tools= 'Reply with exactly: PROXY_OK'" 2>&1 | strip)
[[ "$r" == *PROXY_OK* ]] && pass "kiro-cli after 'off' answered" || fail "kiro-cli after off: ${r: -200}"
expect "no Kiro traffic through Squid from the 'off' run" 0 "$(( $(squid_lines) - before ))"

echo; [[ $fails -eq 0 ]] && echo "ALL CHECKS PASSED" || echo "$fails CHECK(S) FAILED"
exit $fails

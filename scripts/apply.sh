#!/usr/bin/env bash
# Declarative apply: PUT every object to the Admin API. Idempotent. Sources, per kind:
#   config/<kind>/*.json            hand-written, tracked in git
#   $KGW_DATA_DIR/generated/<kind>/ built from the live rules by build-policy.sh (not tracked)
#   pki/ssls/*.json                 intercept certs incl. private keys (not tracked)
# Kinds: plugin_metadata, upstreams, plugin_configs, global_rules, consumers, ssls, routes.
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; source .env; set +a
DATA=${KGW_DATA_DIR:-data}
ENV_VARS=$(sed -nE 's/^([A-Za-z_][A-Za-z0-9_]*)=.*/${\1}/p' .env | tr '\n' ' ')
ADMIN="${APISIX_ADMIN_URL:-https://127.0.0.1:9181}/apisix/admin"   # host-local admin port
./scripts/build-policy.sh
for kind in ${APPLY_KINDS:-plugin_metadata upstreams plugin_configs global_rules consumers ssls routes}; do
  for f in config/$kind/*.json "$DATA/generated/$kind"/*.json $( [[ $kind == ssls ]] && echo pki/ssls/*.json ); do
    [[ -e "$f" ]] || continue
    [[ "$(basename "$f")" == _* ]] && continue   # _*.json = shared fragments, not objects
    id=$(basename "$f" .json)
    # Substitute ONLY variables defined in .env; APISIX's own $vars (log_format) must survive.
    body=$(envsubst "$ENV_VARS" < "$f")
    # Fail closed: an unresolved ${VAR} would otherwise become a literal (guessable) secret.
    if grep -qE '\$\{[A-Za-z_][A-Za-z0-9_]*\}' <<<"$body"; then
      echo "unresolved placeholder in $f: $(grep -oE '\$\{[A-Za-z_][A-Za-z0-9_]*\}' <<<"$body" | sort -u | tr '\n' ' ')" >&2
      exit 1
    fi
    resp=$(mktemp)
    code=$(curl -sS --cacert pki/ca.crt -o "$resp" -w '%{http_code}' -X PUT "$ADMIN/$kind/$id" \
      -H "X-API-KEY: $APISIX_ADMIN_KEY" -H 'Content-Type: application/json' --data-binary "$body")
    echo "$kind/$id -> $code"
    if [[ ! "$code" =~ ^20[01]$ ]]; then
      echo "apply failed for $f: $(head -c 500 "$resp")" >&2; rm -f "$resp"; exit 1
    fi
    rm -f "$resp"
  done
done

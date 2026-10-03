#!/usr/bin/env bash
# Thin Admin API wrapper that loads the key internally (key never appears on the command line).
# Usage: scripts/admin.sh GET|DELETE <kind>/<id>
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; source ./.env; set +a
method=${1:?method}; path=${2:?path}
[[ "$method" =~ ^(GET|DELETE)$ ]] || { echo "only GET/DELETE" >&2; exit 1; }
[[ "$path" =~ ^[a-z_]+(/[A-Za-z0-9_-]+)?$ ]] || { echo "bad path" >&2; exit 1; }
curl -sS --cacert pki/ca.crt -w '\n%{http_code}\n' -X "$method" -H "X-API-KEY: $APISIX_ADMIN_KEY" \
  "${APISIX_ADMIN_URL:-https://127.0.0.1:9181}/apisix/admin/$path"

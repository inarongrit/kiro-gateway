#!/usr/bin/env bash
# First-time setup for a fresh clone (idempotent: never overwrites an existing secret, key or cert).
#   - .env from .env.example, with generated secrets (admin key, AI route keys, console password)
#   - pki/: test CA, intercept certs for every host in squid/hosts, the portal's TLS cert,
#     Grafana admin password
#   - data/: live guardrail rules (seeded from config/guardrails.default.json, own git history)
#     and the Squid client allow list from KGW_PROXY_ALLOW_CIDRS (rewritten on every run)
# Then: docker compose up -d && scripts/apply.sh
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077

[[ -f .env ]] || { cp .env.example .env; echo "created .env from .env.example"; }
chmod 600 .env

# Set KEY in .env only if it is missing or empty.
fill() {
  local key=$1 value=$2
  if ! grep -qE "^${key}=.+" .env; then
    local tmp; tmp=$(mktemp .env.XXXX)
    grep -vE "^${key}=" .env > "$tmp" || true
    printf '%s=%s\n' "$key" "$value" >> "$tmp"
    mv "$tmp" .env; chmod 600 .env
    echo "generated $key"
  fi
}
fill APISIX_ADMIN_KEY "$(openssl rand -hex 24)"
fill AI_GW_DEMO_KEY "$(openssl rand -hex 24)"
fill AI_GW_MOCK_TOKEN "$(openssl rand -hex 24)"
# The console container runs as the user owning this checkout, so it can write data/ (rules,
# their git history). Never root: as root (e.g. a provisioning script) fall back to 1000.
uid=$(id -u); gid=$(id -g); (( uid == 0 )) && { uid=1000; gid=1000; }
fill KGW_UID "$uid"
fill KGW_GID "$gid"
set -a; source .env; set +a

mkdir -p pki data && chmod 700 pki
[[ -n "${CONSOLE_PASSWORD_HASH:-}" ]] || scripts/console-passwd.sh "${CONSOLE_USER:-admin}"

scripts/make-ca.sh
# Intercept certs (+ APISIX ssl objects in pki/ssls) for every intercepted host.
hosts=$(awk '!/^#/ && NF >= 2 {print $2}' squid/hosts)
missing=(); for h in $hosts; do [[ -f "pki/ssls/$(tr . - <<<"$h").json" ]] || missing+=("$h"); done
(( ${#missing[@]} == 0 )) || scripts/issue-cert.sh "${missing[@]}"
# Portal / Admin API TLS cert.
if [[ ! -f pki/admin/admin.crt ]]; then
  IFS=',' read -ra names <<<"${KGW_PUBLIC_NAMES:-}"
  scripts/make-admin-cert.sh "${names[@]}"
fi
if [[ ! -f pki/grafana-admin-password ]]; then
  openssl rand -base64 24 | tr -d '\n' > pki/grafana-admin-password
  chmod 644 pki/grafana-admin-password   # read by the Grafana container user; pki/ itself is 0700
  echo "generated pki/grafana-admin-password"
fi

# Squid client allow list (one CIDR per line). Empty = only this host.
: > data/squid-allowed-clients.txt
IFS=',' read -ra cidrs <<<"${KGW_PROXY_ALLOW_CIDRS:-}"
for c in "${cidrs[@]}"; do
  c=$(tr -d '[:space:]' <<<"$c"); [[ -n "$c" ]] || continue
  [[ "$c" =~ ^[0-9a-fA-F:.]+/[0-9]{1,3}$ ]] || { echo "bad CIDR in KGW_PROXY_ALLOW_CIDRS: $c" >&2; exit 1; }
  echo "$c" >> data/squid-allowed-clients.txt
done
# Squid rejects an acl file with no entries; a loopback entry keeps the file valid when empty.
[[ -s data/squid-allowed-clients.txt ]] || echo "127.0.0.1/32" > data/squid-allowed-clients.txt
chmod 644 data/squid-allowed-clients.txt

# Live rules (build-policy.sh also seeds; the console starts the rule history on first use).
[[ -f data/guardrails.json ]] || cp config/guardrails.default.json data/guardrails.json
chmod 755 data; chmod 644 data/guardrails.json

echo "init done. Next: docker compose up -d && scripts/apply.sh"
if [[ -f pki/console-initial-password ]]; then
  echo "console sign-in: ${CONSOLE_USER:-admin} / password in pki/console-initial-password"
fi

#!/usr/bin/env bash
# Declaratively add an intercepted hostname:
#   - leaf cert from the test CA          -> pki/ssls/<id>.json  (secret, git-ignored)
#   - upstream to the real host over TLS  -> config/upstreams/<id>.json
#   - route matching the Host             -> config/routes/<id>.json
#   - Squid DNS override to APISIX        -> squid/hosts
# Upstream trust anchors are copied from config/upstreams/_trust.json (public root certs).
# Usage: scripts/intercept-host.sh <hostname> ...   then: scripts/apply.sh && docker compose restart squid
set -euo pipefail
cd "$(dirname "$0")/.."
APISIX_IP=172.30.0.10
for host in "$@"; do
  [[ "$host" =~ ^[A-Za-z0-9.-]+$ ]] || { echo "bad hostname: $host" >&2; exit 1; }
  id=$(echo "$host" | tr '.' '-')
  ./scripts/issue-cert.sh "$host" >/dev/null
  jq --arg h "$host" '{
      name: $h, desc: ("Real " + $h + " endpoint; TLS verified against pinned public roots"),
      type: "roundrobin", scheme: "https", pass_host: "node",
      nodes: {($h + ":443"): 1},
      tls: {verify: true, ca_certs: .ca_certs},
      timeout: {connect: 10, send: 300, read: 300}
    }' config/upstreams/_trust.json > "config/upstreams/$id.json"
  jq -n --arg h "$host" --arg id "$id" '{
      name: $h, desc: ("Intercept " + $h + ": TLS terminated at APISIX, re-encrypted upstream"),
      hosts: [$h], uri: "/*", upstream_id: $id
    }' > "config/routes/$id.json"
  grep -qE "[[:space:]]$host\$" squid/hosts || echo "$APISIX_IP $host" >> squid/hosts
  echo "intercepting $host (id=$id)"
done

#!/usr/bin/env bash
# Issue a leaf cert from the test CA for each hostname and emit an APISIX SSL object.
# Private keys never enter git: output lands in pki/ (git-ignored) and apply.sh picks up pki/ssls/*.json.
# Usage: scripts/issue-cert.sh host1 [host2 ...]
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -f pki/ca.key ]] || { echo "run scripts/make-ca.sh first" >&2; exit 1; }
mkdir -p pki/leaf pki/ssls
umask 077
for host in "$@"; do
  [[ "$host" =~ ^[A-Za-z0-9.-]+$ ]] || { echo "bad hostname: $host" >&2; exit 1; }
  key="pki/leaf/$host.key"; crt="pki/leaf/$host.crt"
  openssl req -new -nodes -newkey rsa:2048 -keyout "$key" -subj "/CN=$host" -out "pki/leaf/$host.csr" 2>/dev/null
  openssl x509 -req -in "pki/leaf/$host.csr" -CA pki/ca.crt -CAkey pki/ca.key -CAcreateserial \
    -days 90 -sha256 -out "$crt" 2>/dev/null \
    -extfile <(printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\nbasicConstraints=CA:FALSE\n' "$host")
  id=$(echo "$host" | tr '.' '-')
  jq -n --arg sni "$host" --rawfile cert "$crt" --rawfile key "$key" \
    '{snis: [$sni], cert: $cert, key: $key}' > "pki/ssls/$id.json"
  echo "issued $host -> pki/ssls/$id.json"
done

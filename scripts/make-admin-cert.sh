#!/usr/bin/env bash
# Issue the Admin API / dashboard TLS cert from the test CA.
# Usage: scripts/make-admin-cert.sh <public-ip-or-dns> [more SANs...]   (127.0.0.1, localhost and apisix always added)
# Output: pki/admin/admin.{crt,key}. pki/ is 0700 and git-ignored; the key file is 0644 only so the
# container's non-root apisix user can read it through the read-only bind mount.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -f pki/ca.key ]] || { echo "run scripts/make-ca.sh first" >&2; exit 1; }
san="IP:127.0.0.1,DNS:localhost,DNS:apisix"   # apisix: the console reaches the Admin API by service name
for n in "$@"; do
  if [[ "$n" =~ ^[0-9]+(\.[0-9]+){3}$ ]]; then san+=",IP:$n"
  elif [[ "$n" =~ ^[A-Za-z0-9.-]+$ ]]; then san+=",DNS:$n"
  else echo "bad name: $n" >&2; exit 1; fi
done
mkdir -p pki/admin
openssl req -new -nodes -newkey rsa:2048 -keyout pki/admin/admin.key -subj "/CN=apisix-admin" \
  -out pki/admin/admin.csr 2>/dev/null
openssl x509 -req -in pki/admin/admin.csr -CA pki/ca.crt -CAkey pki/ca.key -CAcreateserial \
  -days 90 -sha256 -out pki/admin/admin.crt 2>/dev/null \
  -extfile <(printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\nbasicConstraints=CA:FALSE\n' "$san")
rm -f pki/admin/admin.csr
chmod 755 pki/admin; chmod 644 pki/admin/admin.crt pki/admin/admin.key
echo "issued pki/admin/admin.crt  SAN=$san"

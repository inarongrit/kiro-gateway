#!/usr/bin/env bash
# Create a local TEST root CA (never use in production; org rollout uses the internal PKI).
# Output: pki/ca.key (0600), pki/ca.crt. Idempotent: keeps an existing CA.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p pki && chmod 700 pki
if [[ -f pki/ca.crt && -f pki/ca.key ]]; then
  echo "CA already exists: pki/ca.crt"; exit 0
fi
umask 077
openssl req -x509 -new -nodes -newkey rsa:3072 -sha256 -days 365 \
  -keyout pki/ca.key -out pki/ca.crt \
  -subj "/CN=Kiro Gateway Test CA/O=Kiro Gateway" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"
chmod 644 pki/ca.crt
echo "Created pki/ca.crt"

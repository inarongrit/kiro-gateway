#!/usr/bin/env bash
# Set the Guardrail Console login. Stores only an scrypt hash in .env.
#   scripts/console-passwd.sh <username>            # generate a random password
#   scripts/console-passwd.sh <username> --stdin    # read the password from stdin
# A generated password is written once to pki/console-initial-password (0600, git-ignored)
# and never printed. Restart the console afterwards: docker compose up -d console
set -euo pipefail
cd "$(dirname "$0")/.."
user=${1:?usage: $0 <username> [--stdin]}
[[ "$user" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || { echo "bad username" >&2; exit 1; }
if [[ "${2:-}" == --stdin ]]; then
  IFS= read -r pw; [[ ${#pw} -ge 12 ]] || { echo "password must be at least 12 characters" >&2; exit 1; }
else
  pw=$(openssl rand -base64 18 | tr -d '/+=' | cut -c1-20)
  ( umask 077; printf '%s\n' "$pw" > pki/console-initial-password )
fi
hash=$(PW="$pw" python3 -c '
import hashlib, os, secrets
s = secrets.token_bytes(16); n, r, p = 2**14, 8, 1
dk = hashlib.scrypt(os.environ["PW"].encode(), salt=s, n=n, r=r, p=p, dklen=32)
print(f"scrypt:{n}:{r}:{p}:{s.hex()}:{dk.hex()}")')
tmp=$(mktemp .env.XXXX); chmod 600 "$tmp"
grep -vE '^CONSOLE_(USER|PASSWORD_HASH)=' .env > "$tmp" || true
printf 'CONSOLE_USER=%s\nCONSOLE_PASSWORD_HASH=%s\n' "$user" "$hash" >> "$tmp"
mv "$tmp" .env
echo "console login set for '$user'${2:+}$( [[ "${2:-}" == --stdin ]] || echo '; password in pki/console-initial-password')"

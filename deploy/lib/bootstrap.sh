# shellcheck shell=bash
# --- Kiro Gateway host bootstrap (Amazon Linux 2023, x86_64) --------------------------------------
# Runs once per instance from EC2 user data; the KGW_* variables above are filled in by the stack.
# Everything stateful (.env, pki/, data/, Docker volumes and images) lives on the attached data
# volume, so a replacement instance from the Auto Scaling group re-attaches it and brings the same
# gateway back: same CA, same rules, same audit history.
set -euo pipefail
exec > >(tee -a /var/log/kiro-gateway-bootstrap.log) 2>&1
signal() {
  /opt/aws/bin/cfn-signal -e "$1" --stack "$KGW_STACK" --resource "$KGW_ASG_LOGICAL_ID" --region "$KGW_REGION" || true
}
trap 'echo "bootstrap FAILED at line $LINENO"; signal 1' ERR
aws() { command aws --region "$KGW_REGION" "$@"; }

echo "== packages"
dnf install -y -q docker git jq gettext openssl unzip python3 aws-cfn-bootstrap
install_plugin() {   # name url sha256: Docker CLI plugins, checksum-verified
  local dst=/usr/local/lib/docker/cli-plugins/$1
  mkdir -p "${dst%/*}"
  curl -fsSL --retry 5 -o "$dst.tmp" "$2"
  echo "$3  $dst.tmp" | sha256sum -c --quiet -
  chmod 755 "$dst.tmp" && mv "$dst.tmp" "$dst"
}
install_plugin docker-compose https://github.com/docker/compose/releases/download/v5.6.0/docker-compose-linux-x86_64 \
  40343e21ca777173e69cff5dbafeb37c6f81f3b0d57d9e597f036e95eb63e76a
install_plugin docker-buildx https://github.com/docker/buildx/releases/download/v0.37.2/buildx-v0.37.2.linux-amd64 \
  982ca20490b45ed1ec8d99795974d3d874a358f75938c9c237305010e6b7e548

echo "== data volume $KGW_VOLUME_ID"
imds() {
  local t; t=$(curl -fsS -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 60')
  curl -fsS -H "X-aws-ec2-metadata-token: $t" "http://169.254.169.254/latest/meta-data/$1"
}
IID=$(imds instance-id)
dev=/dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_${KGW_VOLUME_ID/-/}
for _ in $(seq 120); do   # up to 20 min: the instance being replaced may still be detaching it
  read -r state owner < <(aws ec2 describe-volumes --volume-ids "$KGW_VOLUME_ID" \
    --query 'Volumes[0].[State, Attachments[0].InstanceId]' --output text)
  [[ $state == available || $owner == "$IID" ]] && break
  echo "volume is $state (attached to $owner), waiting"; sleep 10
done
[[ $owner == "$IID" ]] || aws ec2 attach-volume --volume-id "$KGW_VOLUME_ID" --instance-id "$IID" --device /dev/sdf >/dev/null
for _ in $(seq 90); do [[ -e $dev ]] && break; sleep 2; done
[[ -e $dev ]] || { echo "data volume did not appear at $dev"; false; }
blkid "$dev" >/dev/null || mkfs.xfs -q -L kgw-data "$dev"
uuid=$(blkid -s UUID -o value "$dev")
mkdir -p /data
grep -q "$uuid" /etc/fstab || echo "UUID=$uuid /data xfs defaults,nofail 0 2" >> /etc/fstab
mountpoint -q /data || mount /data

echo "== docker (data-root on the data volume, container logs to CloudWatch $KGW_LOG_GROUP)"
mkdir -p /etc/docker /data/docker /etc/systemd/system/docker.service.d
printf '[Unit]\nRequiresMountsFor=/data\n' > /etc/systemd/system/docker.service.d/data.conf
jq -n --arg r "$KGW_REGION" --arg g "$KGW_LOG_GROUP" '{
  "data-root": "/data/docker", "live-restore": true, "log-driver": "awslogs",
  "log-opts": {"awslogs-region": $r, "awslogs-group": $g, "tag": "{{.Name}}", "mode": "non-blocking"}}' \
  > /etc/docker/daemon.json
systemctl daemon-reload && systemctl enable --now docker

echo "== source"
APP=/data/kiro-gateway; NEW=$APP.new
rm -rf "$NEW"
if [[ -n ${KGW_SOURCE_S3:-} ]]; then
  aws s3 cp --quiet "$KGW_SOURCE_S3" /tmp/kgw-src.zip && unzip -q /tmp/kgw-src.zip -d "$NEW" && rm -f /tmp/kgw-src.zip
else
  git clone -q --depth 1 --branch "$KGW_SOURCE_REF" "$KGW_SOURCE_REPO" "$NEW"
fi
chmod 755 "$NEW"/scripts/*.sh "$NEW"/scripts/kiro-via-gateway
if [[ -d $APP ]]; then   # keep the state, replace the code
  for f in .env pki data; do
    if [[ -e $APP/$f ]]; then mv "$APP/$f" "$NEW/"; fi
  done
  rm -rf "$APP"
fi
mv "$NEW" "$APP"
cd "$APP"

echo "== configuration"
[[ -f .env ]] || cp .env.example .env
setenv() {   # KEY VALUE: (re)set on every boot so stack parameter changes apply
  local tmp; tmp=$(mktemp .env.XXXX)
  grep -vE "^$1=" .env > "$tmp" || true
  printf '%s=%s\n' "$1" "$2" >> "$tmp"; chmod 600 "$tmp"; mv "$tmp" .env
}
setenv KGW_BIND_ADDR 0.0.0.0
setenv KGW_PROXY_BIND_ADDR 0.0.0.0
setenv CONSOLE_ALLOW_CIDRS "127.0.0.0/8,172.30.0.1/32,$KGW_PORTAL_CIDR"
setenv KGW_PROXY_ALLOW_CIDRS "$KGW_PROXY_CIDR"
setenv KGW_PUBLIC_NAMES "$KGW_PORTAL_DNS"
setenv BEDROCK_GUARDRAIL_ID "$KGW_GUARDRAIL_ID"
setenv BEDROCK_GUARDRAIL_VERSION "$KGW_GUARDRAIL_VERSION"
setenv AWS_REGION "$KGW_REGION"

# Portal sign-in from Secrets Manager (only the scrypt hash is stored on disk).
if ! grep -qE '^CONSOLE_PASSWORD_HASH=.+' .env; then
  login=$(aws secretsmanager get-secret-value --secret-id "$KGW_CONSOLE_SECRET" --query SecretString --output text)
  jq -r .password <<<"$login" | scripts/console-passwd.sh "$(jq -r .username <<<"$login")" --stdin
  unset login
fi
# Interception CA: restore the backup if this volume has none (e.g. rebuilt from scratch).
mkdir -p pki && chmod 700 pki
ca=$(aws secretsmanager get-secret-value --secret-id "$KGW_CA_SECRET" --query SecretString --output text)
if [[ ! -f pki/ca.key ]] && jq -e .key <<<"$ca" >/dev/null; then
  jq -r .crt <<<"$ca" > pki/ca.crt
  ( umask 077; jq -r .key <<<"$ca" > pki/ca.key )
  echo "restored the CA from Secrets Manager"
fi
scripts/init.sh
if ! jq -e .key <<<"$ca" >/dev/null; then
  f=$(mktemp); chmod 600 "$f"
  jq -n --rawfile crt pki/ca.crt --rawfile key pki/ca.key '{crt: $crt, key: $key}' > "$f"
  aws secretsmanager put-secret-value --secret-id "$KGW_CA_SECRET" --secret-string "file://$f" >/dev/null
  rm -f "$f"; echo "backed up the CA to Secrets Manager"
fi
unset ca
aws ssm put-parameter --name "$KGW_CA_PARAM" --type String --overwrite --value "file://$APP/pki/ca.crt" >/dev/null
# First boot on this volume: the stack created a Bedrock guardrail, so switch layer 2 on.
if [[ ! -f data/.aws-initialized ]]; then
  jq '.guardrails.kiro_ml_guard.enabled = true' data/guardrails.json > data/guardrails.json.tmp
  mv data/guardrails.json.tmp data/guardrails.json && chmod 644 data/guardrails.json
  touch data/.aws-initialized
fi

echo "== start"
docker compose build -q
docker compose up -d --wait --wait-timeout 300
scripts/apply.sh
# Last: everything above ran as root (apply.sh writes data/generated/); the console container
# runs as uid 1000 (ec2-user) and must own the checkout to save rules.
chown -R 1000:1000 "$APP"
echo "bootstrap OK"
signal 0

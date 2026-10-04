# Runbook

Commands run from the repository root on the gateway host. On AWS, open a shell with
`aws ssm start-session --target <instance-id>`, then `sudo -i` and `cd /data/kiro-gateway`.

## Everyday

| Task | How |
|---|---|
| Change block rules or limits | Portal → **Rules** → **Save & apply**. Or edit `data/guardrails.json` and run `scripts/apply.sh`. History: `git -C data log --oneline`. |
| Test a prompt | Portal → **Prompt tester** (nothing is sent anywhere but Bedrock, if that layer is on). |
| See what was blocked | Portal → **Activity** / **Overview**, or Grafana → *Guardrails*. |
| Audit log | `docker compose exec apisix tail -f /usr/local/apisix/logs/kiro-audit.log \| jq .` |
| Proxy log | `docker compose exec squid tail -f /var/log/squid/access.log` |
| Container logs (AWS) | CloudWatch Logs group `LogGroup` (stack output), one stream per container. |
| Admin API (read) | `scripts/admin.sh GET routes` (the key never appears on the command line). |
| Health | `scripts/verify.sh` (full check, uses real kiro-cli), `docker compose ps`. |

## Access and secrets

| Task | How |
|---|---|
| Change the portal password | `scripts/console-passwd.sh admin --stdin` then `docker compose up -d console`. On AWS, also update the `PortalLoginSecret` value so a rebuilt instance uses the new one (the hash on the data volume wins while it exists). |
| Rotate the admin key | Remove `APISIX_ADMIN_KEY=` from `.env`, `scripts/init.sh`, `docker compose up -d`, `scripts/apply.sh`. |
| Give a client the CA | `pki/ca.crt` (AWS: `aws ssm get-parameter --name <CaCertificateParameter> --query Parameter.Value --output text`). For kiro-cli: `SSL_CERT_FILE` / `AWS_CA_BUNDLE` pointing at the system bundle plus this CA (`scripts/kiro-via-gateway` builds `pki/trust-bundle.pem`). |
| Allow more proxy clients | Compose: `KGW_PROXY_ALLOW_CIDRS` in `.env`, `scripts/init.sh`, `docker compose restart squid`. AWS: update the `ProxyAllowedCidr` parameter (replaces the instance; state is kept). |
| Portal access on AWS | CloudFront + WAF, no IP list. To restrict, add an IP-set rule to the stack's web ACL (`PortalWebAcl`); changes apply at the edge in about a minute. |

## Interception

| Task | How |
|---|---|
| Intercept another Kiro host | `scripts/intercept-host.sh <hostname> && scripts/apply.sh && docker compose restart squid` |
| Find Kiro's current endpoints | Temporarily empty `squid/hosts` (keep the comments), `docker compose restart squid`, run kiro-cli through the proxy and read the Squid log for the CONNECT hosts. Restore the file afterwards. |
| Stop interception, keep the proxy | Empty `squid/hosts` (keep the comments), `docker compose restart squid`. All traffic is then tunnelled. |
| Bedrock layer | Portal → Rules → *Bedrock Guardrails*: switch, timeout, fail mode. If Bedrock is slow or down, fail-open keeps the regex verdict. |

## Upgrades

1. `git pull` (or a new release tag), read the release notes.
2. `docker compose build && docker compose up -d && scripts/apply.sh`, or with released images set
   `KGW_CONSOLE_IMAGE` / `KGW_ML_GUARD_IMAGE` and `docker compose pull && docker compose up -d`.
3. `scripts/verify.sh`.

On AWS, update the stack with the new `SourceRef`. The Auto Scaling group replaces the instance (the
old one stops first, so expect about 10 minutes of downtime) and the new one re-attaches the data
volume. The `PortalUnhealthy` / `ProxyUnhealthy` alarms fire during that window and clear by
themselves a few minutes after the new instance is healthy. The deploy fails, and CloudFormation rolls back, if the new instance does not report success.

APISIX upgrades: `apisix/config.yaml` lists every plugin explicitly (setting `plugins` replaces the
defaults), so compare it with the new version's default list.

## Backup and restore

- **Compose**: back up `.env`, `pki/` and `data/` (the rules and their history) plus the Docker volumes
  you care about (`apisix-audit`, `loki-data`, `grafana-data`, ...).
- **AWS**: Data Lifecycle Manager snapshots the data volume daily (`SnapshotRetentionDays`), and
  deleting the stack takes a final snapshot. To restore, create a volume from the snapshot in the
  gateway's AZ, tag it `KiroGateway=<stack name>`, and either replace the stack's volume or deploy a new
  stack and swap it in while the instance is stopped. The CA is also in Secrets Manager (`CaBackup`), so
  even a fresh volume keeps client trust.

## Troubleshooting

| Symptom | Check |
|---|---|
| Kiro says the certificate is not trusted | The client does not trust the gateway CA: check `SSL_CERT_FILE` points at a bundle that contains `pki/ca.crt`. |
| Kiro shows the block message unexpectedly | Portal → Activity: the entry names the rule (`bedrock:pii:NAME`, `aws-access-key-id`, ...). Try the text in the Prompt tester, then refine or disable the rule. |
| Proxy refuses connections (403 from Squid) | The client is not in `KGW_PROXY_ALLOW_CIDRS` / `ProxyAllowedCidr`. |
| Portal: "Source not allowed" | Compose: your network is not in `CONSOLE_ALLOW_CIDRS`. |
| Portal: 403 "Forbidden" (plain text) on AWS | The request reached the load balancer without CloudFront's origin header: use the CloudFront URL. |
| Portal: 403 from CloudFront | WAF blocked it: CloudWatch metrics of the web ACL, or WAF sampled requests, show which rule. |
| Rule save fails with 502 | `docker compose logs console`; the gateway rejected the generated policy and nothing was saved. |
| Bedrock layer shows unavailable | `BEDROCK_GUARDRAIL_ID` empty, missing `bedrock:ApplyGuardrail` permission, or region mismatch: `docker compose logs ml-guard`. |
| AWS deploy fails at `GatewayAsg` | The instance's boot log: `/var/log/kiro-gateway-bootstrap.log` (Session Manager), or the EC2 console's system log. |

## Rollback and teardown

| Scope | Command | Reversible |
|---|---|---|
| One shell | `source scripts/kiro-via-gateway off` | yes |
| Stop interception | empty `squid/hosts`, `docker compose restart squid` | yes |
| Stop the stack | `docker compose down` | yes (volumes kept) |
| Delete everything local | `docker compose down -v` and remove `data/`, `pki/`, `.env` | **no** |
| AWS | `npx cdk destroy KiroGateway` or delete the stack | final snapshot and log group are kept; delete them separately |

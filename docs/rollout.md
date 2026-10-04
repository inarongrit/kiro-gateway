# Org-wide rollout

The same architecture scales from one host to an organisation. Steps, roughly in order:

1. **PKI**: replace the gateway CA with an intermediate from your internal PKI; issue the Kiro host
   certificates from it (`scripts/issue-cert.sh`, or cert-manager on Kubernetes). Push the root to
   clients with MDM.
2. **Clients**: MDM sets `HTTPS_PROXY` / `NO_PROXY` (or a PAC file) and the CA. If Kiro turns out to
   ignore the OS trust store, also push `SSL_CERT_FILE`. Test the Kiro IDE as well as kiro-cli.
3. **Proxy tier**: Squid is stateless; run two or more behind an internal TCP load balancer across
   AZs. If you already have a secure web gateway (Zscaler, Netskope, ...), have it forward the Kiro
   hosts to APISIX and drop Squid.
4. **APISIX**: the official Helm chart (`apisix/apisix`) on Kubernetes, data plane behind an internal
   load balancer with autoscaling, 3-node etcd or standalone YAML mode. The `config/` objects apply
   unchanged (`scripts/apply.sh` or ADC in CI).
5. **Enforcement**: an egress firewall or security groups so that only the proxy tier reaches the Kiro
   hosts on 443. Without it, unsetting `HTTPS_PROXY` bypasses the gateway.
6. **Identity**: proxy authentication (Kerberos / SSO) or mTLS client certificates passed to APISIX for
   real per-user attribution; the portal behind your IdP with MFA; AI route consumers via
   `openid-connect` instead of static keys.
7. **Inspection**: extend the regex rules and the Bedrock guardrail, or add `forward-auth` to a central
   DLP service shared by the Kiro and AI routes. Decide fail-open vs fail-closed per layer.
8. **Logs and data handling**: ship the audit log to your SIEM / S3 with a retention policy
   (`kafka-logger`, `http-logger`, ...). Prompts contain source code: get privacy and legal sign-off.
9. **Limits**: switch `limit-count` / `ai-rate-limiting` to `policy: redis` so limits hold across replicas.
10. **AI providers**: `ai-proxy` also supports Amazon Bedrock (SigV4), Anthropic, Azure OpenAI and Gemini.

Also review Kiro's own administrative controls for your plan; they may cover part of the requirement
without interception.

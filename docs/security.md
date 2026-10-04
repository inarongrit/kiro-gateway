# Security notes

What Kiro Gateway protects, how, and what it does not cover. Report vulnerabilities privately to the
maintainers (GitHub: **Security → Report a vulnerability**), not in public issues.

## What the gateway sees

Kiro Gateway decrypts Kiro's traffic. Whoever runs it can read every prompt, including source code and
anything else the developer sends to Kiro. Treat the host, its data volume and its logs as holding
source code and personal data, and get privacy / legal approval before pointing real users at it.

| Data | Where | Protection |
|---|---|---|
| Prompts (allowed and blocked) | audit log (APISIX volume) → Loki; portal Activity | Every rule match (regex and Bedrock) is masked before writing (`AK****OP`). `PROMPT_LOG=off` stores no prompt text at all, only verdict and rule. |
| Bearer tokens, AWS session tokens, request headers | never stored | The audit log uses an allow list of fields; users are keyed by a truncated SHA-256 of the token. |
| User message sent to Bedrock | Amazon Bedrock in your account | Only the user's own message, not Kiro's injected context; nothing is stored by the guardrail. |
| Traces | Tempo | Timing and status only; no prompt text in span attributes. |
| Rule history | `data/.git` | Who changed which rule, when, from which IP. |

`LOG_FULL_BODY=1` (debug) logs raw request bodies and bypasses masking. Never use it with real users.

## Trust and TLS

- **Gateway CA**: `scripts/make-ca.sh` creates a CA (`pki/ca.key`, 0600) that signs the interception
  certificates for the Kiro hosts and the portal certificate. Anyone holding `ca.key` can impersonate
  those hosts to clients that trust the CA. Clients should trust it only for Kiro (`SSL_CERT_FILE` /
  `AWS_CA_BUNDLE` for the Kiro process), and an organisation should replace it with an intermediate
  from its internal PKI ([rollout.md](rollout.md)). On AWS the key also lives in Secrets Manager
  (`CaBackup`) so a rebuilt instance keeps the same CA.
- **Upstream**: APISIX verifies the real Kiro endpoints against pinned Amazon roots
  (`config/upstreams/_trust.json`). Non-Kiro hosts are never decrypted.

## Portal

- **Sign-in**: one account; scrypt password hash in `.env`; random server-side session tokens; cookie
  `Secure; HttpOnly; SameSite=Strict`; 5 failed sign-ins from one IP lock it out for 5 minutes.
- **CSRF**: every change needs the `X-Console` header and a same-origin `Origin`.
- **Content Security Policy**: strict on the sign-in page; the portal and Grafana allow inline scripts
  because they need them.
- **Least exposure**: the APISIX Admin API is bound to `127.0.0.1:9181` and reached from the portal
  only through the console, which adds the admin key server-side for signed-in users. Grafana trusts
  the user header only from the console container. Prometheus, Loki, Tempo and etcd publish no ports.
- **Secrets on disk**: the console container mounts the repository read-only and sees only the public
  CA certificate from `pki/`; it never handles private keys.

### On AWS

- The portal is reachable only through CloudFront. The internal load balancer forwards only requests
  carrying CloudFront's secret origin header (Secrets Manager `OriginVerify`) and answers 403 otherwise.
  Its security group accepts only CloudFront's origin-facing addresses (AWS-managed prefix list).
- **No IP allow list**: anyone on the internet can reach the sign-in page. Protection is AWS WAF
  (20 sign-in attempts per IP per 5 minutes, 3,000 requests per IP per 5 minutes, AWS IP reputation,
  known bad inputs, the common rule set) plus the password. The common rules' body checks run in count
  mode because prompts, regex patterns and dashboard queries legitimately look like code.
  **Before real use, add an identity provider with MFA** (for example Amazon Cognito or your SSO via
  OIDC in front of the portal), or restrict the web ACL to your networks.
- CloudFront → load balancer is HTTP over CloudFront's private VPC-origin path (CloudFront only makes
  HTTPS connections to origins with a publicly trusted certificate); load balancer → instance is HTTPS.
  With a custom domain and an ACM certificate, the origin hop can use HTTPS too.
- The instance has no public IP and no SSH key (Session Manager only), IMDSv2 only, encrypted volumes.
  Its role may apply only the stack's guardrail, attach only the stack's data volume, read only the
  stack's secrets, and write logs; it has no model invocation rights.
- The proxy load balancer is internal and limited to `ProxyAllowedCidr`; Squid applies the same list.

## Known gaps

- Users who unset `HTTPS_PROXY` bypass the gateway unless egress to the Kiro hosts is blocked for
  everything except the gateway.
- Per-user identity is a token hash, not a person; see [rollout.md](rollout.md).
- Model responses are not inspected; prompt-injection detection is off (see the evaluation).
- The portal has a single shared admin account and no roles.

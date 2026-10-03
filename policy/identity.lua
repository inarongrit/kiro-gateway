-- Global (all intercepted hosts): derive a stable, NON-reversible per-user key from the bearer
-- token so logs and rate limits are per user without ever storing the credential.
-- Squid tunnels TLS, so every request arrives from Squid's IP; source IP cannot identify users.
-- NOTE: tokens rotate, so the key changes on refresh. Production: map to IdC user via SSO/mTLS.
return function(conf, ctx)
  local core = require("apisix.core")
  local auth = core.request.header(ctx, "authorization")
  if auth and #auth > 0 then
    local sha256 = require("resty.sha256")
    local to_hex = require("resty.string").to_hex
    local h = sha256:new()
    h:update(auth)
    ctx.var.kiro_user = to_hex(h:final()):sub(1, 12)
  else
    ctx.var.kiro_user = "anonymous"
  end
  ctx.var.kiro_policy = "observed"
end

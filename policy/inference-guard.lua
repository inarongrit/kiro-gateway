-- Inference route policy (runtime.*.kiro.dev): inspect the CURRENT prompt and block on match.
-- Rules come from the live rules (data/guardrails.json): scripts/build-policy.sh replaces __GUARDRAILS_JSON__
-- with the enabled rules for the "kiro" path. Do not edit rules here.
-- Body shape (awsJson, GenerateAssistantResponse):
--   conversationState.currentMessage.userInputMessage.content  <- this turn's prompt
--   conversationState.history[*]                               <- prior turns (not re-checked,
--     otherwise one blocked turn would poison every later turn of the session)
-- Privacy: the prompt that reaches the audit log (and from there Loki and the portal) has every
-- rule match MASKED, for blocked and allowed requests alike, so the guard never stores the
-- secret or PII it exists to stop. Matching itself always runs on the full, normalised prompt.
-- Production: replace with forward-auth to a central DLP service (same hook, no redesign).
local core = require("apisix.core")
local CFG = core.json.decode([==[__GUARDRAILS_JSON__]==]) or { rules = {}, guard = false }
local PROMPT_LOG_MAX = 4096   -- characters of (masked) prompt kept in the audit log
local MASK_WINDOW = 8192      -- mask before truncating, so a match on the cut line is still masked
local LOG_PROMPT = "__PROMPT_LOG_MODE__" ~= "off"   -- PROMPT_LOG=off at build time: log no text
local ML_URL = "http://172.30.0.40:8080/check"      -- ml-guard (Bedrock Guardrails), Docker network only
local ML = CFG.ml or { enabled = false }

-- Normalise common evasions before matching: full-width ASCII (ＡＫＩＡ, １２３) and Thai digits
-- (๐-๙) become ASCII, the ideographic space becomes a space, zero-width characters are removed.
-- console/app/rules.py:normalise() mirrors this so the prompt tester gives the same verdict.
local function normalise(s)
  s = s:gsub("\226\128[\139-\141]", "")        -- U+200B..U+200D zero-width space/joiners
       :gsub("\226\129\160", "")                -- U+2060 word joiner
       :gsub("\239\187\191", "")                -- U+FEFF zero-width no-break space
       :gsub("\227\128\128", " ")               -- U+3000 ideographic space
  s = s:gsub("\239([\188\189])([\128-\191])", function(b2, b3)   -- U+FF01..U+FF5E
    local cp = 0xF000 + (b2:byte() - 0x80) * 64 + (b3:byte() - 0x80)
    if cp >= 0xFF01 and cp <= 0xFF5E then return string.char(cp - 0xFEE0) end
  end)
  s = s:gsub("\224\185([\144-\153])", function(b3)              -- U+0E50..U+0E59 Thai digits
    return string.char(48 + b3:byte() - 0x90)
  end)
  return s
end

-- "somchai.j@example.co.th" -> "so*******************th"; short or non-ASCII ends -> all stars.
-- Lengths are counted in characters, not UTF-8 bytes.
local function mask(m)
  local s = m[0]
  local n = #(s:gsub("[\128-\191]", ""))
  local head, tail = s:sub(1, 2), s:sub(-2)
  if n >= 8 and not head:find("[\128-\255]") and not tail:find("[\128-\255]") then
    return head .. string.rep("*", n - 4) .. tail
  end
  return string.rep("*", n)
end

local function masked_for_log(prompt)
  if not LOG_PROMPT then return "" end
  local text, n = prompt:sub(1, MASK_WINDOW), 0
  for _, rule in ipairs(CFG.rules) do
    local out, cnt = ngx.re.gsub(text, rule.pattern, mask, "jo")
    if out then text, n = out, n + cnt end
  end
  -- Cut on a UTF-8 boundary so the log line stays valid JSON text.
  local cut = text:sub(1, PROMPT_LOG_MAX)
  if #text > PROMPT_LOG_MAX then cut = cut:gsub("[\192-\255][\128-\191]*$", "") end
  return cut, n
end

-- Replace every literal occurrence of each detected span (longest first) with its mask.
local function mask_literals(text, spans)
  for _, span in ipairs(spans or {}) do
    if type(span) == "string" and #span > 0 then
      local out, i = {}, 1
      while true do
        local a, b = text:find(span, i, true)
        if not a then break end
        out[#out + 1] = text:sub(i, a - 1) .. mask({ [0] = span })
        i = b + 1
      end
      out[#out + 1] = text:sub(i)
      text = table.concat(out)
    end
  end
  return text
end

local function deny(ctx, rule_id, label)
  ctx.var.kiro_policy = "blocked"
  ctx.var.kiro_rule = rule_id
  -- awsJson error shape so the Kiro client surfaces a readable message.
  core.response.set_header("x-amzn-errortype", "AccessDeniedException")
  return core.response.exit(403, { __type = "AccessDeniedException",
    message = CFG.message .. " (" .. label .. ")" })
end

-- Second layer: Amazon Bedrock Guardrails via ml-guard. Returns a deny() result or nil.
-- fail_mode "open": a slow/unavailable layer lets the request through (regex already passed);
-- "closed": it blocks with rule "ml-unavailable".
-- Kiro wraps what the user typed in "--- USER MESSAGE BEGIN/END ---" after context entries it
-- injects itself (time, steering). Bedrock sees only the user's words: the wrapper's role-style
-- markers make the prompt-attack filter flag harmless instructions ("Reply with exactly: OK").
-- The regex rules above still check the full content.
local function user_text(prompt)
  local s = prompt:match("%-%-%- USER MESSAGE BEGIN %-%-%-\n(.*)\n%-%-%- USER MESSAGE END %-%-%-")
  return s or prompt
end

local function ml_check(ctx, prompt)
  prompt = user_text(prompt)
  local http = require("resty.http")
  local c = http.new()
  -- connect, send, read: a dead ml-guard fails in 300 ms; a slow Bedrock call gets the full budget.
  c:set_timeouts(300, 1000, ML.timeout_ms or 1500)
  local t0 = ngx.now()
  local res, err = c:request_uri(ML_URL, { method = "POST", body = core.json.encode({ text = prompt }),
                                           headers = { ["Content-Type"] = "application/json" } })
  ngx.update_time()
  ctx.var.kiro_ml_ms = tostring(math.floor((ngx.now() - t0) * 1000 + 0.5))
  local r = res and res.status == 200 and core.json.decode(res.body)
  if type(r) ~= "table" then
    ctx.var.kiro_ml = "error"
    core.log.warn("kiro-policy: ml-guard unavailable: ", err or (res and res.status))
    if ML.fail_mode == "closed" then
      return deny(ctx, "ml-unavailable", "the second guardrail layer is unavailable")
    end
    return nil
  end
  ctx.var.kiro_prompt = mask_literals(ctx.var.kiro_prompt or "", r.mask)   -- Bedrock-found PII too
  ctx.var.kiro_ml = r.action
  if r.action == "block" then
    local first = type(r.policies) == "table" and r.policies[1] or "policy"
    return deny(ctx, "bedrock:" .. first, "Bedrock Guardrails: " .. first)
  end
  return nil
end

return function(conf, ctx)
  local body, err = core.request.get_body(16 * 1024 * 1024, ctx)
  if err then
    -- Fail CLOSED: a request we cannot inspect must not reach the model unchecked.
    ctx.var.kiro_policy = "blocked"
    ctx.var.kiro_rule = "uninspectable"
    core.log.warn("kiro-policy: cannot read body: ", err)
    core.response.set_header("x-amzn-errortype", "AccessDeniedException")
    return core.response.exit(403, { __type = "AccessDeniedException",
      message = CFG.message .. " (the request could not be inspected)" })
  end
  if not body then              -- no body (e.g. a GET probe): nothing to inspect
    ctx.var.kiro_policy = "unreadable"
    return
  end
  local doc = core.json.decode(body)
  local cur = type(doc) == "table" and doc.conversationState
              and doc.conversationState.currentMessage
              and doc.conversationState.currentMessage.userInputMessage
  local prompt = normalise(type(cur) == "table" and type(cur.content) == "string" and cur.content or "")
  ctx.var.kiro_prompt = masked_for_log(prompt)
  ctx.var.kiro_body_bytes = tostring(#body)

  if not CFG.guard then
    ctx.var.kiro_policy = "guard-off"
    return
  end
  for _, rule in ipairs(CFG.rules) do
    local from, _, rerr = ngx.re.find(prompt, rule.pattern, "jo")   -- returns from, to, err
    if rerr then
      core.log.error("kiro-policy: bad pattern in rule ", rule.id, ": ", rerr)
    elseif from then
      ctx.var.kiro_ml = "skipped"            -- already blocked: no need to pay for layer 2
      return deny(ctx, rule.id, "rule: " .. rule.label)
    end
  end
  if ML.enabled and prompt ~= "" then
    local blocked = ml_check(ctx, prompt)
    if blocked then return blocked end
  else
    ctx.var.kiro_ml = "off"
  end
  ctx.var.kiro_policy = "allowed"
end

local cjson = require("cjson.safe")

local plugin = {
  PRIORITY = 1200,
  VERSION = "0.1.0",
}

local function b64url_to_b64(value)
  if not value or value == "" then
    return nil
  end

  local converted = value:gsub("-", "+"):gsub("_", "/")
  local remainder = #converted % 4
  if remainder == 2 then
    converted = converted .. "=="
  elseif remainder == 3 then
    converted = converted .. "="
  elseif remainder == 1 then
    return nil
  end

  return converted
end

local function decode_jwt_payload(jwt)
  if not jwt or jwt == "" then
    return nil
  end

  local parts = {}
  for part in jwt:gmatch("[^%.]+") do
    parts[#parts + 1] = part
  end

  if #parts ~= 3 then
    return nil
  end

  local payload_b64 = b64url_to_b64(parts[2])
  if not payload_b64 then
    return nil
  end

  local payload_json = ngx.decode_base64(payload_b64)
  if not payload_json then
    return nil
  end

  return cjson.decode(payload_json)
end

local function replay_error(description)
  local body = cjson.encode({
    message = description,
    error = "invalid_dpop_proof",
    error_description = description,
  })

  kong.response.set_header(
    "WWW-Authenticate",
    'DPoP error="invalid_dpop_proof", error_description="' .. description .. '"'
  )
  kong.response.set_header("Content-Type", "application/json")
  kong.ctx.shared.obs_response_body = body

  return kong.response.exit(401, cjson.decode(body))
end

function plugin:access(conf)
  local dpop = kong.request.get_header("DPoP")
  if not dpop then
    return
  end

  local payload = decode_jwt_payload(dpop)
  if type(payload) ~= "table" or type(payload.jti) ~= "string" or payload.jti == "" then
    return
  end

  local dict = ngx.shared.kong_db_cache
  if not dict then
    kong.log.err("[dpop-replay-demo] ngx.shared.kong_db_cache is unavailable")
    return
  end

  local cache_key = string.format("%s:%s", conf.cache_prefix or "dpop-replay-demo", payload.jti)
  local ok, err = dict:add(cache_key, true, conf.replay_ttl_seconds or 300)
  if ok then
    return
  end

  if err == "exists" then
    return replay_error("DPoP proof replay detected: jti has already been used")
  end

  kong.log.err("[dpop-replay-demo] failed to store replay cache entry: ", err)
end

return plugin

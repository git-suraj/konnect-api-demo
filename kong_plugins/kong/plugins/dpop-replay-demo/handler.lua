local cjson = require("cjson.safe")

local plugin = {
  PRIORITY = 1200,
  VERSION = "0.2.0",
}

local function fail(code, message)
  local body = cjson.encode({
    error = "invalid_dpop_proof",
    error_code = code,
    message = message,
  })

  kong.response.set_header(
    "WWW-Authenticate",
    'DPoP error="invalid_dpop_proof", error_description="' .. code .. '"'
  )
  kong.response.set_header("X-DPoP-Error", code)
  kong.response.set_header("Content-Type", "application/json")
  kong.ctx.shared.obs_response_body = body

  return kong.response.exit(401, cjson.decode(body))
end

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

local function split_jwt(value)
  local parts = {}
  for part in (value or ""):gmatch("[^%.]+") do
    parts[#parts + 1] = part
  end
  return parts, #parts
end

local function decode_jwt_segment(segment)
  local b64 = b64url_to_b64(segment)
  if not b64 then
    return nil
  end
  return ngx.decode_base64(b64)
end

local function decode_jwt_payload(jwt)
  local parts, count = split_jwt(jwt)
  if count ~= 3 then
    return nil
  end

  local payload_json = decode_jwt_segment(parts[2])
  if not payload_json then
    return nil
  end

  return cjson.decode(payload_json)
end

local function looks_like_json_object(raw)
  if not raw then
    return false
  end

  local trimmed = raw:match("^%s*(.-)%s*$")
  return trimmed:sub(1, 1) == "{" and trimmed:sub(-1) == "}"
end

local function json_str(raw, key)
  local pat = '"' .. key .. '"%s*:%s*"([^"\\]*)"'
  return string.match(raw, pat)
end

local function json_has(raw, key)
  local pat = '"' .. key .. '"%s*:%s*[^,}%s]'
  return string.find(raw, pat) ~= nil
end

local function json_nested_str(raw, outer, inner)
  local outer_start = string.find(raw, '"' .. outer .. '"%s*:%s*{')
  if not outer_start then
    return nil
  end
  local rest = string.sub(raw, outer_start)
  return json_str(rest, inner)
end

local function actual_htu()
  local scheme = kong.request.get_forwarded_scheme() or kong.request.get_scheme()
  local host = kong.request.get_forwarded_host() or kong.request.get_host()
  local port = kong.request.get_forwarded_port() or kong.request.get_port()
  local path = kong.request.get_forwarded_path() or kong.request.get_path()
  local default_port = (scheme == "https" and 443) or (scheme == "http" and 80) or nil

  if port and default_port and port ~= default_port then
    return scheme .. "://" .. host .. ":" .. port .. path
  end

  return scheme .. "://" .. host .. path
end

function plugin:access(conf)
  local auth = kong.request.get_header("Authorization")
  if not auth or auth == "" then
    return fail("DPOP_AUTH_HEADER_MISSING", "Authorization header is missing")
  end

  local access_token = string.match(auth, "^[Dd][Pp][Oo][Pp]%s+(.+)$")
  if not access_token then
    return fail("DPOP_AUTH_SCHEME_NOT_DPOP", "Authorization header must use the DPoP scheme")
  end

  local proof = kong.request.get_header("DPoP")
  if not proof or proof == "" then
    return fail("DPOP_PROOF_HEADER_MISSING", "Missing DPoP proof header")
  end

  local at_parts, at_count = split_jwt(access_token)
  if at_count ~= 3 then
    return fail("DPOP_ACCESS_TOKEN_MALFORMED", "Malformed access token")
  end

  local proof_parts, proof_count = split_jwt(proof)
  if proof_count ~= 3 then
    return fail("DPOP_PROOF_MALFORMED", "Malformed DPoP proof")
  end

  local hdr_raw = decode_jwt_segment(proof_parts[1])
  if not hdr_raw then
    return fail("DPOP_HEADER_BAD_BASE64", "DPoP proof header is not valid base64url")
  end
  if not looks_like_json_object(hdr_raw) then
    return fail("DPOP_HEADER_INVALID_JSON", "DPoP proof header is not a JSON object")
  end

  local typ = json_str(hdr_raw, "typ")
  if typ ~= "dpop+jwt" then
    return fail("DPOP_TYP_INVALID", "DPoP typ must be dpop+jwt")
  end

  local payload_raw = decode_jwt_segment(proof_parts[2])
  if not payload_raw then
    return fail("DPOP_PAYLOAD_BAD_BASE64", "DPoP proof payload is not valid base64url")
  end
  if not looks_like_json_object(payload_raw) then
    return fail("DPOP_PAYLOAD_INVALID_JSON", "DPoP proof payload is not a JSON object")
  end

  if not json_has(hdr_raw, "jwk") then
    return fail("DPOP_JWK_MISSING", "DPoP header is missing jwk")
  end

  local jwk_start = string.find(hdr_raw, '"jwk"%s*:%s*{')
  if not jwk_start then
    return fail("DPOP_JWK_MISSING", "DPoP header jwk is not an object")
  end
  local jwk_rest = string.sub(hdr_raw, jwk_start)
  if not json_str(jwk_rest, "kty") then
    return fail("DPOP_JWK_MISSING_KTY", "DPoP jwk is missing kty")
  end

  local at_payload_raw = decode_jwt_segment(at_parts[2])
  if not at_payload_raw or not looks_like_json_object(at_payload_raw) then
    return fail("DPOP_ACCESS_TOKEN_PAYLOAD_INVALID", "Access token payload is not a valid JSON object")
  end

  local at_jkt = json_nested_str(at_payload_raw, "cnf", "jkt")
  if not at_jkt then
    return fail("DPOP_CNF_JKT_MISSING", "Access token is missing cnf.jkt")
  end

  if not json_has(payload_raw, "ath") then
    return fail("DPOP_ATH_MISSING", "DPoP proof missing ath claim")
  end

  local htm = json_str(payload_raw, "htm")
  if not htm then
    return fail("DPOP_HTM_MISSING", "DPoP proof missing htm claim")
  end
  local method = kong.request.get_method()
  if htm ~= method then
    return fail("DPOP_HTM_MISMATCH", "DPoP htm does not match the request method")
  end

  local htu = json_str(payload_raw, "htu")
  if not htu then
    return fail("DPOP_HTU_MISSING", "DPoP proof missing htu claim")
  end
  local proof_htu_stripped = htu:gsub("[%?#].*$", "")
  local expected_htu = actual_htu()
  if proof_htu_stripped ~= expected_htu then
    return fail("DPOP_HTU_MISMATCH", "DPoP htu does not match the request URI")
  end

  local payload = cjson.decode(payload_raw)
  if type(payload) ~= "table" or type(payload.jti) ~= "string" or payload.jti == "" then
    return fail("DPOP_JTI_MISSING", "DPoP proof missing jti claim")
  end

  if type(payload.iat) == "number" then
    local now = ngx.time()
    local max_age = conf.max_iat_skew_seconds or 300
    local age = now - payload.iat
    if age > max_age then
      return fail("DPOP_PROOF_EXPIRED", "DPoP proof is expired")
    end
    if age < -max_age then
      return fail("DPOP_PROOF_FUTURE", "DPoP proof iat is in the future")
    end
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
    return fail("DPOP_JTI_REPLAY", "DPoP proof replay detected: jti has already been used")
  end

  kong.log.err("[dpop-replay-demo] failed to store replay cache entry: ", err)
end

return plugin

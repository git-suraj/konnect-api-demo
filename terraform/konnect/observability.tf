locals {
  observability_rewrite_snippet = <<-LUA
    kong.ctx.shared.obs_request_headers = kong.request.get_headers(1000) or {}
    local headers = kong.ctx.shared.obs_request_headers
    local request_id = headers["x-request-id"] or headers["X-Request-Id"]
      or kong.request.get_header("x-request-id")
      or kong.request.get_header("X-Request-Id")

    local span = kong.tracing.active_span()
    if span and request_id then
      span:set_attribute("request.id", request_id)
    end
  LUA

  observability_access_snippet = <<-LUA
    kong.service.request.enable_buffering()
    if not kong.ctx.shared.obs_request_headers then
      kong.ctx.shared.obs_request_headers = kong.request.get_headers(1000) or {}
    end
    local body, err = kong.request.get_raw_body()
    if body ~= nil then
      kong.ctx.shared.obs_request_body = body
    else
      kong.ctx.shared.obs_request_body = ""
    end

    local headers = kong.ctx.shared.obs_request_headers
    local request_id = headers["x-request-id"] or headers["X-Request-Id"]
      or kong.request.get_header("x-request-id")
      or kong.request.get_header("X-Request-Id")

    local span = kong.tracing.active_span()
    if span and request_id then
      span:set_attribute("request.id", request_id)
    end
  LUA

  observability_body_filter_snippet = <<-LUA
    local body = kong.response.get_raw_body()
    if body ~= nil then
      kong.ctx.shared.obs_response_body = body
    end
  LUA

  observability_log_snippet = <<-LUA
    local serialized = kong.log.serialize()
    local headers = kong.ctx.shared.obs_request_headers or {}
    local request_id = headers["x-request-id"] or headers["X-Request-Id"]
      or kong.request.get_header("x-request-id")
      or kong.request.get_header("X-Request-Id")
      or (serialized.request and serialized.request.id)

    local span = kong.tracing.active_span()
    if span then
      if request_id then
        span:set_attribute("request.id", request_id)
      end

      if serialized.request and serialized.request.id then
        span:set_attribute("kong.request.id", serialized.request.id)
      end
    end
  LUA

  access_log_request_id = <<-LUA
    local serialized = kong.log.serialize()
    local headers = kong.ctx.shared.obs_request_headers or {}
    return headers["x-request-id"] or headers["X-Request-Id"]
      or kong.request.get_header("x-request-id")
      or kong.request.get_header("X-Request-Id")
      or (serialized.request and serialized.request.id)
  LUA

  access_log_trace_id = <<-LUA
    local serialized = kong.log.serialize()
    if type(serialized.trace_id) == "table" then
      return serialized.trace_id.w3c or serialized.trace_id.datadog
    end
    return serialized.trace_id
  LUA

  access_log_consumer_name = <<-LUA
    local serialized = kong.log.serialize()
    if serialized.consumer and serialized.consumer.username then
      return serialized.consumer.username
    end
    return "anonymous"
  LUA

  access_log_service_name = <<-LUA
    local serialized = kong.log.serialize()
    return serialized.service and serialized.service.name or "unmatched"
  LUA

  access_log_route_name = <<-LUA
    local serialized = kong.log.serialize()
    return serialized.route and serialized.route.name or "unmatched"
  LUA

  access_log_status_code = <<-LUA
    return kong.response.get_status()
  LUA

  access_log_end_to_end_latency = <<-LUA
    local serialized = kong.log.serialize()
    return serialized.latencies and serialized.latencies.request or nil
  LUA

  access_log_kong_latency = <<-LUA
    local serialized = kong.log.serialize()
    return serialized.latencies and serialized.latencies.kong or nil
  LUA

  access_log_upstream_latency = <<-LUA
    local serialized = kong.log.serialize()
    return serialized.latencies and serialized.latencies.proxy or nil
  LUA

  access_log_response_source = <<-LUA
    local serialized = kong.log.serialize()
    return serialized.source or nil
  LUA

  access_log_request_headers_json = <<-LUA
    local cjson = require("cjson.safe")
    return cjson.encode(kong.ctx.shared.obs_request_headers or {})
  LUA

  access_log_response_headers_json = <<-LUA
    local cjson = require("cjson.safe")
    return cjson.encode(kong.response.get_headers(1000) or {})
  LUA
}

resource "konnect_gateway_plugin_post_function" "observability_capture" {
  enabled          = true
  control_plane_id = var.konnect_control_plane_id

  config = {
    rewrite     = [local.observability_rewrite_snippet]
    access      = [local.observability_access_snippet]
    body_filter = [local.observability_body_filter_snippet]
    log         = [local.observability_log_snippet]
  }
}

resource "konnect_gateway_plugin_opentelemetry" "observability" {
  enabled          = true
  control_plane_id = var.konnect_control_plane_id

  config = {
    traces_endpoint = "http://otel-collector:4318/v1/traces"
    logs_endpoint   = "http://otel-collector:4318/v1/logs"
    sampling_rate   = 1
    http_span_name  = "method_path"
    resource_attributes = {
      "service.name"           = "kong-data-plane"
      "service.namespace"      = "konnect-api-demo"
      "deployment.environment" = "local-demo"
    }
    access_logs = {
      endpoint = "http://otel-collector:4318/v1/logs"
      custom_attributes_by_lua = {
        "request_id"                        = local.access_log_request_id
        "trace_id"                          = local.access_log_trace_id
        "consumer_name"                     = local.access_log_consumer_name
        "service_name_extracted"            = local.access_log_service_name
        "route_name"                        = local.access_log_route_name
        "status_code"                       = local.access_log_status_code
        "end_to_end_latency_ms"             = local.access_log_end_to_end_latency
        "kong_latency_ms"                   = local.access_log_kong_latency
        "upstream_latency_ms"               = local.access_log_upstream_latency
        "response_source"                   = local.access_log_response_source
        "request_headers"                   = local.access_log_request_headers_json
        "request.body"                      = "return kong.ctx.shared.obs_request_body"
        "response_headers"                  = local.access_log_response_headers_json
        "response.body"                     = "return kong.ctx.shared.obs_response_body"
        "crypto_algorithm"                  = "return kong.ctx.shared.crypto_algorithm"
        "crypto_encrypted_request_payload"  = "return kong.ctx.shared.crypto_encrypted_request_payload"
        "crypto_decrypted_request_payload"  = "return kong.ctx.shared.crypto_decrypted_request_payload"
        "crypto_plain_response_payload"     = "return kong.ctx.shared.crypto_plain_response_payload"
        "crypto_encrypted_response_payload" = "return kong.ctx.shared.crypto_encrypted_response_payload"
      }
    }
  }
}

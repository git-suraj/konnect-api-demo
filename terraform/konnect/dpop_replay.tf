resource "konnect_gateway_custom_plugin_schema" "dpop_replay_demo" {
  count            = local.auth0_dpop_enabled ? 1 : 0
  control_plane_id = var.konnect_control_plane_id
  lua_schema       = file("${path.module}/../../kong_plugins/kong/plugins/dpop-replay-demo/schema.lua")
}

resource "konnect_gateway_custom_plugin" "dpop_replay_demo" {
  count            = local.auth0_dpop_enabled ? 1 : 0
  name             = "dpop-replay-demo"
  enabled          = true
  control_plane_id = var.konnect_control_plane_id
  config = jsonencode({
    replay_ttl_seconds   = 300
    cache_prefix         = "dpop-replay-demo"
    max_iat_skew_seconds = 300
  })

  route = {
    id = konnect_gateway_route.route_orders_auth0_dpop[0].id
  }

  depends_on = [
    konnect_gateway_custom_plugin_schema.dpop_replay_demo,
  ]
}

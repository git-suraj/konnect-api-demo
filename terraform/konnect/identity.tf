locals {
  azure_ad_enabled = alltrue([
    try(trimspace(var.azure_ad_tenant_id), "") != "",
    try(trimspace(var.azure_ad_audience), "") != "",
    try(trimspace(var.azure_ad_consumer1_client_id), "") != "",
    try(trimspace(var.azure_ad_consumer2_client_id), "") != "",
  ])
  auth0_dpop_enabled = alltrue([
    try(trimspace(var.auth0_domain), "") != "",
    try(trimspace(var.auth0_dpop_api_identifier), "") != "",
    try(trimspace(var.auth0_dpop_client_id), "") != "",
    try(trimspace(var.auth0_dpop_client_secret), "") != "",
  ])
  azure_ad_v1_issuer_discovery = local.azure_ad_enabled ? "https://login.microsoftonline.com/${var.azure_ad_tenant_id}/.well-known/openid-configuration" : null
  azure_ad_v1_issuer_claim     = local.azure_ad_enabled ? "https://sts.windows.net/${var.azure_ad_tenant_id}/" : null
  auth0_dpop_discovery_url     = local.auth0_dpop_enabled ? "https://${var.auth0_domain}/.well-known/openid-configuration" : null
  keycloak_internal_issuer     = "http://keycloak:8080/realms/${var.keycloak_realm}"
}

resource "konnect_gateway_consumer" "consumer_azure_ad_consumer_1" {
  count            = local.azure_ad_enabled ? 1 : 0
  username         = "azure-ad-consumer-1"
  custom_id        = var.azure_ad_consumer1_client_id
  control_plane_id = var.konnect_control_plane_id
}

resource "konnect_gateway_consumer" "consumer_azure_ad_consumer_2" {
  count            = local.azure_ad_enabled ? 1 : 0
  username         = "azure-ad-consumer-2"
  custom_id        = var.azure_ad_consumer2_client_id
  control_plane_id = var.konnect_control_plane_id
}

resource "konnect_gateway_consumer" "consumer_keycloak_consumer_1" {
  username         = "keycloak-consumer-1"
  custom_id        = "consumer-1"
  control_plane_id = var.konnect_control_plane_id
}

resource "konnect_gateway_consumer" "consumer_keycloak_consumer_2" {
  username         = "keycloak-consumer-2"
  custom_id        = "consumer-2"
  control_plane_id = var.konnect_control_plane_id
}

resource "konnect_gateway_consumer" "consumer_auth0_dpop_client" {
  count            = local.auth0_dpop_enabled ? 1 : 0
  username         = "auth0-dpop-client"
  custom_id        = var.auth0_dpop_client_id
  control_plane_id = var.konnect_control_plane_id
}

resource "konnect_gateway_service" "svc_orders_auth_azure" {
  count            = local.azure_ad_enabled ? 1 : 0
  name             = "svc-orders-auth-azure"
  protocol         = "http"
  host             = "orders-east"
  port             = 9101
  path             = "/"
  control_plane_id = var.konnect_control_plane_id
}

resource "konnect_gateway_route" "route_orders_auth_azure" {
  count            = local.azure_ad_enabled ? 1 : 0
  name             = "route-orders-auth-azure"
  methods          = ["GET"]
  paths            = ["/orders/auth/azure"]
  protocols        = ["http", "https"]
  strip_path       = false
  control_plane_id = var.konnect_control_plane_id

  service = {
    id = konnect_gateway_service.svc_orders_auth_azure[0].id
  }
}

resource "konnect_gateway_plugin_openid_connect" "openid_connect_azure" {
  count            = local.azure_ad_enabled ? 1 : 0
  control_plane_id = var.konnect_control_plane_id
  route = {
    id = konnect_gateway_route.route_orders_auth_azure[0].id
  }

  config = {
    issuer                  = local.azure_ad_v1_issuer_discovery
    auth_methods            = ["bearer"]
    bearer_token_param_type = ["header"]
    audience_claim          = ["aud"]
    audience_required       = [var.azure_ad_audience]
    issuers_allowed         = [local.azure_ad_v1_issuer_claim]
    consumer_claims         = [["appid"]]
    consumer_by             = ["custom_id"]
    verify_parameters       = false
  }
}

resource "konnect_gateway_service" "svc_orders_auth0_dpop" {
  count            = local.auth0_dpop_enabled ? 1 : 0
  name             = "svc-orders-auth0-dpop"
  protocol         = "http"
  host             = "orders-east"
  port             = 9101
  path             = "/"
  control_plane_id = var.konnect_control_plane_id
}

resource "konnect_gateway_route" "route_orders_auth0_dpop" {
  count            = local.auth0_dpop_enabled ? 1 : 0
  name             = "route-orders-auth0-dpop"
  methods          = ["GET"]
  paths            = ["/orders/auth/auth0-dpop"]
  protocols        = ["http", "https"]
  strip_path       = false
  control_plane_id = var.konnect_control_plane_id

  service = {
    id = konnect_gateway_service.svc_orders_auth0_dpop[0].id
  }
}

resource "konnect_gateway_plugin_openid_connect" "openid_connect_auth0_dpop" {
  count            = local.auth0_dpop_enabled ? 1 : 0
  control_plane_id = var.konnect_control_plane_id
  route = {
    id = konnect_gateway_route.route_orders_auth0_dpop[0].id
  }

  config = {
    issuer                   = local.auth0_dpop_discovery_url
    auth_methods             = ["bearer"]
    bearer_token_param_type  = ["header"]
    audience_claim           = ["aud"]
    audience_required        = [var.auth0_dpop_api_identifier]
    consumer_claims          = [["azp"]]
    consumer_by              = ["custom_id"]
    client_id                = [var.auth0_dpop_client_id]
    client_secret            = [var.auth0_dpop_client_secret]
    display_errors           = true
    proof_of_possession_dpop = "strict"
    verify_parameters        = false
  }
}

resource "konnect_gateway_service" "svc_orders_auth_keycloak" {
  name             = "svc-orders-auth-keycloak"
  protocol         = "http"
  host             = "orders-east"
  port             = 9101
  path             = "/"
  control_plane_id = var.konnect_control_plane_id
}

resource "konnect_gateway_route" "route_orders_auth_keycloak" {
  name             = "route-orders-auth-keycloak"
  methods          = ["GET"]
  paths            = ["/orders/auth/keycloak"]
  protocols        = ["http", "https"]
  strip_path       = false
  control_plane_id = var.konnect_control_plane_id

  service = {
    id = konnect_gateway_service.svc_orders_auth_keycloak.id
  }
}

resource "konnect_gateway_plugin_openid_connect" "openid_connect_keycloak" {
  control_plane_id = var.konnect_control_plane_id
  route = {
    id = konnect_gateway_route.route_orders_auth_keycloak.id
  }

  config = {
    issuer                  = local.keycloak_internal_issuer
    auth_methods            = ["bearer"]
    bearer_token_param_type = ["header"]
    consumer_claims         = [["azp"]]
    consumer_by             = ["custom_id"]
    roles_claim             = ["realm_access", "roles"]
    roles_required          = [var.keycloak_allowed_role]
    verify_parameters       = false
  }
}

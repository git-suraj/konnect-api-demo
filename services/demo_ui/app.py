import base64
import hashlib
import json
import os
import ssl
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"
IMG_DIR = Path("/img")
KONG_PROXY_URL = os.environ.get("KONG_PROXY_URL", "http://localhost:8000")
KONG_TLS_PROXY_URL = os.environ.get("KONG_TLS_PROXY_URL", "https://kong-dp:8443")
LOKI_QUERY_URL = os.environ.get("LOKI_QUERY_URL", "http://loki:3100/loki/api/v1/query")
KONNECT_UI_BASE_URL = os.environ.get("KONNECT_UI_BASE_URL", "https://cloud.konghq.com/us").rstrip("/")
KONNECT_CP_ID = os.environ.get("KONNECT_CP_ID", "").strip()


def build_konnect_ui_url(path: str, *, query: dict[str, str] | None = None) -> str:
    base = f"{KONNECT_UI_BASE_URL}/{path.lstrip('/')}"
    if not query:
        return base
    filtered = {key: value for key, value in query.items() if value}
    if not filtered:
        return base
    return f"{base}?{urllib.parse.urlencode(filtered)}"


DEMO_LOGS_URL = os.environ.get("DEMO_LOGS_URL") or build_konnect_ui_url(
    "/analytics/dashboards/85891a7b-d91e-4548-ba83-f82cd561342d"
)
DEMO_REQUEST_AUDIT_URL = os.environ.get("DEMO_REQUEST_AUDIT_URL", "https://cloud.konghq.com")
DEMO_AUDIT_URL = os.environ.get(
    "DEMO_AUDIT_URL",
    "http://localhost:3001/d/konnect-audit-trail/konnect-audit-trail",
)
DEMO_TRACE_URL = os.environ.get("DEMO_TRACE_URL", "http://localhost:3001/explore")
DEMO_PAYLOAD_INSPECTION_URL = os.environ.get("DEMO_PAYLOAD_INSPECTION_URL", "http://localhost:3001/explore")
DEMO_DEBUGGER_URL = os.environ.get("DEMO_DEBUGGER_URL") or build_konnect_ui_url(
    "/analytics/debugger/sessions", query={"cp_id": KONNECT_CP_ID}
)
DOCKER_SOCKET_PATH = os.environ.get("DOCKER_SOCKET_PATH", "/var/run/docker.sock")
AD_PROTECTED_API_TENANT_ID = os.environ.get("AD_PROTECTED_API_TENANT_ID", "")
AD_PROTECTED_API_AUDIENCE = os.environ.get("AD_PROTECTED_API_AUDIENCE", "")
AD_CONSUMER1_CLIENT_ID = os.environ.get("AD_CONSUMER1_CLIENT_ID", "")
AD_CONSUMER1_SECRET = os.environ.get("AD_CONSUMER1_SECRET", "")
AD_CONSUMER2_CLIENT_ID = os.environ.get("AD_CONSUMER2_CLIENT_ID", "")
AD_CONSUMER2_SECRET = os.environ.get("AD_CONSUMER2_SECRET", "")
KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM", "kong-demo")
KEYCLOAK_CONSUMER1_CLIENT_ID = os.environ.get("KEYCLOAK_CONSUMER1_CLIENT_ID", "consumer-1")
KEYCLOAK_CONSUMER1_SECRET = os.environ.get("KEYCLOAK_CONSUMER1_SECRET", "consumer-1-secret")
KEYCLOAK_CONSUMER2_CLIENT_ID = os.environ.get("KEYCLOAK_CONSUMER2_CLIENT_ID", "consumer-2")
KEYCLOAK_CONSUMER2_SECRET = os.environ.get("KEYCLOAK_CONSUMER2_SECRET", "consumer-2-secret")
KEYCLOAK_INTERNAL_BASE_URL = os.environ.get("KEYCLOAK_INTERNAL_BASE_URL", "http://keycloak:8080")
CRYPTO_HELPER_URL = os.environ.get("CRYPTO_HELPER_URL", "http://localhost:8092")
KONNECT_TOKEN = os.environ.get("KONNECT_TOKEN", "").strip()
KONNECT_SERVER_URL = os.environ.get("KONNECT_SERVER_URL", "https://us.api.konghq.com").rstrip("/")
AUTH0_DOMAIN = os.environ.get("AUTH0_DOMAIN", "").strip()
AUTH0_DPOP_API_IDENTIFIER = os.environ.get("AUTH0_DPOP_API_IDENTIFIER", "").strip()
AUTH0_DPOP_CLIENT_ID = os.environ.get("AUTH0_DPOP_EXISTING_CLIENT_ID", "").strip()
AUTH0_DPOP_CLIENT_SECRET = os.environ.get("AUTH0_DPOP_CLIENT_SECRET", "").strip()

CANARY_COUNTERS_LOCK = threading.Lock()
CANARY_COUNTERS = {
    "40-rollout": {"orders-v1": 0, "orders-v2": 0},
    "time-based": {"orders-v1": 0, "orders-v2": 0},
}
DPOP_HAPPY_PATH_CACHE = None
CANARY_TIME_ROLLOUT_DURATION_SECONDS = 120
CANARY_TIME_ROLLOUT_STARTED_AT = None
CANARY_TIME_REQUEST_INDEX = 0
CANARY_TIME_USE_FALLBACK = False

SCENES = {
    "traffic-routing-header": {
        "id": "traffic-routing-header",
        "label": "Traffic and Routing: Header-Based Routing",
        "title": "Header-Based Routing",
        "services": [
            "svc-orders-header-east",
            "svc-orders-header-west",
            "svc-orders-header-missing-region",
        ],
        "routes": [
            "route-orders-header-east",
            "route-orders-header-west",
            "route-orders-header-catchall",
        ],
        "plugins": ["request-termination on route-orders-header-catchall"],
        "controlPlane": "Konnect control plane",
        "dataPlane": "Local hybrid data plane",
        "publicPath": "/orders",
        "routingHeader": "x-region",
        "architecture": [
            "Client requests enter the Kong data plane through a single public path.",
            "The local data plane receives its configuration from a Konnect-hosted control plane.",
            "Kong evaluates the x-region request header and forwards the request to the matching upstream service.",
        ],
    },
    "traffic-control-rate-limiting": {
        "id": "traffic-control-rate-limiting",
        "label": "Traffic Control: Rate Limiting",
        "title": "Service And Consumer Rate Limiting",
        "services": ["svc-orders-rate-anonymous", "svc-orders-rate-consumer"],
        "routes": ["route-orders-rate-anonymous", "route-orders-rate-consumer"],
        "plugins": [
            "rate-limiting-advanced on svc-orders-rate-anonymous",
            "key-auth on svc-orders-rate-consumer",
            "rate-limiting-advanced on consumer-gold",
            "rate-limiting-advanced on consumer-standard",
        ],
        "consumers": ["consumer-gold", "consumer-standard"],
        "controlPlane": "Konnect control plane",
        "dataPlane": "Local hybrid data plane",
        "publicPath": "/orders/rate/anonymous | /orders/rate/consumer",
        "routingHeader": "apikey",
        "architecture": [
            "Anonymous traffic is throttled by a service-level fixed-window policy with no consumer required.",
            "Consumer mode adds key-auth, resolves the Kong consumer, and applies a consumer-scoped fixed-window policy.",
            "The UI reads Kong response headers from the local data plane to show the active limit, remaining budget, and reset window.",
        ],
    },
    "resilience-failover-health-checks": {
        "id": "resilience-failover-health-checks",
        "label": "Resilience: Failover And Health Checks",
        "title": "Failover And Health Checks",
        "services": ["svc-orders-resilience-weighted", "svc-orders-circuit-breaker"],
        "routes": ["route-orders-resilience-weighted", "route-orders-circuit-breaker"],
        "upstreams": ["upstream-orders-weighted", "upstream-orders-circuit-breaker"],
        "plugins": ["Kong upstream active health checks", "Kong upstream passive health checks"],
        "controlPlane": "Konnect control plane",
        "dataPlane": "Local hybrid data plane",
        "publicPath": "/orders/resilience/weighted | /orders/resilience/circuit-breaker",
        "routingHeader": "none",
        "architecture": [
            "Weighted Load Balancing uses one Kong upstream with two targets weighted 30:70.",
            "Circuit Breaker uses one Kong upstream with two round-robin targets and both active and passive health checks.",
            "Stopping a backend container makes Kong mark that target unhealthy and remove it from load balancing until active checks recover it.",
        ],
        "scenarios": ["weighted-load-balancing", "circuit-breaker"],
    },
    "identity-azure-token-validation": {
        "id": "identity-azure-token-validation",
        "label": "Identity: Azure AD Token Validation",
        "title": "Azure AD Token Validation",
        "services": ["svc-orders-auth-azure"],
        "routes": ["route-orders-auth-azure"],
        "plugins": ["openid-connect on route-orders-auth-azure"],
        "controlPlane": "Konnect control plane",
        "dataPlane": "Local hybrid data plane",
        "publicPath": "/orders/auth/azure",
        "routingHeader": "authorization",
        "identityProvider": "Azure AD",
        "consumers": ["consumer-1", "consumer-2"],
        "architecture": [
            "The UI requests a client-credentials token from Azure AD and lets you edit it before sending.",
            "Kong validates the bearer token with the openid-connect plugin against Azure AD discovery and JWKS metadata.",
            "Kong maps the Azure AD appid claim to a Kong Consumer by custom_id.",
            "If authentication fails, Kong blocks the request before the protected API is reached.",
        ],
    },
    "identity-keycloak-authorization": {
        "id": "identity-keycloak-authorization",
        "label": "Identity: Keycloak Authorization",
        "title": "Keycloak Role Authorization",
        "services": ["svc-orders-auth-keycloak"],
        "routes": ["route-orders-auth-keycloak"],
        "plugins": ["openid-connect on route-orders-auth-keycloak"],
        "controlPlane": "Konnect control plane",
        "dataPlane": "Local hybrid data plane",
        "publicPath": "/orders/auth/keycloak",
        "routingHeader": "authorization",
        "identityProvider": "Keycloak",
        "consumers": ["consumer-1", "consumer-2"],
        "architecture": [
            "The UI requests a client-credentials token from Keycloak for the selected consumer and lets you edit it before sending.",
            "Kong validates the bearer token and authorizes access using the configured role claim from Keycloak.",
            "Kong maps the Keycloak azp claim to a Kong Consumer by custom_id.",
            "consumer-1 has the required role and consumer-2 does not, so authorization succeeds for one and fails for the other.",
        ],
    },
    "identity-auth0-dpop": {
        "id": "identity-auth0-dpop",
        "label": "Identity: Auth0 DPoP",
        "title": "Auth0 DPoP Validation",
        "services": ["svc-orders-auth0-dpop"],
        "routes": ["route-orders-auth0-dpop"],
        "plugins": [
            "dpop-replay-demo on route-orders-auth0-dpop",
            "openid-connect on route-orders-auth0-dpop",
        ],
        "controlPlane": "Konnect control plane",
        "dataPlane": "Local hybrid data plane",
        "publicPath": "/orders/auth/auth0-dpop",
        "routingHeader": "authorization, dpop",
        "identityProvider": "Auth0",
        "consumers": ["auth0-dpop-client"],
        "architecture": [
            "The client generates an ephemeral asymmetric key pair and uses the public JWK inside each DPoP proof JWT.",
            "The first DPoP proof is sent to Auth0's token endpoint so the access token is bound to the client's key material.",
            "The second DPoP proof is sent to Kong together with Authorization: DPoP <token>, and Kong validates proof-of-possession in strict mode before proxying the request upstream.",
        ],
        "scenarios": [
            "happy-path",
            "invalid-htu",
            "invalid-htm",
            "missing-ath",
            "replay-attack",
        ],
    },
    "network-policy-ip-allow-deny": {
        "id": "network-policy-ip-allow-deny",
        "label": "Network Policy: IP Allow/Deny",
        "title": "IP Allow And Deny Listing",
        "services": ["svc-orders-ip-restriction"],
        "routes": ["route-orders-ip-restriction"],
        "plugins": ["ip-restriction on route-orders-ip-restriction"],
        "controlPlane": "Konnect control plane",
        "dataPlane": "Local hybrid data plane",
        "publicPath": "/orders/network/ip",
        "routingHeader": "x-forwarded-for",
        "architecture": [
            "The local data plane trusts forwarded client IP headers for this demo so Kong can evaluate IP policy on one laptop.",
            "Kong applies a route-scoped ip-restriction policy with both allow and deny entries.",
            "Requests that do not pass the IP policy are blocked at Kong before the protected API is reached.",
        ],
    },
    "data-quality-schema-validation": {
        "id": "data-quality-schema-validation",
        "label": "Data Quality: Schema Validation",
        "title": "Request Schema Validation",
        "services": ["svc-orders-schema-validation"],
        "routes": ["route-orders-schema-validation"],
        "plugins": ["request-validator on route-orders-schema-validation"],
        "controlPlane": "Konnect control plane",
        "dataPlane": "Local hybrid data plane",
        "publicPath": "/orders/validate/schema",
        "routingHeader": "content-type, x-order-source",
        "architecture": [
            "Kong validates the request body, query parameters, and headers before proxying to the upstream.",
            "The request-validator plugin enforces an exact Content-Type contract and a typed payload schema.",
            "Requests that fail validation are rejected at Kong and never reach the upstream service.",
        ],
    },
    "traffic-control-request-size-limiting": {
        "id": "traffic-control-request-size-limiting",
        "label": "Traffic Control: Request Size Limiting",
        "title": "Request Size Limiting",
        "services": ["svc-orders-request-size"],
        "routes": ["route-orders-request-size"],
        "plugins": ["request-size-limiting on route-orders-request-size"],
        "controlPlane": "Konnect control plane",
        "dataPlane": "Local hybrid data plane",
        "publicPath": "/orders/limits/request-size",
        "routingHeader": "content-type",
        "architecture": [
            "Kong enforces a hard request payload limit before the request reaches the upstream.",
            "The request-size-limiting plugin is configured to allow up to 2 KB on this route.",
            "Positive and negative requests use the same route so the customer can see the exact enforcement boundary.",
        ],
    },
    "monetization-metering-billing": {
        "id": "monetization-metering-billing",
        "label": "Monetization: Usage Metering",
        "title": "Usage Metering",
        "services": ["svc-orders-metering"],
        "routes": ["route-orders-metering-consumer"],
        "plugins": [
            "usage metering plugin on route-orders-metering-consumer",
            "key-auth on route-orders-metering-consumer",
        ],
        "consumers": ["demo-bank-1", "demo-bank-2"],
        "controlPlane": "Konnect control plane",
        "dataPlane": "Local hybrid data plane",
        "publicPath": "/orders/metering/consumer",
        "routingHeader": "apikey",
        "architecture": [
            "Kong meters real API requests on a single route using the route-scoped usage metering plugin.",
            "The authenticated Kong Consumer becomes the billable subject for each request.",
            "The scene keeps the gateway side simple by using one metered route and two named demo consumers.",
        ],
        "scenarios": ["consumer-based"],
    },
    "datakit-plugin-orchestration": {
        "id": "datakit-plugin-orchestration",
        "label": "DataKit: Plugin Orchestration",
        "title": "DataKit Plugin Orchestration",
        "services": [
            "svc-datakit-fallback",
            "svc-datakit-combine",
            "svc-datakit-cache",
        ],
        "routes": [
            "route-datakit-fallback",
            "route-datakit-combine",
            "route-datakit-cache",
        ],
        "plugins": [
            "openid-connect on DataKit routes",
            "datakit on route-datakit-fallback",
            "datakit on route-datakit-combine",
            "datakit on route-datakit-cache",
        ],
        "controlPlane": "Konnect control plane",
        "dataPlane": "Local hybrid data plane",
        "publicPath": "/orders/datakit/fallback | /orders/datakit/combine | /orders/datakit/cache",
        "routingHeader": "authorization",
        "identityProvider": "Keycloak",
        "consumers": ["consumer-1"],
        "architecture": [
            "All three routes are protected by Keycloak bearer-token validation at Kong before the Datakit flow is allowed to execute.",
            "All three scenarios use Datakit callout nodes: conditional fallback, cross-API join on accountId, and Redis-backed cache lookup with a 30-second TTL.",
            "Each route returns the authenticated role in x-authenticated-role so the client can see which token role Kong accepted for the request.",
        ],
        "scenarios": ["fallback", "combine", "cache"],
    },
    "transformation-gateway-payload-encryption": {
        "id": "transformation-gateway-payload-encryption",
        "label": "Transformation: Gateway Payload Encryption/Decryption",
        "title": "Gateway Payload Encryption/Decryption",
        "services": ["svc-orders-payload-crypto"],
        "routes": ["route-orders-payload-crypto"],
        "plugins": ["payload-crypto-demo on route-orders-payload-crypto"],
        "controlPlane": "Konnect control plane",
        "dataPlane": "Local hybrid data plane",
        "publicPath": "/orders/security/payload-crypto",
        "routingHeader": "content-type",
        "architecture": [
            "The client sends an encrypted request envelope containing an encrypted AES session key, an IV, and an encrypted payload.",
            "Kong decrypts the session key with the gateway private key, decrypts the payload, and forwards plaintext JSON to the upstream.",
            "Kong then encrypts the upstream response with a new AES session key, wraps that key with the client public key, and returns the encrypted response envelope.",
        ],
    },
    "security-injection-protection": {
        "id": "security-injection-protection",
        "label": "Security: Injection Protection",
        "title": "Injection Protection",
        "services": ["svc-orders-injection-protection"],
        "routes": [
            "route-orders-injection-query",
            "route-orders-injection-body",
            "route-orders-injection-headers",
        ],
        "plugins": [
            "injection-protection on route-orders-injection-query",
            "injection-protection on route-orders-injection-body",
            "injection-protection on route-orders-injection-headers",
        ],
        "controlPlane": "Konnect control plane",
        "dataPlane": "Local hybrid data plane",
        "publicPath": "/orders/security/injection/query | /orders/security/injection/body | /orders/security/injection/headers",
        "routingHeader": "content-type, x-search-term",
        "architecture": [
            "Each subscene applies the Enterprise Injection Protection plugin to a dedicated route.",
            "Kong inspects query parameters, request bodies, or headers for SQL-style injection patterns.",
            "When a malicious pattern is detected, Kong blocks the request before any upstream call is made.",
        ],
        "scenarios": ["query-params", "body", "headers"],
    },
    "transport-security-http-enforcement": {
        "id": "transport-security-http-enforcement",
        "label": "Transport Security: HTTP Enforcement",
        "title": "HTTP Blocked And HTTP To HTTPS Redirect",
        "services": ["svc-orders-transport-security"],
        "routes": [
            "route-orders-http-blocked",
            "route-orders-http-redirect",
        ],
        "plugins": ["native Kong HTTPS-only route policy"],
        "controlPlane": "Konnect control plane",
        "dataPlane": "Local hybrid data plane",
        "publicPath": "/orders/transport/http-blocked | /orders/transport/http-redirect",
        "routingHeader": "none",
        "architecture": [
            "Kong uses native route protocol policy to allow only HTTPS on these transport-security routes.",
            "One route responds with 426 to block plain HTTP while the other returns a 308 redirect with a Location header.",
            "In both flows, Kong decides at the edge and the protected API is not reached over the initial HTTP request.",
        ],
        "scenarios": ["http-blocked", "http-to-https-redirect"],
    },
    "api-lifecycle-versioned-routing": {
        "id": "api-lifecycle-versioned-routing",
        "label": "API Lifecycle: Versioned Routing",
        "title": "Versioned API Routing",
        "services": ["svc-orders-version-v1", "svc-orders-version-v2"],
        "routes": [
            "route-orders-version-path-v1",
            "route-orders-version-path-v2",
            "route-orders-version-header-v1",
            "route-orders-version-header-v2",
        ],
        "plugins": ["route matching on path and x-api-version header"],
        "controlPlane": "Konnect control plane",
        "dataPlane": "Local hybrid data plane",
        "publicPath": "/api/v1/orders | /api/v2/orders | /orders/version/header",
        "routingHeader": "x-api-version",
        "architecture": [
            "Kong exposes both path-based and header-based version routing for the same logical Orders API.",
            "Path-based routing sends /api/v1/orders to the v1 upstream and /api/v2/orders to the v2 upstream.",
            "Header-based routing keeps a single path and lets Kong select v1 or v2 based on x-api-version.",
        ],
        "scenarios": ["path", "header"],
    },
    "api-lifecycle-canary-migration": {
        "id": "api-lifecycle-canary-migration",
        "label": "API Lifecycle: Canary Migration",
        "title": "Canary Migration",
        "services": ["svc-orders-canary-primary"],
        "routes": [
            "route-orders-canary-40",
            "route-orders-canary-time",
            "route-orders-canary-header",
            "route-orders-canary-consumer",
        ],
        "plugins": [
            "canary on route-orders-canary-40",
            "canary on route-orders-canary-time",
            "canary on route-orders-canary-header",
            "key-auth on route-orders-canary-consumer",
            "acl on route-orders-canary-consumer",
            "canary on route-orders-canary-consumer",
        ],
        "consumers": ["consumer-pilot", "consumer-standard-lifecycle"],
        "controlPlane": "Konnect control plane",
        "dataPlane": "Local hybrid data plane",
        "publicPath": "/orders/canary/40 | /orders/canary/time | /orders/canary/header | /orders/canary/consumer",
        "routingHeader": "x-canary-version, apikey",
        "architecture": [
            "Kong keeps v1 as the primary upstream and uses the Canary Release plugin to gradually or selectively shift traffic to v2.",
            "The demo covers fixed-percentage rollout, time-based rollout, explicit header override, and consumer-based routing.",
            "Header and consumer modes are sticky by policy, while time-based rollout changes the effective percentage over a two-minute migration window.",
        ],
        "scenarios": ["40-rollout", "time-based", "header-based", "consumer-based"],
    },
    "api-lifecycle-deprecation": {
        "id": "api-lifecycle-deprecation",
        "label": "API Lifecycle: Deprecation",
        "title": "API Deprecation",
        "services": ["svc-orders-deprecation-v1", "svc-orders-deprecation-v2"],
        "routes": [
            "route-orders-deprecation-v1",
            "route-orders-deprecation-v2",
            "route-orders-deprecation-sunset",
        ],
        "plugins": [
            "response-transformer on route-orders-deprecation-v1",
            "request-termination on route-orders-deprecation-sunset",
        ],
        "controlPlane": "Konnect control plane",
        "dataPlane": "Local hybrid data plane",
        "publicPath": "/orders/deprecation/v1 | /orders/deprecation/v2 | /orders/deprecation/v1/sunset",
        "routingHeader": "none",
        "architecture": [
            "Kong signals API lifecycle status at the edge by adding deprecation, sunset, and successor-version headers on v1.",
            "Clients can continue using the deprecated version during the migration window while v2 remains current.",
            "After the sunset point, Kong enforces retirement and blocks the old version before the upstream is reached.",
        ],
        "scenarios": ["deprecated-v1", "current-v2", "sunset-enforced"],
    },
}

LATENCY_HEADERS = {
    "x-kong-proxy-latency",
    "x-kong-upstream-latency",
    "x-kong-response-latency",
}

RATE_LIMIT_KEYS = {
    "consumer-gold": "key-consumer-gold",
    "consumer-standard": "key-consumer-standard",
}

RATE_LIMIT_POLICIES = {
    "anonymous": {
        "route": "route-orders-rate-anonymous",
        "service": "svc-orders-rate-anonymous",
        "plugin": "rate-limiting-advanced on svc-orders-rate-anonymous",
        "window_seconds": 30,
        "plugin_scope": "svc-orders-rate-anonymous",
    },
    "consumer-standard": {
        "route": "route-orders-rate-consumer",
        "service": "svc-orders-rate-consumer",
        "plugin": "rate-limiting-advanced on consumer-standard",
        "window_seconds": 30,
        "plugin_scope": "consumer-standard",
    },
    "consumer-gold": {
        "route": "route-orders-rate-consumer",
        "service": "svc-orders-rate-consumer",
        "plugin": "rate-limiting-advanced on consumer-gold",
        "window_seconds": 30,
        "plugin_scope": "consumer-gold",
    },
}

RATE_LIMIT_EXECUTIONS = {}
RESILIENCE_WEIGHTED_COUNTS = {"orders-instance-1": 0, "orders-instance-2": 0}
RESILIENCE_INSTANCES = {
    "instance-1": {
        "label": "Service Instance 1",
        "container": "konnect-demo-orders-instance-1",
        "service": "orders-instance-1",
        "target": "orders-instance-1:9201",
    },
    "instance-2": {
        "label": "Service Instance 2",
        "container": "konnect-demo-orders-instance-2",
        "service": "orders-instance-2",
        "target": "orders-instance-2:9202",
    },
}

IP_PRESETS = {
    "allowed": "10.10.10.8",
    "denied": "10.10.10.66",
    "not-listed": "203.0.113.25",
}

SCHEMA_CASES = {
    "valid-request": {
        "path": "/orders/validate/schema?channel=web",
        "headers": {
            "Content-Type": "application/json",
            "x-order-source": "portal",
        },
        "body": {"orderId": "ORD-1001", "amount": 42.5, "currency": "USD"},
    },
    "invalid-body": {
        "path": "/orders/validate/schema?channel=web",
        "headers": {
            "Content-Type": "application/json",
            "x-order-source": "portal",
        },
        "body": {"orderId": "ORD-1001", "amount": "forty-two"},
    },
    "invalid-query-param": {
        "path": "/orders/validate/schema?channel=partner",
        "headers": {
            "Content-Type": "application/json",
            "x-order-source": "portal",
        },
        "body": {"orderId": "ORD-1001", "amount": 42.5, "currency": "USD"},
    },
    "invalid-header-content-type": {
        "path": "/orders/validate/schema?channel=web",
        "headers": {
            "Content-Type": "application/json; charset=UTF-8",
            "x-order-source": "external",
        },
        "body": {"orderId": "ORD-1001", "amount": 42.5, "currency": "USD"},
    },
}

REQUEST_SIZE_CASES = {
    "positive": {
        "path": "/orders/limits/request-size",
        "headers": {"Content-Type": "application/json"},
        "body": {"payload": "x" * 512},
    },
    "negative": {
        "path": "/orders/limits/request-size",
        "headers": {"Content-Type": "application/json"},
        "body": {"payload": "x" * 2600},
    },
}

METERING_CONSUMERS = {
    "demo-bank-1": {
        "path": "/orders/metering/consumer",
        "method": "GET",
        "headers": {
            "Accept": "application/json",
            "apikey": "key-demo-bank-1",
        },
        "route": "route-orders-metering-consumer",
        "service": "svc-orders-metering",
        "subject": "demo-bank-1",
        "subject_source": "consumer",
        "dimensions": {},
        "policy": "consumer subject",
    },
    "demo-bank-2": {
        "path": "/orders/metering/consumer",
        "method": "GET",
        "headers": {
            "Accept": "application/json",
            "apikey": "key-demo-bank-2",
        },
        "route": "route-orders-metering-consumer",
        "service": "svc-orders-metering",
        "subject": "demo-bank-2",
        "subject_source": "consumer",
        "dimensions": {},
        "policy": "consumer subject",
    },
}

DATAKIT_SCENARIOS = {
    "fallback": {
        "path": "/orders/datakit/fallback",
        "route": "route-datakit-fallback",
        "service": "svc-datakit-fallback",
        "method": "GET",
        "label": "Conditional Fallback",
    },
    "combine": {
        "path": "/orders/datakit/combine",
        "route": "route-datakit-combine",
        "service": "svc-datakit-combine",
        "method": "GET",
        "label": "Combine Results",
    },
    "cache": {
        "path": "/orders/datakit/cache",
        "route": "route-datakit-cache",
        "service": "svc-datakit-cache",
        "method": "GET",
        "label": "Redis Cache",
        "ttl_seconds": 30,
    },
}

INJECTION_CASES = {
    "query-params": {
        "method": "GET",
        "path": "/orders/security/injection/query?search=insert%20into%20test",
        "headers": {"Accept": "application/json"},
        "body": None,
        "route": "route-orders-injection-query",
        "location": "Query Params",
    },
    "body": {
        "method": "POST",
        "path": "/orders/security/injection/body",
        "headers": {"Content-Type": "application/json"},
        "body": {"search": "insert into test"},
        "route": "route-orders-injection-body",
        "location": "Body",
    },
    "headers": {
        "method": "GET",
        "path": "/orders/security/injection/headers",
        "headers": {"Accept": "application/json", "x-search-term": "insert into test"},
        "body": None,
        "route": "route-orders-injection-headers",
        "location": "Headers",
    },
}

VERSION_ROUTING_CASES = {
    "path:v1": {
        "path": "/api/v1/orders",
        "headers": {"Accept": "application/json"},
        "route": "route-orders-version-path-v1",
        "service": "svc-orders-version-v1",
        "mode": "path",
        "version": "v1",
    },
    "path:v2": {
        "path": "/api/v2/orders",
        "headers": {"Accept": "application/json"},
        "route": "route-orders-version-path-v2",
        "service": "svc-orders-version-v2",
        "mode": "path",
        "version": "v2",
    },
    "header:v1": {
        "path": "/orders/version/header",
        "headers": {"Accept": "application/json", "x-api-version": "v1"},
        "route": "route-orders-version-header-v1",
        "service": "svc-orders-version-v1",
        "mode": "header",
        "version": "v1",
    },
    "header:v2": {
        "path": "/orders/version/header",
        "headers": {"Accept": "application/json", "x-api-version": "v2"},
        "route": "route-orders-version-header-v2",
        "service": "svc-orders-version-v2",
        "mode": "header",
        "version": "v2",
    },
}

CANARY_CONSUMER_KEYS = {
    "consumer-pilot": "key-consumer-pilot",
    "consumer-standard-lifecycle": "key-consumer-standard-lifecycle",
}

DEPRECATION_CASES = {
    "deprecated-v1": {
        "path": "/orders/deprecation/v1",
        "route": "route-orders-deprecation-v1",
        "service": "svc-orders-deprecation-v1",
        "label": "Deprecated v1",
    },
    "current-v2": {
        "path": "/orders/deprecation/v2",
        "route": "route-orders-deprecation-v2",
        "service": "svc-orders-deprecation-v2",
        "label": "Current v2",
    },
    "sunset-enforced": {
        "path": "/orders/deprecation/v1/sunset",
        "route": "route-orders-deprecation-sunset",
        "service": "svc-orders-deprecation-v1",
        "label": "Sunset Enforced",
    },
}

DPOP_TEST_MODES = {
    "happy-path": "The client sends the required DPoP proof to Auth0 when requesting the token, then sends a second DPoP proof to Kong when calling the protected API. The same key is used consistently across both steps.",
    "invalid-htu": "Auth0 issues a valid DPoP-bound token, but the client sends an API DPoP proof whose `htu` claim does not match the actual Kong URL being called. Kong should reject the request because the proof is bound to the wrong endpoint.",
    "invalid-htm": "Auth0 issues a valid DPoP-bound token, but the client sends an API DPoP proof whose `htm` claim does not match the actual HTTP method. Kong should reject the request because the proof is bound to a different method.",
    "missing-ath": "Auth0 issues a valid DPoP-bound token, but the client sends an API DPoP proof without the required `ath` claim. Kong should reject the request because the proof is not bound to the presented access token.",
    "replay-attack": "The client first makes one valid DPoP-protected API call, then immediately replays the exact same Authorization token and exact same DPoP proof to Kong. Kong should reject the replayed proof because it is being reused instead of being freshly generated for a new request.",
}

DPOP_CLAIM_GLOSSARY = {
    "htu": "HTTP URI. The exact URL the DPoP proof is meant for. If this does not match the real API URL, the proof is being presented to the wrong endpoint.",
    "htm": "HTTP Method. The exact HTTP verb the proof is meant for, such as GET or POST. If this does not match the real method, the proof is for a different kind of request.",
    "ath": "Access Token Hash. A SHA-256 hash of the presented access token, base64url-encoded. It ties the proof to that exact token so the proof cannot be reused with some other token.",
    "iat": "Issued At. The time the proof was created. Kong can reject proofs that are too old or too far in the future.",
    "jti": "JWT ID. A unique identifier for one proof instance. Reusing the same jti means the same proof is being replayed instead of freshly generated.",
}

DPOP_NEGATIVE_SCENARIO_GUIDE = {
    "invalid-htu": {
        "broken_claim": "htu",
        "simple_explanation": "The proof says it was created for a different URL than the one being called.",
        "what_kong_checks": "Kong compares the proof's htu claim with the actual request URL it received.",
        "why_rejected": "If those URLs do not match, the proof could have been created for some other endpoint, so Kong rejects it.",
    },
    "invalid-htm": {
        "broken_claim": "htm",
        "simple_explanation": "The proof says it was created for a different HTTP method than the one actually used.",
        "what_kong_checks": "Kong compares the proof's htm claim with the real request method, such as GET or POST.",
        "why_rejected": "If the proof says POST but the request is actually GET, the proof does not describe this request, so Kong rejects it.",
    },
    "missing-ath": {
        "broken_claim": "ath",
        "simple_explanation": "The proof is not cryptographically tied to the access token being presented.",
        "what_kong_checks": "Kong expects the proof to carry ath, which is the hash of the exact access token in Authorization: DPoP.",
        "why_rejected": "Without ath, the proof does not prove that this specific token is the one the client intended to use.",
    },
    "replay-attack": {
        "broken_claim": "jti",
        "simple_explanation": "The same proof is being reused instead of generating a fresh one.",
        "what_kong_checks": "The custom plugin reads jti from the DPoP proof payload and stores it in a replay cache.",
        "why_rejected": "When the same jti appears again, Kong treats the proof as a replay and rejects it.",
    },
}

TRANSPORT_SECURITY_CASES = {
    "http-blocked": {
        "path": "/orders/transport/http-blocked",
        "route": "route-orders-http-blocked",
        "expected_outcome": "Kong should reject the plain HTTP request with 426 and keep the protected API untouched.",
    },
    "http-to-https-redirect": {
        "path": "/orders/transport/http-redirect",
        "route": "route-orders-http-redirect",
        "expected_outcome": "Kong should return a 308 redirect with a Location header that points the caller to HTTPS.",
    },
}


def shell_quote(value):
    return "'" + str(value).replace("'", "'\"'\"'") + "'"


def build_curl_command(url, headers, method="GET", body=None):
    parts = ["curl", "-i", "-X", method.upper()]
    for key, value in headers.items():
        parts.extend(["-H", shell_quote(f"{key}: {value}")])
    if body is not None:
        body_value = body if isinstance(body, str) else json.dumps(body)
        parts.extend(["--data", shell_quote(body_value)])
    parts.append(shell_quote(url))
    return " ".join(parts)


def json_bytes(payload):
    return json.dumps(payload).encode("utf-8")


def sanitize_headers(headers):
    return {k: v for k, v in headers.items() if k.lower() not in LATENCY_HEADERS}


def normalize_detail_entities(items):
    return [[label, value if value not in (None, "") else "None"] for label, value in items]


def lookup_trace_id_for_request(request_id: str, attempts: int = 5, delay_seconds: float = 0.5) -> str | None:
    if not request_id:
        return None
    query = (
        '{service_name="kong-data-plane"} | log_type="access" '
        f'| request_id="{request_id}" | line_format "{{{{.trace_id}}}}"'
    )
    for attempt in range(attempts):
        try:
            url = f"{LOKI_QUERY_URL}?{urllib.parse.urlencode({'query': query})}"
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=3, context=ssl._create_unverified_context()) as response:
                payload = json.loads(response.read().decode("utf-8"))
            results = (((payload or {}).get("data") or {}).get("result")) or []
            for stream in results:
                for value in stream.get("values", []):
                    if len(value) >= 2:
                        trace_id = (value[1] or "").strip()
                        if trace_id and trace_id != "null":
                            return trace_id
        except Exception:
            pass
        if attempt < attempts - 1:
            time.sleep(delay_seconds)
    return None


def enrich_payload_with_trace(payload):
    if not isinstance(payload, dict):
        return payload

    console_view = payload.get("consoleView")
    if not isinstance(console_view, dict):
        return payload

    request_view = console_view.get("request")
    if not isinstance(request_view, dict):
        return payload

    headers = request_view.get("headers") or {}
    if not isinstance(headers, dict):
        return payload

    request_id = headers.get("x-request-id") or headers.get("X-Request-Id")
    if not request_id:
        return payload

    payload["requestId"] = request_id

    result = payload.get("result")
    if isinstance(result, dict):
        result["requestId"] = request_id

    response_view = console_view.get("response")
    response_headers = response_view.get("headers") if isinstance(response_view, dict) else {}
    if isinstance(response_headers, dict):
        kong_request_id = (
            response_headers.get("x-kong-request-id")
            or response_headers.get("X-Kong-Request-Id")
            or response_headers.get("kong-request-id")
            or response_headers.get("Kong-Request-Id")
        )
        if kong_request_id:
            payload["kongRequestId"] = kong_request_id
            if isinstance(result, dict):
                result["kongRequestId"] = kong_request_id

    trace_id = lookup_trace_id_for_request(request_id)
    if trace_id:
        payload["traceId"] = trace_id
        if isinstance(result, dict):
            result["traceId"] = trace_id

    detail_view = payload.get("detailView")
    if isinstance(detail_view, dict):
        if trace_id:
            detail_view["traceId"] = trace_id
        entities = detail_view.get("entities")
        if isinstance(entities, list):
            if payload.get("kongRequestId"):
                entities.append(["Kong Request Id", payload["kongRequestId"]])
            entities.append(["Client Request Id", request_id])
            entities.append(
                [
                    "Trace Source",
                    (
                        f"{trace_id} resolved from Loki using request_id {request_id}"
                        if trace_id
                        else f"Trace lookup uses Loki with request_id {request_id}; trace_id not resolved yet"
                    ),
                ]
            )

    return payload


def docker_api_request(method, path, body=b""):
    if not os.path.exists(DOCKER_SOCKET_PATH):
        raise FileNotFoundError(DOCKER_SOCKET_PATH)

    request = (
        f"{method} {path} HTTP/1.1\r\n"
        "Host: docker\r\n"
        "Connection: close\r\n"
        f"Content-Length: {len(body)}\r\n"
        "\r\n"
    ).encode("utf-8") + body

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(DOCKER_SOCKET_PATH)
        sock.sendall(request)
        response = bytearray()
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            response.extend(chunk)
    finally:
        sock.close()

    header_bytes, _, body_bytes = bytes(response).partition(b"\r\n\r\n")
    header_lines = header_bytes.decode("utf-8", errors="replace").split("\r\n")
    status_code = int(header_lines[0].split(" ")[1])
    headers = {}
    for line in header_lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()

    if headers.get("transfer-encoding", "").lower() == "chunked":
        decoded = bytearray()
        remaining = body_bytes
        while remaining:
            line, _, remaining = remaining.partition(b"\r\n")
            if not line:
                break
            size = int(line.decode("utf-8"), 16)
            if size == 0:
                break
            decoded.extend(remaining[:size])
            remaining = remaining[size + 2 :]
        body_bytes = bytes(decoded)

    parsed_body = {}
    if body_bytes:
        try:
            parsed_body = json.loads(body_bytes.decode("utf-8"))
        except json.JSONDecodeError:
            parsed_body = {"raw": body_bytes.decode("utf-8", errors="replace")}
    return {"status": status_code, "headers": headers, "body": parsed_body}


def docker_container_status(container_name):
    response = docker_api_request("GET", f"/containers/{container_name}/json")
    if response["status"] != 200:
        return {"status": "unknown", "running": False}
    state = response["body"].get("State", {})
    return {
        "status": state.get("Status", "unknown"),
        "running": bool(state.get("Running")),
    }


def set_container_state(container_name, action):
    action_path = "/start" if action == "start" else "/stop?t=1"
    response = docker_api_request("POST", f"/containers/{container_name}{action_path}")
    return response["status"] in {204, 304}


def get_resilience_instance_states():
    states = {}
    for instance_id, meta in RESILIENCE_INSTANCES.items():
        try:
            states[instance_id] = {
                "label": meta["label"],
                "service": meta["service"],
                **docker_container_status(meta["container"]),
            }
        except Exception as exc:  # noqa: BLE001
            states[instance_id] = {
                "label": meta["label"],
                "service": meta["service"],
                "status": f"error: {exc}",
                "running": False,
            }
    return states


def parse_response_body(raw_body):
    if not raw_body:
        return {}
    try:
        return json.loads(raw_body)
    except json.JSONDecodeError:
        return {"raw": raw_body}


def parse_int(value):
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def extract_rate_limit_metrics(headers):
    metrics = {"limit": None, "remaining": None, "reset": None, "retry_after": None}
    for key, value in headers.items():
        lower_key = key.lower()
        if "ratelimit" not in lower_key and lower_key != "retry-after":
            continue
        parsed = parse_int(value)
        if parsed is None:
            continue
        if lower_key == "retry-after":
            metrics["retry_after"] = parsed
        elif "remaining" in lower_key and metrics["remaining"] is None:
            metrics["remaining"] = parsed
        elif "reset" in lower_key and metrics["reset"] is None:
            metrics["reset"] = parsed
        elif "limit" in lower_key and metrics["limit"] is None:
            metrics["limit"] = parsed
    return metrics


def update_execution_counter(counter_key, limit, remaining, reset_seconds, response_status):
    now = time.time()
    state = RATE_LIMIT_EXECUTIONS.get(counter_key)
    if state and now >= state["window_expires_at"]:
        state = None

    if limit is not None and remaining is not None and response_status != 429:
        execution_count = max(limit - remaining, 0)
    elif state:
        execution_count = state["execution_count"] + 1
    elif limit is not None:
        execution_count = limit + 1 if response_status == 429 else 1
    else:
        execution_count = 1

    window_expires_at = now + max(reset_seconds or 0, 0)
    RATE_LIMIT_EXECUTIONS[counter_key] = {
        "execution_count": execution_count,
        "window_expires_at": window_expires_at,
        "window_started_at": window_expires_at - max(reset_seconds or 0, 0),
    }
    return execution_count, max(int(round(window_expires_at - now)), 0), window_expires_at


def build_rate_limit_expected_outcome(mode, consumer, window_seconds, limit):
    scope = "Anonymous requests" if mode == "anonymous" else f"{consumer} requests"
    blocked_request = (limit or 0) + 1 if limit is not None else "the next blocked request"
    return (
        f"{scope} should pass through Kong for requests 1-{limit} in each {window_seconds}-second fixed window. "
        f"Request {blocked_request} should return 429 until the window resets."
    )


def request_through_kong(url, headers, method="GET", body=None):
    body_bytes = None
    if body is not None:
        if isinstance(body, (dict, list)):
            body_bytes = json.dumps(body).encode("utf-8")
        elif isinstance(body, bytes):
            body_bytes = body
        else:
            body_bytes = str(body).encode("utf-8")
    req = urllib.request.Request(url, data=body_bytes, headers=headers, method=method.upper())
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw_body = resp.read().decode("utf-8")
            return {
                "status": resp.status,
                "headers": sanitize_headers({k.lower(): v for k, v in resp.headers.items()}),
                "body": parse_response_body(raw_body),
            }
    except urllib.error.HTTPError as exc:
        raw_body = exc.read().decode("utf-8") if exc.fp else ""
        return {
            "status": exc.code,
            "headers": sanitize_headers({k.lower(): v for k, v in exc.headers.items()}),
            "body": parse_response_body(raw_body),
        }


def request_through_kong_tls(url, headers, method="GET", body=None):
    body_bytes = None
    if body is not None:
        if isinstance(body, (dict, list)):
            body_bytes = json.dumps(body).encode("utf-8")
        elif isinstance(body, bytes):
            body_bytes = body
        else:
            body_bytes = str(body).encode("utf-8")
    req = urllib.request.Request(url, data=body_bytes, headers=headers, method=method.upper())
    context = ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(req, timeout=10, context=context) as resp:
            raw_body = resp.read().decode("utf-8")
            return {
                "status": resp.status,
                "headers": sanitize_headers({k.lower(): v for k, v in resp.headers.items()}),
                "body": parse_response_body(raw_body),
            }
    except urllib.error.HTTPError as exc:
        raw_body = exc.read().decode("utf-8") if exc.fp else ""
        return {
            "status": exc.code,
            "headers": sanitize_headers({k.lower(): v for k, v in exc.headers.items()}),
            "body": parse_response_body(raw_body),
        }
    except urllib.error.URLError as exc:
        return {
            "status": None,
            "headers": {},
            "body": {"message": f"HTTPS follow-up request failed: {exc.reason}"},
        }


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request_through_kong_no_redirect(url, headers, method="GET", body=None):
    body_bytes = None
    if body is not None:
        if isinstance(body, (dict, list)):
            body_bytes = json.dumps(body).encode("utf-8")
        elif isinstance(body, bytes):
            body_bytes = body
        else:
            body_bytes = str(body).encode("utf-8")
    req = urllib.request.Request(url, data=body_bytes, headers=headers, method=method.upper())
    opener = urllib.request.build_opener(NoRedirectHandler)
    try:
        with opener.open(req, timeout=10) as resp:
            raw_body = resp.read().decode("utf-8")
            return {
                "status": resp.status,
                "headers": sanitize_headers({k.lower(): v for k, v in resp.headers.items()}),
                "body": parse_response_body(raw_body),
            }
    except urllib.error.HTTPError as exc:
        raw_body = exc.read().decode("utf-8") if exc.fp else ""
        return {
            "status": exc.code,
            "headers": sanitize_headers({k.lower(): v for k, v in exc.headers.items()}),
            "body": parse_response_body(raw_body),
        }


def post_form(url, form_data):
    body = urllib.parse.urlencode(form_data).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw_body = resp.read().decode("utf-8")
            return {"status": resp.status, "headers": {k.lower(): v for k, v in resp.headers.items()}, "body": json.loads(raw_body)}
    except urllib.error.HTTPError as exc:
        raw_body = exc.read().decode("utf-8") if exc.fp else ""
        parsed = parse_response_body(raw_body)
        return {"status": exc.code, "headers": {k.lower(): v for k, v in exc.headers.items()}, "body": parsed}


def post_json(url, payload):
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw_body = resp.read().decode("utf-8")
            parsed = json.loads(raw_body) if raw_body else {}
            return {"status": resp.status, "headers": {k.lower(): v for k, v in resp.headers.items()}, "body": parsed}
    except urllib.error.HTTPError as exc:
        raw_body = exc.read().decode("utf-8") if exc.fp else ""
        parsed = parse_response_body(raw_body)
        return {"status": exc.code, "headers": {k.lower(): v for k, v in exc.headers.items()}, "body": parsed}


def konnect_api_json(method, path, payload=None):
    if not KONNECT_TOKEN or not KONNECT_CP_ID:
        raise RuntimeError("Konnect API credentials are not available in demo-ui.")
    url = f"{KONNECT_SERVER_URL}/v2/control-planes/{KONNECT_CP_ID}/core-entities/{path.lstrip('/')}"
    request = urllib.request.Request(
        url,
        data=None if payload is None else json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {KONNECT_TOKEN}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            body = response.read().decode("utf-8")
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{method} {path} failed with {exc.code}: {error_body}") from exc


def get_route_by_name(route_name):
    routes = konnect_api_json("GET", "routes?size=1000")
    route_items = routes.get("data") or []
    return next((item for item in route_items if item.get("name") == route_name), None)


def get_route_plugin(route_id, plugin_name):
    plugins = konnect_api_json("GET", f"routes/{route_id}/plugins?size=1000")
    plugin_items = plugins.get("data") or []
    return next((item for item in plugin_items if item.get("name") == plugin_name), None)


def reset_canary_time_rollout():
    global CANARY_TIME_ROLLOUT_STARTED_AT
    route = get_route_by_name("route-orders-canary-time")
    if route is None:
        raise RuntimeError("route-orders-canary-time not found in Konnect.")
    plugin = get_route_plugin(route["id"], "canary")
    if plugin is None:
        raise RuntimeError("canary plugin not found on route-orders-canary-time.")
    start_epoch = int(time.time())
    konnect_api_json(
        "PUT",
        f"routes/{route['id']}/plugins/{plugin['id']}",
        {
            "name": "canary",
            "config": {
                "upstream_host": "orders-v2",
                "upstream_port": 9302,
                "hash": "none",
                "steps": 20,
                "duration": CANARY_TIME_ROLLOUT_DURATION_SECONDS,
                "start": start_epoch,
            },
        },
    )
    with CANARY_COUNTERS_LOCK:
        CANARY_COUNTERS["time-based"] = {"orders-v1": 0, "orders-v2": 0}
    CANARY_TIME_ROLLOUT_STARTED_AT = start_epoch
    return start_epoch


def ensure_time_based_rollout_window():
    global CANARY_TIME_ROLLOUT_STARTED_AT
    now = int(time.time())
    if (
        CANARY_TIME_ROLLOUT_STARTED_AT is None
        or now - CANARY_TIME_ROLLOUT_STARTED_AT >= CANARY_TIME_ROLLOUT_DURATION_SECONDS
    ):
        return reset_canary_time_rollout()
    return CANARY_TIME_ROLLOUT_STARTED_AT


def record_canary_counter(scenario, selected_service):
    if scenario not in CANARY_COUNTERS or selected_service not in CANARY_COUNTERS[scenario]:
        return
    with CANARY_COUNTERS_LOCK:
        CANARY_COUNTERS[scenario][selected_service] += 1
        return dict(CANARY_COUNTERS[scenario])


def reset_canary_scene_runtime():
    global CANARY_TIME_ROLLOUT_STARTED_AT, CANARY_TIME_REQUEST_INDEX, CANARY_TIME_USE_FALLBACK
    with CANARY_COUNTERS_LOCK:
        CANARY_COUNTERS["40-rollout"] = {"orders-v1": 0, "orders-v2": 0}
        CANARY_COUNTERS["time-based"] = {"orders-v1": 0, "orders-v2": 0}
    CANARY_TIME_ROLLOUT_STARTED_AT = None
    CANARY_TIME_REQUEST_INDEX = 0
    CANARY_TIME_USE_FALLBACK = False
    rollout_reset_error = None
    rollout_started_at = None
    try:
        rollout_started_at = reset_canary_time_rollout()
    except RuntimeError as exc:
        rollout_reset_error = str(exc)
        CANARY_TIME_USE_FALLBACK = True
    return {
        "ok": True,
        "rolloutStartedAt": rollout_started_at,
        "rolloutResetError": rollout_reset_error,
    }


def build_bearer_headers(token):
    headers = {"Accept": "application/json", "x-request-id": str(uuid.uuid4())}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def kong_identity_consumer_name(idp_name, consumer_label):
    if idp_name == "Azure AD":
        return f"azure-ad-{consumer_label}"
    if idp_name == "Keycloak":
        return f"keycloak-{consumer_label}"
    if idp_name == "Auth0":
        return consumer_label
    return consumer_label


def consumer_mapping_description(idp_name):
    if idp_name == "Azure AD":
        return "appid claim -> Kong Consumer custom_id"
    if idp_name == "Keycloak":
        return "azp claim -> Kong Consumer custom_id"
    if idp_name == "Auth0":
        return "azp claim -> Kong Consumer custom_id with DPoP-bound access token"
    return "No consumer mapping"


def generate_keycloak_access_token(consumer="consumer-1"):
    client_id = KEYCLOAK_CONSUMER1_CLIENT_ID if consumer == "consumer-1" else KEYCLOAK_CONSUMER2_CLIENT_ID
    client_secret = KEYCLOAK_CONSUMER1_SECRET if consumer == "consumer-1" else KEYCLOAK_CONSUMER2_SECRET
    token_url = f"{KEYCLOAK_INTERNAL_BASE_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
    response = post_form(
        token_url,
        {
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "client_credentials",
        },
    )
    token = response["body"].get("access_token", "") if isinstance(response["body"], dict) else ""
    return token, response


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def json_b64url(payload) -> str:
    return b64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=False).encode("utf-8"))


def decode_jwt_parts(token: str) -> dict:
    parts = token.split(".")
    if len(parts) < 2:
        return {"raw": token}

    def decode_part(value: str):
        padded = value + "=" * ((4 - len(value) % 4) % 4)
        return json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))

    return {"header": decode_part(parts[0]), "payload": decode_part(parts[1])}


def auth0_dpop_ready() -> tuple[bool, str | None]:
    missing = []
    if not AUTH0_DOMAIN:
        missing.append("AUTH0_DOMAIN")
    if not AUTH0_DPOP_API_IDENTIFIER:
        missing.append("AUTH0_DPOP_API_IDENTIFIER")
    if not AUTH0_DPOP_CLIENT_ID:
        missing.append("AUTH0_DPOP_EXISTING_CLIENT_ID")
    if not AUTH0_DPOP_CLIENT_SECRET:
        missing.append("AUTH0_DPOP_CLIENT_SECRET")
    if missing:
        return False, f"Missing Auth0 DPoP configuration in demo-ui: {', '.join(missing)}"
    return True, None


def run_openssl(args, *, input_bytes=None) -> bytes:
    completed = subprocess.run(
        ["openssl", *args],
        input=input_bytes,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.decode("utf-8", errors="replace").strip() or "openssl failed")
    return completed.stdout


def parse_asn1_length(data: bytes, index: int) -> tuple[int, int]:
    first = data[index]
    if first < 0x80:
        return first, index + 1
    octet_count = first & 0x7F
    value = int.from_bytes(data[index + 1 : index + 1 + octet_count], "big")
    return value, index + 1 + octet_count


def der_ecdsa_to_jose(signature: bytes, part_size: int = 32) -> bytes:
    if not signature or signature[0] != 0x30:
        raise RuntimeError("Unexpected ECDSA signature format from openssl")

    sequence_length, index = parse_asn1_length(signature, 1)
    sequence_end = index + sequence_length
    if sequence_end > len(signature):
        raise RuntimeError("Invalid ECDSA DER signature length")

    if signature[index] != 0x02:
        raise RuntimeError("Invalid ECDSA DER signature: missing R integer")
    r_length, index = parse_asn1_length(signature, index + 1)
    r_value = signature[index : index + r_length]
    index += r_length

    if signature[index] != 0x02:
        raise RuntimeError("Invalid ECDSA DER signature: missing S integer")
    s_length, index = parse_asn1_length(signature, index + 1)
    s_value = signature[index : index + s_length]

    r_bytes = r_value.lstrip(b"\x00").rjust(part_size, b"\x00")
    s_bytes = s_value.lstrip(b"\x00").rjust(part_size, b"\x00")
    if len(r_bytes) != part_size or len(s_bytes) != part_size:
        raise RuntimeError("Invalid ECDSA signature component size")
    return r_bytes + s_bytes


def generate_dpop_key_material():
    tempdir = tempfile.TemporaryDirectory()
    tempdir_path = Path(tempdir.name)
    private_key_path = tempdir_path / "dpop_private.pem"
    public_key_path = tempdir_path / "dpop_public.pem"

    run_openssl(["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(private_key_path)])
    run_openssl(["ec", "-in", str(private_key_path), "-pubout", "-out", str(public_key_path)])
    public_key_text = run_openssl(["ec", "-pubin", "-in", str(public_key_path), "-text", "-noout"]).decode("utf-8")
    public_key_lines = []
    capture = False
    for line in public_key_text.splitlines():
        stripped = line.strip()
        if stripped == "pub:":
            capture = True
            continue
        if capture:
            if stripped.startswith("ASN1 OID:"):
                break
            public_key_lines.append(stripped.replace(":", ""))
    public_key_hex = "".join(public_key_lines)
    public_key_bytes = bytes.fromhex(public_key_hex)
    if len(public_key_bytes) != 65 or public_key_bytes[0] != 0x04:
        raise RuntimeError("Unexpected EC public key format from openssl")
    x_bytes = public_key_bytes[1:33]
    y_bytes = public_key_bytes[33:65]
    public_jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url_encode(x_bytes),
        "y": b64url_encode(y_bytes),
    }
    thumbprint_json = json.dumps(
        {"crv": public_jwk["crv"], "kty": public_jwk["kty"], "x": public_jwk["x"], "y": public_jwk["y"]},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return {
        "tempdir": tempdir,
        "private_key_path": private_key_path,
        "public_key_path": public_key_path,
        "public_jwk": public_jwk,
        "thumbprint": b64url_encode(hashlib.sha256(thumbprint_json).digest()),
    }


def build_dpop_proof(url: str, method: str, private_key_path: Path, public_jwk: dict, *, nonce: str | None = None, ath: str | None = None):
    header = {"alg": "ES256", "typ": "dpop+jwt", "jwk": public_jwk}
    payload = {
        "htu": url,
        "htm": method.upper(),
        "iat": int(time.time()),
        "jti": str(uuid.uuid4()),
    }
    if nonce:
        payload["nonce"] = nonce
    if ath:
        payload["ath"] = ath

    signing_input = f"{json_b64url(header)}.{json_b64url(payload)}"
    der_signature = run_openssl(["dgst", "-sha256", "-sign", str(private_key_path)], input_bytes=signing_input.encode("utf-8"))
    signature = der_ecdsa_to_jose(der_signature)
    return {
        "jwt": f"{signing_input}.{b64url_encode(signature)}",
        "header": header,
        "payload": payload,
    }


def auth0_dpop_http_request(url: str, method: str, headers: dict[str, str], body: bytes | None = None):
    req = urllib.request.Request(url, data=body, headers=headers, method=method.upper())
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw_body = resp.read().decode("utf-8")
            return {"status": resp.status, "headers": {k.lower(): v for k, v in resp.headers.items()}, "body": parse_response_body(raw_body)}
    except urllib.error.HTTPError as exc:
        raw_body = exc.read().decode("utf-8") if exc.fp else ""
        return {"status": exc.code, "headers": {k.lower(): v for k, v in exc.headers.items()}, "body": parse_response_body(raw_body)}


def request_with_dpop(
    url: str,
    method: str,
    *,
    body: bytes | None,
    extra_headers: dict[str, str],
    key_material: dict,
    access_token: str | None = None,
    include_proof: bool = True,
    wrong_htu: bool = False,
    proof_method_override: str | None = None,
    include_ath: bool = True,
):
    nonce = None
    proof = None
    for _ in range(2):
        headers = dict(extra_headers)
        if access_token:
            headers["Authorization"] = access_token
        if include_proof:
            htu = f"{url}/wrong" if wrong_htu else url
            proof_method = proof_method_override or method
            ath = (
                b64url_encode(hashlib.sha256(access_token.split(" ", 1)[1].encode("utf-8")).digest())
                if include_ath and access_token and access_token.startswith("DPoP ")
                else None
            )
            proof = build_dpop_proof(htu, proof_method, key_material["private_key_path"], key_material["public_jwk"], nonce=nonce, ath=ath)
            headers["DPoP"] = proof["jwt"]
        response = auth0_dpop_http_request(url, method, headers, body)
        next_nonce = response["headers"].get("dpop-nonce")
        if include_proof and next_nonce and response["status"] in {400, 401} and nonce is None:
            nonce = next_nonce
            continue
        return {"request_headers": headers, "proof": proof, "response": response, "nonce": nonce}
    return {"request_headers": headers, "proof": proof, "response": response, "nonce": nonce}


def tamper_jwt_signature(jwt_value: str) -> str:
    parts = jwt_value.split(".")
    if len(parts) != 3:
        return jwt_value + ".tampered"
    signature = parts[2]
    if not signature:
        signature = "x"
    replacement = "A" if signature[-1] != "A" else "B"
    parts[2] = signature[:-1] + replacement
    return ".".join(parts)


class DemoHandler(BaseHTTPRequestHandler):
    server_version = "TcsKongDemo/1.0"

    def do_HEAD(self):
        if (
            self.path == "/"
            or self.path == "/favicon.ico"
            or self.path.startswith("/static/")
            or self.path.startswith("/img/")
        ):
            self.serve_static(head_only=True)
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_GET(self):
        if self.path == "/api/config":
            self.respond_json(
                {
                    "sceneOptions": [
                        {"id": scene["id"], "label": scene["label"]} for scene in SCENES.values()
                    ],
                    "scenes": SCENES,
                    "links": {
                        "logs": DEMO_LOGS_URL,
                        "requestAudit": DEMO_REQUEST_AUDIT_URL,
                        "audit": DEMO_AUDIT_URL,
                        "trace": DEMO_TRACE_URL,
                        "payloadInspection": DEMO_PAYLOAD_INSPECTION_URL,
                        "debugger": DEMO_DEBUGGER_URL,
                    },
                }
            )
            return
        if self.path == "/api/scenes/resilience/status":
            self.respond_json({"instances": get_resilience_instance_states()})
            return

        if (
            self.path == "/"
            or self.path == "/favicon.ico"
            or self.path.startswith("/static/")
            or self.path.startswith("/img/")
        ):
            self.serve_static()
            return

        self.respond_json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)

    def do_POST(self):
        if self.path == "/api/scenes/header-routing/run":
            self.handle_run_header_routing()
            return
        if self.path == "/api/scenes/header-routing/reset":
            self.respond_json({"ok": True})
            return
        if self.path == "/api/scenes/rate-limiting/run":
            self.handle_run_rate_limiting()
            return
        if self.path == "/api/scenes/rate-limiting/reset":
            self.respond_json({"ok": True})
            return
        if self.path == "/api/scenes/resilience/run":
            self.handle_run_resilience()
            return
        if self.path == "/api/scenes/resilience/reset":
            self.handle_reset_resilience()
            return
        if self.path == "/api/scenes/canary/reset":
            self.respond_json(reset_canary_scene_runtime())
            return
        if self.path == "/api/scenes/resilience/instance":
            self.handle_resilience_instance()
            return
        if self.path == "/api/scenes/identity/azure/token":
            self.handle_generate_azure_token()
            return
        if self.path == "/api/scenes/identity/azure/run":
            self.handle_run_identity_azure()
            return
        if self.path == "/api/scenes/identity/keycloak/token":
            self.handle_generate_keycloak_token()
            return
        if self.path == "/api/scenes/identity/keycloak/run":
            self.handle_run_identity_keycloak()
            return
        if self.path == "/api/scenes/identity/auth0-dpop/run":
            self.handle_run_identity_auth0_dpop()
            return
        if self.path == "/api/scenes/ip-restriction/run":
            self.handle_run_ip_restriction()
            return
        if self.path == "/api/scenes/schema-validation/run":
            self.handle_run_schema_validation()
            return
        if self.path == "/api/scenes/request-size/run":
            self.handle_run_request_size()
            return
        if self.path == "/api/scenes/metering-billing/run":
            self.handle_run_metering_billing()
            return
        if self.path == "/api/scenes/datakit/run":
            self.handle_run_datakit()
            return
        if self.path == "/api/scenes/payload-crypto/run":
            self.handle_run_payload_crypto()
            return
        if self.path == "/api/scenes/injection-protection/run":
            self.handle_run_injection_protection()
            return
        if self.path == "/api/scenes/transport-security/run":
            self.handle_run_transport_security()
            return
        if self.path == "/api/scenes/versioned-routing/run":
            self.handle_run_versioned_routing()
            return
        if self.path == "/api/scenes/canary/run":
            self.handle_run_canary()
            return
        if self.path == "/api/scenes/deprecation/run":
            self.handle_run_deprecation()
            return

        self.respond_json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)

    def handle_run_header_routing(self):
        scene = SCENES["traffic-routing-header"]
        body = self.read_json()
        region = body.get("region", "")
        header_value = region if region in {"east", "west"} else ""
        request_id = str(uuid.uuid4())

        target_url = f"{KONG_PROXY_URL}/orders"
        request_headers = {"Accept": "application/json", "x-request-id": request_id}
        if header_value:
            request_headers["x-region"] = header_value

        response = request_through_kong(target_url, request_headers)
        response_body = response["body"]
        response_status = response["status"]
        route_state = "unmatched"
        route_matched = None
        plugin_applied = None
        error_message = None

        if response_status == 200:
            route_state = "matched"
            route_matched = (
                "route-orders-header-east" if header_value == "east" else "route-orders-header-west"
            )
        elif response_status == 400 and response_body.get("policy") == "orders-header-missing-region-policy":
            route_state = "policy"
            route_matched = "route-orders-header-catchall"
            plugin_applied = "request-termination"
            error_message = "Kong applied the missing-header policy route."
        else:
            error_message = "No Kong route matched the supplied header."

        selected_service = response_body.get("service")
        selected_region = response_body.get("region")
        kong_service_matched = None
        if header_value == "east":
            kong_service_matched = "svc-orders-header-east"
        elif header_value == "west":
            kong_service_matched = "svc-orders-header-west"
        elif route_state == "policy":
            kong_service_matched = "svc-orders-header-missing-region"

        payload = {
            "scene": scene["id"],
            "sceneDetails": scene,
            "requestPreview": [
                ("Method", "GET"),
                ("Path", "/orders"),
                ("Header", f"x-region: {header_value}" if header_value else "x-region: <missing>"),
            ],
            "expectedOutcome": (
                "Orders East should receive the request."
                if header_value == "east"
                else "Orders West should receive the request."
                if header_value == "west"
                else "Kong should apply the catch-all policy route and return a guided missing-header response."
            ),
            "actualOutcome": [
                ("Kong Route", route_matched or "No match"),
                ("Kong Service", kong_service_matched or "No match"),
                ("Backend Service", selected_service or "No backend"),
                ("Status", str(response_status or 502)),
            ],
            "result": {
                "status": response_status or 502,
                "routeState": route_state,
                "routeMatched": route_matched,
                "kongServiceMatched": kong_service_matched,
                "pluginApplied": plugin_applied,
                "selectedService": selected_service,
                "selectedRegion": selected_region,
                "error": error_message,
                "responseBody": response_body,
                "responseHeaders": response["headers"],
            },
            "consoleView": {
                "request": {
                    "method": "GET",
                    "endpoint": "/orders",
                    "headers": request_headers,
                    "body": None,
                },
                "response": {
                    "status": response_status or 502,
                    "headers": response["headers"],
                    "body": response_body,
                },
            },
            "detailView": {
                "entities": normalize_detail_entities(
                    [
                        ("Kong Route", route_matched or "No match"),
                        ("Kong Service", kong_service_matched or "No match"),
                        ("Kong Plugin", f"{plugin_applied} on {route_matched}" if plugin_applied else "None"),
                        ("Actual Service Name", selected_service or "No backend service"),
                    ]
                ),
                "curl": build_curl_command(target_url, request_headers),
                "response": {
                    "status": response_status or 502,
                    "headers": response["headers"],
                    "body": response_body,
                },
            },
            "topology": {
                "labels": {
                    "client": ("Client", "Web Caller", "GET /orders"),
                    "kong": ("Gateway", "Kong Data Plane", "Header routing policy"),
                    "east": ("Upstream", "Orders East", "x-region: east"),
                    "west": ("Upstream", "Orders West", "x-region: west"),
                },
                "nodes": {
                    "kong": "active" if route_state != "unmatched" else "error",
                    "east": "active" if selected_region == "east" else "idle",
                    "west": "active" if selected_region == "west" else "idle",
                },
                "connectors": {
                    "clientKong": "active",
                    "kongEast": "active" if selected_region == "east" else ("error" if route_state == "unmatched" else "idle"),
                    "kongWest": "active" if selected_region == "west" else ("error" if route_state == "unmatched" else "idle"),
                },
                "statusKong": "Kong Matched Route" if route_state == "matched" else "Kong Applied Policy" if route_state == "policy" else "Kong Rejected Request",
                "statusKongClass": "success" if route_state != "unmatched" else "error",
                "statusRoute": "Route: East" if selected_region == "east" else "Route: West" if selected_region == "west" else "Policy Route" if route_state == "policy" else "No Route Match",
                "statusRouteClass": "success" if route_state != "unmatched" else "error",
            },
            "architecture": scene["architecture"],
        }
        self.respond_json(payload)

    def handle_run_rate_limiting(self):
        scene = SCENES["traffic-control-rate-limiting"]
        body = self.read_json()
        mode = body.get("mode", "anonymous")
        consumer = body.get("consumer", "consumer-standard")

        path = "/orders/rate/anonymous" if mode == "anonymous" else "/orders/rate/consumer"
        target_url = f"{KONG_PROXY_URL}{path}"
        request_headers = {"Accept": "application/json"}
        if mode == "consumer":
            request_headers["apikey"] = RATE_LIMIT_KEYS.get(consumer, RATE_LIMIT_KEYS["consumer-standard"])

        policy_key = "anonymous" if mode == "anonymous" else consumer
        policy = RATE_LIMIT_POLICIES[policy_key]
        window_seconds = policy["window_seconds"]
        route_name = policy["route"]
        service_name = policy["service"]
        plugin_detail = policy["plugin"]

        req_headers = dict(request_headers)
        req_headers["x-request-id"] = str(uuid.uuid4())
        response = request_through_kong(target_url, req_headers)
        response_body = response["body"] if isinstance(response["body"], dict) else {}
        rate_metrics = extract_rate_limit_metrics(response["headers"])
        limit = rate_metrics["limit"]
        remaining = rate_metrics["remaining"]
        reset_seconds = rate_metrics["reset"] or rate_metrics["retry_after"] or 0
        execution_key = f"{mode}:{consumer if mode == 'consumer' else 'anonymous'}"
        execution_count, seconds_until_reset, window_expires_at = update_execution_counter(
            execution_key,
            limit,
            remaining,
            reset_seconds,
            response["status"],
        )
        next_blocked_request = limit + 1 if limit is not None else None
        backend_service = response_body.get("service", "orders-east")
        final_status = response["status"]
        current_window_text = f"{window_seconds}-second fixed window"

        expected_outcome = build_rate_limit_expected_outcome(mode, consumer, window_seconds, limit)

        payload = {
            "scene": scene["id"],
            "sceneDetails": scene,
            "requestPreview": [
                ("Method", "GET"),
                ("Path", path),
                ("Mode", mode),
                ("Consumer", consumer if mode == "consumer" else "none"),
                ("Window", current_window_text),
            ],
            "expectedOutcome": expected_outcome,
            "actualOutcome": [
                ("Mode", mode),
                ("Kong Consumer", consumer if mode == "consumer" else "none"),
                ("Kong Route", route_name),
                ("Kong Service", service_name),
                ("Kong Plugin", plugin_detail),
                ("Backend Service", backend_service),
                ("Execution Count", str(execution_count)),
                ("Window", current_window_text),
                ("Limit", str(limit) if limit is not None else "unknown"),
                ("Remaining", str(remaining) if remaining is not None else "unknown"),
                ("Next Blocked Request", str(next_blocked_request) if next_blocked_request is not None else "unknown"),
                ("Reset In", f"{seconds_until_reset}s"),
                ("Final Status", str(final_status)),
            ],
            "result": {
                "status": final_status,
                "routeState": "throttled" if final_status == 429 else "matched",
                "routeMatched": route_name,
                "kongServiceMatched": service_name,
                "pluginApplied": policy["plugin_scope"],
                "selectedService": backend_service,
                "selectedRegion": "allowed" if final_status != 429 else None,
                "executionCount": execution_count,
                "limit": limit,
                "remaining": remaining,
                "resetSeconds": seconds_until_reset,
                "windowExpiresAt": window_expires_at,
                "windowSeconds": window_seconds,
                "responseBody": response["body"],
                "responseHeaders": response["headers"],
            },
            "consoleView": {
                "request": {
                    "method": "GET",
                    "endpoint": path,
                    "headers": req_headers,
                    "body": None,
                },
                "response": {
                    "status": final_status,
                    "headers": response["headers"],
                    "body": response["body"],
                },
            },
            "detailView": {
                "entities": normalize_detail_entities(
                    [
                        ("Kong Route", route_name),
                        ("Kong Service", service_name),
                        ("Kong Plugin", plugin_detail),
                        ("Kong Consumer", consumer if mode == "consumer" else "None"),
                        ("Actual Service Name", backend_service),
                    ]
                ),
                "curl": build_curl_command(target_url, req_headers),
                "response": {
                    "status": final_status,
                    "headers": response["headers"],
                    "body": response["body"],
                },
            },
            "topology": {
                "labels": {
                    "client": ("Client", "API Caller", f"Mode: {mode}"),
                    "kong": ("Gateway", "Kong Data Plane", f"{limit or '?'} requests per {window_seconds}s"),
                    "east": ("Backend", "Orders API", f"Status: {final_status}"),
                    "west": ("Policy Window", "Fixed Window Counter", f"Request {execution_count}, reset in {seconds_until_reset}s"),
                },
                "nodes": {
                    "kong": "error" if final_status == 429 else "active",
                    "east": "active",
                    "west": "static",
                },
                "connectors": {
                    "clientKong": "active",
                    "kongEast": "active",
                    "kongWest": "hidden",
                },
                "statusKong": "Kong Throttled Request" if final_status == 429 else "Kong Allowed Request",
                "statusKongClass": "error" if final_status == 429 else "success",
                "statusRoute": (
                    f"Request {execution_count} throttled"
                    if final_status == 429
                    else f"Request {execution_count} of {limit or '?'}"
                ),
                "statusRouteClass": "error" if final_status == 429 else "success",
            },
            "architecture": scene["architecture"],
        }
        self.respond_json(payload)

    def handle_run_resilience(self):
        scene = SCENES["resilience-failover-health-checks"]
        body = self.read_json()
        scenario = body.get("scenario", "weighted-load-balancing")
        scenario = scenario if scenario in {"weighted-load-balancing", "circuit-breaker"} else "weighted-load-balancing"

        path = (
            "/orders/resilience/weighted"
            if scenario == "weighted-load-balancing"
            else "/orders/resilience/circuit-breaker"
        )
        route_name = (
            "route-orders-resilience-weighted"
            if scenario == "weighted-load-balancing"
            else "route-orders-circuit-breaker"
        )
        service_name = (
            "svc-orders-resilience-weighted"
            if scenario == "weighted-load-balancing"
            else "svc-orders-circuit-breaker"
        )
        upstream_name = (
            "upstream-orders-weighted"
            if scenario == "weighted-load-balancing"
            else "upstream-orders-circuit-breaker"
        )

        req_headers = {
            "Accept": "application/json",
            "x-request-id": str(uuid.uuid4()),
            "Host": "localhost:8000",
        }
        target_url = f"{KONG_PROXY_URL}{path}"
        response = request_through_kong(target_url, req_headers)
        response_body = response["body"] if isinstance(response["body"], dict) else {}
        response_status = response["status"]
        backend_service = response_body.get("service")
        instance_states = get_resilience_instance_states()

        if response_status == 200 and backend_service in RESILIENCE_WEIGHTED_COUNTS and scenario == "weighted-load-balancing":
            RESILIENCE_WEIGHTED_COUNTS[backend_service] += 1

        if scenario == "weighted-load-balancing":
            expected_outcome = (
                "Kong should distribute requests across the two healthy targets using the configured 30:70 weights."
            )
            east_subtitle = f"Weight 30 | observed {RESILIENCE_WEIGHTED_COUNTS['orders-instance-1']}"
            west_subtitle = f"Weight 70 | observed {RESILIENCE_WEIGHTED_COUNTS['orders-instance-2']}"
            status_kong = "Weighted Policy Applied" if response_status == 200 else "Weighted Route Failed"
            status_route = (
                f"Selected: {backend_service}" if response_status == 200 else f"HTTP {response_status}"
            )
        else:
            healthy_instances = [key for key, value in instance_states.items() if value["running"]]
            expected_outcome = (
                "Kong should round robin across both targets while healthy, then remove an unhealthy target from rotation and reroute traffic to the healthy target."
            )
            east_subtitle = "Healthy" if instance_states["instance-1"]["running"] else "Unhealthy / removed"
            west_subtitle = "Healthy" if instance_states["instance-2"]["running"] else "Unhealthy / removed"
            if response_status == 200 and len(healthy_instances) == 1:
                status_kong = "Circuit Open: Failed Over"
                status_route = f"Traffic rerouted to {backend_service}"
            elif response_status == 200:
                status_kong = "Round Robin Healthy"
                status_route = f"Selected: {backend_service}"
            else:
                status_kong = "No Healthy Targets"
                status_route = f"HTTP {response_status}"

        selected_instance = None
        for instance_id, meta in RESILIENCE_INSTANCES.items():
            if meta["service"] == backend_service:
                selected_instance = instance_id
                break

        payload = {
            "scene": scene["id"],
            "sceneDetails": scene,
            "requestPreview": [
                ("Method", "GET"),
                ("Path", path),
                ("Scenario", "Weighted Load Balancing" if scenario == "weighted-load-balancing" else "Circuit Breaker"),
                ("Strategy", "30:70 weighted" if scenario == "weighted-load-balancing" else "Round robin with active + passive health checks"),
            ],
            "expectedOutcome": expected_outcome,
            "instanceStates": instance_states,
            "result": {
                "status": response_status,
                "routeMatched": route_name,
                "kongServiceMatched": service_name,
                "upstreamMatched": upstream_name,
                "selectedService": backend_service,
                "selectedInstance": selected_instance,
                "responseBody": response["body"],
                "responseHeaders": response["headers"],
                "scenario": scenario,
                "weightedCounts": dict(RESILIENCE_WEIGHTED_COUNTS),
            },
            "consoleView": {
                "request": {
                    "method": "GET",
                    "endpoint": path,
                    "headers": req_headers,
                    "body": None,
                },
                "response": {
                    "status": response_status,
                    "headers": response["headers"],
                    "body": response["body"],
                },
            },
            "detailView": {
                "entities": normalize_detail_entities(
                    [
                        ("Kong Route", route_name),
                        ("Kong Service", service_name),
                        ("Kong Upstream", upstream_name),
                        ("Kong Target Selected", RESILIENCE_INSTANCES[selected_instance]["target"] if selected_instance else "None"),
                        ("Actual Service Name", backend_service or "None"),
                    ]
                ),
                "curl": build_curl_command(target_url, req_headers),
                "response": {
                    "status": response_status,
                    "headers": response["headers"],
                    "body": response["body"],
                },
            },
            "topology": {
                "labels": {
                    "client": ("Client", "API Caller", "GET resilience route"),
                    "kong": (
                        "Gateway",
                        "Kong Data Plane",
                        "30:70 weighted" if scenario == "weighted-load-balancing" else "Round robin + health checks",
                    ),
                    "east": ("Target", "Service Instance 1", east_subtitle),
                    "west": ("Target", "Service Instance 2", west_subtitle),
                },
                "nodes": {
                    "kong": "error" if response_status >= 500 else "active",
                    "east": "active" if selected_instance == "instance-1" else ("error" if not instance_states["instance-1"]["running"] else None),
                    "west": "active" if selected_instance == "instance-2" else ("error" if not instance_states["instance-2"]["running"] else None),
                },
                "connectors": {
                    "clientKong": "active",
                    "kongEast": "active" if selected_instance == "instance-1" else ("error" if not instance_states["instance-1"]["running"] else None),
                    "kongWest": "active" if selected_instance == "instance-2" else ("error" if not instance_states["instance-2"]["running"] else None),
                },
                "statusKong": status_kong,
                "statusKongClass": "error" if response_status >= 500 else "success",
                "statusRoute": status_route,
                "statusRouteClass": "error" if response_status >= 500 else "success",
            },
            "architecture": scene["architecture"],
        }
        self.respond_json(payload)

    def handle_reset_resilience(self):
        for meta in RESILIENCE_INSTANCES.values():
            try:
                set_container_state(meta["container"], "start")
            except Exception:  # noqa: BLE001
                pass
        RESILIENCE_WEIGHTED_COUNTS["orders-instance-1"] = 0
        RESILIENCE_WEIGHTED_COUNTS["orders-instance-2"] = 0
        self.respond_json({"ok": True, "instances": get_resilience_instance_states()})

    def handle_resilience_instance(self):
        body = self.read_json()
        instance_id = body.get("instance")
        action = body.get("action")
        meta = RESILIENCE_INSTANCES.get(instance_id)
        if meta is None or action not in {"start", "stop"}:
            self.respond_json({"error": "Invalid resilience instance request"}, status=HTTPStatus.BAD_REQUEST)
            return

        try:
            set_container_state(meta["container"], action)
            self.respond_json({"ok": True, "instances": get_resilience_instance_states()})
        except Exception as exc:  # noqa: BLE001
            self.respond_json(
                {"error": f"Failed to {action} {instance_id}: {exc}", "instances": get_resilience_instance_states()},
                status=HTTPStatus.BAD_GATEWAY,
            )

    def handle_generate_azure_token(self):
        body = self.read_json()
        consumer = body.get("consumer", "consumer-1")
        client_id = AD_CONSUMER1_CLIENT_ID if consumer == "consumer-1" else AD_CONSUMER2_CLIENT_ID
        client_secret = AD_CONSUMER1_SECRET if consumer == "consumer-1" else AD_CONSUMER2_SECRET
        token_url = f"https://login.microsoftonline.com/{AD_PROTECTED_API_TENANT_ID}/oauth2/v2.0/token"
        response = post_form(
            token_url,
            {
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": f"{AD_PROTECTED_API_AUDIENCE}/.default",
                "grant_type": "client_credentials",
            },
        )
        self.respond_json(
            {
                "token": response["body"].get("access_token", ""),
                "tokenResponse": response["body"],
                "idp": "Azure AD",
                "consumer": consumer,
            },
            status=response["status"],
        )

    def handle_generate_keycloak_token(self):
        body = self.read_json()
        consumer = body.get("consumer", "consumer-1")
        token, response = generate_keycloak_access_token(consumer)
        self.respond_json(
            {
                "token": token,
                "tokenResponse": response["body"],
                "idp": "Keycloak",
                "consumer": consumer,
            },
            status=response["status"],
        )

    def handle_run_identity_azure(self):
        scene = SCENES["identity-azure-token-validation"]
        body = self.read_json()
        token = body.get("token", "").strip()
        payload = self.build_identity_payload(
            scene=scene,
            path="/orders/auth/azure",
            token=token,
            idp_name="Azure AD",
            route_name="route-orders-auth-azure",
            service_name="svc-orders-auth-azure",
            plugin_name="openid-connect on route-orders-auth-azure",
            consumer_label=body.get("consumer", "consumer-1"),
            allowed_role=None,
        )
        self.respond_json(payload)

    def handle_run_identity_keycloak(self):
        scene = SCENES["identity-keycloak-authorization"]
        body = self.read_json()
        token = body.get("token", "").strip()
        consumer = body.get("consumer", "consumer-1")
        payload = self.build_identity_payload(
            scene=scene,
            path="/orders/auth/keycloak",
            token=token,
            idp_name="Keycloak",
            route_name="route-orders-auth-keycloak",
            service_name="svc-orders-auth-keycloak",
            plugin_name="openid-connect on route-orders-auth-keycloak",
            consumer_label=consumer,
            allowed_role=os.environ.get("KEYCLOAK_ALLOWED_ROLE", "api-access"),
        )
        self.respond_json(payload)

    def handle_run_identity_auth0_dpop(self):
        global DPOP_HAPPY_PATH_CACHE
        scene = SCENES["identity-auth0-dpop"]
        ready, error_message = auth0_dpop_ready()
        if not ready:
            self.respond_json({"error": error_message}, status=HTTPStatus.BAD_REQUEST)
            return

        body = self.read_json()
        mode = body.get("mode", "happy-path")
        if mode not in DPOP_TEST_MODES:
            self.respond_json({"error": f"Unsupported DPoP mode: {mode}"}, status=HTTPStatus.BAD_REQUEST)
            return

        token_url = f"https://{AUTH0_DOMAIN}/oauth/token"
        api_path = "/orders/auth/auth0-dpop"
        api_url = f"{KONG_PROXY_URL}{api_path}"
        token_request_body = urllib.parse.urlencode(
            {
                "grant_type": "client_credentials",
                "client_id": AUTH0_DPOP_CLIENT_ID,
                "client_secret": AUTH0_DPOP_CLIENT_SECRET,
                "audience": AUTH0_DPOP_API_IDENTIFIER,
            }
        ).encode("utf-8")
        token_headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        api_headers = {
            "Accept": "application/json",
            "x-request-id": str(uuid.uuid4()),
            "x-dpop-test-case": mode,
        }

        if mode == "replay-attack":
            cached = DPOP_HAPPY_PATH_CACHE
            if not cached:
                self.respond_json(
                    {"error": "Replay mode requires a successful happy-path DPoP run first so the previous token and proof can be reused."},
                    status=HTTPStatus.BAD_REQUEST,
                )
                return

            replay_headers = dict(cached["api_exchange"]["request_headers"])
            replay_headers["x-request-id"] = str(uuid.uuid4())
            replay_response = auth0_dpop_http_request(api_url, "GET", replay_headers, None)
            replay_exchange = {
                "request_headers": replay_headers,
                "proof": {
                    **cached["api_exchange"]["proof"],
                    "replayed": True,
                },
                "response": replay_response,
            }
            token_response = cached["token_response"]
            token_exchange = cached["token_exchange"]
            decoded_access_token = cached["decoded_access_token"]
            primary_key = cached["primary_key"]
            api_exchange = cached["api_exchange"]
            final_exchange = replay_exchange
            api_response = replay_response
            api_body = api_exchange["response"]["body"] if isinstance(api_exchange["response"]["body"], dict) else {}
            token_success = token_response["status"] == 200
            first_api_status = api_exchange["response"]["status"]
            replay_status = replay_exchange["response"]["status"]
            initial_api_success = first_api_status == 200
            api_success = replay_status == 200

            if first_api_status == 200 and replay_status != 200:
                route_state = "unauthorized"
                status_route = "Replay rejected at Kong"
                status_class = "error"
                error_message = "Kong rejected the replayed DPoP proof."
            elif first_api_status == 200 and replay_status == 200:
                route_state = "authorized"
                status_route = "Replay accepted by Kong"
                status_class = "error"
                error_message = "Kong accepted the replayed DPoP proof."
            else:
                route_state = "unauthorized"
                status_route = "Cached happy-path request unavailable"
                status_class = "error"
                error_message = "The cached happy-path request was not successful enough to demonstrate a replay."
        else:
            primary_key = generate_dpop_key_material()

            try:
                token_exchange = request_with_dpop(
                    token_url,
                    "POST",
                    body=token_request_body,
                    extra_headers=token_headers,
                    key_material=primary_key,
                    include_proof=True,
                )
                token_response = token_exchange["response"]
                token_body = token_response["body"] if isinstance(token_response["body"], dict) else {}
                access_token = token_body.get("access_token", "")
                decoded_access_token = decode_jwt_parts(access_token) if access_token else None

                api_exchange = None
                replay_exchange = None
                if access_token:
                    authorization_value = f"DPoP {access_token}"
                    api_exchange = request_with_dpop(
                        api_url,
                        "GET",
                        body=None,
                        extra_headers=api_headers,
                        key_material=primary_key,
                        access_token=authorization_value,
                        include_proof=True,
                        wrong_htu=mode == "invalid-htu",
                        proof_method_override="POST" if mode == "invalid-htm" else None,
                        include_ath=mode != "missing-ath",
                    )
                final_exchange = api_exchange
                api_response = final_exchange["response"] if final_exchange else None
                api_body = api_exchange["response"]["body"] if api_exchange and isinstance(api_exchange["response"]["body"], dict) else {}
                token_success = token_response["status"] == 200 and bool(access_token)
                api_success = api_response is not None and api_response["status"] == 200
                first_api_status = api_exchange["response"]["status"] if api_exchange else None
                replay_status = None
                initial_api_success = first_api_status == 200

                if token_success and api_success:
                    route_state = "authorized"
                    status_route = "DPoP validated"
                    status_class = "success"
                    error_message = None
                    DPOP_HAPPY_PATH_CACHE = {
                        "primary_key": primary_key,
                        "token_exchange": token_exchange,
                        "token_response": token_response,
                        "decoded_access_token": decoded_access_token,
                        "api_exchange": api_exchange,
                    }
                elif token_success:
                    route_state = "unauthorized"
                    status_route = "DPoP rejected at Kong"
                    status_class = "error"
                    error_message = "Kong rejected the DPoP-bound request."
                else:
                    route_state = "unauthorized"
                    status_route = "DPoP token request failed"
                    status_class = "error"
                    error_message = "Auth0 rejected the token exchange before Kong received a usable access token."
            finally:
                pass

        try:
            proof_key_used = "same ephemeral proof key"
            failure_reason = (
                "htu claim does not match the Kong API URL"
                if mode == "invalid-htu"
                else "htm claim does not match the actual HTTP method"
                if mode == "invalid-htm"
                else "ath claim is missing from the proof"
                if mode == "missing-ath"
                else "replayed proof reused from previous request"
                if mode == "replay-attack"
                else "none"
            )
            actual_service = api_response["body"].get("service") if api_success and isinstance(api_response["body"], dict) else "No upstream call"
            negative_scenario = DPOP_NEGATIVE_SCENARIO_GUIDE.get(mode)
            payload = {
                "scene": scene["id"],
                "sceneDetails": scene,
                "requestPreview": [
                    ("Method", "GET"),
                    ("Path", api_path),
                    ("Identity Provider", "Auth0"),
                    ("Authorization", "Authorization: DPoP <token>"),
                    ("DPoP Test Mode", mode.replace("-", " ")),
                ],
                "expectedOutcome": DPOP_TEST_MODES[mode],
                "result": {
                    "status": api_response["status"] if api_response else token_response["status"],
                    "routeState": route_state,
                    "routeMatched": "route-orders-auth0-dpop",
                    "kongServiceMatched": "svc-orders-auth0-dpop",
                    "pluginApplied": "dpop-replay-demo + openid-connect on route-orders-auth0-dpop",
                    "selectedService": api_response["body"].get("service") if api_success and isinstance(api_response["body"], dict) else None,
                    "responseBody": api_response["body"] if api_response else token_response["body"],
                    "responseHeaders": api_response["headers"] if api_response else token_response["headers"],
                    "consumer": "auth0-dpop-client",
                    "idp": "Auth0",
                    "tokenStatus": token_response["status"],
                    "apiStatus": api_response["status"] if api_response else None,
                    "initialApiStatus": first_api_status,
                    "replayApiStatus": replay_status,
                    "dpopMode": mode,
                    "dpopFailureReason": failure_reason,
                },
                "consoleView": {
                    "request": {
                        "method": "GET" if final_exchange else "POST",
                        "endpoint": api_path if final_exchange else "/oauth/token",
                        "headers": final_exchange["request_headers"] if final_exchange else token_exchange["request_headers"],
                        "body": None if final_exchange else urllib.parse.parse_qs(token_request_body.decode("utf-8")),
                    },
                    "response": {
                        "status": api_response["status"] if api_response else token_response["status"],
                        "headers": api_response["headers"] if api_response else token_response["headers"],
                        "body": api_response["body"] if api_response else token_response["body"],
                    },
                },
                "detailView": {
                    "entities": normalize_detail_entities(
                        [
                            ("Kong Route", "route-orders-auth0-dpop"),
                            ("Kong Service", "svc-orders-auth0-dpop"),
                            ("Kong Plugin", "dpop-replay-demo + openid-connect on route-orders-auth0-dpop"),
                            ("Kong Consumer", "auth0-dpop-client"),
                            ("Consumer Mapping", consumer_mapping_description("Auth0")),
                            ("Identity Provider", "Auth0"),
                            ("API Audience", AUTH0_DPOP_API_IDENTIFIER),
                            ("DPoP Mode", mode),
                            ("DPoP Mode Meaning", DPOP_TEST_MODES[mode]),
                            ("DPoP Failure Injection", failure_reason),
                            (
                                "Negative Scenario Summary",
                                negative_scenario["simple_explanation"] if negative_scenario else "Not a negative scenario",
                            ),
                            (
                                "Broken DPoP Claim",
                                negative_scenario["broken_claim"] if negative_scenario else "None",
                            ),
                            ("Claim htu", DPOP_CLAIM_GLOSSARY["htu"]),
                            ("Claim htm", DPOP_CLAIM_GLOSSARY["htm"]),
                            ("Claim ath", DPOP_CLAIM_GLOSSARY["ath"]),
                            ("Claim jti", DPOP_CLAIM_GLOSSARY["jti"]),
                            ("Proof Key Usage", proof_key_used),
                            ("Auth0 Token Status", token_response["status"]),
                            (
                                "Kong API Status",
                                (
                                    replay_status
                                    if mode == "replay-attack" and replay_exchange
                                    else api_exchange["response"]["status"] if api_exchange else "Not called"
                                ),
                            ),
                            (
                                "Initial Kong API Status",
                                first_api_status if mode == "replay-attack" else "Not applicable",
                            ),
                            (
                                "Replay Kong API Status",
                                replay_status if mode == "replay-attack" else "Not applicable",
                            ),
                            ("Actual Service Name", actual_service),
                        ]
                    ),
                    "steps": [
                        {
                            "title": "Generate ephemeral DPoP key material",
                            "explanation": (
                                "Replay mode does not generate a new key pair. It reuses the exact ephemeral key material from the most recent successful happy-path run so the proof and token are the same artifacts that already succeeded once."
                                if mode == "replay-attack"
                                else "Inputs: none; this is the starting point. The command generates a new P-256 private key and derives the matching public key. An EC public key is the public half of an elliptic-curve key pair: it is safe to share, and it mathematically corresponds to the private key that stays secret on the client. In this case, the EC public key is represented as a point on the curve written as bytes: `04 || X || Y`. The first byte `04` only means 'uncompressed point'. After that come 32 bytes for `X` and 32 bytes for `Y`. To create the JWK, we simply split the public key bytes into those two coordinates and base64url-encode each one: `x = base64url(X)` and `y = base64url(Y)`. Outputs: `private_key`, `public_jwk`, and `jkt_thumbprint`. Mapping to Step 2: Step 2 uses `private_key` to sign the DPoP proof JWT, and copies `public_jwk` directly into the proof header as `jwk`."
                            ),
                            "command": (
                                "Reused from previous happy-path run; no new key generation command is executed."
                                if mode == "replay-attack"
                                else "openssl ecparam -name prime256v1 -genkey -noout -out dpop_private.pem\nopenssl ec -in dpop_private.pem -pubout -out dpop_public.pem\nopenssl ec -pubin -in dpop_public.pem -text -noout\n# read pub: 04 || X || Y, drop 04, take next 32 bytes as X and next 32 bytes as Y"
                            ),
                            "response": {
                                "curve": "P-256 / prime256v1",
                                "public_point_format": "04 || X || Y (65 bytes total, 32 bytes each for X and Y after the leading 04 byte)",
                                "pseudo_logic": [
                                    *(
                                        [
                                            "1. Read the cached ephemeral key pair from the previous happy-path run.",
                                            "2. Reuse the same public JWK and thumbprint that were already used successfully once.",
                                            "3. Do not generate a new private key, public key, or thumbprint.",
                                        ]
                                        if mode == "replay-attack"
                                        else [
                                            "1. Generate a P-256 private key.",
                                            "2. Derive the matching public key from the private key.",
                                            "3. Ask OpenSSL to print the public key bytes in uncompressed form.",
                                            "4. Read them as: 04 || X || Y.",
                                            "5. Ignore the first byte 04; it only says 'this is an uncompressed EC point'.",
                                            "6. Take bytes 1-32 as the X coordinate.",
                                            "7. Take bytes 33-64 as the Y coordinate.",
                                            "8. base64url(X) -> JWK field x.",
                                            "9. base64url(Y) -> JWK field y.",
                                            "10. Example shape: if the public key bytes are [04][32 bytes X][32 bytes Y], then x is exactly the middle 32-byte block and y is exactly the final 32-byte block.",
                                            "11. Build canonical JWK JSON: {\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"...\",\"y\":\"...\"}.",
                                            "12. thumbprint = base64url(SHA-256(canonical_jwk_json)).",
                                        ]
                                    ),
                                ],
                                "public_jwk": primary_key["public_jwk"],
                                "jkt_thumbprint": primary_key["thumbprint"],
                                "jwk_construction": {
                                    "kty": "EC",
                                    "crv": "P-256",
                                    "x": "base64url(bytes_1_to_32_of_public_point_after_dropping_04)",
                                    "y": "base64url(bytes_33_to_64_of_public_point_after_dropping_04)",
                                },
                                "plain_english_mapping": {
                                    "04": "format marker, not part of x or y",
                                    "x": "the first 32-byte coordinate of the EC public key",
                                    "y": "the second 32-byte coordinate of the EC public key",
                                },
                                "thumbprint_construction": "base64url(sha256('{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"...\",\"y\":\"...\"}'))",
                                "output_to_next_step": {
                                    "private_key": "used locally to sign the Step 2 DPoP JWT",
                                    "public_jwk": "copied into the Step 2 DPoP JWT header as `jwk`",
                                    "thumbprint": "represents the same key identity that Auth0 later binds the token to",
                                },
                                "mode": mode,
                            },
                        },
                        {
                            "title": "Request DPoP-bound token from Auth0",
                            "explanation": (
                                "Replay mode does not request a new token from Auth0. It reuses the exact token that was minted in the previous happy-path run, because the whole point of the replay is to send the same already-used token and proof again."
                                if mode == "replay-attack"
                                else "Inputs from Step 1: `private_key` and `public_jwk`. Mapping into this command: `public_jwk` is inserted into the DPoP JWT header as `jwk`, and `private_key` is used locally to sign that JWT. Additional inputs are the OAuth values `client_id`, `client_secret`, `grant_type=client_credentials`, and `audience`. The proof payload adds `htu=Auth0 token URL`, `htm=POST`, `iat`, and `jti`, but you will not see those as separate curl arguments because they are embedded inside the encoded `DPoP` JWT header value. Output of this step: an `access_token` returned by Auth0. Mapping to Step 3: Step 3 sends this exact `access_token` in `Authorization: DPoP <token>`, and also hashes this token into the Step 3 proof as the `ath` claim."
                            ),
                            "command": (
                                "Reused token from previous happy-path run; no new Auth0 token request is executed."
                                if mode == "replay-attack"
                                else build_curl_command(
                                    token_url,
                                    token_exchange["request_headers"],
                                    method="POST",
                                    body=token_request_body.decode("utf-8"),
                                )
                            ),
                            "response": {
                                "status": token_response["status"],
                                "headers": token_response["headers"],
                                "body": token_response["body"],
                                "what_is_sent": {
                                    "http_headers": (
                                        "none; no Auth0 request is sent in replay mode"
                                        if mode == "replay-attack"
                                        else list(token_exchange["request_headers"].keys())
                                    ),
                                    "public_key": (
                                        "not sent in this replay step because no new Auth0 token request is made"
                                        if mode == "replay-attack"
                                        else "sent inside the DPoP JWT header as `jwk`"
                                    ),
                                    "private_key": (
                                        "not sent; no new signing happens at this step in replay mode"
                                        if mode == "replay-attack"
                                        else "not sent; only used locally to sign the DPoP JWT"
                                    ),
                                },
                                "pseudo_logic": [
                                    *(
                                        [
                                            "1. Read the previously issued access_token from the last successful happy-path run.",
                                            "2. Reuse that exact token for the replay scenario instead of generating a new one.",
                                        ]
                                        if mode == "replay-attack"
                                        else [
                                            "1. Take public_jwk from Step 1 and place it into the JWT header as jwk.",
                                            "2. Build JWT header: {alg: ES256, typ: dpop+jwt, jwk: public_jwk}.",
                                            "3. Build JWT payload: {htu: token_url, htm: POST, iat: now, jti: random_uuid}.",
                                            "4. base64url_encode(header_json) -> encoded_header.",
                                            "5. base64url_encode(payload_json) -> encoded_payload.",
                                            "6. signing_input = encoded_header + '.' + encoded_payload.",
                                            "7. Sign signing_input with private_key from Step 1 using ES256.",
                                            "8. Convert ECDSA signature to JOSE format and base64url encode it.",
                                            "9. dpop_jwt = encoded_header + '.' + encoded_payload + '.' + encoded_signature.",
                                            "10. Send HTTP POST to Auth0 token endpoint with header DPoP: dpop_jwt and body grant_type/client_id/client_secret/audience.",
                                            "11. Receive access_token bound to the key identified by jwk.",
                                        ]
                                    ),
                                ],
                                "input_mapping": {
                                    **(
                                        {
                                            "source": "previous happy-path run",
                                        }
                                        if mode == "replay-attack"
                                        else {
                                            "from_step_1.private_key": "used to sign the DPoP JWT signature",
                                            "from_step_1.public_jwk": "copied into DPoP JWT header field `jwk`",
                                            "fixed_input.htu": token_url,
                                            "fixed_input.htm": "POST",
                                        }
                                    ),
                                },
                                "where_proof_fields_appear": (
                                    "No new proof is created in replay mode at this step."
                                    if mode == "replay-attack"
                                    else "The curl command only shows one `DPoP: <jwt>` header. Fields such as `htu`, `htm`, `iat`, and `jti` are inside that encoded JWT and are shown below under `proof.payload`."
                                ),
                                "output_to_next_step": {
                                    "access_token": "sent to Kong as `Authorization: DPoP <token>` in Step 3",
                                    "access_token_hash": "used to build the Step 3 `ath` claim",
                                },
                                "proof": token_exchange["proof"],
                                "access_token_decoded": decoded_access_token,
                            },
                        },
                        {
                            "title": "Call Kong with Authorization: DPoP",
                            "explanation": "Inputs from earlier steps: `private_key` and `public_jwk` from Step 1, plus `access_token` from Step 2. Mapping into this command: the `access_token` is placed in the header as `Authorization: DPoP <token>`. That header carries the OAuth access token itself. The separate `DPoP: <proof-jwt>` header carries the freshly signed proof JWT for this specific API call. That proof is not the access token. It contains claims such as `htu` for the URL being called, `htm` for the HTTP method, `iat` for proof creation time, `jti` for replay protection, and `ath` for the hash of the access token. The same `private_key` from Step 1 signs this new proof, and the same `public_jwk` is inserted into the JWT header as `jwk`. Output: either Kong forwards the request upstream, or it rejects it because one of those carried-forward inputs is missing or does not match.",
                            "command": (
                                build_curl_command(api_url, api_exchange["request_headers"])
                                if api_exchange
                                else "No Kong call was made because the token exchange failed."
                            ),
                            "response": (
                                {
                                    "status": api_exchange["response"]["status"],
                                    "headers": api_exchange["response"]["headers"],
                                    "body": api_exchange["response"]["body"],
                                    "header_roles": {
                                        "Authorization: DPoP <access_token>": "carries the OAuth access token issued by Auth0",
                                        "DPoP: <proof_jwt>": "carries the freshly signed proof JWT for this exact request",
                                        "proof_claims": {
                                            "htu": "the exact API URL being called",
                                            "htm": "the HTTP method being used",
                                            "iat": "when the proof was created",
                                            "jti": "a unique identifier used for replay protection",
                                            "ath": "hash of the presented access token",
                                        },
                                    },
                                    "pseudo_logic": [
                                        "1. Take access_token from Step 2 and place it in Authorization: DPoP <token>.",
                                        "2. Reuse public_jwk from Step 1 in the new DPoP JWT header.",
                                        "3. Build API proof payload with htu: kong_api_url, htm: GET, iat: now, jti: random_uuid.",
                                        "4. Compute ath = base64url(SHA-256(access_token)).",
                                        "5. Add ath to the API proof payload so the proof is tied to this exact token.",
                                        "6. Sign the new proof with the same private_key from Step 1.",
                                        "7. Send request to Kong with Authorization header and DPoP header.",
                                    "8. Kong checks: token valid, proof present, proof URL/method match, ath matches token, and proof key matches token-bound key.",
                                    "9. If all checks pass, Kong proxies upstream; otherwise it rejects the request.",
                                ],
                                    "what_is_missing_or_wrong": (
                                    "Nothing is missing in happy-path mode."
                                    if mode == "happy-path"
                                    else (
                                        "The DPoP header is present, but the proof payload says `htu=<wrong url>` instead of the real Kong API URL. Kong should reject it because the proof is bound to a different endpoint."
                                        if mode == "invalid-htu"
                                        else "The DPoP header is present, but the proof payload says `htm=POST` while the actual request is `GET`. Kong should reject it because the proof is bound to a different HTTP method."
                                        if mode == "invalid-htm"
                                        else "The DPoP header is present, but the proof is missing the `ath` claim that binds the proof to the presented access token. Kong should reject it."
                                        if mode == "missing-ath"
                                        else "Nothing is wrong in this first API call. It is the original valid request whose token and proof will be reused unchanged in the replay step."
                                    )
                                ),
                                    "negative_scenario_explained": (
                                        {
                                            "scenario": mode,
                                            "broken_claim": negative_scenario["broken_claim"],
                                            "claim_meaning": DPOP_CLAIM_GLOSSARY[negative_scenario["broken_claim"]],
                                            "simple_explanation": negative_scenario["simple_explanation"],
                                            "what_kong_checks": negative_scenario["what_kong_checks"],
                                            "why_kong_rejects_it": negative_scenario["why_rejected"],
                                        }
                                        if negative_scenario
                                        else {
                                            "scenario": mode,
                                            "summary": "This is the happy path, so no DPoP field is intentionally wrong or missing.",
                                        }
                                    ),
                                    "dpop_claim_glossary": DPOP_CLAIM_GLOSSARY,
                                    "proof": api_exchange["proof"],
                                }
                                if api_exchange
                                else {
                                    "status": None,
                                    "body": {"message": "Kong call skipped"},
                                    "what_is_missing_or_wrong": "No API request was sent because Auth0 rejected the token request earlier.",
                                }
                            ),
                        },
                        *(
                            [
                                {
                                    "title": "Replay the exact same API proof",
                                    "explanation": "Inputs from Step 3: the already-used `Authorization: DPoP <token>` header and the already-used DPoP JWT. Mapping into this command: nothing new is generated. The exact same token string and exact same DPoP proof JWT from Step 3 are sent again. That means the same `jti`, same `iat`, same `ath`, same `jwk`, and same signature are being reused. This is what makes it a replay attempt rather than a fresh proof-of-possession request. The custom replay-cache plugin does not verify the proof signature itself. It only decodes the JWT payload to read `jti` and stores that `jti` in Kong local shared memory so a reused proof can be rejected. The actual proof signature validation is still done by Kong's `openid-connect` plugin.",
                                    "command": (
                                        build_curl_command(api_url, replay_exchange["request_headers"])
                                        if replay_exchange
                                        else "Replay step was not executed."
                                    ),
                                    "response": (
                                        {
                                            "status": replay_exchange["response"]["status"],
                                            "headers": replay_exchange["response"]["headers"],
                                            "body": replay_exchange["response"]["body"],
                                            "pseudo_logic": [
                                                "1. Take the exact Authorization header from Step 3 with no changes.",
                                                "2. Take the exact DPoP JWT from Step 3 with no changes.",
                                                "3. Do not generate a new jti, iat, ath, or signature.",
                                                "4. Send the same API request to Kong again.",
                                                "5. Kong should detect that this proof is being reused instead of freshly generated for a new call.",
                                            ],
                                            "input_mapping": {
                                                "from_step_3.authorization_header": "reused exactly as-is",
                                                "from_step_3.dpop_header": "reused exactly as-is",
                                                "new_input": "none",
                                            },
                                            "replay_cache_note": {
                                                "cache_backend": "ngx.shared.kong_db_cache",
                                                "what_it_is": "Kong local shared memory on this data plane node, not Redis",
                                                "how_jti_is_read": "split proof JWT into header.payload.signature, base64url-decode the payload part, parse JSON, then read payload.jti",
                                                "signature_verification": "not done by the replay plugin; still done by the openid-connect plugin",
                                            },
                                            "what_is_missing_or_wrong": "The replay request is missing a fresh DPoP proof. Instead of creating a new proof with a new jti and new signature, it reuses the old proof from Step 3.",
                                            "negative_scenario_explained": {
                                                "scenario": "replay-attack",
                                                "broken_claim": "jti",
                                                "claim_meaning": DPOP_CLAIM_GLOSSARY["jti"],
                                                "simple_explanation": DPOP_NEGATIVE_SCENARIO_GUIDE["replay-attack"]["simple_explanation"],
                                                "what_kong_checks": DPOP_NEGATIVE_SCENARIO_GUIDE["replay-attack"]["what_kong_checks"],
                                                "why_kong_rejects_it": DPOP_NEGATIVE_SCENARIO_GUIDE["replay-attack"]["why_rejected"],
                                            },
                                            "proof": replay_exchange["proof"],
                                        }
                                        if replay_exchange
                                        else {
                                            "status": None,
                                            "body": {"message": "Replay step not executed"},
                                            "what_is_missing_or_wrong": "Replay was skipped because the first API call did not complete successfully enough to capture a proof to reuse.",
                                        }
                                    ),
                                }
                            ]
                            if mode == "replay-attack"
                            else []
                        ),
                    ],
                },
                "topology": {
                    "labels": {
                        "client": ("Client", "DPoP Caller", mode.replace("-", " ")),
                        "kong": ("Gateway", "Kong Data Plane", "dpop-replay-demo + openid-connect strict DPoP"),
                        "east": ("Protected API", "Orders API", "Reached" if api_success else "Not reached"),
                        "west": ("Identity Provider", "Auth0", "DPoP token exchange"),
                    },
                    "nodes": {
                        "kong": "active" if token_success else "error",
                        "east": "active" if api_success else None,
                        "west": "active" if token_success else "error",
                    },
                    "connectors": {
                        "clientKong": "active",
                        "kongWest": "active",
                        "kongEast": "active" if api_success else None,
                    },
                    "statusKong": (
                        "Initial request forwarded, replay rejected"
                        if mode == "replay-attack" and first_api_status == 200 and replay_status and replay_status != 200
                        else "Replay accepted by Kong"
                        if mode == "replay-attack" and first_api_status == 200 and replay_status == 200
                        else "Kong Forwarded Request"
                        if api_success
                        else "Kong Rejected Request"
                        if token_success
                        else "Auth0 Rejected Token Request"
                    ),
                    "statusKongClass": status_class,
                    "statusRoute": status_route,
                    "statusRouteClass": status_class,
                },
                "architecture": scene["architecture"],
                "errorMessage": error_message,
            }
            self.respond_json(enrich_payload_with_trace(payload))
        finally:
            primary_key["tempdir"].cleanup()

    def build_identity_payload(
        self,
        *,
        scene,
        path,
        token,
        idp_name,
        route_name,
        service_name,
        plugin_name,
        consumer_label,
        allowed_role,
    ):
        req_headers = build_bearer_headers(token)
        target_url = f"{KONG_PROXY_URL}{path}"
        response = request_through_kong(target_url, req_headers)
        response_body = response["body"] if isinstance(response["body"], dict) else {}
        response_status = response["status"]
        selected_service = response_body.get("service")
        kong_consumer = kong_identity_consumer_name(idp_name, consumer_label)
        consumer_mapping = consumer_mapping_description(idp_name)

        if response_status == 200:
            route_state = "authorized"
            error_message = None
        elif response_status == 403:
            route_state = "forbidden"
            error_message = "Authorization failed. Kong denied the token based on policy."
        else:
            route_state = "unauthorized"
            error_message = "Authentication failed. Kong rejected the token."

        expected_outcome = (
            "Kong should validate the Azure AD token and forward the request only when the token is valid."
            if scene["id"] == "identity-azure-token-validation"
            else "consumer-1 should be authorized while consumer-2 should be denied based on the role claim."
        )

        return {
            "scene": scene["id"],
            "sceneDetails": scene,
            "requestPreview": [
                ("Method", "GET"),
                ("Path", path),
                ("Identity Provider", idp_name),
                ("Token", "Bearer token in Authorization header"),
            ],
            "expectedOutcome": expected_outcome,
            "result": {
                "status": response_status,
                "routeState": route_state,
                "routeMatched": route_name,
                "kongServiceMatched": service_name,
                "pluginApplied": plugin_name,
                "selectedService": selected_service,
                "responseBody": response["body"],
                "responseHeaders": response["headers"],
                "consumer": consumer_label,
                "idp": idp_name,
            },
            "consoleView": {
                "request": {
                    "method": "GET",
                    "endpoint": path,
                    "headers": req_headers,
                    "body": None,
                },
                "response": {
                    "status": response_status,
                    "headers": response["headers"],
                    "body": response["body"],
                },
            },
            "detailView": {
                "entities": normalize_detail_entities(
                    [
                        ("Kong Route", route_name),
                        ("Kong Service", service_name),
                        ("Kong Plugin", plugin_name),
                        ("Kong Consumer", kong_consumer),
                        ("Consumer Mapping", consumer_mapping),
                        ("Identity Provider", idp_name),
                        ("Consumer", consumer_label),
                        ("Required Role", allowed_role or "None"),
                        ("Actual Service Name", selected_service or "No upstream call"),
                    ]
                ),
                "curl": build_curl_command(target_url, req_headers),
                "response": {
                    "status": response_status,
                    "headers": response["headers"],
                    "body": response["body"],
                },
            },
            "topology": {
                "labels": {
                    "client": ("Client", "Token Caller", "Bearer token supplied"),
                    "kong": ("Gateway", "Kong Data Plane", "openid-connect validation"),
                    "east": ("Protected API", "Orders API", "Reached" if response_status == 200 else "Not reached"),
                    "west": (
                        "Identity Provider",
                        idp_name,
                        "Validated",
                    ),
                },
                "nodes": {
                    "kong": "active" if response_status == 200 else "error",
                    "east": "active" if response_status == 200 else None,
                    "west": "active",
                },
                "connectors": {
                    "clientKong": "active",
                    "kongWest": "active",
                    "kongEast": "active" if response_status == 200 else None,
                },
                "statusKong": "Kong Authorized Request" if response_status == 200 else "Kong Rejected Request",
                "statusKongClass": "success" if response_status == 200 else "error",
                "statusRoute": (
                    "Token validated"
                    if response_status == 200
                    else "Authorization denied"
                    if response_status == 403
                    else "Authentication failed"
                ),
                "statusRouteClass": "success" if response_status == 200 else "error",
            },
            "architecture": scene["architecture"],
            "errorMessage": error_message,
        }

    def handle_run_ip_restriction(self):
        scene = SCENES["network-policy-ip-allow-deny"]
        body = self.read_json()
        preset = body.get("preset", "allowed")
        client_ip = IP_PRESETS.get(preset, IP_PRESETS["allowed"])
        target_url = f"{KONG_PROXY_URL}/orders/network/ip"
        req_headers = {
            "Accept": "application/json",
            "x-request-id": str(uuid.uuid4()),
            "X-Forwarded-For": client_ip,
        }
        response = request_through_kong(target_url, req_headers)
        response_status = response["status"]
        allowed = response_status == 200
        preset_text = "Allowed IP" if preset == "allowed" else "Denied IP" if preset == "denied" else "Not listed IP"
        expected_outcome = (
            "The allowed client IP should pass through Kong and reach the protected API."
            if preset == "allowed"
            else "Kong should block the client IP at the IP restriction policy before the protected API is reached."
        )

        self.respond_json(
            {
                "scene": scene["id"],
                "sceneDetails": scene,
                "requestPreview": [
                    ("Method", "GET"),
                    ("Path", "/orders/network/ip"),
                    ("Source IP", client_ip),
                    ("Policy Preset", preset_text),
                ],
                "expectedOutcome": expected_outcome,
                "result": {
                    "status": response_status,
                    "routeMatched": "route-orders-ip-restriction",
                    "kongServiceMatched": "svc-orders-ip-restriction",
                    "pluginApplied": "ip-restriction on route-orders-ip-restriction",
                    "selectedService": response["body"].get("service") if isinstance(response["body"], dict) else None,
                    "responseBody": response["body"],
                    "responseHeaders": response["headers"],
                    "clientIp": client_ip,
                },
                "consoleView": {
                    "request": {
                        "method": "GET",
                        "endpoint": "/orders/network/ip",
                        "headers": req_headers,
                        "body": None,
                    },
                    "response": {
                        "status": response_status,
                        "headers": response["headers"],
                        "body": response["body"],
                    },
                },
                "detailView": {
                    "entities": normalize_detail_entities(
                        [
                            ("Kong Route", "route-orders-ip-restriction"),
                            ("Kong Service", "svc-orders-ip-restriction"),
                            ("Kong Plugin", "ip-restriction on route-orders-ip-restriction"),
                            ("Evaluated Client IP", client_ip),
                            ("Actual Service Name", response["body"].get("service") if isinstance(response["body"], dict) else "No upstream call"),
                        ]
                    ),
                    "curl": build_curl_command(target_url, req_headers),
                    "response": {
                        "status": response_status,
                        "headers": response["headers"],
                        "body": response["body"],
                    },
                },
                "topology": {
                    "labels": {
                        "client": ("Client", "IP Caller", client_ip),
                        "kong": ("Gateway", "Kong Data Plane", "IP restriction policy"),
                        "east": ("Protected API", "Orders API", "Reached" if allowed else "Not reached"),
                        "west": ("Network Policy", "Allow + Deny List", "Policy evaluated"),
                    },
                    "nodes": {
                        "kong": "active" if allowed else "error",
                        "east": "active" if allowed else None,
                        "west": "active",
                    },
                    "connectors": {
                        "clientKong": "active",
                        "kongEast": "active" if allowed else None,
                        "kongWest": "active",
                    },
                    "statusKong": "Kong Allowed Request" if allowed else "Kong Blocked IP",
                    "statusKongClass": "success" if allowed else "error",
                    "statusRoute": "IP Allowed" if allowed else "IP Rejected",
                    "statusRouteClass": "success" if allowed else "error",
                },
                "architecture": scene["architecture"],
            }
        )

    def handle_run_schema_validation(self):
        scene = SCENES["data-quality-schema-validation"]
        body = self.read_json()
        case = body.get("case", "valid-request")
        config = SCHEMA_CASES.get(case, SCHEMA_CASES["valid-request"])
        target_url = f"{KONG_PROXY_URL}{config['path']}"
        req_headers = {"Accept": "application/json", "x-request-id": str(uuid.uuid4()), **config["headers"]}
        response = request_through_kong(target_url, req_headers, method="POST", body=config["body"])
        response_status = response["status"]
        allowed = response_status == 200
        case_label = {
            "valid-request": "Valid Request",
            "invalid-body": "Invalid Body",
            "invalid-query-param": "Invalid Query Param",
            "invalid-header-content-type": "Invalid Header / Content-Type",
        }.get(case, "Request")
        expected_outcome = (
            "A valid request should satisfy the body, query, and header contract and reach the protected API."
            if case == "valid-request"
            else "Kong should reject the request at the validator before it reaches the protected API."
        )

        self.respond_json(
            {
                "scene": scene["id"],
                "sceneDetails": scene,
                "requestPreview": [
                    ("Method", "POST"),
                    ("Path", config["path"]),
                    ("Validation Case", case_label),
                    ("Content-Type", req_headers.get("Content-Type", "None")),
                ],
                "expectedOutcome": expected_outcome,
                "result": {
                    "status": response_status,
                    "routeMatched": "route-orders-schema-validation",
                    "kongServiceMatched": "svc-orders-schema-validation",
                    "pluginApplied": "request-validator on route-orders-schema-validation",
                    "selectedService": response["body"].get("service") if isinstance(response["body"], dict) else None,
                    "responseBody": response["body"],
                    "responseHeaders": response["headers"],
                    "validationCase": case,
                },
                "consoleView": {
                    "request": {
                        "method": "POST",
                        "endpoint": config["path"],
                        "headers": req_headers,
                        "body": config["body"],
                    },
                    "response": {
                        "status": response_status,
                        "headers": response["headers"],
                        "body": response["body"],
                    },
                },
                "detailView": {
                    "entities": normalize_detail_entities(
                        [
                            ("Kong Route", "route-orders-schema-validation"),
                            ("Kong Service", "svc-orders-schema-validation"),
                            ("Kong Plugin", "request-validator on route-orders-schema-validation"),
                            ("Validation Case", case_label),
                            ("Actual Service Name", response["body"].get("service") if isinstance(response["body"], dict) else "No upstream call"),
                        ]
                    ),
                    "curl": build_curl_command(target_url, req_headers, method="POST", body=config["body"]),
                    "response": {
                        "status": response_status,
                        "headers": response["headers"],
                        "body": response["body"],
                    },
                },
                "topology": {
                    "labels": {
                        "client": ("Client", "Schema Caller", case_label),
                        "kong": ("Gateway", "Kong Data Plane", "Request validator"),
                        "east": ("Protected API", "Orders API", "Reached" if allowed else "Not reached"),
                        "west": ("Schema Policy", "Body + Query + Headers", "Validation evaluated"),
                    },
                    "nodes": {
                        "kong": "active" if allowed else "error",
                        "east": "active" if allowed else None,
                        "west": "active",
                    },
                    "connectors": {
                        "clientKong": "active",
                        "kongEast": "active" if allowed else None,
                        "kongWest": "active",
                    },
                    "statusKong": "Kong Accepted Request" if allowed else "Kong Rejected Request",
                    "statusKongClass": "success" if allowed else "error",
                    "statusRoute": case_label,
                    "statusRouteClass": "success" if allowed else "error",
                },
                "architecture": scene["architecture"],
            }
        )

    def handle_run_request_size(self):
        scene = SCENES["traffic-control-request-size-limiting"]
        body = self.read_json()
        case = body.get("case", "positive")
        config = REQUEST_SIZE_CASES.get(case, REQUEST_SIZE_CASES["positive"])
        target_url = f"{KONG_PROXY_URL}{config['path']}"
        req_headers = {"Accept": "application/json", "x-request-id": str(uuid.uuid4()), **config["headers"]}
        response = request_through_kong(target_url, req_headers, method="POST", body=config["body"])
        response_status = response["status"]
        allowed = response_status == 200
        payload_size_bytes = len(json.dumps(config["body"]).encode("utf-8"))
        case_label = "Does Not Exceed Limit" if case == "positive" else "Exceeds Limit"
        expected_outcome = (
            "The request body that does not exceed the 2 KB limit should reach the protected API."
            if case == "positive"
            else "Kong should reject the oversized request body before the protected API is reached."
        )

        self.respond_json(
            {
                "scene": scene["id"],
                "sceneDetails": scene,
                "requestPreview": [
                    ("Method", "POST"),
                    ("Path", "/orders/limits/request-size"),
                    ("Scenario", case_label),
                    ("Payload Size", f"{payload_size_bytes} bytes"),
                ],
                "expectedOutcome": expected_outcome,
                "result": {
                    "status": response_status,
                    "routeMatched": "route-orders-request-size",
                    "kongServiceMatched": "svc-orders-request-size",
                    "pluginApplied": "request-size-limiting on route-orders-request-size",
                    "selectedService": response["body"].get("service") if isinstance(response["body"], dict) else None,
                    "responseBody": response["body"],
                    "responseHeaders": response["headers"],
                    "payloadSizeBytes": payload_size_bytes,
                },
                "consoleView": {
                    "request": {
                        "method": "POST",
                        "endpoint": "/orders/limits/request-size",
                        "headers": req_headers,
                        "body": config["body"],
                    },
                    "response": {
                        "status": response_status,
                        "headers": response["headers"],
                        "body": response["body"],
                    },
                },
                "detailView": {
                    "entities": normalize_detail_entities(
                        [
                            ("Kong Route", "route-orders-request-size"),
                            ("Kong Service", "svc-orders-request-size"),
                            ("Kong Plugin", "request-size-limiting on route-orders-request-size"),
                            ("Payload Size", f"{payload_size_bytes} bytes"),
                            ("Actual Service Name", response["body"].get("service") if isinstance(response["body"], dict) else "No upstream call"),
                        ]
                    ),
                    "curl": build_curl_command(target_url, req_headers, method="POST", body=config["body"]),
                    "response": {
                        "status": response_status,
                        "headers": response["headers"],
                        "body": response["body"],
                    },
                },
                "topology": {
                    "labels": {
                        "client": ("Client", "Payload Caller", f"{payload_size_bytes} bytes"),
                        "kong": ("Gateway", "Kong Data Plane", "2 KB request size limit"),
                        "east": ("Protected API", "Orders API", "Reached" if allowed else "Not reached"),
                        "west": ("Payload Policy", "Request Size Limit", "Limit evaluated"),
                    },
                    "nodes": {
                        "kong": "active" if allowed else "error",
                        "east": "active" if allowed else None,
                        "west": "active",
                    },
                    "connectors": {
                        "clientKong": "active",
                        "kongEast": "active" if allowed else None,
                        "kongWest": "active",
                    },
                    "statusKong": "Kong Accepted Request" if allowed else "Kong Rejected Payload",
                    "statusKongClass": "success" if allowed else "error",
                    "statusRoute": case_label,
                    "statusRouteClass": "success" if allowed else "error",
                },
                "architecture": scene["architecture"],
            }
        )

    def handle_run_metering_billing(self):
        scene = SCENES["monetization-metering-billing"]
        body = self.read_json()
        consumer = body.get("consumer", "demo-bank-1")
        config = METERING_CONSUMERS.get(consumer, METERING_CONSUMERS["demo-bank-1"])

        target_url = f"{KONG_PROXY_URL}{config['path']}"
        req_headers = dict(config["headers"])
        req_headers["x-request-id"] = str(uuid.uuid4())

        response = request_through_kong(target_url, req_headers, method=config["method"])
        response_status = response["status"]
        allowed = response_status == 200
        selected_service = response["body"].get("service") if isinstance(response["body"], dict) else None
        dimensions = dict(config["dimensions"])

        expected_outcome = "Kong should meter one usage event per authenticated request and use the resolved Kong Consumer as the billable subject."

        self.respond_json(
            {
                "scene": scene["id"],
                "sceneDetails": scene,
                "requestPreview": [
                    ("Method", config["method"]),
                    ("Path", config["path"]),
                    ("Demo Consumer", consumer),
                    ("Billable Subject", f"{config['subject_source']} -> {config['subject']}"),
                ],
                "expectedOutcome": expected_outcome,
                "result": {
                    "status": response_status,
                    "routeMatched": config["route"],
                    "kongServiceMatched": config["service"],
                    "pluginApplied": f"usage metering plugin ({config['policy']})",
                    "selectedService": selected_service,
                    "responseBody": response["body"],
                    "responseHeaders": response["headers"],
                    "billableSubject": config["subject"],
                    "subjectSource": config["subject_source"],
                    "dimensions": dimensions,
                    "consumer": consumer,
                },
                "consoleView": {
                    "request": {
                        "method": config["method"],
                        "endpoint": target_url,
                        "headers": req_headers,
                        "body": None,
                    },
                    "response": {
                        "status": response_status,
                        "headers": response["headers"],
                        "body": response["body"],
                    },
                },
                "detailView": {
                    "entities": normalize_detail_entities(
                        [
                            ("Kong Route", config["route"]),
                            ("Kong Service", config["service"]),
                            ("Plugin Scope", "route-scoped usage metering plugin"),
                            ("Ingest Endpoint", "https://us.api.konghq.com/v3/openmeter/events"),
                            ("Billable Subject", config["subject"]),
                            ("Subject Resolution", config["subject_source"]),
                            (
                                "Billing Dimensions",
                                ", ".join(f"{key}={value}" for key, value in dimensions.items()) if dimensions else "none",
                            ),
                            ("Actual Service Name", selected_service or "No upstream call"),
                        ]
                    ),
                    "curl": build_curl_command(target_url, req_headers, method=config["method"]),
                    "steps": [
                        {
                            "title": "Metered API Request",
                            "command": build_curl_command(target_url, req_headers, method=config["method"]),
                            "response": {
                                "status": response_status,
                                "headers": response["headers"],
                                "body": response["body"],
                                "metering": {
                                    "subject": config["subject"],
                                    "subject_source": config["subject_source"],
                                    "dimensions": dimensions,
                                    "event_type": "request",
                                    "ingest_endpoint": "https://us.api.konghq.com/v3/openmeter/events",
                                },
                            },
                        }
                    ],
                    "response": {
                        "status": response_status,
                        "headers": response["headers"],
                        "body": response["body"],
                    },
                },
                "topology": {
                    "labels": {
                        "client": ("Client", "Billable Caller", consumer),
                        "kong": ("Gateway", "Kong Data Plane", "Metering & Billing plugin"),
                        "east": ("Protected API", "Orders API", "Reached" if allowed else "Not reached"),
                        "west": (
                            "Billing Event",
                            config["subject"],
                            ", ".join(f"{key}={value}" for key, value in dimensions.items()) if dimensions else "no extra dimensions",
                        ),
                    },
                    "nodes": {
                        "kong": "active" if allowed else "error",
                        "east": "active" if allowed else None,
                        "west": "active" if allowed else None,
                    },
                    "connectors": {
                        "clientKong": "active",
                        "kongEast": "active" if allowed else None,
                        "kongWest": "active" if allowed else None,
                    },
                    "statusKong": "Usage Event Emitted" if allowed else f"HTTP {response_status}",
                    "statusKongClass": "success" if allowed else "error",
                    "statusRoute": config["route"],
                    "statusRouteClass": "success" if allowed else "error",
                },
                "architecture": scene["architecture"],
            }
        )

    def handle_run_datakit(self):
        scene = SCENES["datakit-plugin-orchestration"]
        body = self.read_json()
        scenario = body.get("scenario", "fallback")
        fallback_mode = body.get("fallbackMode", "api1-success")
        config = DATAKIT_SCENARIOS.get(scenario, DATAKIT_SCENARIOS["fallback"])
        token, token_response = generate_keycloak_access_token("consumer-1")
        if not token:
            self.respond_json(
                {
                    "error": "Failed to obtain Keycloak token for Datakit scene.",
                    "tokenResponse": token_response["body"],
                },
                status=HTTPStatus.BAD_GATEWAY,
            )
            return

        target_url = f"{KONG_PROXY_URL}{config['path']}"
        if scenario == "fallback":
            mode = "success" if fallback_mode == "api1-success" else "fail"
            target_url = f"{target_url}?mode={mode}"

        req_headers = build_bearer_headers(token)
        response = request_through_kong(target_url, req_headers, method=config["method"])
        response_status = response["status"]
        response_body = response["body"] if isinstance(response["body"], dict) else {}
        selected_role = response["headers"].get("x-authenticated-role", "unknown")
        fallback_decision = response["headers"].get("x-datakit-decision", "unknown")
        selected_service = response_body.get("result", {}).get("source") if scenario == "fallback" else None
        if scenario == "combine":
            selected_service = "api1 + api2"
        if scenario == "cache":
            selected_service = response_body.get("source")

        if scenario == "fallback":
            expected_outcome = (
                "Datakit should call API1 through a wrapper callout node. "
                "The wrapper always returns HTTP 200 to Datakit, but carries API1's original status in the payload. "
                "If the original API1 status is 200, Datakit returns the API1 response. "
                "If the original API1 status is non-200, Datakit calls API2 and returns the API2 response instead."
            )
            request_preview = [
                ("Method", "GET"),
                ("Path", "/orders/datakit/fallback"),
                ("Fallback Mode", "API1 success" if fallback_mode == "api1-success" else "API1 non-200"),
                ("API1 Original Status", "200" if fallback_mode == "api1-success" else "503"),
                ("JWT Auth", "Keycloak bearer token (consumer-1)"),
            ]
            detail_entities = [
                ("Kong Route", config["route"]),
                ("Kong Service", config["service"]),
                ("Kong Plugins", "openid-connect + datakit"),
                ("Flow", "call API1 wrapper -> inspect original API1 status -> optionally call API2"),
                ("Execution Model", "API1 wrapper and API2 are both Datakit call nodes"),
                ("API1 Returns 200 When", "Fallback Mode is set to API1 success"),
                ("API1 Returns 503 When", "Fallback Mode is set to API1 non-200"),
                ("Branch Condition", "API1 originalStatus == 200"),
                ("Fallback Trigger", "API1 originalStatus != 200"),
                ("Returned Role Header", f"x-authenticated-role: {selected_role}"),
                ("Decision", fallback_decision),
            ]
        elif scenario == "combine":
            expected_outcome = (
                "Datakit should call API1 for the account list, call API2 for the account details, "
                "join the two payloads on accountId, and return one composed response."
            )
            request_preview = [
                ("Method", "GET"),
                ("Path", "/orders/datakit/combine"),
                ("Join Key", "accountId"),
                ("JWT Auth", "Keycloak bearer token (consumer-1)"),
            ]
            detail_entities = [
                ("Kong Route", config["route"]),
                ("Kong Service", config["service"]),
                ("Kong Plugins", "openid-connect + datakit"),
                ("Join Key", "accountId"),
                ("Account Count", str(len(response_body.get("accounts", [])))),
            ]
        else:
            ttl_seconds = config["ttl_seconds"]
            expected_outcome = (
                f"Datakit should look up Redis first. On a miss, it should fetch fresh data, cache it with a {ttl_seconds}-second TTL, "
                f"and return the fresh payload. During the {ttl_seconds}-second TTL window, Datakit should serve the cached payload unchanged."
            )
            request_preview = [
                ("Method", "GET"),
                ("Path", "/orders/datakit/cache"),
                ("Cache Strategy", "Redis-backed DataKit cache"),
                ("Cache TTL", f"{ttl_seconds} seconds"),
            ]
            detail_entities = [
                ("Kong Route", config["route"]),
                ("Kong Service", config["service"]),
                ("Kong Plugins", "openid-connect + datakit"),
                ("Cache Backend", "Redis"),
                ("Cache TTL", f"{ttl_seconds} seconds"),
                ("Cache Status", response["headers"].get("x-cache-status", "unknown")),
            ]

        if scenario == "fallback":
            east_state = "active" if fallback_decision == "api1-success" else "error" if fallback_decision == "api2-fallback" else "active"
            west_state = "active" if fallback_decision == "api2-fallback" else None
            east_connector = "active"
            west_connector = "active" if fallback_decision == "api2-fallback" else None
            west_detail = "fallback target" if fallback_decision == "api2-fallback" else "not used"
        elif scenario == "cache":
            cache_status = response["headers"].get("x-cache-status", "unknown")
            east_state = None if cache_status == "HIT" else "active" if response_status == 200 else None
            west_state = "active" if response_status == 200 else None
            east_connector = None if cache_status == "HIT" else "active" if response_status == 200 else None
            west_connector = "active" if response_status == 200 else None
            west_detail = f"Redis cache TTL {config['ttl_seconds']}s"
        else:
            east_state = "active" if response_status == 200 else None
            west_state = "active" if response_status == 200 else None
            east_connector = "active" if response_status == 200 else None
            west_connector = "active" if response_status == 200 else None
            west_detail = "account details" if scenario == "combine" else f"Redis cache TTL {config['ttl_seconds']}s"

        self.respond_json(
            {
                "scene": scene["id"],
                "sceneDetails": scene,
                "requestPreview": request_preview,
                "expectedOutcome": expected_outcome,
                "result": {
                    "status": response_status,
                    "routeMatched": config["route"],
                    "kongServiceMatched": config["service"],
                    "pluginApplied": "openid-connect + datakit",
                    "selectedService": selected_service,
                    "responseBody": response["body"],
                    "responseHeaders": response["headers"],
                    "scenario": scenario,
                    "fallbackMode": fallback_mode if scenario == "fallback" else None,
                    "authenticatedRole": selected_role,
                },
                "consoleView": {
                    "request": {
                        "method": config["method"],
                        "endpoint": target_url,
                        "headers": req_headers,
                        "body": None,
                    },
                    "response": {
                        "status": response_status,
                        "headers": response["headers"],
                        "body": response["body"],
                    },
                },
                "detailView": {
                    "entities": normalize_detail_entities(detail_entities),
                    "steps": [
                        {
                            "title": "Authenticated DataKit Request",
                            "command": build_curl_command(target_url, req_headers, method=config["method"]),
                            "response": {
                                "status": response_status,
                                "headers": response["headers"],
                                "body": response["body"],
                            },
                        }
                    ],
                    "curl": build_curl_command(target_url, req_headers, method=config["method"]),
                    "response": {
                        "status": response_status,
                        "headers": response["headers"],
                        "body": response["body"],
                    },
                },
                "topology": {
                    "labels": {
                        "client": ("Client", "Keycloak Authenticated Caller", "consumer-1"),
                        "kong": ("Gateway", "Kong Data Plane", f"Datakit {config['label']}"),
                        "east": (
                            "API1",
                            "Primary Upstream",
                            "list accounts" if scenario == "combine" else "primary source",
                        ),
                        "west": (
                            "API2 / Cache",
                            "Secondary Path",
                            (
                                west_detail
                                if scenario == "fallback"
                                else "account details"
                                if scenario == "combine"
                                else f"Redis cache TTL {config['ttl_seconds']}s"
                            ),
                        ),
                    },
                    "nodes": {
                        "kong": "active" if response_status == 200 else "error",
                        "east": east_state,
                        "west": west_state,
                    },
                    "connectors": {
                        "clientKong": "active",
                        "kongEast": east_connector,
                        "kongWest": west_connector,
                    },
                    "statusKong": "DataKit Flow Executed" if response_status == 200 else f"HTTP {response_status}",
                    "statusKongClass": "success" if response_status == 200 else "error",
                    "statusRoute": config["label"],
                    "statusRouteClass": "success" if response_status == 200 else "error",
                },
                "architecture": scene["architecture"],
            }
        )

    def handle_run_payload_crypto(self):
        scene = SCENES["transformation-gateway-payload-encryption"]
        plaintext_request = {
            "orderId": "ORD-2001",
            "amount": 1250.75,
            "currency": "INR",
            "customerId": "CUST-7788",
            "notes": "Encrypt this request at the gateway before upstream processing.",
        }
        encrypt_response = post_json(f"{CRYPTO_HELPER_URL}/encrypt-request", {"payload": plaintext_request})
        if encrypt_response["status"] >= 400:
            self.respond_json(
                {"error": encrypt_response["body"].get("error", "Failed to encrypt request payload")},
                status=HTTPStatus.BAD_GATEWAY,
            )
            return

        encrypted_request_envelope = encrypt_response["body"]["envelope"]
        encrypted_request_json = json.dumps(encrypted_request_envelope)
        target_url = f"{KONG_PROXY_URL}/orders/security/payload-crypto"
        req_headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "x-request-id": str(uuid.uuid4()),
        }
        response = request_through_kong(target_url, req_headers, method="POST", body=encrypted_request_json)
        response_status = response["status"]
        encrypted_response_envelope = response["body"] if isinstance(response["body"], dict) else {}

        decrypt_response = post_json(f"{CRYPTO_HELPER_URL}/decrypt-response", encrypted_response_envelope)
        decrypted_response_text = ""
        decrypted_response_json = {}
        if decrypt_response["status"] < 400:
            decrypted_response_text = decrypt_response["body"].get("plaintext", "")
            decrypted_response_json = parse_response_body(decrypted_response_text)

        expected_outcome = (
            "Kong should decrypt the request envelope before proxying upstream, then encrypt the upstream response before returning it to the client."
        )
        allowed = response_status == 200 and bool(decrypted_response_json)
        plaintext_response_payload = decrypted_response_json if decrypted_response_json else decrypt_response["body"]

        self.respond_json(
            {
                "scene": scene["id"],
                "sceneDetails": scene,
                "requestPreview": [
                    ("Method", "POST"),
                    ("Path", "/orders/security/payload-crypto"),
                    ("Request Format", "encrypted session key + IV + encrypted payload"),
                    ("Response Format", "encrypted session key + IV + encrypted payload"),
                ],
                "expectedOutcome": expected_outcome,
                "result": {
                    "status": response_status,
                    "routeMatched": "route-orders-payload-crypto",
                    "kongServiceMatched": "svc-orders-payload-crypto",
                    "pluginApplied": "payload-crypto-demo on route-orders-payload-crypto",
                    "selectedService": decrypted_response_json.get("service") if isinstance(decrypted_response_json, dict) else None,
                    "responseBody": response["body"],
                    "responseHeaders": response["headers"],
                    "encryptedRequestPayload": encrypted_request_envelope,
                    "decryptedRequestPayload": plaintext_request,
                    "plaintextResponsePayload": plaintext_response_payload,
                    "encryptedResponsePayload": encrypted_response_envelope,
                },
                "consoleView": {
                    "request": {
                        "method": "POST",
                        "endpoint": "/orders/security/payload-crypto",
                        "headers": req_headers,
                        "body": encrypted_request_envelope,
                    },
                    "response": {
                        "status": response_status,
                        "headers": response["headers"],
                        "body": encrypted_response_envelope,
                    },
                },
                "detailView": {
                    "entities": normalize_detail_entities(
                        [
                            ("Kong Route", "route-orders-payload-crypto"),
                            ("Kong Service", "svc-orders-payload-crypto"),
                            ("Kong Plugin", "payload-crypto-demo on route-orders-payload-crypto"),
                            ("Algorithm", "AES/CBC/PKCS5Padding"),
                            ("Actual Service Name", decrypted_response_json.get("service") if isinstance(decrypted_response_json, dict) else "No upstream call"),
                        ]
                    ),
                    "curl": build_curl_command(target_url, req_headers, method="POST", body=encrypted_request_json),
                    "response": {
                        "status": response_status,
                        "headers": response["headers"],
                        "body": {
                            "encryptedRequestPayload": encrypted_request_envelope,
                            "decryptedRequestPayload": plaintext_request,
                            "plaintextResponsePayload": plaintext_response_payload,
                            "encryptedResponsePayload": encrypted_response_envelope,
                        },
                    },
                },
                "topology": {
                    "labels": {
                        "client": ("Client", "Encrypted Caller", "encrypted session key + IV + payload"),
                        "kong": ("Gateway", "Kong Data Plane", "decrypt request + encrypt response"),
                        "east": ("Upstream", "Orders API", "plaintext request and plaintext response"),
                        "west": ("Crypto Policy", "payload-crypto-demo", "AES/CBC/PKCS5Padding"),
                    },
                    "nodes": {
                        "kong": "active" if allowed else "error",
                        "east": "active" if allowed else None,
                        "west": "active",
                    },
                    "connectors": {
                        "clientKong": "active",
                        "kongEast": "active" if allowed else None,
                        "kongWest": "active",
                    },
                    "statusKong": "Kong Transformed Payloads" if allowed else "Kong Crypto Failure",
                    "statusKongClass": "success" if allowed else "error",
                    "statusRoute": "Decrypted upstream, encrypted downstream" if allowed else "Transformation failed",
                    "statusRouteClass": "success" if allowed else "error",
                },
                "architecture": scene["architecture"],
            }
        )

    def handle_run_injection_protection(self):
        scene = SCENES["security-injection-protection"]
        body = self.read_json()
        subscene = body.get("subscene", "query-params")
        config = INJECTION_CASES.get(subscene, INJECTION_CASES["query-params"])
        target_url = f"{KONG_PROXY_URL}{config['path']}"
        req_headers = {"x-request-id": str(uuid.uuid4()), **config["headers"]}
        response = request_through_kong(target_url, req_headers, method=config["method"], body=config["body"])
        response_status = response["status"]
        allowed = response_status == 200
        expected_outcome = "Kong should detect the injection pattern and block the request before it reaches the protected API."

        self.respond_json(
            {
                "scene": scene["id"],
                "sceneDetails": scene,
                "requestPreview": [
                    ("Method", config["method"]),
                    ("Path", config["path"]),
                    ("Inspection Location", config["location"]),
                    ("Pattern", "SQL-style injection"),
                ],
                "expectedOutcome": expected_outcome,
                "result": {
                    "status": response_status,
                    "routeMatched": config["route"],
                    "kongServiceMatched": "svc-orders-injection-protection",
                    "pluginApplied": f"injection-protection on {config['route']}",
                    "selectedService": response["body"].get("service") if isinstance(response["body"], dict) else None,
                    "responseBody": response["body"],
                    "responseHeaders": response["headers"],
                    "subscene": subscene,
                },
                "consoleView": {
                    "request": {
                        "method": config["method"],
                        "endpoint": config["path"],
                        "headers": req_headers,
                        "body": config["body"],
                    },
                    "response": {
                        "status": response_status,
                        "headers": response["headers"],
                        "body": response["body"],
                    },
                },
                "detailView": {
                    "entities": normalize_detail_entities(
                        [
                            ("Kong Route", config["route"]),
                            ("Kong Service", "svc-orders-injection-protection"),
                            ("Kong Plugin", f"injection-protection on {config['route']}"),
                            ("Inspection Location", config["location"]),
                            ("Actual Service Name", response["body"].get("service") if isinstance(response["body"], dict) else "No upstream call"),
                        ]
                    ),
                    "curl": build_curl_command(target_url, req_headers, method=config["method"], body=config["body"]),
                    "response": {
                        "status": response_status,
                        "headers": response["headers"],
                        "body": response["body"],
                    },
                },
                "topology": {
                    "labels": {
                        "client": ("Client", "Injection Caller", config["location"]),
                        "kong": ("Gateway", "Kong Data Plane", "Injection protection"),
                        "east": ("Protected API", "Orders API", "Reached" if allowed else "Not reached"),
                        "west": ("Inspection Policy", config["location"], "Matched SQL pattern"),
                    },
                    "nodes": {
                        "kong": "active" if allowed else "error",
                        "east": "active" if allowed else None,
                        "west": "active",
                    },
                    "connectors": {
                        "clientKong": "active",
                        "kongEast": "active" if allowed else None,
                        "kongWest": "active",
                    },
                    "statusKong": "Kong Allowed Request" if allowed else "Kong Blocked Injection",
                    "statusKongClass": "success" if allowed else "error",
                    "statusRoute": config["location"],
                    "statusRouteClass": "success" if allowed else "error",
                },
                "architecture": scene["architecture"],
            }
        )

    def handle_run_transport_security(self):
        scene = SCENES["transport-security-http-enforcement"]
        body = self.read_json()
        case = body.get("case", "http-blocked")
        config = TRANSPORT_SECURITY_CASES.get(case, TRANSPORT_SECURITY_CASES["http-blocked"])
        target_url = f"{KONG_PROXY_URL}{config['path']}"
        req_headers = {"Accept": "application/json", "x-request-id": str(uuid.uuid4())}
        response = request_through_kong_no_redirect(target_url, req_headers)
        response_status = response["status"]
        blocked = case == "http-blocked"
        route_status = "HTTP Rejected" if blocked else "Redirect Issued"
        redirect_location = response["headers"].get("location")
        follow_up = None
        follow_up_url = None
        follow_up_display_url = None

        if not blocked and redirect_location:
            parsed_location = urllib.parse.urlparse(redirect_location)
            follow_up_path = parsed_location.path or config["path"]
            if parsed_location.query:
                follow_up_path = f"{follow_up_path}?{parsed_location.query}"
            follow_up_url = f"{KONG_TLS_PROXY_URL}{follow_up_path}"
            follow_up_display_url = redirect_location
            follow_up_headers = {
                "Accept": "application/json",
                "x-request-id": req_headers["x-request-id"],
            }
            follow_up = request_through_kong_tls(follow_up_url, follow_up_headers)

        self.respond_json(
            {
                "scene": scene["id"],
                "sceneDetails": scene,
                "requestPreview": [
                    ("Method", "GET"),
                    ("Path", config["path"]),
                    ("Transport Case", "HTTP blocked" if blocked else "HTTP to HTTPS redirect"),
                    ("Entry Protocol", "http"),
                ],
                "expectedOutcome": config["expected_outcome"],
                "result": {
                    "status": response_status,
                    "routeMatched": config["route"],
                    "kongServiceMatched": "svc-orders-transport-security",
                    "pluginApplied": "native HTTPS-only route policy",
                    "selectedService": (
                        follow_up["body"].get("service")
                        if follow_up and isinstance(follow_up["body"], dict)
                        else None
                    ),
                    "responseBody": response["body"],
                    "responseHeaders": response["headers"],
                    "transportCase": case,
                    "locationHeader": redirect_location,
                    "followUp": (
                        {
                            "url": follow_up_url,
                            "displayUrl": follow_up_display_url,
                            "status": follow_up["status"],
                            "headers": follow_up["headers"],
                            "body": follow_up["body"],
                        }
                        if follow_up
                        else None
                    ),
                },
                "consoleView": {
                    "request": {
                        "method": "GET",
                        "endpoint": target_url,
                        "headers": req_headers,
                        "body": None,
                    },
                    "response": {
                        "status": response_status,
                        "headers": response["headers"],
                        "body": response["body"],
                        "followUp": (
                            {
                                "method": "GET",
                                "endpoint": follow_up_url,
                                "displayEndpoint": follow_up_display_url,
                                "status": follow_up["status"],
                                "headers": follow_up["headers"],
                                "body": follow_up["body"],
                            }
                            if follow_up
                            else None
                        ),
                    },
                },
                "detailView": {
                    "entities": normalize_detail_entities(
                        [
                            ("Kong Route", config["route"]),
                            ("Kong Service", "svc-orders-transport-security"),
                            ("Transport Policy", "HTTPS only"),
                            ("HTTP Behavior", "426 blocked" if blocked else "308 redirect"),
                            ("Location Received", redirect_location or "No redirect issued"),
                            (
                                "Follow-Up HTTPS Call",
                                (
                                    f"HTTP {follow_up['status']} -> {follow_up_display_url}"
                                    if follow_up and follow_up["status"] is not None
                                    else "HTTPS follow-up failed"
                                )
                                if follow_up
                                else "No follow-up call",
                            ),
                        ]
                    ),
                    "curl": build_curl_command(target_url, req_headers),
                    "steps": [
                        {
                            "title": "Initial HTTP Request",
                            "command": build_curl_command(target_url, req_headers),
                            "response": {
                                "status": response_status,
                                "headers": response["headers"],
                                "body": response["body"],
                            },
                        },
                        *(
                            [
                                {
                                    "title": "Follow-Up HTTPS Request",
                                    "command": build_curl_command(
                                        follow_up_display_url or follow_up_url or "",
                                        {"Accept": "application/json", "x-request-id": req_headers["x-request-id"]},
                                    ),
                                    "response": {
                                        "status": follow_up["status"],
                                        "headers": follow_up["headers"],
                                        "body": follow_up["body"],
                                    },
                                }
                            ]
                            if follow_up
                            else []
                        ),
                    ],
                    "response": {
                        "status": response_status,
                        "headers": response["headers"],
                        "body": response["body"],
                        "followUp": (
                            {
                                "url": follow_up_url,
                                "status": follow_up["status"],
                                "headers": follow_up["headers"],
                                "body": follow_up["body"],
                            }
                            if follow_up
                            else None
                        ),
                    },
                },
                "topology": {
                    "labels": {
                        "client": ("Client", "HTTP Caller", "plain HTTP attempt"),
                        "kong": ("Gateway", "Kong Data Plane", "transport security policy"),
                        "east": (
                            "Protected API",
                            "Orders API",
                            "Reached over HTTPS" if follow_up and follow_up["status"] == 200 else "Not reached",
                        ),
                        "west": ("TLS Policy", "HTTPS Enforcement", "blocked" if blocked else "redirected"),
                    },
                    "nodes": {
                        "kong": "error" if blocked else "active",
                        "east": "active" if follow_up and follow_up["status"] == 200 else None,
                        "west": "active",
                    },
                    "connectors": {
                        "clientKong": "active",
                        "kongEast": "active" if follow_up and follow_up["status"] == 200 else None,
                        "kongWest": "active",
                    },
                    "statusKong": "Kong Blocked HTTP" if blocked else "Kong Redirected To HTTPS",
                    "statusKongClass": "error" if blocked else "success",
                    "statusRoute": route_status,
                    "statusRouteClass": "error" if blocked else "success",
                },
                "architecture": scene["architecture"],
            }
        )

    def handle_run_versioned_routing(self):
        scene = SCENES["api-lifecycle-versioned-routing"]
        body = self.read_json()
        mode = body.get("mode", "path")
        version = body.get("version", "v1")
        config = VERSION_ROUTING_CASES.get(f"{mode}:{version}", VERSION_ROUTING_CASES["path:v1"])
        target_url = f"{KONG_PROXY_URL}{config['path']}"
        req_headers = {"x-request-id": str(uuid.uuid4()), **config["headers"]}
        response = request_through_kong(target_url, req_headers)
        response_status = response["status"]
        response_body = response["body"] if isinstance(response["body"], dict) else {}
        selected_service = response_body.get("service")
        selected_version = response_body.get("api_version")
        current_label = "v1" if config["version"] == "v1" else "v2"

        expected_outcome = (
            f"Kong should route the {mode}-based {current_label} request to the {current_label} upstream service."
        )

        self.respond_json(
            {
                "scene": scene["id"],
                "sceneDetails": scene,
                "requestPreview": [
                    ("Method", "GET"),
                    ("Routing Mode", mode),
                    ("Path", config["path"]),
                    ("Version", current_label),
                ],
                "expectedOutcome": expected_outcome,
                "result": {
                    "status": response_status,
                    "routeMatched": config["route"],
                    "kongServiceMatched": config["service"],
                    "selectedService": selected_service,
                    "selectedVersion": selected_version,
                    "responseBody": response["body"],
                    "responseHeaders": response["headers"],
                },
                "consoleView": {
                    "request": {
                        "method": "GET",
                        "endpoint": config["path"],
                        "headers": req_headers,
                        "body": None,
                    },
                    "response": {
                        "status": response_status,
                        "headers": response["headers"],
                        "body": response["body"],
                    },
                },
                "detailView": {
                    "entities": normalize_detail_entities(
                        [
                            ("Kong Route", config["route"]),
                            ("Kong Service", config["service"]),
                            ("Routing Mode", mode),
                            ("Version", current_label),
                            ("Actual Service Name", selected_service or "No upstream call"),
                        ]
                    ),
                    "curl": build_curl_command(target_url, req_headers),
                    "response": {
                        "status": response_status,
                        "headers": response["headers"],
                        "body": response["body"],
                    },
                },
                "topology": {
                    "labels": {
                        "client": ("Client", "Versioned Caller", f"{mode} routing"),
                        "kong": ("Gateway", "Kong Data Plane", "version-aware routing"),
                        "east": ("API Version", "Orders API v1", "deprecated but active"),
                        "west": ("API Version", "Orders API v2", "current release"),
                    },
                    "nodes": {
                        "kong": "active" if response_status == 200 else "error",
                        "east": "active" if selected_version == "v1" else None,
                        "west": "active" if selected_version == "v2" else None,
                    },
                    "connectors": {
                        "clientKong": "active",
                        "kongEast": "active" if selected_version == "v1" else None,
                        "kongWest": "active" if selected_version == "v2" else None,
                    },
                    "statusKong": "Kong Routed Versioned Request" if response_status == 200 else "Kong Routing Failure",
                    "statusKongClass": "success" if response_status == 200 else "error",
                    "statusRoute": f"Matched {config['route']}",
                    "statusRouteClass": "success" if response_status == 200 else "error",
                },
                "architecture": scene["architecture"],
            }
        )

    def handle_run_canary(self):
        scene = SCENES["api-lifecycle-canary-migration"]
        body = self.read_json()
        scenario = body.get("scenario", "40-rollout")
        consumer = body.get("consumer", "consumer-pilot")
        override = body.get("override", "always")
        rollout_reset_error = None
        rollout_started_at = None

        scenario_map = {
            "40-rollout": {
                "path": "/orders/canary/40",
                "route": "route-orders-canary-40",
                "description": "40 percent rollout from v1 to v2",
            },
            "time-based": {
                "path": "/orders/canary/time",
                "route": "route-orders-canary-time",
                "description": "time-based rollout over 2 minutes",
            },
            "header-based": {
                "path": "/orders/canary/header",
                "route": "route-orders-canary-header",
                "description": "header override",
            },
            "consumer-based": {
                "path": "/orders/canary/consumer",
                "route": "route-orders-canary-consumer",
                "description": "consumer-based canary",
            },
        }
        config = scenario_map.get(scenario, scenario_map["40-rollout"])
        if scenario == "time-based":
            global CANARY_TIME_ROLLOUT_STARTED_AT, CANARY_TIME_USE_FALLBACK
            if CANARY_TIME_USE_FALLBACK:
                now = int(time.time())
                if (
                    CANARY_TIME_ROLLOUT_STARTED_AT is None
                    or now - CANARY_TIME_ROLLOUT_STARTED_AT >= CANARY_TIME_ROLLOUT_DURATION_SECONDS
                ):
                    CANARY_TIME_ROLLOUT_STARTED_AT = now
                    with CANARY_COUNTERS_LOCK:
                        CANARY_COUNTERS["time-based"] = {"orders-v1": 0, "orders-v2": 0}
                rollout_started_at = CANARY_TIME_ROLLOUT_STARTED_AT
                rollout_reset_error = "Fallback rollout mode active because native Konnect canary reset is unavailable."
            else:
                try:
                    rollout_started_at = ensure_time_based_rollout_window()
                except RuntimeError as exc:
                    rollout_reset_error = str(exc)
                    CANARY_TIME_USE_FALLBACK = True
                    now = int(time.time())
                    if (
                        CANARY_TIME_ROLLOUT_STARTED_AT is None
                        or now - CANARY_TIME_ROLLOUT_STARTED_AT >= CANARY_TIME_ROLLOUT_DURATION_SECONDS
                    ):
                        CANARY_TIME_ROLLOUT_STARTED_AT = now
                        with CANARY_COUNTERS_LOCK:
                            CANARY_COUNTERS["time-based"] = {"orders-v1": 0, "orders-v2": 0}
                    rollout_started_at = CANARY_TIME_ROLLOUT_STARTED_AT
        req_headers = {"Accept": "application/json", "x-request-id": str(uuid.uuid4())}
        if scenario == "header-based":
            req_headers["x-canary-version"] = override
        if scenario == "consumer-based":
            req_headers["apikey"] = CANARY_CONSUMER_KEYS.get(consumer, CANARY_CONSUMER_KEYS["consumer-pilot"])
            req_headers["x-canary-version"] = "always" if consumer == "consumer-pilot" else "never"

        effective_percentage = None
        fallback_route = None
        bucket_position = None
        bucket_slots = None
        if scenario == "time-based" and rollout_reset_error and rollout_started_at:
            global CANARY_TIME_REQUEST_INDEX
            elapsed = max(0, int(time.time()) - rollout_started_at)
            current_step = min(20, elapsed // 6)
            effective_percentage = min(100, current_step * 5)
            bucket_slots = current_step
            bucket_position = CANARY_TIME_REQUEST_INDEX % 20
            CANARY_TIME_REQUEST_INDEX += 1
            fallback_route = {
                "path": "/api/v2/orders" if bucket_position < bucket_slots else "/api/v1/orders",
                "route": "route-orders-version-path-v2" if bucket_position < bucket_slots else "route-orders-version-path-v1",
            }

        target_url = f"{KONG_PROXY_URL}{(fallback_route or config)['path']}"
        response = request_through_kong(target_url, req_headers)
        response_status = response["status"]
        response_body = response["body"] if isinstance(response["body"], dict) else {}
        selected_version = response_body.get("api_version")
        selected_service = response_body.get("service")
        counters = record_canary_counter(scenario, selected_service) or {}
        v1_count = counters.get("orders-v1", 0)
        v2_count = counters.get("orders-v2", 0)
        if scenario == "header-based":
            expected_outcome = (
                "Header override should force v2 when x-canary-version is always and force v1 when it is never."
            )
        elif scenario == "consumer-based":
            expected_outcome = (
                "consumer-pilot should route to v2 while consumer-standard-lifecycle remains on v1."
            )
        elif scenario == "time-based":
            expected_outcome = (
                "Kong should gradually shift traffic from v1 to v2 across the configured 2-minute rollout window. "
                "With duration=120s and steps=20, the rollout advances in 5% increments every 6 seconds."
            )
        else:
            expected_outcome = "Kong should split traffic so about 40 percent of requests reach v2 while the rest stay on v1."

        actual_route = (fallback_route or config)["route"]
        plugin_entities = ["canary on " + actual_route]
        if scenario == "consumer-based":
            plugin_entities.insert(0, "key-auth on route-orders-canary-consumer")
            plugin_entities.insert(1, "acl on route-orders-canary-consumer")

        self.respond_json(
            {
                "scene": scene["id"],
                "sceneDetails": scene,
                "requestPreview": [
                    ("Method", "GET"),
                    ("Path", (fallback_route or config)["path"]),
                    ("Scenario", scenario.replace("-", " ")),
                    (
                        "Input",
                        f"x-canary-version: {override}"
                        if scenario == "header-based"
                        else f"{consumer} ({req_headers.get('x-canary-version', 'none')})"
                        if scenario == "consumer-based"
                        else f"effective canary {effective_percentage}%"
                        if scenario == "time-based" and effective_percentage is not None
                        else config["description"],
                    ),
                    (
                        "Observed Split",
                        f"orders-v1={v1_count}, orders-v2={v2_count}"
                        if scenario in {"40-rollout", "time-based"}
                        else "n/a",
                    ),
                ],
                "expectedOutcome": expected_outcome,
                "result": {
                    "status": response_status,
                    "routeMatched": actual_route,
                    "kongServiceMatched": "svc-orders-canary-primary",
                    "pluginApplied": ", ".join(plugin_entities),
                    "selectedService": selected_service,
                    "selectedVersion": selected_version,
                    "responseBody": response["body"],
                    "responseHeaders": response["headers"],
                    "scenario": scenario,
                    "consumer": consumer if scenario == "consumer-based" else None,
                    "override": override if scenario == "header-based" else None,
                    "serviceCounters": counters if scenario in {"40-rollout", "time-based"} else None,
                    "rolloutStartedAt": rollout_started_at,
                    "rolloutResetError": rollout_reset_error,
                    "effectivePercentage": effective_percentage,
                    "fallbackRoute": fallback_route["route"] if fallback_route else None,
                    "bucketPosition": bucket_position,
                    "bucketSlots": bucket_slots,
                },
                "consoleView": {
                    "request": {
                        "method": "GET",
                        "endpoint": (fallback_route or config)["path"],
                        "headers": req_headers,
                        "body": None,
                    },
                    "response": {
                        "status": response_status,
                        "headers": response["headers"],
                        "body": response["body"],
                    },
                },
                "detailView": {
                    "entities": normalize_detail_entities(
                        [
                            ("Kong Route", actual_route),
                            ("Primary Service", "svc-orders-canary-primary"),
                            ("Kong Plugin", ", ".join(plugin_entities)),
                            ("Selected Version", selected_version or "None"),
                            ("Actual Service Name", selected_service or "No upstream call"),
                            (
                                "Consumer Override",
                                req_headers.get("x-canary-version", "n/a") if scenario == "consumer-based" else "n/a",
                            ),
                            (
                                "Observed Split",
                                f"orders-v1={v1_count}, orders-v2={v2_count}"
                                if scenario in {"40-rollout", "time-based"}
                                else "n/a",
                            ),
                            (
                                "Time-Based Window Start",
                                time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(rollout_started_at))
                                if rollout_started_at
                                else "n/a",
                            ),
                            (
                                "Effective Canary Percentage",
                                f"{effective_percentage}%"
                                if effective_percentage is not None
                                else "n/a",
                            ),
                            (
                                "Traffic Bucket",
                                f"slot {bucket_position + 1}/20, canary slots {bucket_slots}/20"
                                if bucket_position is not None and bucket_slots is not None
                                else "n/a",
                            ),
                            ("Fallback Route", fallback_route["route"] if fallback_route else "none"),
                            ("Rollout Reset Error", rollout_reset_error or "none"),
                        ]
                    ),
                    "curl": build_curl_command(target_url, req_headers),
                    "steps": [
                        {
                            "title": "Canary Request",
                            "command": build_curl_command(target_url, req_headers),
                            "response": {
                                "status": response_status,
                                "headers": response["headers"],
                                "body": response["body"],
                                "service_counters": counters if scenario in {"40-rollout", "time-based"} else None,
                                "rollout_started_at": (
                                    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(rollout_started_at))
                                    if rollout_started_at
                                    else None
                                ),
                                "traffic_bucket": (
                                    {
                                        "slot": bucket_position + 1,
                                        "total_slots": 20,
                                        "canary_slots": bucket_slots,
                                    }
                                    if bucket_position is not None and bucket_slots is not None
                                    else None
                                ),
                                "rollout_reset_error": rollout_reset_error,
                            },
                        }
                    ],
                    "response": {
                        "status": response_status,
                        "headers": response["headers"],
                        "body": response["body"],
                    },
                },
                "topology": {
                    "labels": {
                        "client": ("Client", "Migration Caller", scenario.replace("-", " ")),
                        "kong": ("Gateway", "Kong Data Plane", "Canary Release plugin"),
                        "east": (
                            "Primary",
                            "Orders API v1",
                            (
                                f"stable baseline, count {v1_count}"
                                if scenario in {"40-rollout", "time-based"}
                                else "stable baseline"
                            ),
                        ),
                        "west": (
                            "Canary",
                            "Orders API v2",
                            (
                                f"migration target, count {v2_count}"
                                if scenario in {"40-rollout", "time-based"}
                                else "migration target"
                            ),
                        ),
                    },
                    "nodes": {
                        "kong": "active" if response_status == 200 else "error",
                        "east": "active" if selected_version == "v1" else None,
                        "west": "active" if selected_version == "v2" else None,
                    },
                    "connectors": {
                        "clientKong": "active",
                        "kongEast": "active" if selected_version == "v1" else None,
                        "kongWest": "active" if selected_version == "v2" else None,
                    },
                    "statusKong": "Kong Applied Canary Policy" if response_status == 200 else "Kong Canary Failure",
                    "statusKongClass": "success" if response_status == 200 else "error",
                    "statusRoute": f"Selected {selected_version or 'unknown'}",
                    "statusRouteClass": "success" if response_status == 200 else "error",
                },
                "architecture": scene["architecture"],
            }
        )

    def handle_run_deprecation(self):
        scene = SCENES["api-lifecycle-deprecation"]
        body = self.read_json()
        case = body.get("case", "deprecated-v1")
        config = DEPRECATION_CASES.get(case, DEPRECATION_CASES["deprecated-v1"])
        target_url = f"{KONG_PROXY_URL}{config['path']}"
        req_headers = {"Accept": "application/json", "x-request-id": str(uuid.uuid4())}
        response = request_through_kong(target_url, req_headers)
        response_status = response["status"]
        response_body = response["body"] if isinstance(response["body"], dict) else {}
        selected_version = response_body.get("api_version")
        selected_service = response_body.get("service")

        expected_outcome = (
            "Deprecated v1 should still work and return deprecation, sunset, and successor-version headers."
            if case == "deprecated-v1"
            else "Current v2 should return a normal success response with no deprecation signaling."
            if case == "current-v2"
            else "Sunset enforcement should block the old version before the upstream is reached."
        )

        self.respond_json(
            {
                "scene": scene["id"],
                "sceneDetails": scene,
                "requestPreview": [
                    ("Method", "GET"),
                    ("Path", config["path"]),
                    ("Deprecation Case", config["label"]),
                    ("Policy", "headers" if case != "sunset-enforced" else "sunset enforcement"),
                ],
                "expectedOutcome": expected_outcome,
                "result": {
                    "status": response_status,
                    "routeMatched": config["route"],
                    "kongServiceMatched": config["service"],
                    "pluginApplied": (
                        "response-transformer on route-orders-deprecation-v1"
                        if case == "deprecated-v1"
                        else "request-termination on route-orders-deprecation-sunset"
                        if case == "sunset-enforced"
                        else "none"
                    ),
                    "selectedService": selected_service,
                    "selectedVersion": selected_version,
                    "responseBody": response["body"],
                    "responseHeaders": response["headers"],
                },
                "consoleView": {
                    "request": {
                        "method": "GET",
                        "endpoint": config["path"],
                        "headers": req_headers,
                        "body": None,
                    },
                    "response": {
                        "status": response_status,
                        "headers": response["headers"],
                        "body": response["body"],
                    },
                },
                "detailView": {
                    "entities": normalize_detail_entities(
                        [
                            ("Kong Route", config["route"]),
                            ("Kong Service", config["service"]),
                            (
                                "Kong Plugin",
                                "response-transformer on route-orders-deprecation-v1"
                                if case == "deprecated-v1"
                                else "request-termination on route-orders-deprecation-sunset"
                                if case == "sunset-enforced"
                                else "None",
                            ),
                            ("Selected Version", selected_version or "No upstream call"),
                            ("Actual Service Name", selected_service or "No upstream call"),
                        ]
                    ),
                    "curl": build_curl_command(target_url, req_headers),
                    "response": {
                        "status": response_status,
                        "headers": response["headers"],
                        "body": response["body"],
                    },
                },
                "topology": {
                    "labels": {
                        "client": ("Client", "Lifecycle Caller", config["label"]),
                        "kong": ("Gateway", "Kong Data Plane", "deprecation and sunset policy"),
                        "east": ("Deprecated", "Orders API v1", "deprecated lifecycle"),
                        "west": ("Current", "Orders API v2", "preferred successor"),
                    },
                    "nodes": {
                        "kong": "active" if response_status < 400 else "error",
                        "east": "active" if case == "deprecated-v1" and response_status == 200 else None,
                        "west": "active" if case == "current-v2" and response_status == 200 else None,
                    },
                    "connectors": {
                        "clientKong": "active",
                        "kongEast": "active" if case == "deprecated-v1" and response_status == 200 else None,
                        "kongWest": "active" if case == "current-v2" and response_status == 200 else None,
                    },
                    "statusKong": "Kong Applied Lifecycle Policy" if response_status < 400 else "Kong Enforced Sunset",
                    "statusKongClass": "success" if response_status < 400 else "error",
                    "statusRoute": config["label"],
                    "statusRouteClass": "success" if response_status < 400 else "error",
                },
                "architecture": scene["architecture"],
            }
        )

    def serve_static(self, head_only=False):
        if self.path == "/":
            candidate = STATIC_DIR / "index.html"
        elif self.path == "/favicon.ico":
            candidate = IMG_DIR / "image.png"
        elif self.path.startswith("/img/"):
            candidate = IMG_DIR / Path(self.path).name
        else:
            candidate = STATIC_DIR / self.path.removeprefix("/static/")
        if not candidate.exists() or not candidate.is_file():
            self.respond_json({"error": "Static asset not found"}, status=HTTPStatus.NOT_FOUND)
            return

        if candidate.suffix == ".html":
            content_type = "text/html; charset=utf-8"
        elif candidate.suffix == ".css":
            content_type = "text/css; charset=utf-8"
        elif candidate.suffix == ".js":
            content_type = "application/javascript; charset=utf-8"
        elif candidate.suffix == ".svg":
            content_type = "image/svg+xml"
        elif candidate.suffix == ".png":
            content_type = "image/png"
        else:
            content_type = "application/octet-stream"

        raw = candidate.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        if not head_only:
            self.wfile.write(raw)

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8") if length else "{}"
        return json.loads(raw or "{}")

    def respond_json(self, payload, status=HTTPStatus.OK):
        payload = enrich_payload_with_trace(payload)
        raw = json_bytes(payload)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, fmt, *args):
        print(json.dumps({"client": self.address_string(), "message": fmt % args}))


def main():
    host = os.environ.get("DEMO_HOST", "0.0.0.0")
    port = int(os.environ.get("DEMO_PORT", "8080"))
    server = ThreadingHTTPServer((host, port), DemoHandler)
    print(json.dumps({"message": "demo UI ready", "host": host, "port": port}))
    server.serve_forever()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


DEMO_SERVICE_NAMES = {
    "svc-orders-header-east",
    "svc-orders-header-west",
    "svc-orders-header-missing-region",
    "svc-orders-rate-anonymous",
    "svc-orders-rate-consumer",
    "svc-orders-resilience-weighted",
    "svc-orders-circuit-breaker",
    "svc-orders-auth-azure",
    "svc-orders-auth0-dpop",
    "svc-orders-auth-keycloak",
    "svc-orders-ip-restriction",
    "svc-orders-schema-validation",
    "svc-orders-request-size",
    "svc-orders-payload-crypto",
    "svc-orders-injection-protection",
    "svc-orders-version-v1",
    "svc-orders-version-v2",
    "svc-orders-canary-primary",
    "svc-orders-deprecation-v1",
    "svc-orders-deprecation-v2",
    "svc-orders-transport-security",
    "svc-orders-metering",
    "svc-datakit-fallback",
    "svc-datakit-combine",
    "svc-datakit-cache",
}

DEMO_ROUTE_NAMES = {
    "route-orders-header-east",
    "route-orders-header-west",
    "route-orders-header-catchall",
    "route-orders-rate-anonymous",
    "route-orders-rate-consumer",
    "route-orders-resilience-weighted",
    "route-orders-circuit-breaker",
    "route-orders-auth-azure",
    "route-orders-auth0-dpop",
    "route-orders-auth-keycloak",
    "route-orders-ip-restriction",
    "route-orders-schema-validation",
    "route-orders-request-size",
    "route-orders-payload-crypto",
    "route-orders-injection-query",
    "route-orders-injection-body",
    "route-orders-injection-headers",
    "route-orders-version-path-v1",
    "route-orders-version-path-v2",
    "route-orders-version-header-v1",
    "route-orders-version-header-v2",
    "route-orders-canary-40",
    "route-orders-canary-time",
    "route-orders-canary-header",
    "route-orders-canary-consumer",
    "route-orders-deprecation-v1",
    "route-orders-deprecation-v2",
    "route-orders-deprecation-sunset",
    "route-orders-http-blocked",
    "route-orders-http-redirect",
    "route-orders-metering-consumer",
    "route-datakit-fallback",
    "route-datakit-combine",
    "route-datakit-cache",
}

DEMO_UPSTREAM_NAMES = {
    "upstream-orders-weighted",
    "upstream-orders-circuit-breaker",
}

DEMO_CUSTOM_PLUGIN_SCHEMA_NAMES = {
    "payload-crypto-demo",
}

DEMO_CONSUMER_USERNAMES = {
    "consumer-gold",
    "consumer-standard",
    "azure-ad-consumer-1",
    "azure-ad-consumer-2",
    "auth0-dpop-client",
    "keycloak-consumer-1",
    "keycloak-consumer-2",
    "consumer-pilot",
    "consumer-standard-lifecycle",
    "demo-bank-1",
    "demo-bank-2",
}

DEMO_CONSUMER_CUSTOM_IDS = {
    "consumer-gold",
    "consumer-standard",
    "consumer-1",
    "consumer-2",
    "consumer-pilot",
    "consumer-standard-lifecycle",
    "demo-bank-1",
    "demo-bank-2",
}


def env_required(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise SystemExit(f"{name} is required")
    return value


def request(method: str, path: str) -> dict | list | None:
    token = env_required("KONNECT_TOKEN")
    server = os.getenv("KONNECT_SERVER_URL", "https://us.api.konghq.com").rstrip("/")
    cp_id = env_required("KONNECT_CP_ID")
    url = f"{server}/v2/control-planes/{cp_id}/core-entities/{path.lstrip('/')}"
    req = urllib.request.Request(
        url,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            body = response.read().decode()
            return json.loads(body) if body else None
    except urllib.error.HTTPError as exc:
        body = exc.read().decode()
        raise SystemExit(f"{method} {url} failed: {exc.code} {body}") from exc


def list_entities(entity: str) -> list[dict]:
    payload = request("GET", entity)
    if not isinstance(payload, dict):
        return []
    data = payload.get("data", [])
    return data if isinstance(data, list) else []


def delete_entity(entity: str, entity_id: str) -> None:
    request("DELETE", f"{entity}/{entity_id}")


def is_demo_plugin(plugin: dict) -> bool:
    name = plugin.get("name")
    if name not in {"post-function", "opentelemetry"}:
        return False
    return not any(plugin.get(scope) for scope in ("service", "route", "consumer", "consumer_group"))


def cleanup() -> int:
    deleted = 0

    for plugin in list_entities("plugins"):
        if is_demo_plugin(plugin):
            delete_entity("plugins", plugin["id"])
            deleted += 1

    for schema_name in DEMO_CUSTOM_PLUGIN_SCHEMA_NAMES:
        try:
            delete_entity("plugin-schemas", schema_name)
            deleted += 1
        except SystemExit as exc:
            if " 404 " not in str(exc):
                raise

    for route in list_entities("routes"):
        if route.get("name") in DEMO_ROUTE_NAMES:
            delete_entity("routes", route["id"])
            deleted += 1

    for service in list_entities("services"):
        if service.get("name") in DEMO_SERVICE_NAMES:
            delete_entity("services", service["id"])
            deleted += 1

    for upstream in list_entities("upstreams"):
        if upstream.get("name") in DEMO_UPSTREAM_NAMES:
            delete_entity("upstreams", upstream["id"])
            deleted += 1

    for consumer in list_entities("consumers"):
        if (
            consumer.get("username") in DEMO_CONSUMER_USERNAMES
            or consumer.get("custom_id") in DEMO_CONSUMER_CUSTOM_IDS
        ):
            delete_entity("consumers", consumer["id"])
            deleted += 1

    print(json.dumps({"deleted": deleted}))
    return 0


if __name__ == "__main__":
    sys.exit(cleanup())

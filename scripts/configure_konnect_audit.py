import json
import os
import socket
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse


ROOT_DIR = Path(__file__).resolve().parents[1]
RUNTIME_DIR = ROOT_DIR / ".runtime"
STATE_FILE = RUNTIME_DIR / "konnect_audit_state.json"
DESTINATION_NAME_PREFIX = "konnect-api-demo-audit"


def require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise SystemExit(f"{name} must be set")
    return value


def log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def api_json(method: str, url: str, token: str, payload: dict | None = None):
    request = urllib.request.Request(
        url,
        data=None if payload is None else json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method=method,
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        body = response.read().decode("utf-8")
        return json.loads(body) if body else {}


def delete_resource(url: str, token: str):
    request = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"}, method="DELETE")
    with urllib.request.urlopen(request, timeout=20):
        return


def derive_regional_api_base(default_base: str) -> str:
    cluster_server = os.environ.get("KONNECT_CLUSTER_SERVER_NAME", "")
    parts = cluster_server.split(".")
    if len(parts) >= 3:
        region = parts[1]
        if region:
            return f"https://{region}.api.konghq.com"
    return default_base


def list_destinations(global_api_base: str, token: str) -> list[dict]:
    destinations = api_json("GET", f"{global_api_base}/v3/audit-log-destinations", token)
    return destinations.get("data") or destinations.get("items") or destinations.get("results") or []


def is_demo_destination(destination: dict) -> bool:
    return str(destination.get("name", "")).startswith(DESTINATION_NAME_PREFIX)


def destination_name_for_public_url(public_url: str) -> str:
    hostname = urlparse(public_url).hostname or "unknown"
    slug = hostname.split(".")[0].lower().replace("_", "-")
    host = socket.gethostname().lower().replace("_", "-")
    return f"{DESTINATION_NAME_PREFIX}-{host}-{slug}"


def create_destination(global_api_base: str, token: str, payload: dict) -> dict:
    return api_json("POST", f"{global_api_base}/v3/audit-log-destinations", token, payload)


def create_destination_with_fallback_name(
    global_api_base: str,
    token: str,
    *,
    base_name: str,
    payload: dict,
) -> tuple[dict, str]:
    for attempt in range(3):
        name = base_name if attempt == 0 else f"{base_name}-{int(time.time())}"
        payload = dict(payload)
        payload["name"] = name
        try:
            return create_destination(global_api_base, token, payload), name
        except urllib.error.HTTPError as exc:
            if exc.code != 409 or attempt == 2:
                raise
            log(f"Audit destination name conflict for {name}; retrying with a new suffix")
    raise RuntimeError("unreachable")


def attach_audit_webhook(regional_api_base: str, token: str, destination_id: str) -> None:
    api_json(
        "PATCH",
        f"{regional_api_base}/v3/audit-log-webhook",
        token,
        {
            "audit_log_destination_id": destination_id,
            "enabled": True,
        },
    )


def delete_stale_demo_destinations(global_api_base: str, token: str, keep_destination_id: str) -> None:
    for destination in list_destinations(global_api_base, token):
        if not is_demo_destination(destination):
            continue
        destination_id = destination.get("id")
        if not destination_id or destination_id == keep_destination_id:
            continue
        try:
            delete_resource(f"{global_api_base}/v3/audit-log-destinations/{destination_id}", token)
            log(f"Deleted stale audit destination {destination.get('name')} ({destination_id})")
        except urllib.error.HTTPError as exc:
            log(f"Could not delete stale audit destination {destination_id}: {exc}")


def verify_destination_endpoint(global_api_base: str, token: str, destination_id: str, expected_endpoint: str) -> None:
    destination = next(
        (item for item in list_destinations(global_api_base, token) if item.get("id") == destination_id),
        None,
    )
    if destination is None:
        raise SystemExit(f"Configured audit destination {destination_id} was not found after create")
    actual_endpoint = destination.get("endpoint")
    if actual_endpoint != expected_endpoint:
        raise SystemExit(
            f"Konnect audit destination endpoint mismatch: expected {expected_endpoint}, got {actual_endpoint}"
        )


def main():
    token = require_env("KONNECT_TOKEN")
    public_url = require_env("KONNECT_AUDIT_PUBLIC_URL")
    shared_secret = require_env("KONNECT_AUDIT_SHARED_SECRET")
    global_api_base = os.environ.get("KONNECT_GLOBAL_API_BASE_URL", "https://global.api.konghq.com").rstrip("/")
    regional_api_base = derive_regional_api_base(
        os.environ.get("KONNECT_REGIONAL_API_BASE_URL", "https://us.api.konghq.com").rstrip("/")
    )
    endpoint = public_url.rstrip("/") + "/konnect/audit"
    destination_name = destination_name_for_public_url(public_url)

    RUNTIME_DIR.mkdir(exist_ok=True)

    previous_webhook = {}
    try:
        previous_webhook = api_json("GET", f"{regional_api_base}/v3/audit-log-webhook", token)
    except urllib.error.HTTPError:
        previous_webhook = {}

    destination_payload = {
        "endpoint": endpoint,
        "authorization": shared_secret,
        "log_format": "json",
        "name": destination_name,
    }
    created_destination, destination_name = create_destination_with_fallback_name(
        global_api_base,
        token,
        base_name=destination_name,
        payload=destination_payload,
    )
    destination_id = created_destination["id"]

    attach_audit_webhook(regional_api_base, token, destination_id)
    delete_stale_demo_destinations(global_api_base, token, destination_id)
    verify_destination_endpoint(global_api_base, token, destination_id, endpoint)

    STATE_FILE.write_text(
        json.dumps(
            {
                "destination_id": destination_id,
                "destination_name": destination_name,
                "endpoint": endpoint,
                "previous_webhook": previous_webhook,
                "regional_api_base": regional_api_base,
                "global_api_base": global_api_base,
            },
            indent=2,
        )
    )

    print(json.dumps({"destination_id": destination_id, "endpoint": endpoint}, indent=2))


if __name__ == "__main__":
    main()

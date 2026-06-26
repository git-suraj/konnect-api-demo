import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
STATE_FILE = ROOT_DIR / ".runtime" / "konnect_audit_state.json"
DESTINATION_NAME_PREFIX = "konnect-api-demo-audit"


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


def list_destinations(global_api_base: str, token: str) -> list[dict]:
    destinations = api_json("GET", f"{global_api_base}/v3/audit-log-destinations", token)
    return destinations.get("data") or destinations.get("items") or destinations.get("results") or []


def is_demo_destination(destination: dict) -> bool:
    return str(destination.get("name", "")).startswith(DESTINATION_NAME_PREFIX)


def is_demo_destination_id(global_api_base: str, token: str, destination_id: str | None) -> bool:
    if not destination_id:
        return False
    for destination in list_destinations(global_api_base, token):
        if destination.get("id") == destination_id and is_demo_destination(destination):
            return True
    return False


def main():
    token = os.environ.get("KONNECT_TOKEN", "").strip()
    if not token:
        return

    state = {}
    if STATE_FILE.exists():
        state = json.loads(STATE_FILE.read_text())

    previous = state.get("previous_webhook") or {}
    regional_api_base = state.get("regional_api_base", "https://us.api.konghq.com").rstrip("/")
    global_api_base = state.get("global_api_base", "https://global.api.konghq.com").rstrip("/")

    try:
        previous_destination_id = previous.get("audit_log_destination_id")
        if previous and not is_demo_destination_id(global_api_base, token, previous_destination_id):
            payload = {
                "audit_log_destination_id": previous_destination_id,
                "enabled": bool(previous.get("enabled")),
            }
            api_json("PATCH", f"{regional_api_base}/v3/audit-log-webhook", token, payload)
        else:
            api_json(
                "PATCH",
                f"{regional_api_base}/v3/audit-log-webhook",
                token,
                {"enabled": False},
            )
    except urllib.error.HTTPError as exc:
        log(f"Could not restore/disable audit webhook: {exc}")

    for destination in list_destinations(global_api_base, token):
        if not is_demo_destination(destination):
            continue
        destination_id = destination.get("id")
        if not destination_id:
            continue
        try:
            delete_resource(f"{global_api_base}/v3/audit-log-destinations/{destination_id}", token)
            log(f"Deleted audit destination {destination.get('name')} ({destination_id})")
        except urllib.error.HTTPError as exc:
            log(f"Could not delete audit destination {destination_id}: {exc}")

    STATE_FILE.unlink(missing_ok=True)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Upsert the demo Konnect analytics dashboard via the v2 dashboards API."""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
RUNTIME_DIR = ROOT_DIR / ".runtime"
STATE_FILE = RUNTIME_DIR / "konnect_observability_state.json"
DASHBOARD_JSON = ROOT_DIR / "observability" / "konnect" / "dashboards" / "shared-services.json"
DEFAULT_DASHBOARD_NAME = "konnect-api-demo-shared-services"
DEFAULT_SERVER_URL = "https://us.api.konghq.com"
DEFAULT_UI_BASE_URL = "https://cloud.konghq.com/us"
DASHBOARDS_PATH = "/v2/dashboards"


def require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise SystemExit(f"{name} must be set")
    return value


def log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def api_json(method: str, url: str, token: str, payload: dict | None = None) -> dict:
    headers = {
        "Accept": "application/json, application/problem+json",
        "Authorization": f"Bearer {token}",
    }
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=30) as response:
        body = response.read().decode("utf-8")
        return json.loads(body) if body else {}


def list_dashboards(server_url: str, token: str) -> list[dict]:
    url = urllib.parse.urljoin(server_url.rstrip("/") + "/", DASHBOARDS_PATH.lstrip("/"))
    response = api_json("GET", url, token)
    if isinstance(response, dict):
        for key in ("data", "items", "results"):
            items = response.get(key)
            if isinstance(items, list):
                return items
    return response if isinstance(response, list) else []


def find_dashboard_id(existing: list[dict], name: str) -> str | None:
    for item in existing:
        if item.get("name") == name:
            return item.get("id")
    return None


def dashboard_definition(control_plane_id: str) -> dict:
    source = json.loads(DASHBOARD_JSON.read_text(encoding="utf-8"))
    definition = {
        "tiles": source.get("tiles", []),
        "preset_filters": [
            {
                "field": "control_plane",
                "operator": "in",
                "value": [control_plane_id],
            }
        ],
    }
    template_id = source.get("template_id")
    if template_id:
        definition["template_id"] = template_id
    return definition


def build_dashboard_url(ui_base_url: str, dashboard_id: str) -> str:
    return f"{ui_base_url.rstrip('/')}/analytics/dashboards/{dashboard_id}"


def upsert_dashboard(
    *,
    server_url: str,
    token: str,
    name: str,
    definition: dict,
) -> dict:
    existing = list_dashboards(server_url, token)
    dashboard_id = find_dashboard_id(existing, name)
    payload = {"name": name, "definition": definition}
    base = urllib.parse.urljoin(server_url.rstrip("/") + "/", DASHBOARDS_PATH.lstrip("/"))

    if dashboard_id:
        log(f"Updating Konnect dashboard {name} ({dashboard_id})")
        return api_json("PUT", f"{base}/{dashboard_id}", token, payload)

    log(f"Creating Konnect dashboard {name}")
    return api_json("POST", base, token, payload)


def main() -> int:
    token = require_env("KONNECT_TOKEN")
    control_plane_id = require_env("KONNECT_CP_ID")
    server_url = os.environ.get("KONNECT_SERVER_URL", DEFAULT_SERVER_URL).rstrip("/")
    ui_base_url = os.environ.get("KONNECT_UI_BASE_URL", DEFAULT_UI_BASE_URL).rstrip("/")
    dashboard_name = os.environ.get("KONNECT_OBSERVABILITY_DASHBOARD_NAME", DEFAULT_DASHBOARD_NAME).strip()

    if not DASHBOARD_JSON.exists():
        raise SystemExit(f"Dashboard definition not found: {DASHBOARD_JSON}")

    RUNTIME_DIR.mkdir(exist_ok=True)
    definition = dashboard_definition(control_plane_id)
    result = upsert_dashboard(
        server_url=server_url,
        token=token,
        name=dashboard_name,
        definition=definition,
    )
    dashboard_id = result.get("id")
    if not dashboard_id:
        raise SystemExit("Konnect dashboard upsert did not return an id")

    dashboard_url = build_dashboard_url(ui_base_url, dashboard_id)
    STATE_FILE.write_text(
        json.dumps(
            {
                "dashboard_id": dashboard_id,
                "dashboard_name": dashboard_name,
                "dashboard_url": dashboard_url,
                "server_url": server_url,
                "ui_base_url": ui_base_url,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"dashboard_id": dashboard_id, "dashboard_url": dashboard_url}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        log(f"Konnect dashboard API failed ({exc.code}): {body}")
        raise SystemExit(1) from exc

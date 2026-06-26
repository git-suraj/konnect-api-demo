#!/usr/bin/env python3
"""Delete the demo Konnect analytics dashboard."""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
STATE_FILE = ROOT_DIR / ".runtime" / "konnect_observability_state.json"
DEFAULT_DASHBOARD_NAME = "konnect-api-demo-shared-services"
DEFAULT_SERVER_URL = "https://us.api.konghq.com"
DASHBOARDS_PATH = "/v2/dashboards"


def log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def api_json(method: str, url: str, token: str) -> dict:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json, application/problem+json",
            "Authorization": f"Bearer {token}",
        },
        method=method,
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        body = response.read().decode("utf-8")
        return json.loads(body) if body else {}


def delete_resource(url: str, token: str) -> None:
    request = urllib.request.Request(
        url,
        headers={"Authorization": f"Bearer {token}"},
        method="DELETE",
    )
    with urllib.request.urlopen(request, timeout=30):
        return


def list_dashboards(server_url: str, token: str) -> list[dict]:
    url = urllib.parse.urljoin(server_url.rstrip("/") + "/", DASHBOARDS_PATH.lstrip("/"))
    response = api_json("GET", url, token)
    if isinstance(response, dict):
        for key in ("data", "items", "results"):
            items = response.get(key)
            if isinstance(items, list):
                return items
    return response if isinstance(response, list) else []


def main() -> int:
    token = os.environ.get("KONNECT_TOKEN", "").strip()
    if not token:
        return 0

    state = json.loads(STATE_FILE.read_text(encoding="utf-8")) if STATE_FILE.exists() else {}
    server_url = state.get("server_url", os.environ.get("KONNECT_SERVER_URL", DEFAULT_SERVER_URL)).rstrip("/")
    dashboard_name = state.get("dashboard_name", DEFAULT_DASHBOARD_NAME)
    dashboard_id = state.get("dashboard_id")

    if not dashboard_id:
        for item in list_dashboards(server_url, token):
            if item.get("name") == dashboard_name and item.get("id"):
                dashboard_id = item["id"]
                break

    if not dashboard_id:
        log(f"No Konnect dashboard named {dashboard_name} to delete")
        STATE_FILE.unlink(missing_ok=True)
        return 0

    base = urllib.parse.urljoin(server_url.rstrip("/") + "/", DASHBOARDS_PATH.lstrip("/"))
    try:
        delete_resource(f"{base}/{dashboard_id}", token)
        log(f"Deleted Konnect dashboard {dashboard_name} ({dashboard_id})")
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            log(f"Could not delete Konnect dashboard {dashboard_id}: {exc}")
            return 1

    STATE_FILE.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

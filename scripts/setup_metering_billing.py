#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


KONNECT_SERVER_URL = os.environ.get("KONNECT_SERVER_URL", "https://us.api.konghq.com").rstrip("/")
SYSTEM_TOKEN = os.environ.get("KONNECT_SYSTEM_TOKEN", "").strip()
KONG_PROXY_URL = os.environ.get("KONG_PROXY_URL", "http://localhost:8000").rstrip("/")
KONNECT_CP_ID = os.environ.get("KONNECT_CP_ID", "").strip()
TERRAFORM_KONNECT_STATE_PATH = Path(__file__).resolve().parent.parent / "terraform" / "konnect" / "terraform.tfstate"
BOOTSTRAP_READY_TIMEOUT_SECONDS = int(os.environ.get("KONNECT_METERING_BOOTSTRAP_TIMEOUT_SECONDS", "90"))
BOOTSTRAP_READY_POLL_SECONDS = float(os.environ.get("KONNECT_METERING_BOOTSTRAP_POLL_SECONDS", "3"))
MAX_LIST_PAGES = int(os.environ.get("KONNECT_METERING_MAX_LIST_PAGES", "100"))
DELETE_RETRY_ATTEMPTS = int(os.environ.get("KONNECT_METERING_DELETE_RETRY_ATTEMPTS", "10"))
DELETE_RETRY_DELAY_SECONDS = float(os.environ.get("KONNECT_METERING_DELETE_RETRY_DELAY_SECONDS", "2"))
PLAN_SETTLE_TIMEOUT_SECONDS = int(os.environ.get("KONNECT_METERING_PLAN_SETTLE_TIMEOUT_SECONDS", "45"))
PLAN_SETTLE_POLL_SECONDS = float(os.environ.get("KONNECT_METERING_PLAN_SETTLE_POLL_SECONDS", "2"))

DEMO_LABELS = {
    "demo": "konnect_api_demo",
    "managed_by": "repo_automation",
}

METER_SPECS = [
    {
        "key": "demo_api_requests_total",
        "name": "API Requests",
        "description": "Number of API requests",
        "aggregation": "count",
        "event_type": "kong.api_request",
        "dimensions": {
            "control_plane_id": "$.control_plane_id",
            "response_http_status": "$.response_http_status",
            "route_name": "$.route_name",
            "service_name": "$.service_name",
        },
        "labels": DEMO_LABELS,
    },
]

FEATURE_SPECS = [
    {
        "key": "orders_api_request",
        "name": "Demo API Requests Feature Demo Bank",
        "description": "Demo API Requests Feature Demo Bank",
        "meter_key": "demo_api_requests_total",
        "meter_filters": {
            "control_plane_id": {"eq": f"{KONNECT_CP_ID}"},
            "route_name": {"eq": "route-orders-metering-consumer"},
        },
        "labels": DEMO_LABELS,
    },
]

PLAN_SPECS = [
    {
        "key": "demo_api_requests_plan_demo_bank_1",
        "name": "Demo Bank 1 API Requests Plan",
        "currency": "KRW",
        "billing_cadence": "P1M",
        "labels": DEMO_LABELS,
        "pro_rating_enabled": True,
        "phases": [
            {
                "key": "default",
                "name": "Default",
                "rate_cards": [
                    {
                        "key": "orders_api_request",
                        "name": "API Requests at $1/request",
                        "feature_key": "orders_api_request",
                        "billing_cadence": "P1M",
                        "payment_term": "in_arrears",
                        "price": {"type": "unit", "amount": "1"},
                    }
                ],
            }
        ],
    },
    {
        "key": "demo_api_requests_plan_demo_bank_2",
        "name": "Demo Bank 2 API Requests Plan",
        "currency": "USD",
        "billing_cadence": "P1M",
        "labels": DEMO_LABELS,
        "pro_rating_enabled": True,
        "phases": [
            {
                "key": "default",
                "name": "Default",
                "rate_cards": [
                    {
                        "key": "orders_api_request",
                        "name": "API Requests at $2/request",
                        "feature_key": "orders_api_request",
                        "billing_cadence": "P1M",
                        "payment_term": "in_arrears",
                        "price": {"type": "unit", "amount": "2"},
                    }
                ],
            }
        ],
    },
]

CUSTOMER_SPECS = [
    {
        "key": "demo-bank-1",
        "name": "Demo Bank 1",
        "consumer_username": "demo-bank-1",
        "labels": DEMO_LABELS,
        "apikey": "key-demo-bank-1",
        "plan_key": "demo_api_requests_plan_demo_bank_1",
    },
    {
        "key": "demo-bank-2",
        "name": "Demo Bank 2",
        "consumer_username": "demo-bank-2",
        "labels": DEMO_LABELS,
        "apikey": "key-demo-bank-2",
        "plan_key": "demo_api_requests_plan_demo_bank_2",
    },
]


def load_dotenv() -> None:
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


load_dotenv()
KONNECT_SERVER_URL = os.environ.get("KONNECT_SERVER_URL", KONNECT_SERVER_URL).rstrip("/")
SYSTEM_TOKEN = os.environ.get("KONNECT_SYSTEM_TOKEN", SYSTEM_TOKEN).strip()
KONG_PROXY_URL = os.environ.get("KONG_PROXY_URL", KONG_PROXY_URL).rstrip("/")
KONNECT_CP_ID = os.environ.get("KONNECT_CP_ID", KONNECT_CP_ID).strip()


def require_env(name: str, value: str) -> str:
    if not value:
        raise SystemExit(f"{name} is required")
    return value


def api_request(method: str, path: str, payload: dict | None = None, query: dict[str, str] | None = None):
    token = require_env("KONNECT_SYSTEM_TOKEN", SYSTEM_TOKEN)
    url = f"{KONNECT_SERVER_URL}{path}"
    if query:
        url = f"{url}?{urllib.parse.urlencode(query)}"
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            raw = response.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        if exc.code == 404 and method == "GET":
            return {}
        raise RuntimeError(f"{method} {url} failed with {exc.code}: {raw}") from exc


def konnect_control_plane_request(method: str, path: str):
    token = require_env("KONNECT_SYSTEM_TOKEN", SYSTEM_TOKEN)
    control_plane_id = require_env("KONNECT_CP_ID", KONNECT_CP_ID)
    url = f"{KONNECT_SERVER_URL}/v2/control-planes/{control_plane_id}/core-entities{path}"
    req = urllib.request.Request(
        url,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            raw = response.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        if exc.code == 404 and method == "GET":
            return {}
        raise RuntimeError(f"{method} {url} failed with {exc.code}: {raw}") from exc


def resolve_consumer_subject(consumer_username: str) -> str:
    consumer_id = resolve_consumer_id_from_terraform_state(consumer_username)
    if consumer_id:
        return f"consumer:{consumer_id}"

    consumer = konnect_control_plane_request("GET", f"/consumers/{urllib.parse.quote(consumer_username, safe='')}")
    consumer_id = consumer.get("id")
    if not consumer_id:
        raise RuntimeError(
            f"Could not resolve Konnect consumer id for username {consumer_username!r} in control plane {KONNECT_CP_ID!r}."
        )
    return f"consumer:{consumer_id}"


def resolve_consumer_id_from_terraform_state(consumer_username: str) -> str | None:
    if not TERRAFORM_KONNECT_STATE_PATH.exists():
        return None

    try:
        state = json.loads(TERRAFORM_KONNECT_STATE_PATH.read_text())
    except Exception:  # noqa: BLE001
        return None

    resources = state.get("resources") or []
    for resource in resources:
        if resource.get("type") != "konnect_gateway_consumer":
            continue
        for instance in resource.get("instances") or []:
            attributes = instance.get("attributes") or {}
            if attributes.get("username") != consumer_username:
                continue
            consumer_id = attributes.get("id")
            if consumer_id:
                return consumer_id

    return None


def extract_items(payload) -> list[dict]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        return payload.get("items") or payload.get("data") or payload.get("results") or []
    return []


def list_resources(path: str) -> list[dict]:
    items: list[dict] = []
    next_path: str | None = path
    query: dict[str, str] | None = {"page[size]": "100"}
    seen_pages: set[str] = set()
    page_count = 0

    while next_path:
        page_key = next_path if query is None else f"{next_path}?{urllib.parse.urlencode(query)}"
        if page_key in seen_pages:
            raise RuntimeError(f"Pagination loop detected while listing {path}: repeated page {page_key}")
        seen_pages.add(page_key)
        page_count += 1
        if page_count > MAX_LIST_PAGES:
            raise RuntimeError(f"Exceeded {MAX_LIST_PAGES} pages while listing {path}")

        payload = api_request("GET", next_path, query=query)
        items.extend(extract_items(payload))
        query = None
        next_path = ((payload.get("meta") or {}).get("page") or {}).get("next") if isinstance(payload, dict) else None

    return items


def find_by_key(items: list[dict], key: str) -> dict | None:
    return next((item for item in items if item.get("key") == key), None)


def best_effort_delete(path: str) -> str:
    try:
        api_request("DELETE", path)
        return "deleted"
    except Exception as exc:  # noqa: BLE001
        return str(exc)


def best_effort_post(path: str, payload: dict | None = None) -> str:
    try:
        api_request("POST", path, payload)
        return "ok"
    except Exception as exc:  # noqa: BLE001
        return str(exc)


def cancel_subscriptions_for_plan_ids(plan_ids: set[str]) -> None:
    if not plan_ids:
        return
    subscriptions = list_resources("/v3/openmeter/subscriptions")
    for subscription in subscriptions:
        if subscription.get("plan_id") not in plan_ids:
            continue
        if subscription.get("status") in {"inactive", "canceled"}:
            continue
        result = best_effort_post(f"/v3/openmeter/subscriptions/{subscription['id']}/cancel", {"timing": "immediate"})
        if result not in {"ok"} and "inactive not allowed" not in result and "state inactive" not in result:
            raise RuntimeError(f"Failed to cancel subscription {subscription['id']}: {result}")


def wait_for_subscriptions_to_settle(plan_ids: set[str]) -> None:
    deadline = time.time() + PLAN_SETTLE_TIMEOUT_SECONDS
    while time.time() < deadline:
        current = [item for item in list_resources("/v3/openmeter/subscriptions") if item.get("plan_id") in plan_ids]
        blocking = [item for item in current if item.get("status") in {"active", "scheduled", "pending"}]
        if not blocking:
            return
        time.sleep(PLAN_SETTLE_POLL_SECONDS)
    statuses = {item.get("id"): item.get("status") for item in current}
    raise RuntimeError(f"Subscriptions did not settle for plan ids {sorted(plan_ids)}: {statuses}")


def delete_with_retry(path: str) -> None:
    last_error = ""
    for attempt in range(1, DELETE_RETRY_ATTEMPTS + 1):
        try:
            api_request("DELETE", path)
            return
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)
            if attempt == DELETE_RETRY_ATTEMPTS:
                break
            time.sleep(DELETE_RETRY_DELAY_SECONDS)
    raise RuntimeError(f"Failed to delete {path}: {last_error}")


def archive_and_delete_plans(plans: list[dict]) -> None:
    plans.sort(key=lambda item: item.get("version") or 0, reverse=True)
    for plan in plans:
        if plan.get("status") == "active":
            result = best_effort_post(f"/v3/openmeter/plans/{plan['id']}/archive")
            if result != "ok" and "already archived" not in result and "archived" not in result:
                raise RuntimeError(f"Failed to archive plan {plan['id']}: {result}")
        delete_with_retry(f"/v3/openmeter/plans/{plan['id']}")


def plan_references_feature(plan: dict, feature_id: str, feature_key: str | None = None) -> bool:
    for phase in plan.get("phases") or []:
        for rate_card in phase.get("rate_cards") or []:
            if ((rate_card.get("feature") or {}).get("id")) == feature_id:
                return True
            if rate_card.get("feature_id") == feature_id:
                return True
            if feature_key and rate_card.get("key") == feature_key:
                return True
    return False


def describe_plan(plan: dict) -> str:
    return f"{plan.get('key')}@v{plan.get('version')}:{plan.get('status')}"


def replace_feature_after_demo_plan_cleanup(existing_feature_id: str, existing_feature_key: str) -> None:
    plans = [
        plan
        for plan in list_resources("/v3/openmeter/plans")
        if plan_references_feature(plan, existing_feature_id, existing_feature_key)
    ]
    plan_ids = {plan["id"] for plan in plans}
    cancel_subscriptions_for_plan_ids(plan_ids)
    wait_for_subscriptions_to_settle(plan_ids)
    archive_and_delete_plans(plans)
    deadline = time.time() + PLAN_SETTLE_TIMEOUT_SECONDS
    while time.time() < deadline:
        remaining = [
            plan
            for plan in list_resources("/v3/openmeter/plans")
            if plan_references_feature(plan, existing_feature_id, existing_feature_key)
        ]
        if not remaining:
            try:
                delete_with_retry(f"/v3/openmeter/features/{existing_feature_id}")
                return
            except RuntimeError as exc:
                all_plans = list_resources("/v3/openmeter/plans")
                suspected = [
                    plan
                    for plan in all_plans
                    if plan_references_feature(plan, existing_feature_id, existing_feature_key)
                    or plan.get("key") in {spec["key"] for spec in PLAN_SPECS}
                    or plan.get("key") == "demo_api_requests_plan"
                ]
                raise RuntimeError(
                    f"{exc}. Remaining/suspected plans: "
                    + ", ".join(describe_plan(plan) for plan in suspected)
                ) from exc
        time.sleep(PLAN_SETTLE_POLL_SECONDS)
    remaining = [
        plan
        for plan in list_resources("/v3/openmeter/plans")
        if plan_references_feature(plan, existing_feature_id, existing_feature_key)
    ]
    raise RuntimeError(
        "Feature migration blocked because plans still reference feature "
        f"{existing_feature_id}: "
        + ", ".join(describe_plan(plan) for plan in remaining)
    )


def replace_meter_after_feature_cleanup(existing_meter_id: str) -> None:
    features = [feature for feature in list_resources("/v3/openmeter/features") if ((feature.get("meter") or {}).get("id")) == existing_meter_id]
    for feature in features:
        replace_feature_after_demo_plan_cleanup(feature["id"], feature["key"])
    delete_with_retry(f"/v3/openmeter/meters/{existing_meter_id}")


def normalize_meter_spec(spec: dict) -> dict:
    return {
        "name": spec["name"],
        "description": spec.get("description"),
        "labels": spec.get("labels", {}),
        "key": spec["key"],
        "aggregation": spec["aggregation"],
        "event_type": spec["event_type"],
        "value_property": spec.get("value_property"),
        "dimensions": spec.get("dimensions", {}),
    }


def normalize_existing_meter(meter: dict) -> dict:
    return {
        "name": meter.get("name"),
        "description": meter.get("description"),
        "labels": meter.get("labels") or {},
        "key": meter.get("key"),
        "aggregation": meter.get("aggregation"),
        "event_type": meter.get("event_type"),
        "value_property": meter.get("value_property"),
        "dimensions": meter.get("dimensions") or {},
    }


def ensure_meter(spec: dict) -> tuple[dict, str]:
    existing = find_by_key(list_resources("/v3/openmeter/meters"), spec["key"])
    if existing is None:
        created = api_request("POST", "/v3/openmeter/meters", spec)
        return created, "created"

    immutable_keys = ("key", "aggregation", "event_type", "value_property")
    current = normalize_existing_meter(existing)
    desired = normalize_meter_spec(spec)
    for key in immutable_keys:
        if current.get(key) != desired.get(key):
            replace_meter_after_feature_cleanup(existing["id"])
            created = api_request("POST", "/v3/openmeter/meters", spec)
            return created, "recreated"

    update_payload = {
        "name": spec["name"],
        "description": spec.get("description"),
        "labels": spec.get("labels", {}),
        "dimensions": spec.get("dimensions", {}),
    }
    if (
        current["name"] == update_payload["name"]
        and current["description"] == update_payload["description"]
        and current["labels"] == update_payload["labels"]
        and current["dimensions"] == update_payload["dimensions"]
    ):
        return existing, "exists"

    updated = api_request("PUT", f"/v3/openmeter/meters/{existing['id']}", update_payload)
    return updated, "updated"


def ensure_feature(spec: dict, meter_id: str) -> tuple[dict, str]:
    existing = find_by_key(list_resources("/v3/openmeter/features"), spec["key"])
    desired_meter = {"id": meter_id}
    if spec.get("meter_filters"):
        desired_meter["filters"] = spec["meter_filters"]
    desired_description = spec.get("description")
    desired_labels = spec.get("labels", {})
    if existing is None:
        created = api_request(
            "POST",
            "/v3/openmeter/features",
            {
                "name": spec["name"],
                "description": desired_description,
                "key": spec["key"],
                "labels": desired_labels,
                "meter": desired_meter,
            },
        )
        return created, "created"

    current_meter = existing.get("meter") or {}
    current_meter_id = current_meter.get("id") if isinstance(current_meter, dict) else None
    current_meter_filters = current_meter.get("filters") if isinstance(current_meter, dict) else None
    current_labels = existing.get("labels") or {}
    if (
        current_meter_id == meter_id
        and existing.get("name") == spec["name"]
        and existing.get("description") == desired_description
        and current_labels == desired_labels
        and (current_meter_filters or {}) == spec.get("meter_filters", {})
    ):
        return existing, "exists"

    try:
        api_request("DELETE", f"/v3/openmeter/features/{existing['id']}")
    except RuntimeError as exc:
        if "feature is referenced by active plan" not in str(exc):
            raise
        replace_feature_after_demo_plan_cleanup(existing["id"], existing["key"])
    recreated = api_request(
        "POST",
        "/v3/openmeter/features",
        {
            "name": spec["name"],
            "description": desired_description,
            "key": spec["key"],
            "labels": desired_labels,
            "meter": desired_meter,
        },
    )
    return recreated, "recreated"


def build_plan_create_payload(plan_spec: dict, feature_id_by_key: dict[str, str]) -> dict:
    return {
        "name": plan_spec["name"],
        "key": plan_spec["key"],
        "currency": plan_spec["currency"],
        "billing_cadence": plan_spec["billing_cadence"],
        "labels": plan_spec.get("labels", {}),
        "pro_rating_enabled": plan_spec.get("pro_rating_enabled", True),
        "phases": [
            {
                "name": phase["name"],
                "key": phase["key"],
                "rate_cards": [
                    {
                        "name": rate_card["name"],
                        "key": rate_card["key"],
                        "feature": {"id": feature_id_by_key[rate_card["feature_key"]]},
                        "billing_cadence": rate_card.get("billing_cadence"),
                        "price": rate_card["price"],
                        "payment_term": rate_card.get("payment_term", "in_arrears"),
                    }
                    for rate_card in phase["rate_cards"]
                ],
            }
            for phase in plan_spec["phases"]
        ],
    }


def build_plan_update_payload(plan_spec: dict, feature_id_by_key: dict[str, str]) -> dict:
    payload = build_plan_create_payload(plan_spec, feature_id_by_key)
    payload.pop("key", None)
    payload.pop("currency", None)
    payload.pop("billing_cadence", None)
    return payload


def normalize_plan_payload(payload: dict) -> dict:
    return {
        "name": payload["name"],
        "labels": payload.get("labels", {}),
        "pro_rating_enabled": payload.get("pro_rating_enabled", True),
        "phases": [
            {
                "name": phase["name"],
                "key": phase["key"],
                "rate_cards": [
                    {
                        "name": rate_card["name"],
                        "key": rate_card["key"],
                        "feature_id": ((rate_card.get("feature") or {}).get("id")),
                        "billing_cadence": rate_card.get("billing_cadence"),
                        "price": rate_card["price"],
                        "payment_term": rate_card.get("payment_term", "in_arrears"),
                    }
                    for rate_card in phase.get("rate_cards", [])
                ],
            }
            for phase in payload.get("phases", [])
        ],
    }


def normalize_existing_plan(plan: dict) -> dict:
    return {
        "name": plan["name"],
        "labels": plan.get("labels", {}),
        "pro_rating_enabled": plan.get("pro_rating_enabled", True),
        "phases": [
            {
                "name": phase["name"],
                "key": phase["key"],
                "rate_cards": [
                    {
                        "name": rate_card["name"],
                        "key": rate_card["key"],
                        "feature_id": ((rate_card.get("feature") or {}).get("id")),
                        "billing_cadence": rate_card.get("billing_cadence"),
                        "price": rate_card["price"],
                        "payment_term": rate_card.get("payment_term", "in_arrears"),
                    }
                    for rate_card in phase.get("rate_cards", [])
                ],
            }
            for phase in plan.get("phases", [])
        ],
    }


def publish_plan(plan_id: str) -> dict:
    return api_request("POST", f"/v3/openmeter/plans/{plan_id}/publish")


def ensure_plan(plan_spec: dict, feature_id_by_key: dict[str, str]) -> tuple[dict, str]:
    plans = [item for item in list_resources("/v3/openmeter/plans") if item.get("key") == plan_spec["key"]]
    desired_create = build_plan_create_payload(plan_spec, feature_id_by_key)
    desired_update = build_plan_update_payload(plan_spec, feature_id_by_key)
    desired_normalized = normalize_plan_payload(desired_update)

    if not plans:
        created = api_request("POST", "/v3/openmeter/plans", desired_create)
        published = publish_plan(created["id"])
        return published, "created"

    plans.sort(key=lambda item: (item.get("version") or 0, item.get("updated_at") or ""))
    active_plan = next((plan for plan in reversed(plans) if plan.get("status") == "active"), None)

    for plan in plans:
        if plan.get("currency") != plan_spec["currency"] or plan.get("billing_cadence") != plan_spec["billing_cadence"]:
            raise RuntimeError(
                f"Existing plan {plan_spec['key']} has incompatible currency or billing cadence."
            )

    if active_plan and normalize_existing_plan(active_plan) == desired_normalized:
        return active_plan, "exists"

    target_plan = next(
        (plan for plan in reversed(plans) if plan.get("status") in {"draft", "scheduled"}),
        None,
    )
    if target_plan is None:
        created = api_request("POST", "/v3/openmeter/plans", desired_create)
        published = publish_plan(created["id"])
        return published, "created_new_version"

    updated = api_request("PUT", f"/v3/openmeter/plans/{target_plan['id']}", desired_update)
    if updated.get("status") != "active":
        updated = publish_plan(updated["id"])
        return updated, "updated_and_published"
    return updated, "updated"


def ensure_customer(spec: dict) -> tuple[dict, str]:
    existing = find_by_key(list_resources("/v3/openmeter/customers"), spec["key"])
    payload = {
        "name": spec["name"],
        "key": spec["key"],
        "labels": spec.get("labels", {}),
        "usage_attribution": {"subject_keys": [spec["subject"]]},
    }
    if existing is None:
        created = api_request("POST", "/v3/openmeter/customers", payload)
        return created, "created"

    current_subject_keys = (
        existing.get("usageAttribution", {}).get("subjectKeys")
        or existing.get("usage_attribution", {}).get("subject_keys")
        or []
    )
    current_labels = existing.get("labels") or {}
    if (
        existing.get("name") == spec["name"]
        and current_subject_keys == [spec["subject"]]
        and current_labels == spec.get("labels", {})
    ):
        return existing, "exists"

    updated = api_request("PUT", f"/v3/openmeter/customers/{existing['id']}", payload)
    return updated, "updated"


def resolve_subscription_record(payload: dict, *, customer_id: str, desired_plan_id: str) -> dict:
    if isinstance(payload, dict):
        if payload.get("id"):
            return payload
        next_subscription = payload.get("next")
        if isinstance(next_subscription, dict) and next_subscription.get("id"):
            return next_subscription
        current_subscription = payload.get("current")
        if isinstance(current_subscription, dict) and current_subscription.get("id"):
            return current_subscription

    subscriptions = [
        item
        for item in list_resources("/v3/openmeter/subscriptions")
        if item.get("customer_id") == customer_id and item.get("plan_id") == desired_plan_id
    ]
    active_match = next((item for item in subscriptions if item.get("status") in {"active", "scheduled"}), None)
    if active_match is not None:
        return active_match
    if subscriptions:
        return subscriptions[0]
    raise RuntimeError(
        f"Could not resolve subscription for customer_id={customer_id} plan_id={desired_plan_id} from API response."
    )


def ensure_subscription(customer: dict, plan: dict) -> tuple[dict, str]:
    subscriptions = [
        item
        for item in list_resources("/v3/openmeter/subscriptions")
        if item.get("customer_id") == customer["id"]
    ]
    desired_plan_id = plan["id"]

    for subscription in subscriptions:
        if subscription.get("plan_id") == desired_plan_id and subscription.get("status") in {"active", "scheduled"}:
            return subscription, "exists"

    active_other = next(
        (
            subscription
            for subscription in subscriptions
            if subscription.get("status") in {"active", "scheduled"} and subscription.get("plan_id") != desired_plan_id
        ),
        None,
    )
    if active_other is not None:
        changed = api_request(
            "POST",
            f"/v3/openmeter/subscriptions/{active_other['id']}/change",
            {
                "customer": {"id": customer["id"]},
                "plan": {"id": desired_plan_id},
                "timing": "immediate",
                "labels": DEMO_LABELS,
            },
        )
        return resolve_subscription_record(changed, customer_id=customer["id"], desired_plan_id=desired_plan_id), "changed"

    created = api_request(
        "POST",
        "/v3/openmeter/subscriptions",
        {
            "customer": {"id": customer["id"]},
            "plan": {"id": desired_plan_id},
            "labels": DEMO_LABELS,
        },
    )
    return resolve_subscription_record(created, customer_id=customer["id"], desired_plan_id=desired_plan_id), "created"


def emit_bootstrap_requests() -> list[dict]:
    results = []
    for customer in CUSTOMER_SPECS:
        url = f"{KONG_PROXY_URL}/orders/metering/consumer"
        headers = {
            "Accept": "application/json",
            "apikey": customer["apikey"],
            "x-request-id": f"metering-bootstrap-{customer['key']}",
        }
        status = wait_for_bootstrap_route(url, headers)
        results.append({"customer": customer["key"], "url": url, "status": status})
    return results


def issue_request(url: str, headers: dict[str, str]) -> int:
    req = urllib.request.Request(url, method="GET", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            response.read()
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code


def wait_for_bootstrap_route(url: str, headers: dict[str, str]) -> int:
    deadline = time.time() + BOOTSTRAP_READY_TIMEOUT_SECONDS
    last_status = None
    while time.time() < deadline:
        status = issue_request(url, headers)
        last_status = status
        if status == 200:
            return status
        if status not in (404, 503, 504):
            return status
        time.sleep(BOOTSTRAP_READY_POLL_SECONDS)
    return last_status or 0


def main() -> int:
    require_env("KONNECT_SYSTEM_TOKEN", SYSTEM_TOKEN)
    require_env("KONNECT_CP_ID", KONNECT_CP_ID)

    meter_results = {}
    meters_by_key = {}
    for spec in METER_SPECS:
        meter, state = ensure_meter(spec)
        meter_results[spec["key"]] = state
        meters_by_key[spec["key"]] = meter

    feature_results = {}
    features_by_key = {}
    for spec in FEATURE_SPECS:
        feature, state = ensure_feature(spec, meters_by_key[spec["meter_key"]]["id"])
        feature_results[spec["key"]] = state
        features_by_key[spec["key"]] = feature

    plans_by_key = {}
    plan_results = {}
    for plan_spec in PLAN_SPECS:
        plan, state = ensure_plan(plan_spec, {key: value["id"] for key, value in features_by_key.items()})
        plans_by_key[plan_spec["key"]] = plan
        plan_results[plan_spec["key"]] = {"state": state, "id": plan["id"], "status": plan.get("status")}

    customer_specs = []
    for spec in CUSTOMER_SPECS:
        spec_with_subject = dict(spec)
        spec_with_subject["subject"] = resolve_consumer_subject(spec["consumer_username"])
        customer_specs.append(spec_with_subject)

    customer_results = {}
    customers_by_key = {}
    for spec in customer_specs:
        customer, state = ensure_customer(spec)
        customer_results[spec["key"]] = state
        customers_by_key[spec["key"]] = customer

    subscription_results = {}
    for spec in customer_specs:
        subscription, state = ensure_subscription(customers_by_key[spec["key"]], plans_by_key[spec["plan_key"]])
        subscription_results[spec["key"]] = {
            "state": state,
            "subscription_id": subscription["id"],
            "status": subscription.get("status"),
            "plan_key": spec["plan_key"],
            "subject": spec["subject"],
        }

    bootstrap_results = emit_bootstrap_requests()
    time.sleep(2)

    print(
        json.dumps(
            {
                "bootstrap_requests": bootstrap_results,
                "meters": meter_results,
                "features": feature_results,
                "plans": plan_results,
                "customers": customer_results,
                "subscriptions": subscription_results,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

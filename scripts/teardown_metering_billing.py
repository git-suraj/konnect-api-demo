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

METER_KEYS = [
    "demo_api_requests_total",
]

FEATURE_KEYS = [
    "orders_api_request",
    "demo_api_requests_feature",
]

PLAN_KEYS = [
    "demo_api_requests_plan_demo_bank_1",
    "demo_api_requests_plan_demo_bank_2",
    "demo_api_requests_plan",
]

CUSTOMER_KEYS = [
    "demo-bank-1",
    "demo-bank-2",
]

DEMO_LABELS = {
    "demo": "konnect_api_demo",
    "managed_by": "repo_automation",
}

DELETE_RETRY_ATTEMPTS = int(os.environ.get("KONNECT_METERING_DELETE_RETRY_ATTEMPTS", "6"))
DELETE_RETRY_DELAY_SECONDS = float(os.environ.get("KONNECT_METERING_DELETE_RETRY_DELAY_SECONDS", "2"))
CANCEL_SETTLE_TIMEOUT_SECONDS = int(os.environ.get("KONNECT_METERING_CANCEL_SETTLE_TIMEOUT_SECONDS", "30"))
CANCEL_SETTLE_POLL_SECONDS = float(os.environ.get("KONNECT_METERING_CANCEL_SETTLE_POLL_SECONDS", "2"))
MAX_LIST_PAGES = int(os.environ.get("KONNECT_METERING_MAX_LIST_PAGES", "100"))
CUSTOMER_DELETE_RETRY_ATTEMPTS = int(os.environ.get("KONNECT_METERING_CUSTOMER_DELETE_RETRY_ATTEMPTS", "40"))
CUSTOMER_DELETE_RETRY_DELAY_SECONDS = float(os.environ.get("KONNECT_METERING_CUSTOMER_DELETE_RETRY_DELAY_SECONDS", "3"))
INVOICE_SETTLE_TIMEOUT_SECONDS = int(os.environ.get("KONNECT_METERING_INVOICE_SETTLE_TIMEOUT_SECONDS", "120"))
INVOICE_SETTLE_POLL_SECONDS = float(os.environ.get("KONNECT_METERING_INVOICE_SETTLE_POLL_SECONDS", "2"))

TERMINAL_INVOICE_STATUSES = {"void", "paid", "deleted"}
DRAFT_INVOICE_STATUSES = {"draft"}


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


def require_env(name: str, value: str) -> str:
    if not value:
        raise SystemExit(f"{name} is required")
    return value


def log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def has_demo_labels(item: dict) -> bool:
    labels = item.get("labels") or {}
    return all(labels.get(key) == value for key, value in DEMO_LABELS.items())


def is_target_meter(item: dict) -> bool:
    return item.get("key") in set(METER_KEYS) or has_demo_labels(item)


def is_target_feature(item: dict) -> bool:
    return item.get("key") in set(FEATURE_KEYS) or has_demo_labels(item)


def is_target_plan(item: dict) -> bool:
    return item.get("key") in set(PLAN_KEYS) or has_demo_labels(item)


def is_target_customer(item: dict) -> bool:
    return item.get("key") in set(CUSTOMER_KEYS) or has_demo_labels(item)


def api_request(
    method: str,
    path: str,
    payload: dict | None = None,
    query: dict[str, str] | None = None,
):
    token = require_env("KONNECT_SYSTEM_TOKEN", SYSTEM_TOKEN)
    url = path if path.startswith("http://") or path.startswith("https://") else f"{KONNECT_SERVER_URL}{path}"
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
        if exc.code == 404:
            return {}
        raise RuntimeError(f"{method} {url} failed with {exc.code}: {raw}") from exc


def extract_items(payload) -> list[dict]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        return payload.get("items") or payload.get("data") or payload.get("results") or []
    return []


def list_resources(path: str, *, extra_query: dict[str, str] | None = None) -> list[dict]:
    items: list[dict] = []
    next_path: str | None = path
    query: dict[str, str] | None = {"page[size]": "100"}
    if extra_query:
        query.update(extra_query)
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


def best_effort_delete(path: str) -> str:
    last_error = ""
    for attempt in range(1, DELETE_RETRY_ATTEMPTS + 1):
        try:
            api_request("DELETE", path)
            return "deleted"
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)
            if attempt == DELETE_RETRY_ATTEMPTS:
                break
            time.sleep(DELETE_RETRY_DELAY_SECONDS)
    return f"delete_failed: {last_error}"


def best_effort_delete_with_retry(path: str, *, attempts: int, delay_seconds: float) -> str:
    last_error = ""
    for attempt in range(1, attempts + 1):
        try:
            api_request("DELETE", path)
            return "deleted"
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)
            if attempt == attempts:
                break
            time.sleep(delay_seconds)
    return f"delete_failed: {last_error}"


def classify_customer_delete_result(message: str) -> str:
    if "invoice" in message and "not in final state" in message:
        return f"invoice_blocked: {message}"
    return message


def best_effort_post(path: str, payload: dict | None = None) -> str:
    try:
        api_request("POST", path, payload)
        return "ok"
    except Exception as exc:  # noqa: BLE001
        return f"post_failed: {exc}"


def archive_plan_if_needed(plan: dict) -> str:
    status = plan.get("status")
    if status == "archived":
        return "already_archived"
    if status in {"draft", "scheduled"}:
        return f"not_archived_status_{status}"
    if status != "active":
        return f"archive_skipped_status_{status or 'unknown'}"
    try:
        api_request("POST", f"/v3/openmeter/plans/{plan['id']}/archive")
        return "archived"
    except Exception as exc:  # noqa: BLE001
        return f"archive_failed: {exc}"


def filter_target_subscriptions(subscriptions: list[dict], customer_ids: set[str], plan_ids: set[str]) -> list[dict]:
    return [
        subscription
        for subscription in subscriptions
        if subscription.get("customer_id") in customer_ids or subscription.get("plan_id") in plan_ids
    ]


def wait_for_subscription_cancellation(customer_ids: set[str], plan_ids: set[str]) -> tuple[bool, dict[str, str]]:
    deadline = time.time() + CANCEL_SETTLE_TIMEOUT_SECONDS
    last_statuses: dict[str, str] = {}
    poll_count = 0

    while time.time() < deadline:
        poll_count += 1
        current = filter_target_subscriptions(list_resources("/v3/openmeter/subscriptions"), customer_ids, plan_ids)
        blocking = [
            subscription for subscription in current if subscription.get("status") in {"active", "scheduled", "pending"}
        ]
        last_statuses = {subscription["id"]: subscription.get("status", "unknown") for subscription in current}
        if not blocking:
            return True, last_statuses
        log(
            f"Waiting for subscription cancellation to settle "
            f"(poll {poll_count}, blocking={len(blocking)}, statuses={last_statuses})"
        )
        time.sleep(CANCEL_SETTLE_POLL_SECONDS)

    return False, last_statuses


def invoice_statuses(invoice: dict) -> tuple[str, str]:
    status = str(invoice.get("status") or "").lower()
    details = invoice.get("statusDetails") or invoice.get("status_details") or {}
    extended = str(details.get("extendedStatus") or details.get("extended_status") or status).lower()
    return status, extended


def invoice_is_terminal(invoice: dict) -> bool:
    status, extended = invoice_statuses(invoice)
    return status in TERMINAL_INVOICE_STATUSES or extended in TERMINAL_INVOICE_STATUSES


def invoice_is_gathering(invoice: dict) -> bool:
    status, extended = invoice_statuses(invoice)
    return status == "gathering" or extended == "gathering"


def list_customer_invoices(customer_id: str) -> list[dict]:
    return list_resources("/metering/v1/billing/invoices", extra_query={"customers": customer_id})


def settle_invoice(invoice: dict) -> str:
    invoice_id = invoice["id"]
    status, extended = invoice_statuses(invoice)

    if invoice_is_terminal(invoice):
        return f"already_terminal_{status or extended}"

    if invoice_is_gathering(invoice):
        return "waiting_gathering"

    if status in DRAFT_INVOICE_STATUSES or extended in DRAFT_INVOICE_STATUSES:
        result = best_effort_delete(f"/metering/v1/billing/invoices/{invoice_id}")
        if result == "deleted":
            return result
        if "not in final state" not in result and "cannot" not in result.lower():
            return result

    void_result = best_effort_post(f"/metering/v1/billing/invoices/{invoice_id}/void", {})
    if void_result == "ok":
        return "voided"
    return void_result


def wait_and_settle_invoices(customer_ids: set[str]) -> tuple[bool, dict[str, dict[str, str]]]:
    deadline = time.time() + INVOICE_SETTLE_TIMEOUT_SECONDS
    results: dict[str, dict[str, str]] = {}
    poll_count = 0

    while time.time() < deadline:
        poll_count += 1
        blocking: dict[str, list[str]] = {}
        gathering = False

        for customer_id in sorted(customer_ids):
            invoices = list_customer_invoices(customer_id)
            customer_results = results.setdefault(customer_id, {})

            for invoice in invoices:
                invoice_id = invoice["id"]
                if invoice_is_terminal(invoice):
                    customer_results.setdefault(invoice_id, "already_terminal")
                    continue

                status, extended = invoice_statuses(invoice)
                if invoice_is_gathering(invoice):
                    gathering = True
                    customer_results[invoice_id] = "waiting_gathering"
                    blocking.setdefault(customer_id, []).append(f"{invoice_id}:gathering")
                    continue

                action = settle_invoice(invoice)
                customer_results[invoice_id] = action
                log(
                    f"Invoice {invoice_id} for customer {customer_id} "
                    f"(status={status}, extended={extended}): {action}"
                )

            for invoice in list_customer_invoices(customer_id):
                if invoice_is_terminal(invoice):
                    continue
                status, extended = invoice_statuses(invoice)
                blocking.setdefault(customer_id, []).append(f"{invoice['id']}:{status}/{extended}")

        if not blocking:
            return True, results

        if gathering:
            log(f"Waiting for gathering invoices to settle (poll {poll_count}, blocking={blocking})")
        else:
            log(f"Waiting for terminal invoice state (poll {poll_count}, blocking={blocking})")
        time.sleep(INVOICE_SETTLE_POLL_SECONDS)

    return False, results


def main() -> int:
    load_dotenv()
    global KONNECT_SERVER_URL, SYSTEM_TOKEN
    KONNECT_SERVER_URL = os.environ.get("KONNECT_SERVER_URL", KONNECT_SERVER_URL).rstrip("/")
    SYSTEM_TOKEN = os.environ.get("KONNECT_SYSTEM_TOKEN", SYSTEM_TOKEN).strip()
    require_env("KONNECT_SYSTEM_TOKEN", SYSTEM_TOKEN)

    log("Listing Metering and Billing resources")
    customers = [item for item in list_resources("/v3/openmeter/customers") if is_target_customer(item)]
    plans = [item for item in list_resources("/v3/openmeter/plans") if is_target_plan(item)]
    features = [item for item in list_resources("/v3/openmeter/features") if is_target_feature(item)]
    meters = [item for item in list_resources("/v3/openmeter/meters") if is_target_meter(item)]
    subscriptions = list_resources("/v3/openmeter/subscriptions")
    log(
        f"Found customers={len(customers)} plans={len(plans)} features={len(features)} "
        f"meters={len(meters)} subscriptions={len(subscriptions)}"
    )

    target_customer_ids = {item["id"] for item in customers}
    target_plan_ids = {item["id"] for item in plans}

    subscription_results = {}
    for subscription in subscriptions:
        if subscription.get("customer_id") not in target_customer_ids and subscription.get("plan_id") not in target_plan_ids:
            continue
        if subscription.get("status") in {"canceled", "inactive"}:
            subscription_results[subscription["id"]] = f"already_terminal_{subscription.get('status')}"
            continue
        log(f"Cancelling subscription {subscription['id']} (status={subscription.get('status')})")
        subscription_results[subscription["id"]] = best_effort_post(
            f"/v3/openmeter/subscriptions/{subscription['id']}/cancel",
            {"timing": "immediate"},
        )

    settled, final_subscription_statuses = wait_for_subscription_cancellation(target_customer_ids, target_plan_ids)
    log(f"Subscription cancellation settled={settled}")

    log("Settling demo customer invoices before catalog deletion")
    invoices_settled, invoice_results = wait_and_settle_invoices(target_customer_ids)
    log(f"Invoice settlement complete={invoices_settled}")

    plan_archive_results = {}
    refreshed_plans = [item for item in list_resources("/v3/openmeter/plans") if is_target_plan(item)]
    for plan in sorted(refreshed_plans, key=lambda item: item.get("version") or 0, reverse=True):
        log(f"Preparing plan {plan.get('key')}@v{plan.get('version')} for deletion (status={plan.get('status')})")
        plan_archive_results[f"{plan.get('key')}@v{plan.get('version')}"] = archive_plan_if_needed(plan)

    plan_results = {}
    refreshed_plans = [item for item in list_resources("/v3/openmeter/plans") if is_target_plan(item)]
    for plan in sorted(refreshed_plans, key=lambda item: item.get("version") or 0, reverse=True):
        log(f"Deleting plan {plan.get('key')}@v{plan.get('version')} (status={plan.get('status')})")
        plan_results[f"{plan.get('key')}@v{plan.get('version')}"] = best_effort_delete(f"/v3/openmeter/plans/{plan['id']}")

    feature_results = {}
    for feature in features:
        log(f"Deleting feature {feature['key']}")
        feature_results[feature["key"]] = best_effort_delete(f"/v3/openmeter/features/{feature['id']}")

    customer_results = {}
    for customer in customers:
        log(f"Deleting customer {customer['key']}")
        result = best_effort_delete_with_retry(
            f"/v3/openmeter/customers/{customer['id']}",
            attempts=CUSTOMER_DELETE_RETRY_ATTEMPTS,
            delay_seconds=CUSTOMER_DELETE_RETRY_DELAY_SECONDS,
        )
        customer_results[customer["key"]] = classify_customer_delete_result(result)

    meter_results = {}
    for meter in meters:
        log(f"Deleting meter {meter['key']}")
        meter_results[meter["key"]] = best_effort_delete(f"/v3/openmeter/meters/{meter['id']}")

    print(
        json.dumps(
            {
                "subscriptions": subscription_results,
                "subscription_settled": settled,
                "subscription_statuses": final_subscription_statuses,
                "invoices_settled": invoices_settled,
                "invoices": invoice_results,
                "plan_archives": plan_archive_results,
                "plans": plan_results,
                "features": feature_results,
                "customers": customer_results,
                "meters": meter_results,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

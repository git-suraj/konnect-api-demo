#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path


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


def env_required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise SystemExit(f"{name} must be set")
    return value


def env_default(name: str, default: str) -> str:
    value = os.environ.get(name)
    if value is None:
        return default
    stripped = value.strip()
    return stripped if stripped else default


def parse_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


RESERVED_AUTH0_API_SCOPES = {
    "openid",
    "profile",
    "offline_access",
    "name",
    "given_name",
    "family_name",
    "nickname",
    "email",
    "email_verified",
    "picture",
    "created_at",
    "identities",
    "phone",
    "address",
}


AUTH0_DOMAIN = env_required("AUTH0_DOMAIN")
AUTH0_MANAGEMENT_CLIENT_ID = env_required("AUTH0_MANAGEMENT_CLIENT_ID")
AUTH0_MANAGEMENT_CLIENT_SECRET = env_required("AUTH0_MANAGEMENT_CLIENT_SECRET")
AUTH0_MANAGEMENT_AUDIENCE = env_default("AUTH0_MANAGEMENT_AUDIENCE", f"https://{AUTH0_DOMAIN}/api/v2/")

AUTH0_DPOP_API_NAME = env_default("AUTH0_DPOP_API_NAME", "Kong DPoP Demo API")
AUTH0_DPOP_API_IDENTIFIER = env_default("AUTH0_DPOP_API_IDENTIFIER", "https://kong.example.internal/dpop")
AUTH0_DPOP_API_SCOPES = parse_csv(env_default("AUTH0_DPOP_API_SCOPES", "read:orders"))
AUTH0_DPOP_APP_NAME = env_default("AUTH0_DPOP_APP_NAME", "kong-dpop-m2m-client")
AUTH0_DPOP_EXISTING_CLIENT_ID = env_default("AUTH0_DPOP_EXISTING_CLIENT_ID", "")
AUTH0_DPOP_REUSE_ONLY = env_default("AUTH0_DPOP_REUSE_ONLY", "false").lower() in {"1", "true", "yes", "on"}
AUTH0_DPOP_APP_TYPE = env_default("AUTH0_DPOP_APP_TYPE", "non_interactive")
AUTH0_DPOP_CLIENT_SECRET = env_default("AUTH0_DPOP_CLIENT_SECRET", "")
AUTH0_DPOP_TOKEN_ENDPOINT_AUTH_METHOD = env_default(
    "AUTH0_DPOP_TOKEN_ENDPOINT_AUTH_METHOD",
    "client_secret_post",
)
AUTH0_DPOP_GRANT_TYPES = parse_csv(env_default("AUTH0_DPOP_GRANT_TYPES", "client_credentials"))
AUTH0_DPOP_CLIENT_METADATA = env_default("AUTH0_DPOP_CLIENT_METADATA", "")
AUTH0_DPOP_ENABLE_DPOP = env_default("AUTH0_DPOP_ENABLE_DPOP", "false").lower() in {"1", "true", "yes", "on"}
AUTH0_DPOP_CLIENT_FLAG_FIELD = env_default("AUTH0_DPOP_CLIENT_FLAG_FIELD", "dpop_bound_access_tokens")


@dataclass
class Auth0State:
    management_token: str
    api: dict
    client: dict
    client_grant: dict


def validate_auth0_inputs() -> None:
    reserved = [scope for scope in AUTH0_DPOP_API_SCOPES if scope in RESERVED_AUTH0_API_SCOPES]
    if reserved:
        reserved_text = ", ".join(reserved)
        raise RuntimeError(
            "AUTH0_DPOP_API_SCOPES contains reserved OIDC scopes that cannot be created on an Auth0 custom API: "
            f"{reserved_text}. Use custom API scopes such as `read:orders` or `invoke:demo` instead."
        )


def auth0_json(method: str, path: str, token: str | None = None, payload: dict | None = None):
    url = f"https://{AUTH0_DOMAIN}{path}"
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Accept": "application/json"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"

    request = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        details = raw
        try:
            parsed = json.loads(raw)
            details = json.dumps(parsed, indent=2, sort_keys=True)
        except json.JSONDecodeError:
            pass
        raise RuntimeError(f"{method} {url} failed with {exc.code}: {details}") from exc


def get_management_token() -> str:
    payload = {
        "grant_type": "client_credentials",
        "client_id": AUTH0_MANAGEMENT_CLIENT_ID,
        "client_secret": AUTH0_MANAGEMENT_CLIENT_SECRET,
        "audience": AUTH0_MANAGEMENT_AUDIENCE,
    }
    response = auth0_json("POST", "/oauth/token", payload=payload)
    token = response.get("access_token")
    if not token:
        raise RuntimeError("Auth0 did not return a management API access token")
    return token


def list_resource_servers(token: str) -> list[dict]:
    return auth0_json("GET", "/api/v2/resource-servers", token=token)


def find_resource_server(token: str, identifier: str) -> dict | None:
    for server in list_resource_servers(token):
        if server.get("identifier") == identifier:
            return server
    return None


def build_scope_objects(scopes: list[str]) -> list[dict]:
    return [{"value": scope, "description": f"Scope {scope}"} for scope in scopes]


def upsert_resource_server(token: str) -> dict:
    existing = find_resource_server(token, AUTH0_DPOP_API_IDENTIFIER)
    create_payload = {
        "name": AUTH0_DPOP_API_NAME,
        "identifier": AUTH0_DPOP_API_IDENTIFIER,
        "signing_alg": "RS256",
        "allow_offline_access": False,
        "skip_consent_for_verifiable_first_party_clients": True,
        "token_lifetime": 86400,
        "token_lifetime_for_web": 7200,
        "scopes": build_scope_objects(AUTH0_DPOP_API_SCOPES),
    }
    update_payload = {
        "name": AUTH0_DPOP_API_NAME,
        "signing_alg": "RS256",
        "allow_offline_access": False,
        "skip_consent_for_verifiable_first_party_clients": True,
        "token_lifetime": 86400,
        "token_lifetime_for_web": 7200,
        "scopes": build_scope_objects(AUTH0_DPOP_API_SCOPES),
    }

    if existing:
        return auth0_json("PATCH", f"/api/v2/resource-servers/{existing['id']}", token=token, payload=update_payload)
    return auth0_json("POST", "/api/v2/resource-servers", token=token, payload=create_payload)


def list_clients(token: str) -> list[dict]:
    return auth0_json("GET", "/api/v2/clients", token=token)


def find_client(token: str, name: str) -> dict | None:
    for client in list_clients(token):
        if client.get("name") == name:
            return client
    return None


def find_client_by_id(token: str, client_id: str) -> dict | None:
    if not client_id:
        return None
    try:
        return auth0_json("GET", f"/api/v2/clients/{urllib.parse.quote(client_id, safe='')}", token=token)
    except RuntimeError as exc:
        if " failed with 404:" in str(exc):
            return None
        raise


def build_client_payload(include_dpop_flag: bool) -> dict:
    payload = {
        "name": AUTH0_DPOP_APP_NAME,
        "app_type": AUTH0_DPOP_APP_TYPE,
        "oidc_conformant": True,
        "grant_types": AUTH0_DPOP_GRANT_TYPES,
        "token_endpoint_auth_method": AUTH0_DPOP_TOKEN_ENDPOINT_AUTH_METHOD,
        "is_first_party": True,
        "jwt_configuration": {"alg": "RS256"},
        "client_metadata": {
            "managed_by": "repo_automation",
            "scenario": "kong_dpop_demo",
        },
    }

    if AUTH0_DPOP_CLIENT_METADATA:
        try:
            payload["client_metadata"].update(json.loads(AUTH0_DPOP_CLIENT_METADATA))
        except json.JSONDecodeError as exc:
            raise RuntimeError("AUTH0_DPOP_CLIENT_METADATA must be valid JSON") from exc

    if include_dpop_flag and AUTH0_DPOP_ENABLE_DPOP:
        payload[AUTH0_DPOP_CLIENT_FLAG_FIELD] = True

    return payload


def upsert_client(token: str) -> dict:
    existing = find_client_by_id(token, AUTH0_DPOP_EXISTING_CLIENT_ID) or find_client(token, AUTH0_DPOP_APP_NAME)

    if AUTH0_DPOP_REUSE_ONLY and existing is None:
        if AUTH0_DPOP_EXISTING_CLIENT_ID:
            raise RuntimeError(
                f"AUTH0_DPOP_REUSE_ONLY is true but no existing Auth0 client was found for "
                f"AUTH0_DPOP_EXISTING_CLIENT_ID={AUTH0_DPOP_EXISTING_CLIENT_ID!r}."
            )
        raise RuntimeError(
            f"AUTH0_DPOP_REUSE_ONLY is true but no existing Auth0 client was found with "
            f"AUTH0_DPOP_APP_NAME={AUTH0_DPOP_APP_NAME!r}."
        )

    try:
        payload = build_client_payload(include_dpop_flag=True)
        if existing:
            return auth0_json("PATCH", f"/api/v2/clients/{existing['client_id']}", token=token, payload=payload)
        if AUTH0_DPOP_REUSE_ONLY:
            raise RuntimeError("AUTH0_DPOP_REUSE_ONLY is true and client creation is disabled.")
        return auth0_json("POST", "/api/v2/clients", token=token, payload=payload)
    except RuntimeError as exc:
        if not AUTH0_DPOP_ENABLE_DPOP or AUTH0_DPOP_CLIENT_FLAG_FIELD not in str(exc):
            raise

        fallback_payload = build_client_payload(include_dpop_flag=False)
        if existing:
            client = auth0_json(
                "PATCH",
                f"/api/v2/clients/{existing['client_id']}",
                token=token,
                payload=fallback_payload,
            )
        else:
            if AUTH0_DPOP_REUSE_ONLY:
                raise RuntimeError("AUTH0_DPOP_REUSE_ONLY is true and client creation is disabled.") from exc
            client = auth0_json("POST", "/api/v2/clients", token=token, payload=fallback_payload)

        raise RuntimeError(
            "Auth0 client was created or updated, but DPoP could not be enabled automatically. "
            f"The script attempted to set `{AUTH0_DPOP_CLIENT_FLAG_FIELD}=true` and Auth0 rejected it. "
            "Check whether your tenant exposes a different Management API field for DPoP or whether the feature "
            "needs to be enabled in the dashboard first. "
            f"Auth0 response: {exc}"
        ) from exc


def list_client_grants(token: str) -> list[dict]:
    return auth0_json("GET", "/api/v2/client-grants", token=token)


def find_client_grant(token: str, client_id: str, audience: str) -> dict | None:
    for grant in list_client_grants(token):
        if grant.get("client_id") == client_id and grant.get("audience") == audience:
            return grant
    return None


def upsert_client_grant(token: str, client_id: str, audience: str, scopes: list[str]) -> dict:
    existing = find_client_grant(token, client_id, audience)
    create_payload = {
        "client_id": client_id,
        "audience": audience,
        "scope": scopes,
    }
    update_payload = {
        "scope": scopes,
    }
    if existing:
        return auth0_json("PATCH", f"/api/v2/client-grants/{existing['id']}", token=token, payload=update_payload)
    return auth0_json("POST", "/api/v2/client-grants", token=token, payload=create_payload)


def run() -> Auth0State:
    token = get_management_token()
    api = upsert_resource_server(token)
    client = upsert_client(token)
    if not client.get("client_secret"):
        if AUTH0_DPOP_CLIENT_SECRET:
            client["client_secret"] = AUTH0_DPOP_CLIENT_SECRET
        else:
            raise RuntimeError(
                "Auth0 did not return the DPoP application client secret. "
                "Set AUTH0_DPOP_CLIENT_SECRET in .env to the existing app secret, "
                "or rotate the secret in Auth0 and store the new value there before rerunning."
            )
    client_grant = upsert_client_grant(token, client["client_id"], AUTH0_DPOP_API_IDENTIFIER, AUTH0_DPOP_API_SCOPES)
    return Auth0State(
        management_token=token,
        api=api,
        client=client,
        client_grant=client_grant,
    )


def print_summary(state: Auth0State) -> None:
    summary = {
        "auth0_domain": AUTH0_DOMAIN,
        "issuer": f"https://{AUTH0_DOMAIN}/",
        "discovery_url": f"https://{AUTH0_DOMAIN}/.well-known/openid-configuration",
        "api": {
            "id": state.api.get("id"),
            "name": state.api.get("name"),
            "identifier": state.api.get("identifier"),
            "scopes": [scope.get("value") for scope in state.api.get("scopes", [])],
        },
        "client": {
            "name": state.client.get("name"),
            "client_id": state.client.get("client_id"),
            "client_secret": state.client.get("client_secret"),
            "app_type": state.client.get("app_type"),
            "grant_types": state.client.get("grant_types"),
            "reused_existing_client": bool(AUTH0_DPOP_EXISTING_CLIENT_ID or AUTH0_DPOP_REUSE_ONLY),
        },
        "client_grant": {
            "id": state.client_grant.get("id"),
            "audience": state.client_grant.get("audience"),
            "scope": state.client_grant.get("scope"),
        },
        "kong_openid_connect": {
            "issuer": f"https://{AUTH0_DOMAIN}/",
            "client_id": [state.client.get("client_id")],
            "client_secret": [state.client.get("client_secret")],
            "auth_methods": ["bearer"],
            "proof_of_possession_dpop": "strict",
        },
        "token_request_example": {
            "url": f"https://{AUTH0_DOMAIN}/oauth/token",
            "audience": AUTH0_DPOP_API_IDENTIFIER,
            "grant_type": "client_credentials",
            "client_id": state.client.get("client_id"),
            "dpop_required": AUTH0_DPOP_ENABLE_DPOP,
        },
        "next_steps_in_auth0_ui": [
            {
                "area": "API",
                "path": "Applications > APIs > <API> > Settings > Token Sender-Constraining",
                "instructions": [
                    "Open the API created by this script.",
                    "Select DPoP as the sender-constraining method.",
                    "Enable Require Token Sender-Constraining.",
                    "Save the API settings.",
                ],
            },
            {
                "area": "Client Application",
                "path": "Applications > Applications > <client app> > Settings > Token Sender-Constraining",
                "instructions": [
                    "Open the client application created by this script.",
                    "Enable Require Token Sender-Constraining.",
                    "Save the application settings.",
                ],
            },
        ],
    }
    print(json.dumps(summary, indent=2))


def main() -> None:
    validate_auth0_inputs()
    state = run()
    print_summary(state)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        sys.exit(1)

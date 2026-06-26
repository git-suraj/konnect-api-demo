#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"
RUNTIME_DIR="$ROOT_DIR/.runtime"
NGROK_PID_FILE="$RUNTIME_DIR/ngrok.pid"
NGROK_LOG_FILE="$RUNTIME_DIR/ngrok.log"
NGROK_API_URL="http://127.0.0.1:4040/api/tunnels"

if [[ -f ".env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source ".env"
  set +a
fi

mkdir -p "$RUNTIME_DIR"

if [[ -z "${KONNECT_TOKEN:-}" || -z "${KONNECT_CP_ID:-}" ]]; then
  echo "KONNECT_TOKEN and KONNECT_CP_ID must be set in .env" >&2
  exit 1
fi

wait_for_docker() {
  if docker info >/dev/null 2>&1; then
    return
  fi

  if [[ "$(uname -s)" == "Darwin" ]] && command -v open >/dev/null 2>&1; then
    echo "Starting Docker Desktop"
    open -a Docker >/dev/null 2>&1 || true
  fi

  echo "Waiting for Docker daemon"
  for _ in $(seq 1 90); do
    if docker info >/dev/null 2>&1; then
      return
    fi
    sleep 2
  done

  echo "Docker daemon did not become ready in time" >&2
  exit 1
}

wait_for_docker

stop_existing_ngrok() {
  if [[ -f "$NGROK_PID_FILE" ]]; then
    local pid
    pid="$(cat "$NGROK_PID_FILE")"
    if kill -0 "$pid" >/dev/null 2>&1; then
      kill "$pid" >/dev/null 2>&1 || true
      sleep 1
    fi
    rm -f "$NGROK_PID_FILE"
  fi
  if command -v pkill >/dev/null 2>&1; then
    pkill -f "ngrok http 8091" >/dev/null 2>&1 || true
    sleep 1
  fi
}

wait_for_ngrok_tunnel() {
  for _ in $(seq 1 30); do
    local public_url
    public_url="$(curl -s "$NGROK_API_URL" | python3 -c 'import json,sys; data=json.load(sys.stdin); tunnels=data.get("tunnels", []); https=[t.get("public_url","") for t in tunnels if t.get("public_url","").startswith("https://")]; print(https[0] if https else "")' 2>/dev/null || true)"
    if [[ -n "$public_url" ]]; then
      echo "$public_url"
      return
    fi
    sleep 1
  done
  return 1
}

verify_ngrok_tunnel() {
  local public_url="$1"
  curl -fsS \
    -H "ngrok-skip-browser-warning: 1" \
    "${public_url%/}/health" >/dev/null
}

echo "Starting local demo dependencies"
echo "Preparing payload crypto materials"
python3 scripts/setup_payload_crypto_materials.py

echo "Starting local demo dependencies"
docker compose up -d \
  orders-east \
  orders-west \
  orders-instance-1 \
  orders-instance-2 \
  orders-v1 \
  orders-v2 \
  datakit-api1 \
  datakit-api2 \
  redis \
  keycloak \
  loki \
  tempo \
  otel-collector \
  grafana \
  konnect-audit-receiver \
  crypto-helper

echo "Bootstrapping local Keycloak realm"
python3 scripts/bootstrap_keycloak.py

echo "Initializing Konnect Terraform provider"
terraform -chdir=terraform/konnect init -input=false -upgrade

if [[ -z "$(terraform -chdir=terraform/konnect state list 2>/dev/null)" ]]; then
  echo "Local Terraform state is empty, cleaning orphaned Konnect demo entities"
  python3 scripts/cleanup_konnect_demo.py
fi

if ! terraform -chdir=terraform/konnect state show konnect_gateway_custom_plugin_schema.payload_crypto_demo >/dev/null 2>&1; then
  echo "Removing legacy payload crypto plugin objects before Terraform ownership"
  python3 scripts/teardown_payload_crypto_plugin.py || true
fi

echo "Applying Konnect control plane configuration"
TF_VAR_konnect_control_plane_id="$KONNECT_CP_ID" \
TF_VAR_konnect_system_token="${KONNECT_SYSTEM_TOKEN:-}" \
TF_VAR_konnect_metering_ingest_endpoint="${KONNECT_METERING_INGEST_ENDPOINT:-https://us.api.konghq.com/v3/openmeter/events}" \
TF_VAR_azure_ad_tenant_id="${AD_PROTECTED_API_TENANT_ID:-}" \
TF_VAR_azure_ad_audience="${AD_PROTECTED_API_AUDIENCE:-}" \
TF_VAR_azure_ad_consumer1_client_id="${AD_CONSUMER1_CLIENT_ID:-}" \
TF_VAR_azure_ad_consumer2_client_id="${AD_CONSUMER2_CLIENT_ID:-}" \
TF_VAR_keycloak_realm="${KEYCLOAK_REALM:-kong-demo}" \
TF_VAR_keycloak_allowed_role="${KEYCLOAK_ALLOWED_ROLE:-api-access}" \
terraform -chdir=terraform/konnect apply -input=false -auto-approve

echo "Applying Konnect observability dashboard"
DEMO_LOGS_URL="$(python3 scripts/configure_konnect_observability_dashboard.py | python3 -c 'import json,sys; print(json.load(sys.stdin)["dashboard_url"])')"
export DEMO_LOGS_URL
python3 scripts/sync_env_var.py DEMO_LOGS_URL "$DEMO_LOGS_URL"

echo "Starting Konnect hybrid data plane and demo UI"
docker compose up -d --force-recreate kong-dp demo-ui

if [[ -n "${KONNECT_SYSTEM_TOKEN:-}" ]]; then
  echo "Configuring Metering and Billing demo resources"
  python3 scripts/setup_metering_billing.py
else
  echo "Skipping Metering and Billing automation because KONNECT_SYSTEM_TOKEN is not set"
fi

stop_existing_ngrok

echo "Starting ngrok tunnel for Konnect audit webhook receiver"
ngrok http 8091 --log stdout --log-format json >"$NGROK_LOG_FILE" 2>&1 &
echo $! >"$NGROK_PID_FILE"

KONNECT_AUDIT_PUBLIC_URL="$(wait_for_ngrok_tunnel)" || {
  echo "ngrok tunnel did not become ready in time" >&2
  exit 1
}

verify_ngrok_tunnel "$KONNECT_AUDIT_PUBLIC_URL" || {
  echo "ngrok tunnel health check failed for ${KONNECT_AUDIT_PUBLIC_URL}/health" >&2
  exit 1
}

echo "Configuring Konnect audit webhook"
KONNECT_AUDIT_PUBLIC_URL="$KONNECT_AUDIT_PUBLIC_URL" \
KONNECT_AUDIT_SHARED_SECRET="${KONNECT_AUDIT_SHARED_SECRET:-konnect-audit-demo-secret}" \
python3 scripts/configure_konnect_audit.py

echo
echo "Konnect configuration applied"
echo "UI:               http://localhost:8080"
echo "Kong Proxy:        http://localhost:8000"
echo "Kong Proxy TLS:    https://localhost:8443"
echo "Grafana:           http://localhost:3001"
echo "Loki:              http://localhost:3100"
echo "Trace Portal:      http://localhost:3200"
echo "Tempo API:         http://localhost:3201"
echo "Audit Receiver:    http://localhost:8091/health"
echo "ngrok Audit URL:   $KONNECT_AUDIT_PUBLIC_URL"
echo "Orders East Mock:  http://localhost:9101"
echo "Orders West Mock:  http://localhost:9102"
echo "Instance 1 Mock:   http://localhost:9201"
echo "Instance 2 Mock:   http://localhost:9202"
echo "Orders V1 Mock:    http://localhost:9301"
echo "Orders V2 Mock:    http://localhost:9302"
echo "Keycloak:          http://localhost:8081"

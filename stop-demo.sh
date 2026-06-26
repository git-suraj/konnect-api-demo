#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"
RUNTIME_DIR="$ROOT_DIR/.runtime"
NGROK_PID_FILE="$RUNTIME_DIR/ngrok.pid"

if [[ -f ".env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source ".env"
  set +a
fi

if [[ -n "${KONNECT_TOKEN:-}" && -n "${KONNECT_CP_ID:-}" ]]; then
  if [[ -n "${KONNECT_SYSTEM_TOKEN:-}" ]]; then
    echo "Tearing down Metering and Billing demo resources"
    python3 scripts/teardown_metering_billing.py || true
  fi

  echo "Tearing down Konnect audit webhook"
  python3 scripts/teardown_konnect_audit.py || true

  echo "Tearing down Konnect observability dashboard"
  python3 scripts/teardown_konnect_observability_dashboard.py || true

  echo "Destroying Konnect-managed demo entities"
  terraform -chdir=terraform/konnect init -input=false >/dev/null
  TF_VAR_konnect_control_plane_id="$KONNECT_CP_ID" \
  terraform -chdir=terraform/konnect destroy -input=false -auto-approve || true
fi

if [[ -f "$NGROK_PID_FILE" ]]; then
  echo "Stopping ngrok tunnel"
  pid="$(cat "$NGROK_PID_FILE")"
  if kill -0 "$pid" >/dev/null 2>&1; then
    kill "$pid" >/dev/null 2>&1 || true
  fi
  rm -f "$NGROK_PID_FILE"
fi

if docker info >/dev/null 2>&1; then
echo "Stopping local demo containers"
docker compose down -v --remove-orphans --timeout 20
fi

echo "Cleaning Terraform runtime state"
rm -rf terraform/konnect/.terraform
rm -f terraform/konnect/.terraform.tfstate.lock.info
rm -rf "$RUNTIME_DIR"

echo "Cleanup complete"

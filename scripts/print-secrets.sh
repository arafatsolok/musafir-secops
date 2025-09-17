#!/usr/bin/env bash
set -euo pipefail
ENV_FILE="/etc/musafir.env"
if [[ ! -f "$ENV_FILE" ]]; then
  echo "[ERR] $ENV_FILE not found" >&2; exit 1
fi
# shellcheck disable=SC1090
source "$ENV_FILE"
cat <<OUT
MUSAFIR environment (/etc/musafir.env)
-------------------------------------
KAFKA_BROKERS=${KAFKA_BROKERS:-}
CLICKHOUSE_DSN=${CLICKHOUSE_DSN:-}
PORT=${PORT:-8080}
GATEWAY_JWT_SECRET=${GATEWAY_JWT_SECRET:-}
GATEWAY_HMAC_SECRET=${GATEWAY_HMAC_SECRET:-}

Agent setup (Windows):
- Set AGENT_HMAC_SECRET to the same as GATEWAY_HMAC_SECRET above
- Set GATEWAY_URL to http://SERVER_IP:${PORT:-8080}
OUT

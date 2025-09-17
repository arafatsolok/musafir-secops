#!/usr/bin/env bash
set -euo pipefail
ENV_FILE="/etc/musafir.env"
if [[ $EUID -ne 0 ]]; then echo "[ERR] Run as root"; exit 1; fi
if [[ ! -f "$ENV_FILE" ]]; then echo "[ERR] $ENV_FILE not found"; exit 1; fi
NEW_JWT="jwt-$(date +%s)-$RANDOM"
NEW_HMAC="hmac-$(date +%s)-$RANDOM"
sed -i "s/^GATEWAY_JWT_SECRET=.*/GATEWAY_JWT_SECRET=$NEW_JWT/" "$ENV_FILE"
sed -i "s/^GATEWAY_HMAC_SECRET=.*/GATEWAY_HMAC_SECRET=$NEW_HMAC/" "$ENV_FILE"
systemctl restart musafir-gateway.service || true
for svc in musafir-email.service musafir-forensics.service musafir-ml.service musafir-monitor.service musafir-ingest.service; do
  systemctl restart "$svc" || true
 done
echo "[OK] Rotated secrets. Update Windows agents with new AGENT_HMAC_SECRET: $NEW_HMAC"

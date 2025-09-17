#!/usr/bin/env bash
set -euo pipefail
ENV_FILE="/etc/musafir.env"
if [[ $EUID -ne 0 ]]; then echo "[ERR] Run as root"; exit 1; fi
if [[ ! -f "$ENV_FILE" ]]; then
  echo "[INFO] creating $ENV_FILE"
  touch "$ENV_FILE"; chmod 0644 "$ENV_FILE"
fi
ensure_kv() {
  local key="$1" val
  if ! grep -qE "^${key}=.+" "$ENV_FILE"; then
    val="${key,,}-$(date +%s)-$RANDOM"
    echo "${key}=${val}" >> "$ENV_FILE"
    echo "[OK] set ${key}"
  else
    echo "[SKIP] ${key} exists"
  fi
}
ensure_kv GATEWAY_JWT_SECRET
ensure_kv GATEWAY_HMAC_SECRET
systemctl restart musafir-gateway.service || true
for svc in musafir-email.service musafir-forensics.service musafir-ml.service musafir-monitor.service musafir-ingest.service; do
  systemctl restart "$svc" || true
 done
echo "[DONE] Secrets ensured and services restarted."

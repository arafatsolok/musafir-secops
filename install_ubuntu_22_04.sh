#!/usr/bin/env bash
set -euo pipefail

# MUSAFIR SecOps - Automated Installer for Ubuntu 22.04
# This script sets up infra (Kafka/ClickHouse/etc), builds services & UI, configures Nginx, and installs systemd units.

if [[ $(lsb_release -rs) != "22.04" ]]; then
  echo "[WARN] Ubuntu $(lsb_release -rs) detected. This script targets 22.04. Continuing..."
fi

if [[ $EUID -eq 0 ]]; then
  echo "[ERR] Do not run as root. Run as a sudo-enabled user."; exit 1
fi

USER_NAME="${SUDO_USER:-$USER}"
HOME_DIR="$(getent passwd "$USER_NAME" | cut -d: -f6)"
APP_DIR="$HOME_DIR/musafir-secops"
BIN_DIR="$APP_DIR/bin"
ENV_FILE="/etc/musafir.env"
NGINX_SITE="/etc/nginx/sites-available/musafir"
NGINX_SITE_LINK="/etc/nginx/sites-enabled/musafir"

log() { echo "[INFO] $*"; }
warn() { echo "[WARN] $*"; }
err() { echo "[ERR]  $*"; }

log "Updating system and installing prerequisites..."
sudo apt-get update -y
sudo apt-get install -y ca-certificates curl gnupg lsb-release git unzip apt-transport-https software-properties-common nginx jq

log "Installing Docker Engine and Compose plugin..."
sudo apt-get remove -y docker docker-engine docker.io containerd runc || true
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update -y
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker "$USER_NAME"

log "Installing Go 1.23..."
GO_TGZ="go1.23.0.linux-amd64.tar.gz"
curl -fsSLo "$GO_TGZ" https://go.dev/dl/go1.23.0.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf "$GO_TGZ"
rm -f "$GO_TGZ"
if ! grep -q "/usr/local/go/bin" "$HOME_DIR/.bashrc"; then
  echo 'export PATH=$PATH:/usr/local/go/bin' | tee -a "$HOME_DIR/.bashrc" >/dev/null
fi
export PATH=$PATH:/usr/local/go/bin

log "Installing Node.js 20 LTS..."
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

log "Preparing application directory at $APP_DIR..."
mkdir -p "$APP_DIR"
sudo chown -R "$USER_NAME":"$USER_NAME" "$APP_DIR"

if [[ ! -d "$APP_DIR/.git" ]]; then
  log "Cloning repo into $APP_DIR..."
  git clone https://github.com/arafatsolok/musafir-secops "$APP_DIR"
else
  log "Existing repo found; pulling latest..."
  git -C "$APP_DIR" pull --ff-only
fi

log "Creating environment file at $ENV_FILE..."
# Generate defaults, can be edited later
sudo tee "$ENV_FILE" > /dev/null <<EOF
# MUSAFIR environment
KAFKA_BROKERS=localhost:9092
CLICKHOUSE_DSN=tcp://localhost:9000?database=default
GATEWAY_JWT_SECRET=
GATEWAY_HMAC_SECRET=
PORT=8080
EOF
sudo chmod 0644 "$ENV_FILE"

log "Starting infrastructure via Docker Compose..."
cd "$APP_DIR/infra"
sudo docker compose -f docker-compose.yml up -d || true
# Precreate custom network used by advanced compose to avoid errors
sudo docker network create musafir-network || true
if [[ -f docker-compose-advanced.yml ]]; then
  sudo docker compose -f docker-compose-advanced.yml up -d || true
fi

log "Waiting 45s for infra to initialize (ClickHouse, Kafka, etc.)..."
sleep 45

log "Building gateway and services..."
cd "$APP_DIR"
mkdir -p "$BIN_DIR"

build_go() {
  local dir="$1" name="$2"
  if [[ -d "$dir" ]]; then
    log "Building $name..."
    (cd "$dir" && go mod tidy && go build -o "$BIN_DIR/$name") || { err "Failed to build $name"; exit 1; }
  fi
}

build_go gateway gateway
for svc in email forensics ml monitor ingest; do
  build_go "services/$svc" "$svc"
done

log "Building UI..."
cd "$APP_DIR/ui"
# Use npm install to avoid lockfile sync errors on fresh machines
npm install
npm run build
sudo rm -rf /var/www/musafir-ui
sudo mkdir -p /var/www/musafir-ui
sudo cp -r dist/* /var/www/musafir-ui/

log "Configuring Nginx for UI and reverse proxy to gateway..."
sudo tee "$NGINX_SITE" > /dev/null <<'NGINX'
server {
    listen 80;
    server_name _;

    root /var/www/musafir-ui;
    index index.html;

    location /api/ {
        proxy_pass http://127.0.0.1:8080/api/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_http_version 1.1;
    }

    location /v1/ {
        proxy_pass http://127.0.0.1:8080/v1/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_http_version 1.1;
    }

    location /ws {
        proxy_pass http://127.0.0.1:8080/ws;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host $host;
    }

    location / {
        try_files $uri $uri/ /index.html;
    }
}
NGINX

# Ensure our site is enabled and default is disabled
sudo rm -f /etc/nginx/sites-enabled/default || true
sudo ln -sf "$NGINX_SITE" "$NGINX_SITE_LINK" || true
sudo nginx -t && sudo systemctl reload nginx

log "Creating systemd services..."
# Gateway service
sudo tee /etc/systemd/system/musafir-gateway.service > /dev/null <<EOF
[Unit]
Description=MUSAFIR Gateway
After=network-online.target musafir-infra.service
Wants=network-online.target

[Service]
EnvironmentFile=$ENV_FILE
WorkingDirectory=$APP_DIR
ExecStart=$BIN_DIR/gateway
Restart=on-failure
RestartSec=5
User=$USER_NAME
Group=$USER_NAME

[Install]
WantedBy=multi-user.target
EOF

# Optional core services (only if built)
for svc in email forensics ml monitor ingest; do
  if [[ -f "$BIN_DIR/$svc" ]]; then
    sudo tee "/etc/systemd/system/musafir-$svc.service" > /dev/null <<EOF
[Unit]
Description=MUSAFIR $svc service
After=network-online.target musafir-infra.service
Wants=network-online.target

[Service]
EnvironmentFile=$ENV_FILE
WorkingDirectory=$APP_DIR
ExecStart=$BIN_DIR/$svc
Restart=on-failure
RestartSec=5
User=$USER_NAME
Group=$USER_NAME

[Install]
WantedBy=multi-user.target
EOF
  fi
done

# Infra compose unit
sudo tee /etc/systemd/system/musafir-infra.service > /dev/null <<EOF
[Unit]
Description=MUSAFIR Infra (Docker Compose)
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$APP_DIR/infra
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable musafir-infra.service
sudo systemctl enable musafir-gateway.service || true
for svc in email forensics ml monitor ingest; do
  if [[ -f "$BIN_DIR/$svc" ]]; then
    sudo systemctl enable "musafir-$svc.service" || true
  fi
done

log "Starting services..."
sudo systemctl start musafir-infra.service
sleep 30
sudo systemctl start musafir-gateway.service || true
for svc in email forensics ml monitor ingest; do
  if [[ -f "$BIN_DIR/$svc" ]]; then
    sudo systemctl start "musafir-$svc.service" || true
  fi
done

log "Ensuring secrets (auto-generate if missing)..."
sudo bash "$APP_DIR/scripts/setup-secrets.sh" || true

cat <<SUMMARY

===== MUSAFIR SecOps Installation Summary =====
User:          $USER_NAME
Repo:          $APP_DIR
Binaries:      $BIN_DIR
Environment:   $ENV_FILE
UI:            http://$(hostname -I | awk '{print $1}')/
Gateway API:   http://$(hostname -I | awk '{print $1}'):8080/

Systemd units:
  - musafir-infra.service (docker compose up -d)
  - musafir-gateway.service
  - musafir-{email,forensics,ml,monitor,ingest}.service (when built)

Next steps:
  - Edit $ENV_FILE to adjust secrets (GATEWAY_JWT_SECRET, GATEWAY_HMAC_SECRET)
  - JWT for UI calls: set localStorage.musafir_jwt in browser
  - Check statuses: sudo systemctl status musafir-gateway.service
  - Logs: journalctl -u musafir-gateway.service -f

SUMMARY

log "Running sanity checks..."

# 1) Gateway health
if curl -fsS http://localhost:8080/health >/dev/null; then
  echo "[PASS] Gateway health endpoint reachable"
else
  echo "[FAIL] Gateway health endpoint NOT reachable"
fi

# 2) Nginx site enabled
if ls -1 /etc/nginx/sites-enabled | grep -q '^musafir$'; then
  echo "[PASS] Nginx site 'musafir' enabled"
else
  echo "[FAIL] Nginx site 'musafir' not enabled"
fi

# 3) UI artifacts present
if [ -f /var/www/musafir-ui/index.html ]; then
  echo "[PASS] UI published to /var/www/musafir-ui (index.html found)"
else
  echo "[FAIL] UI not published to /var/www/musafir-ui"
fi

# 4) Gateway systemd status
if systemctl is-active --quiet musafir-gateway.service; then
  echo "[PASS] musafir-gateway.service is active"
else
  echo "[FAIL] musafir-gateway.service is NOT active"
fi

echo
echo "===== Credentials & Access ====="
if [ -f /etc/musafir.env ]; then
  # shellcheck disable=SC1091
  . /etc/musafir.env || true
  echo "Gateway Secrets (from /etc/musafir.env):"
  echo "  GATEWAY_JWT_SECRET: ${GATEWAY_JWT_SECRET:-<unset>}"
  echo "  GATEWAY_HMAC_SECRET: ${GATEWAY_HMAC_SECRET:-<unset>}"
  echo "  PORT: ${PORT:-8080}"
else
  echo "  /etc/musafir.env not found"
fi

echo
echo "Default service credentials (from docker-compose-advanced.yml):"
echo "  Grafana: admin / admin (http://<server_ip>:3001)"
echo "  RabbitMQ: musafir / musafir123 (http://<server_ip>:15672)"
echo "  MinIO: musafir / musafir123 (http://<server_ip>:9002)"
echo "  Neo4j: neo4j / password (http://<server_ip>:7474)"
echo "  Postgres: musafir / musafir123 (psql on 5432)"

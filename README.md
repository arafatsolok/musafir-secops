# MUSAFIR SecOps Platform

A production-grade, microservices-powered SecOps platform with a secure gateway, multi-database persistence, streaming pipeline, and a Central Web UI.

- Gateway: JWT on /api/*, HMAC validation for /v1/events, per-agent enrollment, WebSocket fan-out, correlation IDs, W3C traceparent propagation, rate limits, circuit breakers
- Services: email, forensics, ml, monitor, ingest (examples wired), each with /health and /metrics, graceful shutdown, idempotency, Kafka retries with DLQ, ClickHouse schema setup
- UI: Central Portal (live metrics via /ws), Management (Agent Enrollment page), Dashboards
- Agent: Windows endpoint agent with HMAC signed events, retries, on-disk queue, optional mTLS, heartbeats; enrollment-driven per-agent HMAC

## Architecture Overview

- Gateway (Go):
  - Routes /api/* (JWT required), /v1/events (HMAC), /v1/enroll (token-based)
  - WebSocket: /ws for live metrics/event broadcast
  - Admin APIs: /api/admin/* (JWT) including enrollment token generation
  - Observability: correlation IDs, structured logs, W3C traceparent
  - Persistence (ClickHouse): musafir_agents, musafir_enroll_tokens (created on startup if ClickHouse reachable)

- Services (Go): email, forensics, ml, monitor, ingest (examples)
  - Expose /health and /metrics
  - Kafka reader/writer configs with dialer timeouts, retries, and DLQ topics
  - ClickHouse: schema ensured on boot; use v2.15.0 driver
  - Graceful shutdown + idempotent processing (message hash cache)

- UI (React + Vite):
  - CentralPortal: health checks, WebSocket live metrics
  - Management → Agent Enrollment: generate enrollment token (JWT-protected), QR/link display
  - App injects Authorization: Bearer from localStorage.musafir_jwt

- Agent (Windows):
  - One EXE (agent.exe)
  - HMAC request signing, retry with exponential backoff + disk queue fallback, heartbeats
  - Optional mTLS (TLS_CERT_FILE/TLS_KEY_FILE/TLS_CA_FILE)
  - Enrollment flow: one-time token → per-agent HMAC issued by gateway

## Repositories and Layout (key paths)

- gateway/advanced_gateway.go – Gateway server
- services/* – Microservices (email, forensics, ml, monitor, ingest)
- ui/ – Central Portal + dashboards
- infra/ – Docker Compose and Prometheus config (advanced file included)
- scripts/ – Operational helpers
  - setup-secrets.sh – Ensure/generate GATEWAY_JWT_SECRET/HMAC and restart services
  - rotate-secrets.sh – Rotate JWT/HMAC and restart
  - print-secrets.sh – Display current secrets and agent instructions
- install_ubuntu_22_04.sh – Full automated installer for Ubuntu 22.04
- CONFIG.md – Environment variables reference
- QUICKSTART.md – Quick instructions for local dev

## Installation (Automated - Ubuntu 22.04)

Use a fresh Ubuntu 22.04 server.

1) Download & run installer
```
curl -fsSLO https://raw.githubusercontent.com/arafatsolok/musafir-secops/master/install_ubuntu_22_04.sh
bash install_ubuntu_22_04.sh
```

What it does:
- Installs Docker, Go 1.23, Node.js 20, Nginx
- Clones repo at ~/musafir-secops
- Starts infra via Docker Compose (infra/docker-compose.yml and advanced if present)
- Builds gateway/services/UI
- Deploys UI to Nginx (/var/www/musafir-ui) and reverse-proxies /api, /v1, /ws to gateway
- Creates systemd units:
  - musafir-infra.service (Docker Compose up/down)
  - musafir-gateway.service
  - musafir-{email,forensics,ml,monitor,ingest}.service (if built)
- Creates /etc/musafir.env and auto-generates GATEWAY_JWT_SECRET / GATEWAY_HMAC_SECRET

After completion, the script prints:
- UI URL (http://<server_ip>/)
- Gateway API (http://<server_ip>:8080/)
- Where to find/edit /etc/musafir.env, how to check status/logs

## Installation (Manual - Ubuntu 22.04)

1) Prereqs
- Install Docker Engine, docker compose plugin, Go 1.23, Node.js 20, Nginx

2) Clone and build
```
git clone https://github.com/arafatsolok/musafir-secops ~/musafir-secops
cd ~/musafir-secops
```
Start infra:
```
cd infra
sudo docker compose -f docker-compose.yml up -d
# optionally:
sudo docker compose -f docker-compose-advanced.yml up -d
```
Build gateway and services:
```
cd ~/musafir-secops
mkdir -p bin
(cd gateway && go mod tidy && go build -o ../bin/gateway)
for s in email forensics ml monitor ingest; do (cd services/$s && go mod tidy && go build -o ../../bin/$s) || true; done
```
Build UI:
```
cd ui
npm install
npm run build
sudo mkdir -p /var/www/musafir-ui
sudo cp -r dist/* /var/www/musafir-ui/
```
Configure Nginx (see install_ubuntu_22_04.sh for example server block) and reload Nginx.

3) Environment
Create /etc/musafir.env:
```
KAFKA_BROKERS=localhost:9092
CLICKHOUSE_DSN=tcp://localhost:9000?database=default
GATEWAY_JWT_SECRET=<random>
GATEWAY_HMAC_SECRET=<random>
PORT=8080
```
Use scripts to manage secrets:
```
sudo bash scripts/setup-secrets.sh     # generate if missing
sudo bash scripts/rotate-secrets.sh    # rotate anytime
sudo bash scripts/print-secrets.sh     # view
```
4) Run gateway and services (systemd or foreground):
- Systemd: copy unit examples from installer; enable and start
- Foreground (dev): `bin/gateway`

## Configuration

See CONFIG.md for complete variables. Highlights:
- Server (gateway): PORT, GATEWAY_JWT_SECRET, GATEWAY_HMAC_SECRET, CLICKHOUSE_DSN
- Services: KAFKA_BROKERS, CLICKHOUSE_DSN, KAFKA_GROUP
- UI: VITE_API_BASE, VITE_WS_URL, VITE_DEFAULT_JWT (build-time)

## Security

- JWT required for /api/* (admin/user UI calls)
- HMAC required for:
  - /v1/events (agent event ingest)
  - /api/agent/config (agent polling with headers X-Agent-Id, X-Timestamp, X-Signature)
- Enrollment tokens (short-lived) for /v1/enroll → gateway issues per-agent HMAC
- Correlation IDs, W3C traceparent propagation, structured logs (JSON-like)

## Agent Enrollment & Windows Install

1) Web UI → Management → Agent Enrollment → Generate Token
- Requires JWT (set localStorage.musafir_jwt)
- Shows token, enroll endpoint, QR

2) On Windows target:
- Download/place `agent.exe` (one binary)
- Start agent and paste:
  - Gateway URL (http://<server>:8080)
  - Enrollment Token
- Agent calls `/v1/enroll` → receives per-agent HMAC and config → switches to normal operation

3) Optional: run as Windows service via NSSM
- `nssm install MusafirAgent C:\Program Files\MusafirAgent\agent.exe`
- Configure stdout/stderr to `C:\Program Files\MusafirAgent\logs\...`

## Operations

- Start/Stop (systemd):
```
sudo systemctl start musafir-infra.service
sudo systemctl start musafir-gateway.service
sudo systemctl stop musafir-gateway.service
```
- Logs:
```
journalctl -u musafir-gateway.service -f
```
- Secrets:
```
sudo bash scripts/print-secrets.sh
sudo bash scripts/rotate-secrets.sh
```

## Troubleshooting

- UI blank / 401 on admin APIs: set a valid JWT in browser via `localStorage.musafir_jwt = "<token>"`.
- Agent enroll fails (401): token expired or invalid; generate a new token.
- Agent config 401: check headers X-Agent-Id/X-Timestamp/X-Signature; ensure timestamp is recent and signature built with the issued HMAC.
- Gateway can’t write agents to ClickHouse: verify CLICKHOUSE_DSN and infra containers are running; the gateway still functions with in-memory records.
- Kafka DLQ usage: check `musafir.dlq.*` topics for failed writes.
- Nginx 502 on /api: ensure `bin/gateway` is running and PORT matches Nginx upstream.

## Development

- Build all services:
```
for d in services/*; do (cd "$d" && go mod tidy && go build ./...) || true; done
```
- Run gateway locally: `cd gateway && go run .`
- UI dev: `cd ui && npm run dev`

## Roadmap

- Persist agent list and tokens via services instead of gateway direct ClickHouse writes (or use gRPC/service bus)
- Stronger admin auth & RBAC in UI
- Full agent inventory UI (list, status, last_seen, actions)
- mTLS-by-default agent option and key provisioning

---

For a quick local spin-up, see QUICKSTART.md. For environment variables, see CONFIG.md. For automated Ubuntu installs, use install_ubuntu_22_04.sh.

# MUSAFIR SecOps Platform (XDR • EDR • SIEM)

Next‑gen, all‑in‑one security platform: 30+ microservices, advanced detections, unified Central Portal, and full observability.

## 1) Quick Start (Windows)

Prereqs: Docker Desktop, Go 1.22+, Node.js 20+

- Build all: `./build.ps1`
- Run all: `./run.ps1`
- UI: http://localhost:3000

## 2) Quick Start (Ubuntu 22.04)

Prereqs: sudo user, internet access

```bash
# Clone and enter repo
cd ~
# (Create repo directory and copy files here if needed)

# Install & configure platform
chmod +x ubuntu-install.sh build-all.sh
./ubuntu-install.sh
./build-all.sh

# Start infra + services + UI
./start-all.sh
```

Access points:
- Central Portal/UI: http://localhost:3000
- Grafana: http://localhost:3001
- Prometheus: http://localhost:9090
- Jaeger: http://localhost:16686
- Neo4j Browser: http://localhost:7474
- RabbitMQ Management: http://localhost:15672
- MinIO Console: http://localhost:9002

## 3) Default Credentials

- Username: `musafir`
- Password: `Strong@!@#bdnews24#`

Applied to services where credentials are required (Grafana admin, RabbitMQ, MinIO, PostgreSQL URL, etc.). For production, store secrets in Vault/env files.

## 4) Central Portal

A unified landing page inside the UI that links to and monitors:
- Main Dashboard (UI)
- Grafana / Prometheus / Jaeger
- Neo4j Browser
- RabbitMQ Management
- MinIO Console

Features:
- Live service status checks
- Category filters and search
- One‑click open with displayed credentials

## 5) Architecture Overview

Core components:
- Gateway (rate‑limiting, auth, routing)
- 30+ services (ingest, detect, correlate, respond, cases, ueba, threatintel, ml, ai, email, identity, network, forensics, cache, graph, search, observability, vuln, compliance, slsa, tenant, mdm, yara, cloud, spire, sandbox, monitor)
- Databases: ClickHouse, Elasticsearch, Neo4j, Redis, PostgreSQL, MinIO
- Streaming/Queues: Redpanda (Kafka API), RabbitMQ
- Observability: Prometheus, Grafana, Jaeger

Data flow (simplified):
- Agents → Gateway (HTTP/mTLS) → Kafka → Services → Datastores → UI/Observability

## 6) Install, Build, Run (Details)

### Infrastructure (Docker Compose)
```bash
cd infra
# Start/stop infra
docker compose -f docker-compose-advanced.yml up -d
# Verify
docker compose -f docker-compose-advanced.yml ps
```

### Build microservices and gateway
```bash
# From repo root
chmod +x build-all.sh
./build-all.sh
```

### Start services and UI
```bash
./start-all.sh
# UI dev mode (from ui/):
# npm install && npm run dev:full
```

### Verify connectivity
```bash
# From repo root
./verify-connectivity.sh  # Linux/macOS
# Or run verify-connectivity.ps1 on Windows
```

## 7) Development

- GitHub Desktop: Add repo (D:\MW), commit, Publish to `arafatsolok/musafir-secops`.
- CI: GitHub Actions at `.github/workflows/ci.yml` builds Go services and UI on push/PR.
- Line endings: `.gitattributes` enforces LF for code; CRLF for Windows scripts.
- Ignore rules: `.gitignore` excludes binaries, node_modules, logs, env files.

## 8) Security Notes

- TLS/mTLS support for the agent → gateway path (configurable via env TLS_CERT_FILE/TLS_KEY_FILE/TLS_CA_FILE).
- Centralized credentials currently set via Docker Compose/env; move to secrets manager for production.
- UFW, sysctl, limits tuning included in Ubuntu workflow.

## 9) Troubleshooting

- If ports are busy, stop existing services or change mappings in `infra/docker-compose-advanced.yml`.
- If UI cannot reach services due to CORS, use `npm run dev:full` which also starts the proxy.
- For ClickHouse/Elasticsearch startup delays, re-run verify once containers are healthy.

## 10) Licensing

TBD

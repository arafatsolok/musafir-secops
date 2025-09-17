# Configuration Reference

This document summarizes the environment variables used across the MUSAFIR SecOps platform.

Set these via your process manager, container environment, or a local .env file (gateway loads .env via godotenv). UI uses Vite env variables (prefixed with VITE_).

## Common Infrastructure
- KAFKA_BROKERS: Comma-separated broker addresses (e.g., localhost:9092)
- CLICKHOUSE_DSN: ClickHouse DSN (e.g., tcp://localhost:9000?database=default)

## Security and Auth
- GATEWAY_JWT_SECRET: Secret for JWT verification in gateway
- GATEWAY_HMAC_SECRET: Shared HMAC secret for agent → gateway signed requests
- TLS_CERT_FILE: Path to TLS cert (PEM) (if using mTLS)
- TLS_KEY_FILE: Path to TLS key (PEM) (if using mTLS)
- TLS_CA_FILE: Path to CA cert (PEM) (if using mTLS)

## Gateway
- PORT: Optional gateway port (default 8080)
- GATEWAY_JWT_SECRET: JWT signing/verification secret
- GATEWAY_HMAC_SECRET: HMAC secret for /v1/events
- RATE_LIMIT_API: Optional global limit override (requests/sec)

Notes:
- Gateway enforces JWT on /api/* and HMAC (X-Timestamp, X-Signature) on /v1/events.
- Gateway forwards X-Correlation-Id, generates if missing, and propagates W3C traceparent.

## Agents
- AGENT_HMAC_SECRET: Shared secret matching GATEWAY_HMAC_SECRET
- GATEWAY_URL: https:// or http:// to gateway
- TLS_CERT_FILE / TLS_KEY_FILE / TLS_CA_FILE: For strict mTLS (optional)

## Services (email, forensics, ml, etc.)
- KAFKA_BROKERS: Kafka brokers
- KAFKA_GROUP: Consumer group name (service-specific default e.g., email, ml, forensics)
- CLICKHOUSE_DSN: ClickHouse DSN

Operational behavior in services:
- Each service exposes /health and /metrics on its service port.
- Services implement graceful shutdown and idempotent processing using a short-lived message hash cache.
- Kafka consumers/writers use dialer timeouts, backoff retries; persistent failures route to DLQ topics:
  - musafir.dlq.email
  - musafir.dlq.ml
  - musafir.dlq.forensics

## UI (Vite)
- VITE_API_BASE: API base, default http://localhost:8080
- VITE_WS_URL: WebSocket URL, default ws://localhost:8080/ws
- VITE_DEFAULT_JWT: Optional default JWT placed into localStorage by your app shell (or set manually via devtools)

Usage notes:
- In development, place a .env file in the gateway directory (loaded automatically). For other services, set environment variables via your shell, Docker Compose, or systemd.
- UI reads Vite envs at build time. For local testing, create a .env file in ui/ with the variables above (Vite format).

## Example (development)
KAFKA_BROKERS=localhost:9092
CLICKHOUSE_DSN=tcp://localhost:9000?database=default
GATEWAY_JWT_SECRET=changeme-dev
GATEWAY_HMAC_SECRET=changeme-dev

# UI (ui/.env)
VITE_API_BASE=http://localhost:8080
VITE_WS_URL=ws://localhost:8080/ws
VITE_DEFAULT_JWT=

# Agent
AGENT_HMAC_SECRET=changeme-dev
GATEWAY_URL=http://localhost:8080

# MUSAFIR SecOps - Quick Start

This guide helps you run the platform locally for development.

## Prerequisites
- Go 1.22+ (or 1.23)
- Node.js 18+ and npm
- Kafka and ClickHouse (local or container)

## Environment
- Copy relevant variables from CONFIG.md and export them in your shell, or create a .env in `gateway/`.
- Minimum set for local:
```
KAFKA_BROKERS=localhost:9092
CLICKHOUSE_DSN=tcp://localhost:9000?database=default
GATEWAY_JWT_SECRET=changeme-dev
GATEWAY_HMAC_SECRET=changeme-dev
```

## Start Gateway
```
cd gateway
go run .
```
- Gateway listens on http://localhost:8080
- WebSocket at ws://localhost:8080/ws
- JWT enforced on /api/* (set `Authorization: Bearer <token>`)
- HMAC required on /v1/events (X-Timestamp, X-Signature)

## Start Core Services (examples)
Open separate terminals:
```
cd services/email && go run .
cd services/forensics && go run .
cd services/ml && go run .
```
Each service exposes `/health` and `/metrics` on its port.

## Start UI
```
cd ui
npm install
npm run dev
```
- Open http://localhost:3000
- Central Portal checks service statuses and shows live gateway metrics via WebSocket.
- If JWT is enabled, set `localStorage.musafir_jwt = "<token>"` in your browser devtools.

## Optional: Build
```
# Gateway and services
cd gateway && go build ./...
# UI
cd ui && npm run build
```

## Notes
- Services use backoff/retry and DLQ topics on failures (`musafir.dlq.*`).
- Gateway propagates `X-Correlation-Id` and W3C `traceparent` headers downstream.

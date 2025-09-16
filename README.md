# MUSAFIR SecOps Platform (XDR • EDR • SIEM)

Next-gen, all-in-one security platform for ransomware-era defense. This monorepo will contain the agent, gateway, core services, UI, content, and infra.

## Phase 0 (MVP)
- Minimal Go agent producing process/file/network telemetry and basic actions (kill/isolate)
- Ingest gateway with mTLS
- Kafka/Redpanda + ClickHouse for streaming and search
- Basic rules and React dashboards

## Repo Layout
```
repo/
  agent/
  agent-plugins/
  gateway/
  services/
    ingest/
    correlate/
    detect/
    respond/
    cases/
  ui/
  content/
  infra/
  security/
```

## Quickstart (POC)
1. Start infra (Redpanda + ClickHouse): see `infra/docker-compose.yml`.
2. Build components:
   - Gateway: `go build ./gateway`
   - Agent: `go build ./agent`
3. Run gateway, then run agent pointing at the gateway.

## End-to-end (Windows PowerShell)
- Infra
  ```
  cd .\infra
  docker compose up -d
  ```
- Gateway (shell 1)
  ```
  cd ..\gateway
  $env:KAFKA_BROKERS="localhost:9092"
  $env:KAFKA_TOPIC="musafir.events"
  go build .
  .\gateway.exe
  ```
- Ingester (shell 2)
  ```
  cd .\services\ingest
  $env:KAFKA_BROKERS="localhost:9092"
  $env:KAFKA_TOPIC="musafir.events"
  $env:KAFKA_GROUP="ingest"
  $env:CLICKHOUSE_DSN="tcp://localhost:9000?database=default"
  go build .
  .\ingest.exe
  ```
- Agent (shell 3)
  ```
  cd .\agent
  $env:GATEWAY_URL="http://localhost:8080"
  go build .
  .\agent.exe
  ```

Once running, the agent posts a JSON envelope to the gateway, which publishes to Redpanda. The ingester consumes and inserts raw records into ClickHouse table `musafir_events_raw`.

## Licensing
TBD

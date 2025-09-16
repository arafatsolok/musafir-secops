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

## Licensing
TBD

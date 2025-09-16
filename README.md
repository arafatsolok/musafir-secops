# MUSAFIR SecOps Platform (XDR • EDR • SIEM)

Next-gen, all-in-one security platform for ransomware-era defense. This monorepo will contain the agent, gateway, core services, UI, content, and infra.

## Phase 0 (MVP) ✅
- Minimal Go agent producing process/file/network telemetry and basic actions (kill/isolate)
- Ingest gateway with mTLS
- Kafka/Redpanda + ClickHouse for streaming and search
- Basic rules and React dashboards

## Phase 1 (XDR Core) ✅
- UEBA (User & Entity Behavior Analytics) with anomaly detection
- Threat Intelligence integration with indicator matching
- XDR Correlation engine for attack pattern detection
- Multi-tenant alert correlation and attack chain analysis

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

## Quick Start (Windows PowerShell)

### Prerequisites
- Docker Desktop running
- Go 1.22+ installed
- Node.js 18+ installed

### Build Everything
```powershell
.\build.ps1
```

### Run Complete Platform
```powershell
.\run.ps1
```

This will start:
1. **Infrastructure**: Redpanda (Kafka) + ClickHouse
2. **Gateway**: HTTP API + Kafka publisher
3. **Ingester**: Kafka consumer → ClickHouse writer
4. **Detector**: Sigma rule engine → Alert generator
5. **UEBA**: User behavior analytics → Anomaly detection
6. **Threat Intel**: Threat indicator matching → TI alerts
7. **Correlator**: XDR correlation engine → Attack patterns
8. **Responder**: SOAR playbook executor
9. **Agent**: Event generator → Gateway
10. **UI**: React dashboard at http://localhost:3000

### Manual Run (if needed)
- Infra: `cd .\infra && docker compose up -d`
- Gateway: `cd .\bin && .\gateway.exe`
- Ingester: `cd .\bin && .\ingest.exe`
- Detector: `cd .\bin && .\detect.exe`
- Responder: `cd .\bin && .\respond.exe`
- Agent: `cd .\bin && .\agent.exe`
- UI: `cd .\ui && npm run dev`

### What Happens
1. Agent generates sample security events
2. Gateway receives events via HTTP POST `/v1/events`
3. Gateway publishes events to Kafka topic `musafir.events`
4. Ingester consumes from Kafka and stores in ClickHouse `musafir_events_raw`
5. Detector applies Sigma rules and generates alerts to `musafir.alerts`
6. UEBA analyzes user behavior and generates anomaly alerts to `musafir.ueba_alerts`
7. Threat Intel matches indicators and generates TI alerts to `musafir.ti_alerts`
8. Correlator analyzes all alerts and generates correlated attack patterns to `musafir.correlated_alerts`
9. Responder executes SOAR playbooks on correlated alerts
10. UI dashboard shows real-time events, alerts, and attack patterns

## Licensing
TBD

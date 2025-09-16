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

## Phase 2 (Advanced Features) ✅
- eBPF kernel monitoring for Linux (syscalls, file operations)
- macOS Endpoint Security Framework (ESF) integration
- Dynamic sandbox for malware analysis and detonation
- ML pipelines for anomaly detection and risk scoring
- MDM integration for mobile device management
- YARA integration for file scanning and malware detection
- KQL Query Workbench for advanced threat hunting
- Case Management system for incident response
- Ransomware canary files for early detection
- Cloud connectors (AWS/Azure/GCP) for multi-cloud security
- Advanced threat hunting and forensics capabilities

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
8. **Sandbox**: Dynamic malware analysis → Detonation results
9. **ML Service**: Machine learning → Risk predictions
10. **MDM Service**: Mobile device management → Device control
11. **YARA Service**: File scanning → Malware detection
12. **Cases Service**: Incident management → Case tracking
13. **Cloud Service**: Multi-cloud monitoring → Cloud events
14. **Responder**: SOAR playbook executor
15. **Agent**: Multi-platform event generator → Gateway
16. **UI**: React dashboard at http://localhost:3000

### Manual Run (if needed)
- Infra: `cd .\infra && docker compose up -d`
- Gateway: `cd .\bin && .\gateway.exe`
- Ingester: `cd .\bin && .\ingest.exe`
- Detector: `cd .\bin && .\detect.exe`
- Responder: `cd .\bin && .\respond.exe`
- Agent: `cd .\bin && .\agent.exe`
- UI: `cd .\ui && npm run dev`

### What Happens
1. **Multi-platform Agents** generate security events (Windows/Linux/macOS with eBPF/ESF)
2. **Gateway** receives events via HTTP POST `/v1/events` with mTLS
3. **Gateway** publishes events to Kafka topic `musafir.events`
4. **Ingester** consumes from Kafka and stores in ClickHouse `musafir_events_raw`
5. **Detector** applies Sigma rules and generates alerts to `musafir.alerts`
6. **UEBA** analyzes user behavior and generates anomaly alerts to `musafir.ueba_alerts`
7. **Threat Intel** matches indicators and generates TI alerts to `musafir.ti_alerts`
8. **Sandbox** analyzes suspicious files and generates detonation results to `musafir.sandbox_results`
9. **ML Service** applies machine learning and generates risk predictions to `musafir.ml_predictions`
10. **YARA Service** scans files and generates malware detection alerts to `musafir.yara_results`
11. **Cloud Service** monitors AWS/Azure/GCP and generates cloud security events to `musafir.cloud_events`
12. **Correlator** analyzes all alerts and generates correlated attack patterns to `musafir.correlated_alerts`
13. **Cases Service** auto-creates incident cases from high-severity alerts
14. **MDM Service** manages mobile devices and executes security policies
15. **Responder** executes SOAR playbooks on correlated alerts
16. **UI Dashboard** shows real-time events, alerts, attack patterns, ML insights, and KQL query workbench

## Licensing
TBD

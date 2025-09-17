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

## Phase 2 (Advanced Features) ✅ 100% Complete
- eBPF kernel monitoring for Linux (syscalls, file operations) ✅
- macOS Endpoint Security Framework (ESF) integration ✅
- Dynamic sandbox for malware analysis and detonation ✅
- ML pipelines for anomaly detection and risk scoring ✅
- MDM integration for mobile device management ✅
- YARA integration for file scanning and malware detection ✅
- KQL Query Workbench for advanced threat hunting ✅
- Case Management system for incident response ✅
- Ransomware canary files for early detection ✅
- Cloud connectors (AWS/Azure/GCP) for multi-cloud security ✅
- Network sensors (SPAN/TAP, eBPF exporters) for network monitoring ✅
- Email integrations (M365/Google) for email security ✅
- Identity integrations (AD/AAD/Okta) for user context ✅
- Vulnerability & Patch Management with SBOM analysis ✅
- Mobile agents (iOS/Android) for mobile device security ✅
- SPIFFE/SPIRE identity management for secure service communication ✅
- Compliance & Governance (ISO 27001, SOC2, GDPR, NIST, PCI DSS) ✅
- SLSA L3 supply chain security pipelines ✅
- Multi-tenant data isolation and management ✅
- Advanced AI-powered threat prediction and behavior analysis ✅
- Real-time platform monitoring with Prometheus metrics ✅
- Advanced threat hunting and forensics capabilities ✅
- Network traffic analysis and threat detection ✅
- Email security monitoring and threat analysis ✅
- Identity and access management monitoring ✅
- Forensic analysis and incident response ✅

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
14. **Network Service**: Network sensors → Network events
15. **Email Service**: Email connectors → Email events
16. **Identity Service**: Identity providers → Identity events
17. **Vulnerability Service**: Vuln scanning → Vuln events
18. **SPIRE Service**: Identity management → SPIFFE events
19. **Compliance Service**: Compliance monitoring → Compliance events
20. **SLSA Service**: Supply chain security → SLSA events
21. **Tenant Service**: Multi-tenant management → Tenant events
22. **Monitor Service**: Platform monitoring → Prometheus metrics
23. **AI Service**: Advanced AI insights → Threat predictions
24. **Network Service**: Network traffic analysis → Network alerts
25. **Email Service**: Email security monitoring → Email alerts
26. **Identity Service**: Identity and access management → Identity alerts
27. **Forensics Service**: Forensic analysis and incident response → Forensic analysis
28. **Responder**: SOAR playbook executor
29. **Agent**: Multi-platform event generator → Gateway
30. **UI**: React dashboard at http://localhost:3000

### Manual Run (if needed)
- Infra: `cd .\infra && docker compose up -d`
- Gateway: `cd .\bin && .\gateway.exe`
- Ingester: `cd .\bin && .\ingest.exe`
- Detector: `cd .\bin && .\detect.exe`
- Responder: `cd .\bin && .\respond.exe`
- Agent: `cd .\bin && .\agent.exe`
- UI: `cd .\ui && npm run dev`

### What Happens
1. **Multi-platform Agents** generate security events (Windows/Linux/macOS/iOS/Android with eBPF/ESF)
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
12. **Network Service** monitors network traffic and generates network events to `musafir.network_events`
13. **Email Service** monitors M365/Gmail and generates email events to `musafir.email_events`
14. **Identity Service** monitors AD/AAD/Okta and generates identity events to `musafir.identity_events`
15. **Vulnerability Service** scans for vulnerabilities and generates vuln events to `musafir.vuln_events`
16. **SPIRE Service** manages SPIFFE identities and generates identity events to `musafir.spire_events`
17. **Compliance Service** monitors compliance frameworks and generates compliance events to `musafir.compliance_events`
18. **SLSA Service** manages supply chain security and generates SLSA events to `musafir.slsa_events`
19. **Tenant Service** manages multi-tenant isolation and generates tenant events to `musafir.tenant_events`
20. **Monitor Service** tracks platform health and generates Prometheus metrics
21. **AI Service** provides advanced AI insights and threat predictions to `musafir.ai_insights`
22. **Network Service** monitors network traffic and generates network alerts to `musafir.network_alerts`
23. **Email Service** monitors email security and generates email alerts to `musafir.email_alerts`
24. **Identity Service** monitors identity and access management and generates identity alerts to `musafir.identity_alerts`
25. **Forensics Service** performs forensic analysis and generates forensic analysis results to `musafir.forensic_analysis`
26. **Correlator** analyzes all alerts and generates correlated attack patterns to `musafir.correlated_alerts`
27. **Cases Service** auto-creates incident cases from high-severity alerts
28. **MDM Service** manages mobile devices and executes security policies
29. **Responder** executes SOAR playbooks on correlated alerts
30. **UI Dashboard** shows real-time events, alerts, attack patterns, ML insights, AI predictions, and KQL query workbench

## Licensing
TBD

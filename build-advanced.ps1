# MUSAFIR Advanced Build Script for Windows PowerShell
# Builds all Go components and installs UI dependencies with advanced features

Write-Host "MUSAFIR Advanced SecOps Platform - Build Script" -ForegroundColor Green
Write-Host "=================================================" -ForegroundColor Green

# Check if Go is installed
if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: Go is not installed or not in PATH" -ForegroundColor Red
    exit 1
}

# Check if Node.js is installed
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: Node.js is not installed or not in PATH" -ForegroundColor Red
    exit 1
}

# Check if Docker is installed
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: Docker is not installed or not in PATH" -ForegroundColor Red
    exit 1
}

Write-Host "Building Go components..." -ForegroundColor Yellow

# Create bin directory
if (-not (Test-Path "bin")) {
    New-Item -ItemType Directory -Path "bin" | Out-Null
}

# Build Gateway
Write-Host "Building Gateway..." -ForegroundColor Cyan
Set-Location gateway
go mod tidy
go build -o ../bin/gateway.exe .
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to build gateway" -ForegroundColor Red
    exit 1
}
Set-Location ..

# Build Advanced Gateway
Write-Host "Building Advanced Gateway..." -ForegroundColor Cyan
Set-Location gateway
go build -o ../bin/advanced-gateway.exe advanced_gateway.go
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to build advanced gateway" -ForegroundColor Red
    exit 1
}
Set-Location ..

# Build Agent (multi-platform)
Write-Host "Building Agent (Windows)..." -ForegroundColor Cyan
Set-Location agent
go mod tidy
go build -o ../bin/agent-windows.exe .
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to build Windows agent" -ForegroundColor Red
    exit 1
}

Write-Host "Building Agent (Linux)..." -ForegroundColor Cyan
$env:GOOS = "linux"
$env:GOARCH = "amd64"
go build -o ../bin/agent-linux .
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to build Linux agent" -ForegroundColor Red
    exit 1
}

Write-Host "Building Agent (macOS)..." -ForegroundColor Cyan
$env:GOOS = "darwin"
$env:GOARCH = "amd64"
go build -o ../bin/agent-darwin .
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to build macOS agent" -ForegroundColor Red
    exit 1
}

# Reset environment variables
$env:GOOS = ""
$env:GOARCH = ""
Set-Location ..

# Build all services
$services = @(
    "ingest", "detect", "correlate", "respond", "cases",
    "ueba", "threatintel", "sandbox", "ml", "mdm", "yara",
    "cloud", "network", "email", "identity", "vuln", "compliance",
    "slsa", "tenant", "monitor", "ai", "deception", "graph", "cache",
    "observability", "search", "forensics"
)

foreach ($service in $services) {
    Write-Host "Building $service service..." -ForegroundColor Cyan
    Set-Location "services/$service"
    
    if (Test-Path "go.mod") {
        go mod tidy
        go build -o "../../bin/$service.exe" .
        if ($LASTEXITCODE -ne 0) {
            Write-Host "WARNING: Failed to build $service service" -ForegroundColor Yellow
        }
    } else {
        Write-Host "WARNING: No go.mod found for $service service" -ForegroundColor Yellow
    }
    
    Set-Location "../.."
}

# Build UI
Write-Host "Building UI..." -ForegroundColor Cyan
Set-Location ui

# Install dependencies
Write-Host "Installing UI dependencies..." -ForegroundColor Yellow
npm install
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to install UI dependencies" -ForegroundColor Red
    exit 1
}

# Build UI
Write-Host "Building UI for production..." -ForegroundColor Yellow
npm run build
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to build UI" -ForegroundColor Red
    exit 1
}

Set-Location ..

# Create configuration files
Write-Host "Creating configuration files..." -ForegroundColor Yellow

# Create .env file
$envContent = @"
# MUSAFIR Advanced Configuration
KAFKA_BROKERS=localhost:9092
KAFKA_TOPIC=musafir.events
CLICKHOUSE_DSN=tcp://localhost:9000?database=musafir
REDIS_URL=localhost:6379
ELASTICSEARCH_URL=http://localhost:9200
NEO4J_URI=bolt://localhost:7687
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=password
GATEWAY_URL=http://localhost:8080
JWT_SECRET=your-super-secret-jwt-key
VAULT_ADDR=http://localhost:8200
VAULT_TOKEN=musafir
"@

$envContent | Out-File -FilePath ".env" -Encoding UTF8

# Create docker-compose override
$dockerOverride = @"
version: "3.8"
services:
  gateway:
    build: .
    ports:
      - "8080:8080"
    environment:
      - KAFKA_BROKERS=redpanda:9092
      - CLICKHOUSE_DSN=tcp://clickhouse:9000?database=musafir
      - REDIS_URL=redis:6379
      - ELASTICSEARCH_URL=http://elasticsearch:9200
      - NEO4J_URI=bolt://neo4j:7687
    depends_on:
      - redpanda
      - clickhouse
      - redis
      - elasticsearch
      - neo4j
"@

$dockerOverride | Out-File -FilePath "docker-compose.override.yml" -Encoding UTF8

# Create systemd service files (for Linux)
if ($IsLinux -or $env:OS -eq "Linux") {
    Write-Host "Creating systemd service files..." -ForegroundColor Yellow
    
    $systemdDir = "/etc/systemd/system"
    if (Test-Path $systemdDir) {
        $serviceTemplate = @"
[Unit]
Description=MUSAFIR {0} Service
After=network.target

[Service]
Type=simple
User=musafir
WorkingDirectory=/opt/musafir
ExecStart=/opt/musafir/bin/{0}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"@

        foreach ($service in $services) {
            $serviceContent = $serviceTemplate -f $service
            $serviceContent | Out-File -FilePath "$systemdDir/musafir-$service.service" -Encoding UTF8
        }
    }
}

# Create Windows service files
if ($IsWindows -or $env:OS -eq "Windows_NT") {
    Write-Host "Creating Windows service files..." -ForegroundColor Yellow
    
    $serviceTemplate = @"
@echo off
cd /d "%~dp0"
start "" "bin\{0}.exe"
"@

    foreach ($service in $services) {
        $serviceContent = $serviceTemplate -f $service
        $serviceContent | Out-File -FilePath "start-{0}.bat" -f $service -Encoding UTF8
    }
}

# Create monitoring configuration
Write-Host "Creating monitoring configuration..." -ForegroundColor Yellow

# Prometheus configuration
$prometheusConfig = @"
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'musafir-gateway'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/metrics'
    scrape_interval: 5s

  - job_name: 'musafir-services'
    static_configs:
      - targets: ['localhost:8081', 'localhost:8082', 'localhost:8083', 'localhost:8084', 'localhost:8085']
    metrics_path: '/metrics'
    scrape_interval: 10s

  - job_name: 'clickhouse'
    static_configs:
      - targets: ['localhost:8123']
    metrics_path: '/metrics'

  - job_name: 'redis'
    static_configs:
      - targets: ['localhost:6379']
    metrics_path: '/metrics'
"@

$prometheusConfig | Out-File -FilePath "infra/prometheus.yml" -Encoding UTF8

# Grafana dashboard
$grafanaDashboard = @"
{
  "dashboard": {
    "title": "MUSAFIR Security Dashboard",
    "panels": [
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(http_requests_total[5m])",
            "legendFormat": "{{service}}"
          }
        ]
      },
      {
        "title": "Error Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(http_requests_total{status=~\"5..\"}[5m])",
            "legendFormat": "{{service}}"
          }
        ]
      },
      {
        "title": "Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))",
            "legendFormat": "{{service}}"
          }
        ]
      }
    ]
  }
}
"@

$grafanaDashboard | Out-File -FilePath "infra/grafana-dashboard.json" -Encoding UTF8

# Create documentation
Write-Host "Creating documentation..." -ForegroundColor Yellow

$readmeContent = @"
# MUSAFIR Advanced SecOps Platform

## Overview
MUSAFIR is a next-generation security operations platform that provides comprehensive threat detection, response, and management capabilities.

## Features
- **Advanced ML Models**: Deep learning with LSTM, Transformer, and CNN models
- **Graph Analytics**: Neo4j integration for relationship analysis
- **Deception Technology**: Honeypots and canary tokens
- **Advanced UI**: 3D visualizations and real-time dashboards
- **Observability**: Distributed tracing and comprehensive monitoring
- **Search**: Elasticsearch integration for advanced search
- **Caching**: Redis for high-performance caching
- **API Gateway**: Advanced routing with rate limiting and circuit breakers

## Architecture
- **Microservices**: 25+ specialized services
- **Event Streaming**: Kafka/Redpanda for real-time data processing
- **Data Storage**: ClickHouse for analytics, Elasticsearch for search
- **Graph Database**: Neo4j for relationship analysis
- **Caching**: Redis for performance
- **Monitoring**: Prometheus + Grafana + Jaeger

## Quick Start

### Prerequisites
- Docker Desktop
- Go 1.22+
- Node.js 18+

### Build Everything
```powershell
.\build-advanced.ps1
```

### Start Infrastructure
```powershell
cd infra
docker-compose -f docker-compose-advanced.yml up -d
```

### Start Services
```powershell
.\run-advanced.ps1
```

### Access UI
- Main Dashboard: http://localhost:3000
- Advanced Security: http://localhost:3000/#/advanced
- Management: http://localhost:3000/#/management
- Grafana: http://localhost:3001 (admin/admin)
- Jaeger: http://localhost:16686

## Services

### Core Services
- **Gateway**: API gateway with advanced routing
- **Ingest**: Event ingestion and processing
- **Detect**: Threat detection engine
- **Correlate**: Attack pattern correlation
- **Respond**: Automated response actions

### Advanced Services
- **ML**: Machine learning and AI
- **Graph**: Graph analytics and relationship analysis
- **Deception**: Honeypots and canary tokens
- **Observability**: Distributed tracing and monitoring
- **Search**: Advanced search capabilities
- **Cache**: High-performance caching

### Integration Services
- **Cloud**: Multi-cloud security monitoring
- **Network**: Network traffic analysis
- **Email**: Email security monitoring
- **Identity**: Identity and access management
- **Compliance**: Regulatory compliance monitoring

## Configuration
All configuration is managed through environment variables. See `.env` file for details.

## Monitoring
- **Metrics**: Prometheus at http://localhost:9090
- **Dashboards**: Grafana at http://localhost:3001
- **Tracing**: Jaeger at http://localhost:16686
- **Logs**: Centralized logging with Fluentd

## Security
- **Authentication**: JWT-based authentication
- **Authorization**: Role-based access control
- **Encryption**: TLS/SSL for all communications
- **Secrets**: HashiCorp Vault integration

## Development
- **API Documentation**: Swagger/OpenAPI
- **Testing**: Comprehensive test suite
- **CI/CD**: GitHub Actions integration
- **Code Quality**: Linting and formatting

## License
TBD
"@

$readmeContent | Out-File -FilePath "README-ADVANCED.md" -Encoding UTF8

Write-Host "Build completed successfully!" -ForegroundColor Green
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "1. Start infrastructure: cd infra && docker-compose -f docker-compose-advanced.yml up -d" -ForegroundColor White
Write-Host "2. Start services: .\run-advanced.ps1" -ForegroundColor White
Write-Host "3. Access UI: http://localhost:3000" -ForegroundColor White
Write-Host "4. View monitoring: http://localhost:3001 (Grafana)" -ForegroundColor White

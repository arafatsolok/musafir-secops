# MUSAFIR Setup Guide

## Prerequisites

### 1. Install Go 1.22+
Download from https://golang.org/dl/ and install. Verify:
```powershell
go version
```

### 2. Install Node.js 18+
Download from https://nodejs.org/ and install. Verify:
```powershell
node --version
npm --version
```

### 3. Install Docker Desktop
Download from https://www.docker.com/products/docker-desktop/ and start it.

### 4. Install OpenSSL (for certificates)
Download from https://slproweb.com/products/Win32OpenSSL.html or use WSL:
```powershell
# In WSL or Git Bash
openssl version
```

## Quick Start

1. **Clone and setup**:
   ```powershell
   git clone <your-repo>
   cd musafir
   ```

2. **Generate certificates** (optional, for mTLS):
   ```powershell
   cd security/certs
   .\generate-certs.ps1
   cd ..\..
   ```

3. **Build everything**:
   ```powershell
   .\build.ps1
   ```

4. **Run the platform**:
   ```powershell
   .\run.ps1
   ```

5. **Access the dashboard**:
   - Open http://localhost:3000
   - Gateway health: http://localhost:8080/healthz
   - ClickHouse: http://localhost:8123

## Manual Run (if needed)

1. **Start infrastructure**:
   ```powershell
   cd infra
   docker compose up -d
   cd ..
   ```

2. **Set environment variables**:
   ```powershell
   $env:KAFKA_BROKERS = "localhost:9092"
   $env:KAFKA_TOPIC = "musafir.events"
   $env:KAFKA_GROUP_INGEST = "ingest"
   $env:KAFKA_GROUP_DETECT = "detect"
   $env:KAFKA_GROUP_RESPOND = "respond"
   $env:CLICKHOUSE_DSN = "tcp://localhost:9000?database=default"
   $env:GATEWAY_URL = "http://localhost:8080"
   ```

3. **Run components** (in separate terminals):
   ```powershell
   # Terminal 1 - Gateway
   .\bin\gateway-windows.exe

   # Terminal 2 - Ingester
   .\bin\ingest.exe

   # Terminal 3 - Detector
   .\bin\detect.exe

   # Terminal 4 - Responder
   .\bin\respond.exe

   # Terminal 5 - Agent
   .\bin\agent-windows.exe

   # Terminal 6 - UI
   cd ui
   npm run dev
   ```

## Troubleshooting

- **Go not found**: Add Go to PATH or restart terminal
- **Docker not running**: Start Docker Desktop
- **Port conflicts**: Check if ports 3000, 8080, 8123, 9092 are free
- **Certificate errors**: Run without mTLS first (no TLS env vars)

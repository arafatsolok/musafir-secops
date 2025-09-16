# MUSAFIR Run Script for Windows PowerShell
# Starts all components in the correct order

Write-Host "MUSAFIR SecOps Platform - Run Script" -ForegroundColor Green
Write-Host "====================================" -ForegroundColor Green

# Check if Docker is running
if (-not (Get-Process "Docker Desktop" -ErrorAction SilentlyContinue)) {
    Write-Host "WARNING: Docker Desktop may not be running" -ForegroundColor Yellow
}

# Start infrastructure
Write-Host "Starting infrastructure (Redpanda + ClickHouse)..." -ForegroundColor Yellow
Set-Location infra
docker compose up -d
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to start infrastructure" -ForegroundColor Red
    exit 1
}
Write-Host "Waiting for services to be ready..." -ForegroundColor Yellow
Start-Sleep -Seconds 10
Set-Location ..

# Set environment variables
$env:KAFKA_BROKERS = "localhost:9092"
$env:KAFKA_TOPIC = "musafir.events"
$env:KAFKA_GROUP_INGEST = "ingest"
$env:KAFKA_GROUP_DETECT = "detect"
$env:KAFKA_GROUP_RESPOND = "respond"
$env:KAFKA_GROUP_UEBA = "ueba"
$env:KAFKA_GROUP_THREATINTEL = "threatintel"
$env:KAFKA_GROUP_CORRELATE = "correlate"
$env:KAFKA_GROUP_ML = "ml"
$env:KAFKA_GROUP_SANDBOX = "sandbox"
$env:KAFKA_GROUP_MDM = "mdm"
$env:KAFKA_GROUP_YARA = "yara"
$env:KAFKA_GROUP_CASES = "cases"
$env:KAFKA_GROUP_CLOUD = "cloud"
$env:KAFKA_GROUP_NETWORK = "network"
$env:KAFKA_GROUP_EMAIL = "email"
$env:KAFKA_GROUP_IDENTITY = "identity"
$env:KAFKA_GROUP_VULN = "vuln"
$env:SANDBOX_TOPIC = "musafir.sandbox_requests"
$env:YARA_TOPIC = "musafir.yara_requests"
$env:CLICKHOUSE_DSN = "tcp://localhost:9000?database=default"
$env:GATEWAY_URL = "http://localhost:8080"

Write-Host "Starting MUSAFIR components..." -ForegroundColor Yellow

# Start Gateway
Write-Host "Starting Gateway..." -ForegroundColor Cyan
Start-Process -FilePath ".\bin\gateway.exe" -WindowStyle Normal
Start-Sleep -Seconds 2

# Start Ingester
Write-Host "Starting Ingester..." -ForegroundColor Cyan
Start-Process -FilePath ".\bin\ingest.exe" -WindowStyle Normal
Start-Sleep -Seconds 2

# Start Detector
Write-Host "Starting Detector..." -ForegroundColor Cyan
Start-Process -FilePath ".\bin\detect.exe" -WindowStyle Normal
Start-Sleep -Seconds 2

# Start Responder
Write-Host "Starting Responder..." -ForegroundColor Cyan
Start-Process -FilePath ".\bin\respond.exe" -WindowStyle Normal
Start-Sleep -Seconds 2

# Start UEBA
Write-Host "Starting UEBA..." -ForegroundColor Cyan
Start-Process -FilePath ".\bin\ueba.exe" -WindowStyle Normal
Start-Sleep -Seconds 2

# Start Threat Intel
Write-Host "Starting Threat Intel..." -ForegroundColor Cyan
Start-Process -FilePath ".\bin\threatintel.exe" -WindowStyle Normal
Start-Sleep -Seconds 2

# Start Correlator
Write-Host "Starting Correlator..." -ForegroundColor Cyan
Start-Process -FilePath ".\bin\correlate.exe" -WindowStyle Normal
Start-Sleep -Seconds 2

# Start Sandbox
Write-Host "Starting Sandbox..." -ForegroundColor Cyan
Start-Process -FilePath ".\bin\sandbox.exe" -WindowStyle Normal
Start-Sleep -Seconds 2

# Start ML Service
Write-Host "Starting ML Service..." -ForegroundColor Cyan
Start-Process -FilePath ".\bin\ml.exe" -WindowStyle Normal
Start-Sleep -Seconds 2

# Start MDM Service
Write-Host "Starting MDM Service..." -ForegroundColor Cyan
Start-Process -FilePath ".\bin\mdm.exe" -WindowStyle Normal
Start-Sleep -Seconds 2

# Start YARA Service
Write-Host "Starting YARA Service..." -ForegroundColor Cyan
Start-Process -FilePath ".\bin\yara.exe" -WindowStyle Normal
Start-Sleep -Seconds 2

# Start Cases Service
Write-Host "Starting Cases Service..." -ForegroundColor Cyan
Start-Process -FilePath ".\bin\cases.exe" -WindowStyle Normal
Start-Sleep -Seconds 2

# Start Cloud Service
Write-Host "Starting Cloud Service..." -ForegroundColor Cyan
Start-Process -FilePath ".\bin\cloud.exe" -WindowStyle Normal
Start-Sleep -Seconds 2

# Start Network Service
Write-Host "Starting Network Service..." -ForegroundColor Cyan
Start-Process -FilePath ".\bin\network.exe" -WindowStyle Normal
Start-Sleep -Seconds 2

# Start Email Service
Write-Host "Starting Email Service..." -ForegroundColor Cyan
Start-Process -FilePath ".\bin\email.exe" -WindowStyle Normal
Start-Sleep -Seconds 2

# Start Identity Service
Write-Host "Starting Identity Service..." -ForegroundColor Cyan
Start-Process -FilePath ".\bin\identity.exe" -WindowStyle Normal
Start-Sleep -Seconds 2

# Start Vulnerability Service
Write-Host "Starting Vulnerability Service..." -ForegroundColor Cyan
Start-Process -FilePath ".\bin\vuln.exe" -WindowStyle Normal
Start-Sleep -Seconds 2

# Start Agent
Write-Host "Starting Agent..." -ForegroundColor Cyan
Start-Process -FilePath ".\bin\agent-windows.exe" -WindowStyle Normal

# Start UI (in development mode)
Write-Host "Starting UI..." -ForegroundColor Cyan
Set-Location ui
Start-Process -FilePath "npm" -ArgumentList "run", "dev" -WindowStyle Normal
Set-Location ..

Write-Host "All components started!" -ForegroundColor Green
Write-Host "Dashboard: http://localhost:3000" -ForegroundColor Green
Write-Host "Gateway Health: http://localhost:8080/healthz" -ForegroundColor Green
Write-Host "ClickHouse: http://localhost:8123" -ForegroundColor Green
Write-Host ""
Write-Host "Press any key to stop all services..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

# Stop all processes
Write-Host "Stopping services..." -ForegroundColor Yellow
Get-Process | Where-Object {$_.ProcessName -match "gateway|agent|ingest|detect|respond|ueba|threatintel|correlate|sandbox|ml|mdm|yara|cases|cloud|network|email|identity|vuln"} | Stop-Process -Force
docker compose -f infra/docker-compose.yml down

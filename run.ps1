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
Get-Process | Where-Object {$_.ProcessName -match "gateway|agent|ingest|detect|respond|ueba|threatintel|correlate"} | Stop-Process -Force
docker compose -f infra/docker-compose.yml down

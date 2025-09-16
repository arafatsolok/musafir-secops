# MUSAFIR Build Script for Windows PowerShell
# Builds all Go components and installs UI dependencies

Write-Host "MUSAFIR SecOps Platform - Build Script" -ForegroundColor Green
Write-Host "=====================================" -ForegroundColor Green

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

Write-Host "Building Go components..." -ForegroundColor Yellow

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
go build -o ../bin/agent-macos .
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to build macOS agent" -ForegroundColor Red
    exit 1
}

# Reset environment
$env:GOOS = ""
$env:GOARCH = ""
Set-Location ..

# Build Ingester
Write-Host "Building Ingester..." -ForegroundColor Cyan
Set-Location services/ingest
go mod tidy
go build -o ../../bin/ingest.exe .
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to build ingester" -ForegroundColor Red
    exit 1
}
Set-Location ../..

# Build Detector
Write-Host "Building Detector..." -ForegroundColor Cyan
Set-Location services/detect
go mod tidy
go build -o ../../bin/detect.exe .
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to build detector" -ForegroundColor Red
    exit 1
}
Set-Location ../..

# Build Responder
Write-Host "Building Responder..." -ForegroundColor Cyan
Set-Location services/respond
go mod tidy
go build -o ../../bin/respond.exe .
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to build responder" -ForegroundColor Red
    exit 1
}
Set-Location ../..

# Build UEBA
Write-Host "Building UEBA..." -ForegroundColor Cyan
Set-Location services/ueba
go mod tidy
go build -o ../../bin/ueba.exe .
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to build UEBA" -ForegroundColor Red
    exit 1
}
Set-Location ../..

# Build Threat Intel
Write-Host "Building Threat Intel..." -ForegroundColor Cyan
Set-Location services/threatintel
go mod tidy
go build -o ../../bin/threatintel.exe .
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to build threat intel" -ForegroundColor Red
    exit 1
}
Set-Location ../..

# Build Correlator
Write-Host "Building Correlator..." -ForegroundColor Cyan
Set-Location services/correlate
go mod tidy
go build -o ../../bin/correlate.exe .
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to build correlator" -ForegroundColor Red
    exit 1
}
Set-Location ../..

# Build Sandbox
Write-Host "Building Sandbox..." -ForegroundColor Cyan
Set-Location services/sandbox
go mod tidy
go build -o ../../bin/sandbox.exe .
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to build sandbox" -ForegroundColor Red
    exit 1
}
Set-Location ../..

# Build ML Service
Write-Host "Building ML Service..." -ForegroundColor Cyan
Set-Location services/ml
go mod tidy
go build -o ../../bin/ml.exe .
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to build ML service" -ForegroundColor Red
    exit 1
}
Set-Location ../..

# Build MDM Service
Write-Host "Building MDM Service..." -ForegroundColor Cyan
Set-Location services/mdm
go mod tidy
go build -o ../../bin/mdm.exe .
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to build MDM service" -ForegroundColor Red
    exit 1
}
Set-Location ../..

# Build YARA Service
Write-Host "Building YARA Service..." -ForegroundColor Cyan
Set-Location services/yara
go mod tidy
go build -o ../../bin/yara.exe .
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to build YARA service" -ForegroundColor Red
    exit 1
}
Set-Location ../..

# Build Cases Service
Write-Host "Building Cases Service..." -ForegroundColor Cyan
Set-Location services/cases
go mod tidy
go build -o ../../bin/cases.exe .
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to build Cases service" -ForegroundColor Red
    exit 1
}
Set-Location ../..

# Build Cloud Service
Write-Host "Building Cloud Service..." -ForegroundColor Cyan
Set-Location services/cloud
go mod tidy
go build -o ../../bin/cloud.exe .
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to build Cloud service" -ForegroundColor Red
    exit 1
}
Set-Location ../..

# Build UI
Write-Host "Building UI..." -ForegroundColor Cyan
Set-Location ui
if (-not (Test-Path node_modules)) {
    Write-Host "Installing UI dependencies..." -ForegroundColor Yellow
    npm install
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Failed to install UI dependencies" -ForegroundColor Red
        exit 1
    }
}
npm run build
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to build UI" -ForegroundColor Red
    exit 1
}
Set-Location ..

Write-Host "Build completed successfully!" -ForegroundColor Green
Write-Host "Binaries are in the 'bin' directory" -ForegroundColor Green
Write-Host "UI build is in the 'ui/dist' directory" -ForegroundColor Green

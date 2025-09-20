# MUSAFIR Central Platform - Development Setup Script (Windows)
# This script sets up the development environment on Windows

param(
    [switch]$SkipPrerequisites,
    [switch]$Verbose
)

# Set error action preference
$ErrorActionPreference = "Stop"

# Colors for output
$Colors = @{
    Red = "Red"
    Green = "Green"
    Yellow = "Yellow"
    Blue = "Blue"
    White = "White"
}

# Function to print colored output
function Write-Status {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor $Colors.Blue
}

function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor $Colors.Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor $Colors.Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor $Colors.Red
}

# Function to check if command exists
function Test-Command {
    param([string]$Command)
    try {
        Get-Command $Command -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

# Function to compare versions
function Compare-Version {
    param(
        [string]$Version1,
        [string]$Version2
    )
    
    $v1 = [System.Version]::Parse($Version1)
    $v2 = [System.Version]::Parse($Version2)
    
    return $v1.CompareTo($v2)
}

Write-Status "Starting MUSAFIR Central Platform development setup..."

# Check prerequisites
if (-not $SkipPrerequisites) {
    Write-Status "Checking prerequisites..."

    # Check Go
    if (Test-Command "go") {
        $goVersion = (go version) -replace "go version go", "" -replace " .*", ""
        if ((Compare-Version $goVersion "1.21.0") -ge 0) {
            Write-Success "Go $goVersion is installed"
        }
        else {
            Write-Error "Go version $goVersion is too old. Please install Go 1.21 or later"
            exit 1
        }
    }
    else {
        Write-Error "Go is not installed. Please install Go 1.21 or later"
        exit 1
    }

    # Check Node.js
    if (Test-Command "node") {
        $nodeVersion = (node --version) -replace "v", ""
        if ((Compare-Version $nodeVersion "18.0.0") -ge 0) {
            Write-Success "Node.js $nodeVersion is installed"
        }
        else {
            Write-Error "Node.js version $nodeVersion is too old. Please install Node.js 18 or later"
            exit 1
        }
    }
    else {
        Write-Error "Node.js is not installed. Please install Node.js 18 or later"
        exit 1
    }

    # Check npm
    if (Test-Command "npm") {
        $npmVersion = npm --version
        Write-Success "npm $npmVersion is installed"
    }
    else {
        Write-Error "npm is not installed. Please install npm"
        exit 1
    }

    # Check Docker
    if (Test-Command "docker") {
        $dockerVersion = (docker --version) -replace "Docker version ", "" -replace ",.*", ""
        Write-Success "Docker $dockerVersion is installed"
    }
    else {
        Write-Error "Docker is not installed. Please install Docker Desktop"
        exit 1
    }

    # Check Docker Compose
    if (Test-Command "docker-compose") {
        $composeVersion = (docker-compose --version) -replace "docker-compose version ", "" -replace ",.*", ""
        Write-Success "Docker Compose $composeVersion is installed"
    }
    elseif (docker compose version 2>$null) {
        $composeVersion = docker compose version --short
        Write-Success "Docker Compose $composeVersion is installed"
    }
    else {
        Write-Error "Docker Compose is not installed. Please install Docker Compose"
        exit 1
    }

    # Check Git
    if (Test-Command "git") {
        $gitVersion = (git --version) -replace "git version ", ""
        Write-Success "Git $gitVersion is installed"
    }
    else {
        Write-Error "Git is not installed. Please install Git"
        exit 1
    }

    # Optional tools
    Write-Status "Checking optional tools..."

    if (Test-Command "make") {
        Write-Success "Make is installed"
    }
    else {
        Write-Warning "Make is not installed. Some convenience commands may not work. Consider installing chocolatey and running 'choco install make'"
    }

    if (Test-Command "kubectl") {
        Write-Success "kubectl is installed"
    }
    else {
        Write-Warning "kubectl is not installed. Kubernetes deployment commands will not work"
    }
}

# Create necessary directories
Write-Status "Creating project directories..."

$directories = @(
    "backend\cmd\api-gateway",
    "backend\cmd\event-processor",
    "backend\cmd\analytics-engine",
    "backend\cmd\notification-service",
    "backend\internal\auth",
    "backend\internal\events",
    "backend\internal\analytics",
    "backend\internal\storage",
    "backend\internal\websocket",
    "backend\pkg\config",
    "backend\pkg\logger",
    "backend\pkg\utils",
    "backend\api",
    "frontend\src\components",
    "frontend\src\pages",
    "frontend\src\services",
    "frontend\src\store",
    "frontend\src\utils",
    "frontend\public",
    "deployments\docker",
    "deployments\kubernetes",
    "deployments\terraform",
    "deployments\monitoring\prometheus",
    "deployments\monitoring\grafana\dashboards",
    "deployments\monitoring\grafana\provisioning",
    "deployments\nginx\conf.d",
    "docs",
    "scripts",
    "logs"
)

foreach ($dir in $directories) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
}

Write-Success "Project directories created"

# Create environment files
Write-Status "Creating environment configuration files..."

# Backend environment
$backendEnv = @"
# Database Configuration
MONGODB_URI=mongodb://musafir:musafir123@localhost:27017/musafir?authSource=admin
INFLUXDB_URL=http://localhost:8086
INFLUXDB_TOKEN=musafir-super-secret-auth-token
INFLUXDB_ORG=musafir-org
INFLUXDB_BUCKET=events
REDIS_URL=redis://:musafir123@localhost:6379/0

# Message Queue
KAFKA_BROKERS=localhost:9092

# Security
VAULT_ADDR=http://localhost:8200
VAULT_TOKEN=musafir-vault-token
JWT_SECRET=musafir-jwt-super-secret-key
TLS_CERT_FILE=
TLS_KEY_FILE=
TLS_CA_FILE=

# API Configuration
API_PORT=8080
API_HOST=0.0.0.0
CORS_ORIGINS=http://localhost:3000

# Logging
LOG_LEVEL=debug
LOG_FORMAT=json

# Monitoring
PROMETHEUS_PORT=9091
METRICS_ENABLED=true

# Email Configuration (for notifications)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
"@

$backendEnv | Out-File -FilePath "backend\.env.development" -Encoding UTF8

# Frontend environment
$frontendEnv = @"
# API Configuration
REACT_APP_API_URL=http://localhost:8080
REACT_APP_WS_URL=ws://localhost:8080/ws

# Application Configuration
REACT_APP_NAME=MUSAFIR Central Platform
REACT_APP_VERSION=1.0.0
REACT_APP_ENVIRONMENT=development

# Feature Flags
REACT_APP_ENABLE_ANALYTICS=true
REACT_APP_ENABLE_NOTIFICATIONS=true
REACT_APP_ENABLE_DARK_MODE=true

# Monitoring
REACT_APP_SENTRY_DSN=
REACT_APP_GOOGLE_ANALYTICS_ID=
"@

$frontendEnv | Out-File -FilePath "frontend\.env.development" -Encoding UTF8

Write-Success "Environment files created"

# Create monitoring configuration
Write-Status "Creating monitoring configuration..."

# Prometheus configuration
$prometheusConfig = @"
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  # - "first_rules.yml"
  # - "second_rules.yml"

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'musafir-api-gateway'
    static_configs:
      - targets: ['api-gateway:9091']

  - job_name: 'musafir-event-processor'
    static_configs:
      - targets: ['event-processor:9091']

  - job_name: 'musafir-analytics-engine'
    static_configs:
      - targets: ['analytics-engine:9091']

  - job_name: 'musafir-notification-service'
    static_configs:
      - targets: ['notification-service:9091']

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']
"@

$prometheusConfig | Out-File -FilePath "deployments\monitoring\prometheus.yml" -Encoding UTF8

# Grafana provisioning
New-Item -ItemType Directory -Path "deployments\monitoring\grafana\provisioning\dashboards" -Force | Out-Null
New-Item -ItemType Directory -Path "deployments\monitoring\grafana\provisioning\datasources" -Force | Out-Null

$grafanaDatasource = @"
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
"@

$grafanaDatasource | Out-File -FilePath "deployments\monitoring\grafana\provisioning\datasources\prometheus.yml" -Encoding UTF8

$grafanaDashboard = @"
apiVersion: 1

providers:
  - name: 'default'
    orgId: 1
    folder: ''
    type: file
    disableDeletion: false
    updateIntervalSeconds: 10
    allowUiUpdates: true
    options:
      path: /var/lib/grafana/dashboards
"@

$grafanaDashboard | Out-File -FilePath "deployments\monitoring\grafana\provisioning\dashboards\dashboard.yml" -Encoding UTF8

Write-Success "Monitoring configuration created"

# Create NGINX configuration
Write-Status "Creating NGINX configuration..."

$nginxConfig = @"
events {
    worker_connections 1024;
}

http {
    upstream api_backend {
        server api-gateway:8080;
    }

    upstream frontend {
        server frontend:3000;
    }

    server {
        listen 80;
        server_name localhost;

        # Frontend
        location / {
            proxy_pass http://frontend;
            proxy_set_header Host `$host;
            proxy_set_header X-Real-IP `$remote_addr;
            proxy_set_header X-Forwarded-For `$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto `$scheme;
        }

        # API
        location /api/ {
            proxy_pass http://api_backend/;
            proxy_set_header Host `$host;
            proxy_set_header X-Real-IP `$remote_addr;
            proxy_set_header X-Forwarded-For `$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto `$scheme;
        }

        # WebSocket
        location /ws {
            proxy_pass http://api_backend/ws;
            proxy_http_version 1.1;
            proxy_set_header Upgrade `$http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host `$host;
            proxy_set_header X-Real-IP `$remote_addr;
            proxy_set_header X-Forwarded-For `$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto `$scheme;
        }
    }
}
"@

$nginxConfig | Out-File -FilePath "deployments\nginx\nginx.conf" -Encoding UTF8

Write-Success "NGINX configuration created"

# Create database initialization script
Write-Status "Creating database initialization scripts..."

$mongoInit = @"
// MongoDB initialization script
db = db.getSiblingDB('musafir');

// Create collections
db.createCollection('users');
db.createCollection('events');
db.createCollection('alerts');
db.createCollection('assets');
db.createCollection('tenants');

// Create indexes
db.events.createIndex({ "ts": 1 });
db.events.createIndex({ "tenant_id": 1 });
db.events.createIndex({ "asset.id": 1 });
db.events.createIndex({ "event.class": 1 });
db.events.createIndex({ "event.severity": 1 });

db.alerts.createIndex({ "timestamp": 1 });
db.alerts.createIndex({ "tenant_id": 1 });
db.alerts.createIndex({ "severity": 1 });
db.alerts.createIndex({ "status": 1 });

db.users.createIndex({ "email": 1 }, { unique: true });
db.users.createIndex({ "tenant_id": 1 });

db.assets.createIndex({ "id": 1, "tenant_id": 1 }, { unique: true });
db.assets.createIndex({ "tenant_id": 1 });
db.assets.createIndex({ "type": 1 });

db.tenants.createIndex({ "id": 1 }, { unique: true });

print('MongoDB initialized successfully');
"@

$mongoInit | Out-File -FilePath "scripts\mongo-init.js" -Encoding UTF8

Write-Success "Database initialization scripts created"

# Install backend dependencies
Write-Status "Installing backend dependencies..."
Push-Location backend
try {
    go mod tidy
    go mod download
    Write-Success "Backend dependencies installed"
}
catch {
    Write-Error "Failed to install backend dependencies: $_"
}
finally {
    Pop-Location
}

# Install frontend dependencies
Write-Status "Installing frontend dependencies..."
Push-Location frontend
try {
    npm install
    Write-Success "Frontend dependencies installed"
}
catch {
    Write-Error "Failed to install frontend dependencies: $_"
}
finally {
    Pop-Location
}

# Create Git hooks
if (Test-Path ".git") {
    Write-Status "Setting up Git hooks..."
    Push-Location frontend
    try {
        npx husky install
        npx husky add .husky/pre-commit "cd frontend && npm run lint:check && npm run prettier:check && npm run type-check"
        Write-Success "Git hooks configured"
    }
    catch {
        Write-Warning "Failed to configure Git hooks: $_"
    }
    finally {
        Pop-Location
    }
}

# Create helpful scripts
Write-Status "Creating helper scripts..."

# Development start script
$devStartScript = @"
# MUSAFIR Central Platform - Development Start Script (Windows)
Write-Host "Starting MUSAFIR Central Platform development environment..." -ForegroundColor Green

# Start infrastructure services
docker-compose up -d mongodb influxdb redis kafka zookeeper prometheus grafana vault elasticsearch kibana

Write-Host "Waiting for services to be ready..." -ForegroundColor Yellow
Start-Sleep -Seconds 30

Write-Host "Services started successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Available services:" -ForegroundColor Blue
Write-Host "  - MongoDB: localhost:27017"
Write-Host "  - InfluxDB: localhost:8086"
Write-Host "  - Redis: localhost:6379"
Write-Host "  - Kafka: localhost:9092"
Write-Host "  - Prometheus: localhost:9090"
Write-Host "  - Grafana: localhost:3001 (admin/musafir123)"
Write-Host "  - Vault: localhost:8200"
Write-Host "  - Elasticsearch: localhost:9200"
Write-Host "  - Kibana: localhost:5601"
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Run 'make backend-run-gateway' in one terminal"
Write-Host "  2. Run 'make frontend-dev' in another terminal"
Write-Host "  3. Access the application at http://localhost:3000"
"@

$devStartScript | Out-File -FilePath "scripts\dev-start.ps1" -Encoding UTF8

Write-Success "Helper scripts created"

# Final setup
Write-Status "Performing final setup..."

# Create logs directory
New-Item -ItemType Directory -Path "logs" -Force | Out-Null

Write-Success "Development environment setup completed!"

Write-Host ""
Write-Host "🎉 MUSAFIR Central Platform development environment is ready!" -ForegroundColor Green
Write-Host ""
Write-Host "Quick start commands:" -ForegroundColor Blue
Write-Host "  make dev          # Start full development environment"
Write-Host "  make dev-up       # Start infrastructure services only"
Write-Host "  make backend-deps # Install backend dependencies"
Write-Host "  make frontend-deps# Install frontend dependencies"
Write-Host "  make help         # Show all available commands"
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Run 'make dev' to start the development environment"
Write-Host "  2. Open http://localhost:3000 in your browser"
Write-Host "  3. Check the documentation in the docs/ directory"
Write-Host ""
Write-Host "Happy coding! 🚀" -ForegroundColor Green
# MUSAFIR Advanced Run Script for Windows PowerShell
# Starts all services with advanced features

Write-Host "MUSAFIR Advanced SecOps Platform - Run Script" -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Green

# Check if infrastructure is running
Write-Host "Checking infrastructure..." -ForegroundColor Yellow

$infraServices = @("redpanda", "clickhouse", "redis", "elasticsearch", "neo4j")
$infraRunning = $true

foreach ($service in $infraServices) {
    $container = docker ps --filter "name=$service" --format "table {{.Names}}" | Select-String $service
    if (-not $container) {
        Write-Host "WARNING: $service is not running. Please start infrastructure first:" -ForegroundColor Yellow
        Write-Host "cd infra && docker-compose -f docker-compose-advanced.yml up -d" -ForegroundColor White
        $infraRunning = $false
    }
}

if (-not $infraRunning) {
    Write-Host "Please start infrastructure first, then run this script again." -ForegroundColor Red
    exit 1
}

Write-Host "Infrastructure is running. Starting services..." -ForegroundColor Green

# Create logs directory
if (-not (Test-Path "logs")) {
    New-Item -ItemType Directory -Path "logs" | Out-Null
}

# Start services in order
$services = @(
    @{Name="gateway"; Port="8080"; Priority=1},
    @{Name="monitor"; Port="9090"; Priority=2},
    @{Name="ingest"; Port="8081"; Priority=3},
    @{Name="detect"; Port="8082"; Priority=4},
    @{Name="correlate"; Port="8083"; Priority=5},
    @{Name="respond"; Port="8084"; Priority=6},
    @{Name="cases"; Port="8085"; Priority=7},
    @{Name="ueba"; Port="8086"; Priority=8},
    @{Name="threatintel"; Port="8087"; Priority=9},
    @{Name="ml"; Port="8088"; Priority=10},
    @{Name="ai"; Port="8089"; Priority=11},
    @{Name="deception"; Port="8090"; Priority=12},
    @{Name="graph"; Port="8091"; Priority=13},
    @{Name="cache"; Port="8092"; Priority=14},
    @{Name="observability"; Port="8093"; Priority=15},
    @{Name="search"; Port="8094"; Priority=16},
    @{Name="forensics"; Port="8095"; Priority=17}
)

# Sort by priority
$services = $services | Sort-Object Priority

# Start each service
foreach ($service in $services) {
    $exePath = "bin\$($service.Name).exe"
    
    if (Test-Path $exePath) {
        Write-Host "Starting $($service.Name) service on port $($service.Port)..." -ForegroundColor Cyan
        
        # Set environment variables
        $env:KAFKA_BROKERS = "localhost:9092"
        $env:CLICKHOUSE_DSN = "tcp://localhost:9000?database=musafir"
        $env:REDIS_URL = "localhost:6379"
        $env:ELASTICSEARCH_URL = "http://localhost:9200"
        $env:NEO4J_URI = "bolt://localhost:7687"
        $env:NEO4J_USERNAME = "neo4j"
        $env:NEO4J_PASSWORD = "password"
        $env:GATEWAY_URL = "http://localhost:8080"
        $env:JWT_SECRET = "your-super-secret-jwt-key"
        
        # Start service in background
        $logFile = "logs\$($service.Name).log"
        Start-Process -FilePath $exePath -RedirectStandardOutput $logFile -RedirectStandardError $logFile -WindowStyle Hidden
        
        # Wait a moment for service to start
        Start-Sleep -Seconds 2
        
        # Check if service is responding
        $maxRetries = 10
        $retryCount = 0
        $serviceRunning = $false
        
        while ($retryCount -lt $maxRetries) {
            try {
                $response = Invoke-WebRequest -Uri "http://localhost:$($service.Port)/health" -TimeoutSec 5 -ErrorAction SilentlyContinue
                if ($response.StatusCode -eq 200) {
                    $serviceRunning = $true
                    break
                }
            } catch {
                # Service not ready yet
            }
            
            $retryCount++
            Start-Sleep -Seconds 1
        }
        
        if ($serviceRunning) {
            Write-Host "✓ $($service.Name) service started successfully" -ForegroundColor Green
        } else {
            Write-Host "⚠ $($service.Name) service started but health check failed" -ForegroundColor Yellow
        }
    } else {
        Write-Host "⚠ $($service.Name) executable not found at $exePath" -ForegroundColor Yellow
    }
}

# Start UI
Write-Host "Starting UI..." -ForegroundColor Cyan
Set-Location ui

if (Test-Path "package.json") {
    # Check if node_modules exists
    if (-not (Test-Path "node_modules")) {
        Write-Host "Installing UI dependencies..." -ForegroundColor Yellow
        npm install
    }
    
    # Start UI in background
    $uiLogFile = "../logs/ui.log"
    Start-Process -FilePath "npm" -ArgumentList "run", "dev" -RedirectStandardOutput $uiLogFile -RedirectStandardError $uiLogFile -WindowStyle Hidden
    
    # Wait for UI to start
    Start-Sleep -Seconds 5
    
    # Check if UI is running
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:3000" -TimeoutSec 10 -ErrorAction SilentlyContinue
        if ($response.StatusCode -eq 200) {
            Write-Host "✓ UI started successfully" -ForegroundColor Green
        }
    } catch {
        Write-Host "⚠ UI started but may not be ready yet" -ForegroundColor Yellow
    }
} else {
    Write-Host "⚠ UI package.json not found" -ForegroundColor Yellow
}

Set-Location ..

# Display status
Write-Host "`nMUSAFIR Advanced Platform Status:" -ForegroundColor Green
Write-Host "=================================" -ForegroundColor Green

# Check service status
foreach ($service in $services) {
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:$($service.Port)/health" -TimeoutSec 2 -ErrorAction SilentlyContinue
        if ($response.StatusCode -eq 200) {
            Write-Host "✓ $($service.Name): http://localhost:$($service.Port)" -ForegroundColor Green
        } else {
            Write-Host "⚠ $($service.Name): http://localhost:$($service.Port) (unhealthy)" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "✗ $($service.Name): http://localhost:$($service.Port) (not responding)" -ForegroundColor Red
    }
}

# Check UI
try {
    $response = Invoke-WebRequest -Uri "http://localhost:3000" -TimeoutSec 2 -ErrorAction SilentlyContinue
    if ($response.StatusCode -eq 200) {
        Write-Host "✓ UI: http://localhost:3000" -ForegroundColor Green
    } else {
        Write-Host "⚠ UI: http://localhost:3000 (unhealthy)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "✗ UI: http://localhost:3000 (not responding)" -ForegroundColor Red
}

# Display access information
Write-Host "`nAccess Information:" -ForegroundColor Yellow
Write-Host "==================" -ForegroundColor Yellow
Write-Host "Main Dashboard: http://localhost:3000" -ForegroundColor White
Write-Host "Advanced Security: http://localhost:3000/#/advanced" -ForegroundColor White
Write-Host "Management: http://localhost:3000/#/management" -ForegroundColor White
Write-Host "Query Workbench: http://localhost:3000/#/query" -ForegroundColor White
Write-Host "API Gateway: http://localhost:8080" -ForegroundColor White
Write-Host "Grafana: http://localhost:3001 (admin/admin)" -ForegroundColor White
Write-Host "Jaeger: http://localhost:16686" -ForegroundColor White
Write-Host "Elasticsearch: http://localhost:9200" -ForegroundColor White
Write-Host "Neo4j: http://localhost:7474 (neo4j/password)" -ForegroundColor White

Write-Host "`nLogs are available in the 'logs' directory" -ForegroundColor Cyan
Write-Host "To stop all services, press Ctrl+C" -ForegroundColor Cyan

# Keep script running
Write-Host "`nPress Ctrl+C to stop all services..." -ForegroundColor Yellow
try {
    while ($true) {
        Start-Sleep -Seconds 10
        
        # Check if any service has stopped
        $stoppedServices = @()
        foreach ($service in $services) {
            try {
                $response = Invoke-WebRequest -Uri "http://localhost:$($service.Port)/health" -TimeoutSec 1 -ErrorAction SilentlyContinue
            } catch {
                $stoppedServices += $service.Name
            }
        }
        
        if ($stoppedServices.Count -gt 0) {
            Write-Host "WARNING: The following services have stopped: $($stoppedServices -join ', ')" -ForegroundColor Yellow
        }
    }
} catch {
    Write-Host "`nShutting down..." -ForegroundColor Yellow
    
    # Kill all service processes
    Get-Process | Where-Object {$_.ProcessName -like "*musafir*" -or $_.ProcessName -like "*gateway*" -or $_.ProcessName -like "*ingest*" -or $_.ProcessName -like "*detect*" -or $_.ProcessName -like "*correlate*" -or $_.ProcessName -like "*respond*" -or $_.ProcessName -like "*cases*" -or $_.ProcessName -like "*ueba*" -or $_.ProcessName -like "*threatintel*" -or $_.ProcessName -like "*ml*" -or $_.ProcessName -like "*ai*" -or $_.ProcessName -like "*deception*" -or $_.ProcessName -like "*graph*" -or $_.ProcessName -like "*cache*" -or $_.ProcessName -like "*observability*" -or $_.ProcessName -like "*search*"} | Stop-Process -Force -ErrorAction SilentlyContinue
    
    Write-Host "All services stopped." -ForegroundColor Green
}

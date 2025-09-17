# MUSAFIR SecOps Platform - Connectivity Verification Script
# This script verifies all services, databases, and web interfaces are properly connected

Write-Host "🔍 MUSAFIR SecOps Platform - Connectivity Verification" -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan

# Function to test HTTP endpoint
function Test-Endpoint {
    param(
        [string]$Name,
        [string]$Url,
        [int]$ExpectedStatus = 200
    )
    
    try {
        $response = Invoke-WebRequest -Uri $Url -Method GET -TimeoutSec 5 -UseBasicParsing
        if ($response.StatusCode -eq $ExpectedStatus) {
            Write-Host "✅ $Name - $Url (Status: $($response.StatusCode))" -ForegroundColor Green
            return $true
        } else {
            Write-Host "❌ $Name - $Url (Status: $($response.StatusCode), Expected: $ExpectedStatus)" -ForegroundColor Red
            return $false
        }
    } catch {
        Write-Host "❌ $Name - $Url (Error: $($_.Exception.Message))" -ForegroundColor Red
        return $false
    }
}

# Function to test TCP port
function Test-Port {
    param(
        [string]$Name,
        [string]$HostName = "localhost",
        [int]$Port
    )
    
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.Connect($HostName, $Port)
        $tcpClient.Close()
        Write-Host "✅ $Name - $HostName`:$Port" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "❌ $Name - $HostName`:$Port (Error: $($_.Exception.Message))" -ForegroundColor Red
        return $false
    }
}

Write-Host "`n🌐 Testing Web Interfaces..." -ForegroundColor Yellow
$webTests = @(
    @{Name="Main Dashboard"; Url="http://localhost:3000"},
    @{Name="Grafana"; Url="http://localhost:3001"},
    @{Name="Prometheus"; Url="http://localhost:9090"},
    @{Name="Jaeger"; Url="http://localhost:16686"},
    @{Name="Neo4j Browser"; Url="http://localhost:7474"},
    @{Name="Elasticsearch"; Url="http://localhost:9200"},
    @{Name="RabbitMQ Management"; Url="http://localhost:15672"},
    @{Name="MinIO Console"; Url="http://localhost:9002"}
)

$webSuccess = 0
foreach ($test in $webTests) {
    if (Test-Endpoint -Name $test.Name -Url $test.Url) {
        $webSuccess++
    }
}

Write-Host "`n🗄️ Testing Database Connections..." -ForegroundColor Yellow
$dbTests = @(
    @{Name="ClickHouse HTTP"; HostName="localhost"; Port=8123},
    @{Name="ClickHouse Native"; HostName="localhost"; Port=9000},
    @{Name="Elasticsearch HTTP"; HostName="localhost"; Port=9200},
    @{Name="Elasticsearch Transport"; HostName="localhost"; Port=9300},
    @{Name="Neo4j HTTP"; HostName="localhost"; Port=7474},
    @{Name="Neo4j Bolt"; HostName="localhost"; Port=7687},
    @{Name="Redis"; HostName="localhost"; Port=6379},
    @{Name="PostgreSQL"; HostName="localhost"; Port=5432},
    @{Name="MinIO API"; HostName="localhost"; Port=9001},
    @{Name="MinIO Console"; HostName="localhost"; Port=9002}
)

$dbSuccess = 0
foreach ($test in $dbTests) {
    if (Test-Port -Name $test.Name -HostName $test.HostName -Port $test.Port) {
        $dbSuccess++
    }
}

Write-Host "`n📡 Testing Message Queues..." -ForegroundColor Yellow
$queueTests = @(
    @{Name="Redpanda Kafka"; HostName="localhost"; Port=9092},
    @{Name="Redpanda Admin"; HostName="localhost"; Port=9644},
    @{Name="RabbitMQ AMQP"; HostName="localhost"; Port=5672},
    @{Name="RabbitMQ Management"; HostName="localhost"; Port=15672}
)

$queueSuccess = 0
foreach ($test in $queueTests) {
    if (Test-Port -Name $test.Name -HostName $test.HostName -Port $test.Port) {
        $queueSuccess++
    }
}

Write-Host "`n🔧 Testing Core Services..." -ForegroundColor Yellow
$coreServices = @(
    @{Name="Gateway"; Port=8080},
    @{Name="Ingest"; Port=8081},
    @{Name="Detect"; Port=8082},
    @{Name="Correlate"; Port=8083},
    @{Name="Respond"; Port=8084},
    @{Name="Cases"; Port=8085},
    @{Name="UEBA"; Port=8086},
    @{Name="ThreatIntel"; Port=8087},
    @{Name="ML"; Port=8088},
    @{Name="AI"; Port=8089}
)

$coreSuccess = 0
foreach ($service in $coreServices) {
    if (Test-Port -Name $service.Name -HostName "localhost" -Port $service.Port) {
        $coreSuccess++
    }
}

Write-Host "`n🚀 Testing Advanced Services..." -ForegroundColor Yellow
$advancedServices = @(
    @{Name="Deception"; Port=8090},
    @{Name="Graph"; Port=8091},
    @{Name="Cache"; Port=8092},
    @{Name="Observability"; Port=8093},
    @{Name="Search"; Port=8094},
    @{Name="Forensics"; Port=8095},
    @{Name="Network"; Port=8096},
    @{Name="Email"; Port=8097},
    @{Name="Identity"; Port=8098},
    @{Name="Vuln"; Port=8099},
    @{Name="Compliance"; Port=8100},
    @{Name="SLSA"; Port=8101},
    @{Name="Tenant"; Port=8102},
    @{Name="MDM"; Port=8103},
    @{Name="YARA"; Port=8104},
    @{Name="Cloud"; Port=8105},
    @{Name="SPIRE"; Port=8106}
)

$advancedSuccess = 0
foreach ($service in $advancedServices) {
    if (Test-Port -Name $service.Name -HostName "localhost" -Port $service.Port) {
        $advancedSuccess++
    }
}

Write-Host "`n📊 Testing Monitoring Services..." -ForegroundColor Yellow
$monitoringServices = @(
    @{Name="Monitor"; Port=9090},
    @{Name="Prometheus"; Port=9090},
    @{Name="Grafana"; Port=3001},
    @{Name="Jaeger"; Port=16686}
)

$monitoringSuccess = 0
foreach ($service in $monitoringServices) {
    if (Test-Port -Name $service.Name -HostName "localhost" -Port $service.Port) {
        $monitoringSuccess++
    }
}

# Calculate totals
$totalWebTests = $webTests.Count
$totalDbTests = $dbTests.Count
$totalQueueTests = $queueTests.Count
$totalCoreTests = $coreServices.Count
$totalAdvancedTests = $advancedServices.Count
$totalMonitoringTests = $monitoringServices.Count

$totalTests = $totalWebTests + $totalDbTests + $totalQueueTests + $totalCoreTests + $totalAdvancedTests + $totalMonitoringTests
$totalSuccess = $webSuccess + $dbSuccess + $queueSuccess + $coreSuccess + $advancedSuccess + $monitoringSuccess

# Display summary
Write-Host "`n📈 CONNECTIVITY SUMMARY" -ForegroundColor Cyan
Write-Host "=====================" -ForegroundColor Cyan
Write-Host "Web Interfaces: $webSuccess/$totalWebTests" -ForegroundColor $(if ($webSuccess -eq $totalWebTests) { "Green" } else { "Yellow" })
Write-Host "Databases: $dbSuccess/$totalDbTests" -ForegroundColor $(if ($dbSuccess -eq $totalDbTests) { "Green" } else { "Yellow" })
Write-Host "Message Queues: $queueSuccess/$totalQueueTests" -ForegroundColor $(if ($queueSuccess -eq $totalQueueTests) { "Green" } else { "Yellow" })
Write-Host "Core Services: $coreSuccess/$totalCoreTests" -ForegroundColor $(if ($coreSuccess -eq $totalCoreTests) { "Green" } else { "Yellow" })
Write-Host "Advanced Services: $advancedSuccess/$totalAdvancedTests" -ForegroundColor $(if ($advancedSuccess -eq $totalAdvancedTests) { "Green" } else { "Yellow" })
Write-Host "Monitoring Services: $monitoringSuccess/$totalMonitoringTests" -ForegroundColor $(if ($monitoringSuccess -eq $totalMonitoringTests) { "Green" } else { "Yellow" })

Write-Host "`n🎯 OVERALL RESULT: $totalSuccess/$totalTests" -ForegroundColor $(if ($totalSuccess -eq $totalTests) { "Green" } else { "Yellow" })

if ($totalSuccess -eq $totalTests) {
    Write-Host "`n🎉 ALL SYSTEMS OPERATIONAL!" -ForegroundColor Green
    Write-Host "The MUSAFIR SecOps Platform is fully connected and operational." -ForegroundColor Green
    Write-Host "`n🌐 Access the web interface at: http://localhost:3000" -ForegroundColor Cyan
} else {
    Write-Host "`n⚠️  SOME SERVICES ARE NOT RUNNING" -ForegroundColor Yellow
    Write-Host "Please check the failed services and restart them if needed." -ForegroundColor Yellow
    Write-Host "`n💡 To start all services, run:" -ForegroundColor Cyan
    Write-Host "   .\run-advanced.ps1" -ForegroundColor White
}

Write-Host "`n📚 For more information, see:" -ForegroundColor Cyan
Write-Host "   - DATABASE_ARCHITECTURE.md" -ForegroundColor White
Write-Host "   - WEB_INTERFACE_GUIDE.md" -ForegroundColor White
Write-Host "   - README.md" -ForegroundColor White

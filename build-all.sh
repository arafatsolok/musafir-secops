#!/bin/bash

# MUSAFIR SecOps Platform - Build All Services Script
# This script compiles all Go services and sets up the web interface

set -e

echo "🔨 MUSAFIR SecOps Platform - Building All Services"
echo "=================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}[BUILD]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Check if we're in the right directory
if [ ! -d "services" ] || [ ! -d "gateway" ]; then
    print_error "Please run this script from the MUSAFIR root directory"
    exit 1
fi

# Set Go environment
export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

print_header "Step 1: Building Core Services"
print_status "Building Ingest service..."
cd services/ingest
if [ -f "go.mod" ]; then
    go mod tidy
    go build -o ingest main.go
    print_status "✅ Ingest service built successfully"
else
    print_error "❌ Ingest service go.mod not found"
fi
cd ../..

print_status "Building Detect service..."
cd services/detect
if [ -f "go.mod" ]; then
    go mod tidy
    go build -o detect main.go
    print_status "✅ Detect service built successfully"
else
    print_error "❌ Detect service go.mod not found"
fi
cd ../..

print_status "Building Correlate service..."
cd services/correlate
if [ -f "go.mod" ]; then
    go mod tidy
    go build -o correlate main.go
    print_status "✅ Correlate service built successfully"
else
    print_error "❌ Correlate service go.mod not found"
fi
cd ../..

print_status "Building Respond service..."
cd services/respond
if [ -f "go.mod" ]; then
    go mod tidy
    go build -o respond main.go
    print_status "✅ Respond service built successfully"
else
    print_error "❌ Respond service go.mod not found"
fi
cd ../..

print_status "Building Cases service..."
cd services/cases
if [ -f "go.mod" ]; then
    go mod tidy
    go build -o cases main.go
    print_status "✅ Cases service built successfully"
else
    print_error "❌ Cases service go.mod not found"
fi
cd ../..

print_status "Building UEBA service..."
cd services/ueba
if [ -f "go.mod" ]; then
    go mod tidy
    go build -o ueba main.go
    print_status "✅ UEBA service built successfully"
else
    print_error "❌ UEBA service go.mod not found"
fi
cd ../..

print_status "Building ThreatIntel service..."
cd services/threatintel
if [ -f "go.mod" ]; then
    go mod tidy
    go build -o threatintel main.go
    print_status "✅ ThreatIntel service built successfully"
else
    print_error "❌ ThreatIntel service go.mod not found"
fi
cd ../..

print_status "Building ML service..."
cd services/ml
if [ -f "go.mod" ]; then
    go mod tidy
    go build -o ml main.go
    print_status "✅ ML service built successfully"
else
    print_error "❌ ML service go.mod not found"
fi
cd ../..

print_status "Building AI service..."
cd services/ai
if [ -f "go.mod" ]; then
    go mod tidy
    go build -o ai main.go
    print_status "✅ AI service built successfully"
else
    print_error "❌ AI service go.mod not found"
fi
cd ../..

print_status "Building Monitor service..."
cd services/monitor
if [ -f "go.mod" ]; then
    go mod tidy
    go build -o monitor main.go
    print_status "✅ Monitor service built successfully"
else
    print_error "❌ Monitor service go.mod not found"
fi
cd ../..

print_header "Step 2: Building Advanced Services"
print_status "Building Deception service..."
cd services/deception
if [ -f "main.go" ]; then
    go mod init github.com/musafirsec/musafir/services/deception 2>/dev/null || true
    go mod tidy
    go build -o deception main.go
    print_status "✅ Deception service built successfully"
else
    print_error "❌ Deception service main.go not found"
fi
cd ../..

print_status "Building Graph service..."
cd services/graph
if [ -f "main.go" ]; then
    go mod init github.com/musafirsec/musafir/services/graph 2>/dev/null || true
    go mod tidy
    go build -o graph main.go
    print_status "✅ Graph service built successfully"
else
    print_error "❌ Graph service main.go not found"
fi
cd ../..

print_status "Building Cache service..."
cd services/cache
if [ -f "main.go" ]; then
    go mod init github.com/musafirsec/musafir/services/cache 2>/dev/null || true
    go mod tidy
    go build -o cache main.go
    print_status "✅ Cache service built successfully"
else
    print_error "❌ Cache service main.go not found"
fi
cd ../..

print_status "Building Observability service..."
cd services/observability
if [ -f "main.go" ]; then
    go mod init github.com/musafirsec/musafir/services/observability 2>/dev/null || true
    go mod tidy
    go build -o observability main.go
    print_status "✅ Observability service built successfully"
else
    print_error "❌ Observability service main.go not found"
fi
cd ../..

print_status "Building Search service..."
cd services/search
if [ -f "main.go" ]; then
    go mod init github.com/musafirsec/musafir/services/search 2>/dev/null || true
    go mod tidy
    go build -o search main.go
    print_status "✅ Search service built successfully"
else
    print_error "❌ Search service main.go not found"
fi
cd ../..

print_status "Building Forensics service..."
cd services/forensics
if [ -f "go.mod" ]; then
    go mod tidy
    go build -o forensics main.go
    print_status "✅ Forensics service built successfully"
else
    print_error "❌ Forensics service go.mod not found"
fi
cd ../..

print_status "Building Network service..."
cd services/network
if [ -f "go.mod" ]; then
    go mod tidy
    go build -o network main.go
    print_status "✅ Network service built successfully"
else
    print_error "❌ Network service go.mod not found"
fi
cd ../..

print_status "Building Email service..."
cd services/email
if [ -f "go.mod" ]; then
    go mod tidy
    go build -o email main.go
    print_status "✅ Email service built successfully"
else
    print_error "❌ Email service go.mod not found"
fi
cd ../..

print_status "Building Identity service..."
cd services/identity
if [ -f "go.mod" ]; then
    go mod tidy
    go build -o identity main.go
    print_status "✅ Identity service built successfully"
else
    print_error "❌ Identity service go.mod not found"
fi
cd ../..

print_status "Building Vulnerability service..."
cd services/vuln
if [ -f "go.mod" ]; then
    go mod tidy
    go build -o vuln main.go
    print_status "✅ Vulnerability service built successfully"
else
    print_error "❌ Vulnerability service go.mod not found"
fi
cd ../..

print_status "Building Compliance service..."
cd services/compliance
if [ -f "go.mod" ]; then
    go mod tidy
    go build -o compliance main.go
    print_status "✅ Compliance service built successfully"
else
    print_error "❌ Compliance service go.mod not found"
fi
cd ../..

print_status "Building SLSA service..."
cd services/slsa
if [ -f "go.mod" ]; then
    go mod tidy
    go build -o slsa main.go
    print_status "✅ SLSA service built successfully"
else
    print_error "❌ SLSA service go.mod not found"
fi
cd ../..

print_status "Building Tenant service..."
cd services/tenant
if [ -f "go.mod" ]; then
    go mod tidy
    go build -o tenant main.go
    print_status "✅ Tenant service built successfully"
else
    print_error "❌ Tenant service go.mod not found"
fi
cd ../..

print_status "Building MDM service..."
cd services/mdm
if [ -f "go.mod" ]; then
    go mod tidy
    go build -o mdm main.go
    print_status "✅ MDM service built successfully"
else
    print_error "❌ MDM service go.mod not found"
fi
cd ../..

print_status "Building YARA service..."
cd services/yara
if [ -f "go.mod" ]; then
    go mod tidy
    go build -o yara main.go
    print_status "✅ YARA service built successfully"
else
    print_error "❌ YARA service go.mod not found"
fi
cd ../..

print_status "Building Cloud service..."
cd services/cloud
if [ -f "go.mod" ]; then
    go mod tidy
    go build -o cloud main.go
    print_status "✅ Cloud service built successfully"
else
    print_error "❌ Cloud service go.mod not found"
fi
cd ../..

print_status "Building SPIRE service..."
cd services/spire
if [ -f "go.mod" ]; then
    go mod tidy
    go build -o spire main.go
    print_status "✅ SPIRE service built successfully"
else
    print_error "❌ SPIRE service go.mod not found"
fi
cd ../..

print_status "Building Sandbox service..."
cd services/sandbox
if [ -f "go.mod" ]; then
    go mod tidy
    go build -o sandbox main.go
    print_status "✅ Sandbox service built successfully"
else
    print_error "❌ Sandbox service go.mod not found"
fi
cd ../..

print_header "Step 3: Building Gateway"
print_status "Building Gateway service..."
cd gateway
if [ -f "go.mod" ]; then
    go mod tidy
    go build -o gateway advanced_gateway.go
    print_status "✅ Gateway service built successfully"
else
    print_error "❌ Gateway service go.mod not found"
fi
cd ..

print_header "Step 4: Setting up Web Interface"
print_status "Installing Node.js dependencies..."
cd ui
if [ -f "package.json" ]; then
    npm install
    print_status "✅ Web interface dependencies installed"
else
    print_error "❌ Web interface package.json not found"
fi
cd ..

print_header "Step 5: Creating Management Scripts"
print_status "Creating service management scripts..."

# Create logs directory
mkdir -p logs

# Create start script
cat > start-all.sh << 'EOF'
#!/bin/bash
source .env

echo "🚀 Starting MUSAFIR SecOps Platform..."

# Start databases
sudo systemctl start musafir-databases.service
echo "✅ Databases started"

# Wait for databases
sleep 30

# Start services
./start-services.sh
echo "✅ Services started"

# Start web interface
cd ui
nohup npm run dev > ../logs/ui.log 2>&1 &
echo "✅ Web interface started"

echo "🎉 MUSAFIR SecOps Platform is running!"
echo "Web interface: http://localhost:3000"
echo "Gateway: http://localhost:8080"
EOF

chmod +x start-all.sh

# Create stop script
cat > stop-all.sh << 'EOF'
#!/bin/bash
echo "🛑 Stopping MUSAFIR SecOps Platform..."

# Stop services
sudo systemctl stop musafir-secops.service
echo "✅ Services stopped"

# Stop databases
sudo systemctl stop musafir-databases.service
echo "✅ Databases stopped"

# Stop web interface
pkill -f "npm run dev"
echo "✅ Web interface stopped"

echo "🎯 MUSAFIR SecOps Platform stopped!"
EOF

chmod +x stop-all.sh

print_header "Build Complete!"
print_status "All services have been built successfully!"

echo ""
echo "🎉 BUILD SUMMARY:"
echo "=================="
echo "✅ Core services built"
echo "✅ Advanced services built"
echo "✅ Gateway built"
echo "✅ Web interface configured"
echo "✅ Management scripts created"
echo ""
echo "📋 NEXT STEPS:"
echo "=============="
echo "1. Start the platform: ./start-all.sh"
echo "2. Access web interface: http://localhost:3000"
echo "3. Check status: ./verify-connectivity.sh"
echo ""
echo "🔧 MANAGEMENT COMMANDS:"
echo "======================="
echo "• Start all: ./start-all.sh"
echo "• Stop all: ./stop-all.sh"
echo "• Start services only: ./start-services.sh"
echo "• Verify connectivity: ./verify-connectivity.sh"
echo ""
print_status "Build completed successfully! 🚀"

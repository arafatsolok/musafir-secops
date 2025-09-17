#!/bin/bash

# MUSAFIR SecOps Platform - Ubuntu 22.04 Installation Script
# This script automates the complete installation process

set -e

echo "🚀 MUSAFIR SecOps Platform - Ubuntu 22.04 Installation"
echo "======================================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    print_error "Please do not run this script as root. Run as a regular user with sudo privileges."
    exit 1
fi

# Check Ubuntu version
if ! lsb_release -d | grep -q "Ubuntu 22.04"; then
    print_warning "This script is designed for Ubuntu 22.04. Your system: $(lsb_release -d | cut -f2)"
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

print_header "Step 1: System Preparation"
print_status "Updating system packages..."
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl wget git vim nano htop tree unzip redis-tools

print_status "Configuring firewall..."
sudo ufw --force enable
sudo ufw allow ssh
sudo ufw allow 80
sudo ufw allow 443
sudo ufw allow 3000:3001
sudo ufw allow 8080:8107
sudo ufw allow 9000:9002
sudo ufw allow 9090:9092
sudo ufw allow 15672
sudo ufw allow 16686
sudo ufw allow 7474
sudo ufw allow 7687
sudo ufw allow 9200:9300

print_header "Step 2: Docker Installation"
print_status "Installing Docker..."
sudo apt remove -y docker docker-engine docker.io containerd runc || true
sudo apt install -y ca-certificates curl gnupg lsb-release

sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker $USER

print_status "Installing Docker Compose standalone..."
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

print_header "Step 3: Go Installation"
print_status "Installing Go 1.22..."
wget -q https://go.dev/dl/go1.22.0.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz
rm go1.22.0.linux-amd64.tar.gz

echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
echo 'export GOPATH=$HOME/go' >> ~/.bashrc
echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

print_header "Step 4: Node.js Installation"
print_status "Installing Node.js 20 LTS..."
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

print_header "Step 5: Platform Setup"
print_status "Creating application directory..."
cd /home/$USER
if [ -d "musafir-secops" ]; then
    print_warning "Directory musafir-secops already exists. Backing up..."
    mv musafir-secops musafir-secops.backup.$(date +%Y%m%d_%H%M%S)
fi

print_status "Setting up platform structure..."
mkdir -p musafir-secops/{services,gateway,ui,infra,logs,ssl}
cd musafir-secops

# Create basic service structure
mkdir -p services/{ingest,detect,correlate,respond,cases,ueba,threatintel,ml,ai,monitor,deception,graph,cache,observability,search,forensics,network,email,identity,vuln,compliance,slsa,tenant,mdm,yara,cloud,spire,sandbox}

print_status "Creating environment configuration..."
cat > .env << 'EOF'
# Database Configuration
CLICKHOUSE_DSN=tcp://localhost:9000?database=default
ELASTICSEARCH_URL=http://localhost:9200
REDIS_URL=redis://localhost:6379
NEO4J_URL=bolt://localhost:7687
POSTGRES_URL=postgres://musafir:Strong@!@#bdnews24#@localhost:5432/musafir

# Kafka Configuration
KAFKA_BROKERS=localhost:9092
KAFKA_GROUP=musafir

# Service Configuration
GATEWAY_PORT=8080
UI_PORT=3000
MONITOR_PORT=9090

# Security Configuration
JWT_SECRET=musafir-jwt-secret-key-$(date +%s)
ENCRYPTION_KEY=musafir-encryption-key-$(date +%s)
DEFAULT_USERNAME=musafir
DEFAULT_PASSWORD=Strong@!@#bdnews24#
EOF

print_status "Setting up Central Portal..."
cat > ui/package.json << 'EOF'
{
  "name": "musafir-ui",
  "private": true,
  "version": "0.0.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "lint": "eslint . --ext ts,tsx --report-unused-disable-directives --max-warnings 0",
    "preview": "vite preview",
    "proxy": "node proxy-server.js",
    "dev:full": "concurrently \"npm run dev\" \"npm run proxy\""
  },
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "lucide-react": "^0.263.1",
    "clsx": "^2.0.0",
    "tailwind-merge": "^1.14.0",
    "express": "^4.18.2",
    "http-proxy-middleware": "^2.0.6",
    "cors": "^2.8.5",
    "concurrently": "^8.2.0"
  },
  "devDependencies": {
    "@types/react": "^18.2.15",
    "@types/react-dom": "^18.2.7",
    "@typescript-eslint/eslint-plugin": "^6.0.0",
    "@typescript-eslint/parser": "^6.0.0",
    "@vitejs/plugin-react": "^4.0.3",
    "autoprefixer": "^10.4.14",
    "eslint": "^8.45.0",
    "eslint-plugin-react-hooks": "^4.6.0",
    "eslint-plugin-react-refresh": "^0.4.3",
    "postcss": "^8.4.27",
    "tailwindcss": "^3.3.3",
    "typescript": "^5.0.2",
    "vite": "^4.4.5"
  }
}
EOF

print_status "Creating service management scripts..."
cat > start-services.sh << 'EOF'
#!/bin/bash
source .env

# Start services in background
cd /home/$USER/musafir-secops

# Core services (if they exist)
[ -f "./services/ingest/ingest" ] && nohup ./services/ingest/ingest > logs/ingest.log 2>&1 &
[ -f "./services/detect/detect" ] && nohup ./services/detect/detect > logs/detect.log 2>&1 &
[ -f "./services/correlate/correlate" ] && nohup ./services/correlate/correlate > logs/correlate.log 2>&1 &
[ -f "./services/respond/respond" ] && nohup ./services/respond/respond > logs/respond.log 2>&1 &
[ -f "./services/cases/cases" ] && nohup ./services/cases/cases > logs/cases.log 2>&1 &
[ -f "./services/ueba/ueba" ] && nohup ./services/ueba/ueba > logs/ueba.log 2>&1 &
[ -f "./services/threatintel/threatintel" ] && nohup ./services/threatintel/threatintel > logs/threatintel.log 2>&1 &
[ -f "./services/ml/ml" ] && nohup ./services/ml/ml > logs/ml.log 2>&1 &
[ -f "./services/ai/ai" ] && nohup ./services/ai/ai > logs/ai.log 2>&1 &
[ -f "./services/monitor/monitor" ] && nohup ./services/monitor/monitor > logs/monitor.log 2>&1 &

# Advanced services (if they exist)
[ -f "./services/deception/deception" ] && nohup ./services/deception/deception > logs/deception.log 2>&1 &
[ -f "./services/graph/graph" ] && nohup ./services/graph/graph > logs/graph.log 2>&1 &
[ -f "./services/cache/cache" ] && nohup ./services/cache/cache > logs/cache.log 2>&1 &
[ -f "./services/observability/observability" ] && nohup ./services/observability/observability > logs/observability.log 2>&1 &
[ -f "./services/search/search" ] && nohup ./services/search/search > logs/search.log 2>&1 &
[ -f "./services/forensics/forensics" ] && nohup ./services/forensics/forensics > logs/forensics.log 2>&1 &
[ -f "./services/network/network" ] && nohup ./services/network/network > logs/network.log 2>&1 &
[ -f "./services/email/email" ] && nohup ./services/email/email > logs/email.log 2>&1 &
[ -f "./services/identity/identity" ] && nohup ./services/identity/identity > logs/identity.log 2>&1 &
[ -f "./services/vuln/vuln" ] && nohup ./services/vuln/vuln > logs/vuln.log 2>&1 &
[ -f "./services/compliance/compliance" ] && nohup ./services/compliance/compliance > logs/compliance.log 2>&1 &
[ -f "./services/slsa/slsa" ] && nohup ./services/slsa/slsa > logs/slsa.log 2>&1 &
[ -f "./services/tenant/tenant" ] && nohup ./services/tenant/tenant > logs/tenant.log 2>&1 &
[ -f "./services/mdm/mdm" ] && nohup ./services/mdm/mdm > logs/mdm.log 2>&1 &
[ -f "./services/yara/yara" ] && nohup ./services/yara/yara > logs/yara.log 2>&1 &
[ -f "./services/cloud/cloud" ] && nohup ./services/cloud/cloud > logs/cloud.log 2>&1 &
[ -f "./services/spire/spire" ] && nohup ./services/spire/spire > logs/spire.log 2>&1 &
[ -f "./services/sandbox/sandbox" ] && nohup ./services/sandbox/sandbox > logs/sandbox.log 2>&1 &

# Start gateway last
[ -f "./gateway/gateway" ] && nohup ./gateway/gateway > logs/gateway.log 2>&1 &

echo "Services started. Check logs/ directory for service logs."
echo "Web interface: http://localhost:3000"
echo "Gateway: http://localhost:8080"
EOF

chmod +x start-services.sh

cat > verify-connectivity.sh << 'EOF'
#!/bin/bash

echo "🔍 MUSAFIR SecOps Platform - Connectivity Verification"
echo "================================================="

# Test web interfaces
echo "🌐 Testing Web Interfaces..."
curl -s http://localhost:3000 > /dev/null && echo "✅ Main Dashboard: http://localhost:3000" || echo "❌ Main Dashboard: Not accessible"
curl -s http://localhost:3001 > /dev/null && echo "✅ Grafana: http://localhost:3001" || echo "❌ Grafana: Not accessible"
curl -s http://localhost:9090 > /dev/null && echo "✅ Prometheus: http://localhost:9090" || echo "❌ Prometheus: Not accessible"
curl -s http://localhost:16686 > /dev/null && echo "✅ Jaeger: http://localhost:16686" || echo "❌ Jaeger: Not accessible"

# Test databases
echo "🗄️ Testing Databases..."
curl -s http://localhost:8123/ping > /dev/null && echo "✅ ClickHouse: Connected" || echo "❌ ClickHouse: Not connected"
curl -s http://localhost:9200 > /dev/null && echo "✅ Elasticsearch: Connected" || echo "❌ Elasticsearch: Not connected"
curl -s http://localhost:7474 > /dev/null && echo "✅ Neo4j: Connected" || echo "❌ Neo4j: Not connected"
redis-cli -h localhost -p 6379 ping > /dev/null && echo "✅ Redis: Connected" || echo "❌ Redis: Not connected"

# Test services
echo "🔧 Testing Services..."
curl -s http://localhost:8080/health > /dev/null && echo "✅ Gateway: Running" || echo "❌ Gateway: Not running"
curl -s http://localhost:8081/health > /dev/null && echo "✅ Ingest: Running" || echo "❌ Ingest: Not running"
curl -s http://localhost:9090/health > /dev/null && echo "✅ Monitor: Running" || echo "❌ Monitor: Not running"

echo "🎯 Verification complete!"
EOF

chmod +x verify-connectivity.sh

print_header "Step 6: Database Setup"
print_status "Creating Docker Compose configuration..."
cat > infra/docker-compose-advanced.yml << 'EOF'
version: "3.8"

services:
  # Core Infrastructure
  redpanda:
    image: redpandadata/redpanda:v24.1.5
    command:
      - redpanda start
      - --overprovisioned
      - --smp=1
      - --memory=2048M
      - --reserve-memory=0M
      - --node-id=0
      - --check=false
    ports:
      - "9092:9092"   # Kafka API
      - "9644:9644"   # Admin API
    volumes:
      - redpanda_data:/var/lib/redpanda/data
    environment:
      - REDPANDA_AUTO_CREATE_TOPICS_ENABLED=true

  clickhouse:
    image: clickhouse/clickhouse-server:24.8
    ports:
      - "8123:8123"   # HTTP
      - "9000:9000"   # Native
    ulimits:
      nofile:
        soft: 262144
        hard: 262144
    volumes:
      - clickhouse_data:/var/lib/clickhouse
    environment:
      - CLICKHOUSE_DB=musafir
      - CLICKHOUSE_USER=musafir
      - CLICKHOUSE_PASSWORD=musafir123

  # Advanced Services
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    command: redis-server --appendonly yes

  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.11.0
    ports:
      - "9200:9200"
      - "9300:9300"
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - "ES_JAVA_OPTS=-Xms1g -Xmx1g"
    volumes:
      - elasticsearch_data:/usr/share/elasticsearch/data
    ulimits:
      memlock:
        soft: -1
        hard: -1

  neo4j:
    image: neo4j:5.15-community
    ports:
      - "7474:7474"   # HTTP
      - "7687:7687"   # Bolt
    environment:
      - NEO4J_AUTH=neo4j/password
      - NEO4J_PLUGINS=["apoc"]
    volumes:
      - neo4j_data:/data
      - neo4j_logs:/logs

  # Monitoring and Observability
  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--storage.tsdb.retention.time=200h'
      - '--web.enable-lifecycle'

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3001:3000"
    volumes:
      - grafana_data:/var/lib/grafana
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
      - GF_USERS_ALLOW_SIGN_UP=false

  jaeger:
    image: jaegertracing/all-in-one:latest
    ports:
      - "16686:16686"  # Web UI
      - "14268:14268"  # HTTP
    environment:
      - COLLECTOR_OTLP_ENABLED=true

  # Database Services
  postgres:
    image: postgres:15-alpine
    ports:
      - "5432:5432"
    environment:
      - POSTGRES_DB=musafir
      - POSTGRES_USER=musafir
      - POSTGRES_PASSWORD=musafir123
    volumes:
      - postgres_data:/var/lib/postgresql/data

  # Message Queue
  rabbitmq:
    image: rabbitmq:3-management-alpine
    ports:
      - "5672:5672"   # AMQP
      - "15672:15672" # Management UI
    environment:
      - RABBITMQ_DEFAULT_USER=musafir
      - RABBITMQ_DEFAULT_PASS=musafir123
    volumes:
      - rabbitmq_data:/var/lib/rabbitmq

  # Object Storage
  minio:
    image: minio/minio:latest
    ports:
      - "9001:9000"   # API
      - "9002:9001"   # Console
    environment:
      - MINIO_ROOT_USER=musafir
      - MINIO_ROOT_PASSWORD=musafir123
    volumes:
      - minio_data:/data
    command: server /data --console-address ":9001"

volumes:
  redpanda_data:
  clickhouse_data:
  redis_data:
  elasticsearch_data:
  neo4j_data:
  neo4j_logs:
  prometheus_data:
  grafana_data:
  postgres_data:
  rabbitmq_data:
  minio_data:
EOF

print_status "Creating Prometheus configuration..."
cat > infra/prometheus.yml << 'EOF'
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'musafir-services'
    static_configs:
      - targets: ['localhost:8080', 'localhost:8081', 'localhost:9090']
    scrape_interval: 5s
    metrics_path: /metrics
EOF

print_status "Starting databases..."
cd infra
docker compose -f docker-compose-advanced.yml up -d

print_status "Waiting for databases to start..."
sleep 60

print_header "Step 7: Systemd Service Setup"
print_status "Creating systemd services..."
sudo tee /etc/systemd/system/musafir-databases.service << 'EOF'
[Unit]
Description=MUSAFIR SecOps Databases
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
User=musafir
Group=musafir
WorkingDirectory=/home/musafir/musafir-secops/infra
ExecStart=/usr/bin/docker compose -f docker-compose-advanced.yml up -d
ExecStop=/usr/bin/docker compose -f docker-compose-advanced.yml down

[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/systemd/system/musafir-secops.service << 'EOF'
[Unit]
Description=MUSAFIR SecOps Platform
After=docker.service
Requires=docker.service

[Service]
Type=forking
User=musafir
Group=musafir
WorkingDirectory=/home/musafir/musafir-secops
ExecStart=/home/musafir/musafir-secops/start-services.sh
ExecStop=/bin/kill -TERM $MAINPID
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable musafir-databases.service

print_header "Step 8: Final Configuration"
print_status "Optimizing system parameters..."
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
echo "net.core.somaxconn=65535" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

echo "* soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.conf

print_status "Creating startup scripts..."
cat > /home/$USER/start-musafir.sh << 'EOF'
#!/bin/bash
echo "Starting MUSAFIR SecOps Platform..."
sudo systemctl start musafir-databases.service
sleep 60
sudo systemctl start musafir-secops.service
echo "MUSAFIR SecOps Platform started!"
echo "Web interface: http://localhost:3000"
echo "Gateway: http://localhost:8080"
EOF

cat > /home/$USER/stop-musafir.sh << 'EOF'
#!/bin/bash
echo "Stopping MUSAFIR SecOps Platform..."
sudo systemctl stop musafir-secops.service
sudo systemctl stop musafir-databases.service
echo "MUSAFIR SecOps Platform stopped!"
EOF

chmod +x /home/$USER/start-musafir.sh
chmod +x /home/$USER/stop-musafir.sh

print_header "Installation Complete!"
print_status "MUSAFIR SecOps Platform has been installed successfully!"

echo ""
echo "🎉 INSTALLATION SUMMARY:"
echo "========================"
echo "✅ System prepared and optimized"
echo "✅ Docker and Docker Compose installed"
echo "✅ Go 1.22 installed"
echo "✅ Node.js 20 LTS installed"
echo "✅ Platform structure created"
echo "✅ Databases configured and started"
echo "✅ Systemd services created"
echo "✅ Management scripts created"
echo ""
echo "📋 NEXT STEPS:"
echo "=============="
echo "1. Copy your MUSAFIR source code to /home/$USER/musafir-secops/"
echo "2. Build the services: cd /home/$USER/musafir-secops && ./build-all.sh"
echo "3. Start the platform: ./start-musafir.sh"
echo "4. Access web interface: http://localhost:3000"
echo ""
echo "📚 DOCUMENTATION:"
echo "================="
echo "• Installation Guide: UBUNTU_INSTALLATION_GUIDE.md"
echo "• Database Architecture: DATABASE_ARCHITECTURE.md"
echo "• Web Interface Guide: WEB_INTERFACE_GUIDE.md"
echo ""
echo "🔧 MANAGEMENT COMMANDS:"
echo "======================="
echo "• Start platform: ./start-musafir.sh"
echo "• Stop platform: ./stop-musafir.sh"
echo "• Check status: sudo systemctl status musafir-secops.service"
echo "• View logs: tail -f /home/$USER/musafir-secops/logs/gateway.log"
echo "• Verify connectivity: cd /home/$USER/musafir-secops && ./verify-connectivity.sh"
echo ""
echo "🌐 ACCESS POINTS:"
echo "================="
echo "• Main Dashboard: http://localhost:3000"
echo "• Grafana: http://localhost:3001 (admin/admin)"
echo "• Prometheus: http://localhost:9090"
echo "• Jaeger: http://localhost:16686"
echo "• Neo4j Browser: http://localhost:7474 (neo4j/password)"
echo "• RabbitMQ Management: http://localhost:15672 (musafir/musafir123)"
echo "• MinIO Console: http://localhost:9002 (musafir/musafir123)"
echo ""
print_status "Installation completed successfully! 🚀"

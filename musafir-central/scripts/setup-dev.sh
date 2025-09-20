#!/bin/bash

# MUSAFIR Central Platform - Development Setup Script
# This script sets up the development environment

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check version
check_version() {
    local cmd=$1
    local min_version=$2
    local current_version=$($cmd 2>/dev/null || echo "0.0.0")
    
    if [ "$(printf '%s\n' "$min_version" "$current_version" | sort -V | head -n1)" = "$min_version" ]; then
        return 0
    else
        return 1
    fi
}

print_status "Starting MUSAFIR Central Platform development setup..."

# Check prerequisites
print_status "Checking prerequisites..."

# Check Go
if command_exists go; then
    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    if check_version "echo $GO_VERSION" "1.21.0"; then
        print_success "Go $GO_VERSION is installed"
    else
        print_error "Go version $GO_VERSION is too old. Please install Go 1.21 or later"
        exit 1
    fi
else
    print_error "Go is not installed. Please install Go 1.21 or later"
    exit 1
fi

# Check Node.js
if command_exists node; then
    NODE_VERSION=$(node --version | sed 's/v//')
    if check_version "echo $NODE_VERSION" "18.0.0"; then
        print_success "Node.js $NODE_VERSION is installed"
    else
        print_error "Node.js version $NODE_VERSION is too old. Please install Node.js 18 or later"
        exit 1
    fi
else
    print_error "Node.js is not installed. Please install Node.js 18 or later"
    exit 1
fi

# Check npm
if command_exists npm; then
    NPM_VERSION=$(npm --version)
    print_success "npm $NPM_VERSION is installed"
else
    print_error "npm is not installed. Please install npm"
    exit 1
fi

# Check Docker
if command_exists docker; then
    DOCKER_VERSION=$(docker --version | awk '{print $3}' | sed 's/,//')
    print_success "Docker $DOCKER_VERSION is installed"
else
    print_error "Docker is not installed. Please install Docker"
    exit 1
fi

# Check Docker Compose
if command_exists docker-compose; then
    COMPOSE_VERSION=$(docker-compose --version | awk '{print $3}' | sed 's/,//')
    print_success "Docker Compose $COMPOSE_VERSION is installed"
elif docker compose version >/dev/null 2>&1; then
    COMPOSE_VERSION=$(docker compose version --short)
    print_success "Docker Compose $COMPOSE_VERSION is installed"
else
    print_error "Docker Compose is not installed. Please install Docker Compose"
    exit 1
fi

# Check Git
if command_exists git; then
    GIT_VERSION=$(git --version | awk '{print $3}')
    print_success "Git $GIT_VERSION is installed"
else
    print_error "Git is not installed. Please install Git"
    exit 1
fi

# Optional tools
print_status "Checking optional tools..."

if command_exists make; then
    print_success "Make is installed"
else
    print_warning "Make is not installed. Some convenience commands may not work"
fi

if command_exists kubectl; then
    print_success "kubectl is installed"
else
    print_warning "kubectl is not installed. Kubernetes deployment commands will not work"
fi

# Create necessary directories
print_status "Creating project directories..."

mkdir -p backend/{cmd/{api-gateway,event-processor,analytics-engine,notification-service},internal/{auth,events,analytics,storage,websocket},pkg/{config,logger,utils},api}
mkdir -p frontend/{src/{components,pages,services,store,utils},public}
mkdir -p deployments/{docker,kubernetes,terraform,monitoring/{prometheus,grafana/{dashboards,provisioning}},nginx/{conf.d}}
mkdir -p docs
mkdir -p scripts
mkdir -p logs

print_success "Project directories created"

# Create environment files
print_status "Creating environment configuration files..."

# Backend environment
cat > backend/.env.development << EOF
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
EOF

# Frontend environment
cat > frontend/.env.development << EOF
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
EOF

print_success "Environment files created"

# Create monitoring configuration
print_status "Creating monitoring configuration..."

# Prometheus configuration
cat > deployments/monitoring/prometheus.yml << EOF
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
EOF

# Grafana provisioning
mkdir -p deployments/monitoring/grafana/provisioning/{dashboards,datasources}

cat > deployments/monitoring/grafana/provisioning/datasources/prometheus.yml << EOF
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
EOF

cat > deployments/monitoring/grafana/provisioning/dashboards/dashboard.yml << EOF
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
EOF

print_success "Monitoring configuration created"

# Create NGINX configuration
print_status "Creating NGINX configuration..."

cat > deployments/nginx/nginx.conf << EOF
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
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
        }

        # API
        location /api/ {
            proxy_pass http://api_backend/;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
        }

        # WebSocket
        location /ws {
            proxy_pass http://api_backend/ws;
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
        }
    }
}
EOF

print_success "NGINX configuration created"

# Create database initialization script
print_status "Creating database initialization scripts..."

cat > scripts/mongo-init.js << EOF
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
EOF

print_success "Database initialization scripts created"

# Install backend dependencies
print_status "Installing backend dependencies..."
cd backend
go mod tidy
go mod download
cd ..
print_success "Backend dependencies installed"

# Install frontend dependencies
print_status "Installing frontend dependencies..."
cd frontend
npm install
cd ..
print_success "Frontend dependencies installed"

# Create Git hooks
if [ -d ".git" ]; then
    print_status "Setting up Git hooks..."
    cd frontend
    npx husky install
    npx husky add .husky/pre-commit "cd frontend && npm run lint:check && npm run prettier:check && npm run type-check"
    cd ..
    print_success "Git hooks configured"
fi

# Create helpful scripts
print_status "Creating helper scripts..."

# Development start script
cat > scripts/dev-start.sh << EOF
#!/bin/bash
echo "Starting MUSAFIR Central Platform development environment..."

# Start infrastructure services
docker-compose up -d mongodb influxdb redis kafka zookeeper prometheus grafana vault elasticsearch kibana

echo "Waiting for services to be ready..."
sleep 30

echo "Services started successfully!"
echo ""
echo "Available services:"
echo "  - MongoDB: localhost:27017"
echo "  - InfluxDB: localhost:8086"
echo "  - Redis: localhost:6379"
echo "  - Kafka: localhost:9092"
echo "  - Prometheus: localhost:9090"
echo "  - Grafana: localhost:3001 (admin/musafir123)"
echo "  - Vault: localhost:8200"
echo "  - Elasticsearch: localhost:9200"
echo "  - Kibana: localhost:5601"
echo ""
echo "Next steps:"
echo "  1. Run 'make backend-run-gateway' in one terminal"
echo "  2. Run 'make frontend-dev' in another terminal"
echo "  3. Access the application at http://localhost:3000"
EOF

chmod +x scripts/dev-start.sh

print_success "Helper scripts created"

# Final setup
print_status "Performing final setup..."

# Make scripts executable
chmod +x scripts/*.sh

# Create logs directory
mkdir -p logs

print_success "Development environment setup completed!"

echo ""
echo -e "${GREEN}🎉 MUSAFIR Central Platform development environment is ready!${NC}"
echo ""
echo "Quick start commands:"
echo "  make dev          # Start full development environment"
echo "  make dev-up       # Start infrastructure services only"
echo "  make backend-deps # Install backend dependencies"
echo "  make frontend-deps# Install frontend dependencies"
echo "  make help         # Show all available commands"
echo ""
echo "Next steps:"
echo "  1. Run 'make dev' to start the development environment"
echo "  2. Open http://localhost:3000 in your browser"
echo "  3. Check the documentation in the docs/ directory"
echo ""
echo "Happy coding! 🚀"
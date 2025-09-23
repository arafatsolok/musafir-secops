# MUSAFIR Central Web UI Platform
## EDR • XDR • SIEM Unified Security Operations Center

### 📋 Table of Contents
1. [System Architecture Overview](#system-architecture-overview)
2. [Backend Services (Go)](#backend-services-go)
3. [Frontend UI Components](#frontend-ui-components)
4. [Data Pipeline & Processing](#data-pipeline--processing)
5. [Docker Deployment Strategy](#docker-deployment-strategy)
6. [Security & Authentication](#security--authentication)
7. [Implementation Guide](#implementation-guide)
8. [API Documentation](#api-documentation)
9. [Database Schema](#database-schema)
10. [Monitoring & Alerting](#monitoring--alerting)

---

## 🏗️ System Architecture Overview

### High-Level Architecture
```
┌─────────────────────────────────────────────────────────────────┐
│                    MUSAFIR Central Web UI                       │
├─────────────────────────────────────────────────────────────────┤
│  Frontend (React/Vue.js)                                        │
│  ├── EDR Dashboard        ├── XDR Analytics    ├── SIEM Console │
│  ├── Threat Intelligence  ├── Incident Response ├── Reports     │
├─────────────────────────────────────────────────────────────────┤
│  API Gateway (Go Gin/Fiber)                                     │
│  ├── Authentication       ├── Rate Limiting    ├── Load Balance │
├─────────────────────────────────────────────────────────────────┤
│  Backend Services (Go Microservices)                            │
│  ├── Agent Manager        ├── Event Processor  ├── Analytics    │
│  ├── Threat Detection     ├── Compliance       ├── Forensics    │
├─────────────────────────────────────────────────────────────────┤
│  Data Layer                                                      │
│  ├── TimeSeries DB        ├── Document DB      ├── Cache Layer  │
│  │   (InfluxDB)           │   (MongoDB)        │   (Redis)      │
├─────────────────────────────────────────────────────────────────┤
│  Message Queue & Streaming                                       │
│  ├── Apache Kafka         ├── Redis Streams   ├── NATS         │
├─────────────────────────────────────────────────────────────────┤
│  Agent Communication Layer                                       │
│  ├── gRPC/WebSocket       ├── TLS Encryption  ├── Load Balance  │
└─────────────────────────────────────────────────────────────────┘
                                    ↑
                    ┌───────────────────────────────┐
                    │     MUSAFIR Agents            │
                    │  ├── Windows Agent            │
                    │  ├── Linux Agent              │
                    │  ├── macOS Agent              │
                    │  └── Mobile Agents            │
                    └───────────────────────────────┘
```

### Core Components

#### 1. **Frontend Layer**
- **Technology**: React.js with TypeScript
- **UI Framework**: Material-UI or Ant Design
- **State Management**: Redux Toolkit
- **Real-time Updates**: WebSocket connections
- **Visualization**: D3.js, Chart.js for security dashboards

#### 2. **API Gateway**
- **Technology**: Go with Gin or Fiber framework
- **Features**: Authentication, rate limiting, request routing
- **Load Balancing**: Nginx or HAProxy integration
- **SSL/TLS**: Automatic certificate management

#### 3. **Backend Microservices**
- **Language**: Go 1.21+
- **Architecture**: Clean Architecture pattern
- **Communication**: gRPC for internal, REST for external
- **Database**: GORM for ORM, database migrations

#### 4. **Data Storage**
- **Time-Series**: InfluxDB for metrics and events
- **Document**: MongoDB for configurations and reports
- **Cache**: Redis for session management and caching
- **Search**: Elasticsearch for log analysis

---

## 🔧 Backend Services (Go)

### Service Architecture

#### 1. **Agent Manager Service**
```go
// Agent Manager handles agent registration, health monitoring, and configuration
type AgentManagerService struct {
    db          *gorm.DB
    redis       *redis.Client
    grpcServer  *grpc.Server
    agentStore  map[string]*Agent
    mutex       sync.RWMutex
}

type Agent struct {
    ID              string    `json:"id" gorm:"primaryKey"`
    Hostname        string    `json:"hostname"`
    IPAddress       string    `json:"ip_address"`
    OS              string    `json:"os"`
    Version         string    `json:"version"`
    LastHeartbeat   time.Time `json:"last_heartbeat"`
    Status          string    `json:"status"` // online, offline, error
    Capabilities    []string  `json:"capabilities" gorm:"type:json"`
    Configuration   string    `json:"configuration" gorm:"type:text"`
}
```

#### 2. **Event Processor Service**
```go
// Event Processor handles real-time event ingestion and processing
type EventProcessorService struct {
    kafkaConsumer *kafka.Consumer
    influxClient  influxdb2.Client
    mongoClient   *mongo.Client
    ruleEngine    *RuleEngine
    alertManager  *AlertManager
}

type SecurityEvent struct {
    ID          string                 `json:"id"`
    AgentID     string                 `json:"agent_id"`
    Timestamp   time.Time              `json:"timestamp"`
    EventType   string                 `json:"event_type"` // process, network, file, registry
    Severity    string                 `json:"severity"`   // low, medium, high, critical
    Data        map[string]interface{} `json:"data"`
    Enrichment  map[string]interface{} `json:"enrichment"`
    ThreatScore int                    `json:"threat_score"`
}
```

#### 3. **Threat Detection Service**
```go
// Threat Detection Service implements ML-based threat detection
type ThreatDetectionService struct {
    mlModel     *tensorflow.SavedModel
    ruleEngine  *YaraEngine
    iocDatabase *IOCDatabase
    behaviorDB  *BehaviorDatabase
}

type ThreatAlert struct {
    ID              string    `json:"id"`
    EventID         string    `json:"event_id"`
    ThreatType      string    `json:"threat_type"`
    Confidence      float64   `json:"confidence"`
    MITRE_TTPs      []string  `json:"mitre_ttps"`
    IOCs            []IOC     `json:"iocs"`
    RecommendedAction string  `json:"recommended_action"`
    CreatedAt       time.Time `json:"created_at"`
}
```

### API Endpoints Structure

#### Authentication & Authorization
```go
// JWT-based authentication with role-based access control
POST   /api/v1/auth/login
POST   /api/v1/auth/logout
POST   /api/v1/auth/refresh
GET    /api/v1/auth/profile
```

#### Agent Management
```go
GET    /api/v1/agents                    // List all agents
GET    /api/v1/agents/{id}               // Get agent details
POST   /api/v1/agents/{id}/config        // Update agent configuration
DELETE /api/v1/agents/{id}               // Remove agent
GET    /api/v1/agents/{id}/health        // Agent health status
```

#### Event & Alert Management
```go
GET    /api/v1/events                    // List events with filtering
GET    /api/v1/events/{id}               // Get event details
POST   /api/v1/events/search             // Advanced event search
GET    /api/v1/alerts                    // List active alerts
PUT    /api/v1/alerts/{id}/acknowledge   // Acknowledge alert
POST   /api/v1/alerts/{id}/investigate   // Start investigation
```

#### Dashboard & Analytics
```go
GET    /api/v1/dashboard/overview        // Security overview metrics
GET    /api/v1/dashboard/threats         // Threat landscape
GET    /api/v1/analytics/trends          // Security trends
POST   /api/v1/analytics/query           // Custom analytics query
```

---

## 🎨 Frontend UI Components

### Dashboard Layout Structure

#### 1. **Main Security Dashboard**
```typescript
interface SecurityDashboard {
  // Real-time security metrics
  threatLevel: 'low' | 'medium' | 'high' | 'critical';
  activeAlerts: number;
  connectedAgents: number;
  eventsPerSecond: number;
  
  // Visualization components
  threatMap: GeographicalThreatMap;
  timelineChart: SecurityTimelineChart;
  topThreats: ThreatRankingList;
  agentStatus: AgentStatusGrid;
}
```

#### 2. **EDR (Endpoint Detection & Response) Interface**
```typescript
interface EDRDashboard {
  // Endpoint monitoring
  endpointList: EndpointGrid;
  processMonitoring: ProcessTreeView;
  fileSystemActivity: FileActivityTimeline;
  networkConnections: NetworkConnectionGraph;
  
  // Response capabilities
  isolationControls: EndpointIsolationPanel;
  remoteShell: SecureRemoteShell;
  forensicsCollector: ForensicsDataCollector;
}
```

#### 3. **XDR (Extended Detection & Response) Interface**
```typescript
interface XDRDashboard {
  // Cross-platform correlation
  attackChainVisualization: AttackChainGraph;
  crossPlatformEvents: UnifiedEventTimeline;
  threatHunting: ThreatHuntingWorkbench;
  
  // Advanced analytics
  behaviorAnalytics: UEBADashboard;
  threatIntelligence: ThreatIntelFeed;
  incidentResponse: IncidentResponseWorkflow;
}
```

#### 4. **SIEM (Security Information & Event Management) Interface**
```typescript
interface SIEMDashboard {
  // Log management
  logSearch: AdvancedLogSearch;
  logParsing: LogParsingRules;
  logRetention: LogRetentionPolicies;
  
  // Correlation & alerting
  correlationRules: CorrelationRuleEngine;
  alertManagement: AlertManagementConsole;
  complianceReporting: ComplianceReportGenerator;
}
```

### Component Architecture
```typescript
// Main App Component Structure
src/
├── components/
│   ├── common/
│   │   ├── Layout/
│   │   ├── Navigation/
│   │   └── Charts/
│   ├── edr/
│   │   ├── EndpointGrid/
│   │   ├── ProcessMonitor/
│   │   └── ForensicsPanel/
│   ├── xdr/
│   │   ├── AttackChain/
│   │   ├── ThreatHunting/
│   │   └── BehaviorAnalytics/
│   └── siem/
│       ├── LogSearch/
│       ├── AlertConsole/
│       └── ComplianceReports/
├── services/
│   ├── api/
│   ├── websocket/
│   └── auth/
├── store/
│   ├── slices/
│   └── middleware/
└── utils/
    ├── formatters/
    ├── validators/
    └── constants/
```

---

## 📊 Data Pipeline & Processing

### Real-time Data Flow

#### 1. **Agent Data Ingestion**
```go
// Agent sends data via gRPC streaming
type AgentDataStream struct {
    AgentID   string
    Events    chan SecurityEvent
    Metrics   chan SystemMetric
    Logs      chan LogEntry
}

// Data ingestion pipeline
func (s *EventProcessorService) ProcessAgentStream(stream AgentDataStream) {
    go func() {
        for event := range stream.Events {
            // 1. Validate and enrich event
            enrichedEvent := s.enrichEvent(event)
            
            // 2. Apply threat detection rules
            threats := s.detectThreats(enrichedEvent)
            
            // 3. Store in time-series database
            s.storeEvent(enrichedEvent)
            
            // 4. Generate alerts if needed
            if len(threats) > 0 {
                s.generateAlerts(threats)
            }
            
            // 5. Forward to real-time dashboard
            s.broadcastToUI(enrichedEvent)
        }
    }()
}
```

#### 2. **Data Processing Pipeline**
```yaml
# Kafka Topics for data streaming
topics:
  - raw-events          # Raw events from agents
  - enriched-events     # Processed and enriched events
  - threat-alerts       # Generated threat alerts
  - system-metrics      # System performance metrics
  - audit-logs          # Audit and compliance logs

# Processing stages
pipeline:
  1. ingestion:         # Receive data from agents
     - validation
     - deduplication
     - rate limiting
  
  2. enrichment:        # Add context to events
     - geo-location
     - threat intelligence
     - asset information
  
  3. analysis:          # Apply detection rules
     - signature-based detection
     - behavioral analysis
     - machine learning models
  
  4. correlation:       # Cross-event analysis
     - attack chain detection
     - lateral movement detection
     - privilege escalation detection
  
  5. storage:           # Persist processed data
     - time-series storage (InfluxDB)
     - document storage (MongoDB)
     - search indexing (Elasticsearch)
```

#### 3. **Database Schema Design**

##### Time-Series Database (InfluxDB)
```sql
-- Security Events Measurement
CREATE MEASUREMENT security_events (
    time TIMESTAMP,
    agent_id TAG,
    event_type TAG,
    severity TAG,
    threat_score FIELD,
    process_name TAG,
    file_path TAG,
    network_destination TAG,
    user_name TAG,
    raw_data FIELD
);

-- System Metrics Measurement
CREATE MEASUREMENT system_metrics (
    time TIMESTAMP,
    agent_id TAG,
    metric_type TAG,
    cpu_usage FIELD,
    memory_usage FIELD,
    disk_usage FIELD,
    network_io FIELD
);
```

##### Document Database (MongoDB)
```javascript
// Agents Collection
{
  _id: ObjectId,
  agent_id: String,
  hostname: String,
  ip_address: String,
  os_info: {
    name: String,
    version: String,
    architecture: String
  },
  capabilities: [String],
  configuration: Object,
  last_heartbeat: Date,
  status: String,
  created_at: Date,
  updated_at: Date
}

// Threat Intelligence Collection
{
  _id: ObjectId,
  ioc_type: String, // ip, domain, hash, url
  ioc_value: String,
  threat_type: String,
  confidence: Number,
  source: String,
  first_seen: Date,
  last_seen: Date,
  tags: [String],
  mitre_ttps: [String]
}

// Investigation Cases Collection
{
  _id: ObjectId,
  case_id: String,
  title: String,
  description: String,
  severity: String,
  status: String, // open, investigating, resolved, closed
  assigned_to: String,
  events: [ObjectId], // References to related events
  timeline: [{
    timestamp: Date,
    action: String,
    user: String,
    details: Object
  }],
  artifacts: [Object],
  created_at: Date,
  updated_at: Date
}
```

---

## 🐳 Docker Deployment Strategy

### Container Architecture

#### 1. **Docker Compose Structure**
```yaml
version: '3.8'

services:
  # Frontend Application
  musafir-ui:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    ports:
      - "3000:3000"
    environment:
      - REACT_APP_API_URL=http://api-gateway:8080
    depends_on:
      - api-gateway
    networks:
      - musafir-network

  # API Gateway
  api-gateway:
    build:
      context: ./backend/api-gateway
      dockerfile: Dockerfile
    ports:
      - "8080:8080"
    environment:
      - JWT_SECRET=${JWT_SECRET}
      - REDIS_URL=redis:6379
    depends_on:
      - redis
      - agent-manager
      - event-processor
    networks:
      - musafir-network

  # Agent Manager Service
  agent-manager:
    build:
      context: ./backend/agent-manager
      dockerfile: Dockerfile
    ports:
      - "9090:9090"
    environment:
      - DB_HOST=postgres
      - DB_NAME=musafir_agents
      - REDIS_URL=redis:6379
    depends_on:
      - postgres
      - redis
    networks:
      - musafir-network

  # Event Processor Service
  event-processor:
    build:
      context: ./backend/event-processor
      dockerfile: Dockerfile
    environment:
      - KAFKA_BROKERS=kafka:9092
      - INFLUXDB_URL=http://influxdb:8086
      - MONGODB_URL=mongodb://mongodb:27017
    depends_on:
      - kafka
      - influxdb
      - mongodb
    networks:
      - musafir-network

  # Threat Detection Service
  threat-detection:
    build:
      context: ./backend/threat-detection
      dockerfile: Dockerfile
    environment:
      - ML_MODEL_PATH=/models/threat_detection.pb
      - YARA_RULES_PATH=/rules/
    volumes:
      - ./models:/models:ro
      - ./yara-rules:/rules:ro
    networks:
      - musafir-network

  # Databases
  postgres:
    image: postgres:15
    environment:
      - POSTGRES_DB=musafir
      - POSTGRES_USER=musafir
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - musafir-network

  mongodb:
    image: mongo:6.0
    environment:
      - MONGO_INITDB_ROOT_USERNAME=musafir
      - MONGO_INITDB_ROOT_PASSWORD=${MONGO_PASSWORD}
    volumes:
      - mongodb_data:/data/db
    networks:
      - musafir-network

  influxdb:
    image: influxdb:2.7
    environment:
      - INFLUXDB_DB=musafir_metrics
      - INFLUXDB_ADMIN_USER=admin
      - INFLUXDB_ADMIN_PASSWORD=${INFLUXDB_PASSWORD}
    volumes:
      - influxdb_data:/var/lib/influxdb2
    networks:
      - musafir-network

  redis:
    image: redis:7-alpine
    command: redis-server --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis_data:/data
    networks:
      - musafir-network

  # Message Queue
  kafka:
    image: confluentinc/cp-kafka:latest
    environment:
      KAFKA_ZOOKEEPER_CONNECT: zookeeper:2181
      KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://kafka:9092
      KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR: 1
    depends_on:
      - zookeeper
    networks:
      - musafir-network

  zookeeper:
    image: confluentinc/cp-zookeeper:latest
    environment:
      ZOOKEEPER_CLIENT_PORT: 2181
      ZOOKEEPER_TICK_TIME: 2000
    networks:
      - musafir-network

  # Elasticsearch for log search
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.8.0
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
    volumes:
      - elasticsearch_data:/usr/share/elasticsearch/data
    networks:
      - musafir-network

  # Nginx Load Balancer
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/ssl:ro
    depends_on:
      - musafir-ui
      - api-gateway
    networks:
      - musafir-network

volumes:
  postgres_data:
  mongodb_data:
  influxdb_data:
  redis_data:
  elasticsearch_data:

networks:
  musafir-network:
    driver: bridge
```

#### 2. **Individual Service Dockerfiles**

##### Backend Service Dockerfile
```dockerfile
# Backend Service Dockerfile Template
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

FROM alpine:latest
RUN apk --no-cache add ca-certificates tzdata
WORKDIR /root/

COPY --from=builder /app/main .
COPY --from=builder /app/config ./config/

EXPOSE 8080
CMD ["./main"]
```

##### Frontend Dockerfile
```dockerfile
# Frontend Dockerfile
FROM node:18-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/build /usr/share/nginx/html
COPY nginx.conf /etc/nginx/nginx.conf

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

#### 3. **Kubernetes Deployment (Optional)**
```yaml
# Kubernetes deployment for scalability
apiVersion: apps/v1
kind: Deployment
metadata:
  name: musafir-api-gateway
spec:
  replicas: 3
  selector:
    matchLabels:
      app: musafir-api-gateway
  template:
    metadata:
      labels:
        app: musafir-api-gateway
    spec:
      containers:
      - name: api-gateway
        image: musafir/api-gateway:latest
        ports:
        - containerPort: 8080
        env:
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: musafir-secrets
              key: jwt-secret
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
---
apiVersion: v1
kind: Service
metadata:
  name: musafir-api-gateway-service
spec:
  selector:
    app: musafir-api-gateway
  ports:
  - protocol: TCP
    port: 80
    targetPort: 8080
  type: LoadBalancer
```

---

## 🔐 Security & Authentication

### Authentication & Authorization Framework

#### 1. **JWT-based Authentication**
```go
// JWT Token Structure
type JWTClaims struct {
    UserID      string   `json:"user_id"`
    Username    string   `json:"username"`
    Email       string   `json:"email"`
    Roles       []string `json:"roles"`
    Permissions []string `json:"permissions"`
    jwt.RegisteredClaims
}

// Role-based Access Control
type Role struct {
    ID          string       `json:"id"`
    Name        string       `json:"name"`
    Description string       `json:"description"`
    Permissions []Permission `json:"permissions"`
}

type Permission struct {
    ID       string `json:"id"`
    Resource string `json:"resource"` // agents, events, alerts, users
    Action   string `json:"action"`   // read, write, delete, execute
}

// Predefined Roles
var DefaultRoles = []Role{
    {
        Name: "Security Analyst",
        Permissions: []Permission{
            {Resource: "events", Action: "read"},
            {Resource: "alerts", Action: "read"},
            {Resource: "alerts", Action: "acknowledge"},
            {Resource: "investigations", Action: "create"},
        },
    },
    {
        Name: "Security Engineer",
        Permissions: []Permission{
            {Resource: "*", Action: "read"},
            {Resource: "agents", Action: "write"},
            {Resource: "rules", Action: "write"},
            {Resource: "investigations", Action: "*"},
        },
    },
    {
        Name: "Administrator",
        Permissions: []Permission{
            {Resource: "*", Action: "*"},
        },
    },
}
```

#### 2. **API Security Middleware**
```go
// Rate Limiting Middleware
func RateLimitMiddleware(limit int, window time.Duration) gin.HandlerFunc {
    limiter := rate.NewLimiter(rate.Every(window), limit)
    
    return func(c *gin.Context) {
        if !limiter.Allow() {
            c.JSON(http.StatusTooManyRequests, gin.H{
                "error": "Rate limit exceeded",
            })
            c.Abort()
            return
        }
        c.Next()
    }
}

// Authentication Middleware
func AuthMiddleware(jwtSecret string) gin.HandlerFunc {
    return func(c *gin.Context) {
        token := c.GetHeader("Authorization")
        if token == "" {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing token"})
            c.Abort()
            return
        }
        
        claims, err := validateJWT(token, jwtSecret)
        if err != nil {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
            c.Abort()
            return
        }
        
        c.Set("user", claims)
        c.Next()
    }
}

// Authorization Middleware
func AuthorizeMiddleware(requiredPermission Permission) gin.HandlerFunc {
    return func(c *gin.Context) {
        user, exists := c.Get("user")
        if !exists {
            c.JSON(http.StatusForbidden, gin.H{"error": "User not found"})
            c.Abort()
            return
        }
        
        claims := user.(*JWTClaims)
        if !hasPermission(claims.Permissions, requiredPermission) {
            c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
            c.Abort()
            return
        }
        
        c.Next()
    }
}
```

#### 3. **Agent Authentication**
```go
// Agent Certificate-based Authentication
type AgentAuth struct {
    CertificateStore *x509.CertPool
    TLSConfig        *tls.Config
}

func (a *AgentAuth) ValidateAgentCertificate(cert *x509.Certificate) error {
    // Validate agent certificate against CA
    opts := x509.VerifyOptions{
        Roots: a.CertificateStore,
    }
    
    _, err := cert.Verify(opts)
    if err != nil {
        return fmt.Errorf("certificate validation failed: %w", err)
    }
    
    // Additional validation logic
    if time.Now().After(cert.NotAfter) {
        return fmt.Errorf("certificate expired")
    }
    
    return nil
}

// Agent Registration Process
func (s *AgentManagerService) RegisterAgent(ctx context.Context, req *pb.RegisterAgentRequest) (*pb.RegisterAgentResponse, error) {
    // 1. Validate agent certificate
    if err := s.auth.ValidateAgentCertificate(req.Certificate); err != nil {
        return nil, status.Errorf(codes.Unauthenticated, "Invalid certificate: %v", err)
    }
    
    // 2. Generate agent ID and API key
    agentID := generateAgentID()
    apiKey := generateAPIKey()
    
    // 3. Store agent information
    agent := &Agent{
        ID:            agentID,
        Hostname:      req.Hostname,
        IPAddress:     req.IpAddress,
        OS:            req.OsInfo,
        Capabilities:  req.Capabilities,
        APIKey:        hashAPIKey(apiKey),
        Status:        "registered",
        CreatedAt:     time.Now(),
    }
    
    if err := s.db.Create(agent).Error; err != nil {
        return nil, status.Errorf(codes.Internal, "Failed to register agent: %v", err)
    }
    
    return &pb.RegisterAgentResponse{
        AgentId: agentID,
        ApiKey:  apiKey,
        Config:  s.getDefaultAgentConfig(),
    }, nil
}
```

---

## 📈 Implementation Guide

### Phase 1: Foundation Setup (Weeks 1-2)

#### 1. **Project Structure Setup**
```bash
# Create project structure
mkdir musafir-central-ui
cd musafir-central-ui

# Backend structure
mkdir -p backend/{api-gateway,agent-manager,event-processor,threat-detection}
mkdir -p backend/{shared,migrations,scripts}

# Frontend structure
mkdir -p frontend/{src,public,tests}
mkdir -p frontend/src/{components,services,store,utils,types}

# Infrastructure
mkdir -p infrastructure/{docker,kubernetes,nginx,ssl}
mkdir -p docs/{api,deployment,user-guide}

# Initialize Go modules for each service
cd backend/api-gateway && go mod init musafir/api-gateway
cd ../agent-manager && go mod init musafir/agent-manager
cd ../event-processor && go mod init musafir/event-processor
cd ../threat-detection && go mod init musafir/threat-detection

# Initialize React frontend
cd ../../frontend
npx create-react-app . --template typescript
```

#### 2. **Database Setup Scripts**
```sql
-- PostgreSQL setup script
-- File: backend/migrations/001_initial_schema.sql

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users and Authentication
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Roles and Permissions
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    resource VARCHAR(50) NOT NULL,
    action VARCHAR(50) NOT NULL,
    description TEXT,
    UNIQUE(resource, action)
);

CREATE TABLE role_permissions (
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE user_roles (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

-- Agents
CREATE TABLE agents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id VARCHAR(100) UNIQUE NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    ip_address INET,
    os_name VARCHAR(50),
    os_version VARCHAR(50),
    architecture VARCHAR(20),
    agent_version VARCHAR(20),
    api_key_hash VARCHAR(255),
    capabilities TEXT[], -- Array of capabilities
    configuration JSONB,
    status VARCHAR(20) DEFAULT 'offline',
    last_heartbeat TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Threat Intelligence
CREATE TABLE threat_indicators (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ioc_type VARCHAR(20) NOT NULL, -- ip, domain, hash, url, email
    ioc_value VARCHAR(500) NOT NULL,
    threat_type VARCHAR(50),
    confidence INTEGER CHECK (confidence >= 0 AND confidence <= 100),
    source VARCHAR(100),
    description TEXT,
    tags TEXT[],
    mitre_ttps TEXT[],
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Investigation Cases
CREATE TABLE investigation_cases (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    case_number VARCHAR(50) UNIQUE NOT NULL,
    title VARCHAR(200) NOT NULL,
    description TEXT,
    severity VARCHAR(20) DEFAULT 'medium',
    status VARCHAR(20) DEFAULT 'open',
    assigned_to UUID REFERENCES users(id),
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    closed_at TIMESTAMP
);

-- Indexes for performance
CREATE INDEX idx_agents_status ON agents(status);
CREATE INDEX idx_agents_last_heartbeat ON agents(last_heartbeat);
CREATE INDEX idx_threat_indicators_type_value ON threat_indicators(ioc_type, ioc_value);
CREATE INDEX idx_investigation_cases_status ON investigation_cases(status);
CREATE INDEX idx_investigation_cases_assigned ON investigation_cases(assigned_to);
```

### Phase 2: Core Backend Services (Weeks 3-6)

#### 1. **API Gateway Implementation**
```go
// File: backend/api-gateway/main.go
package main

import (
    "log"
    "os"
    
    "github.com/gin-gonic/gin"
    "musafir/api-gateway/handlers"
    "musafir/api-gateway/middleware"
    "musafir/api-gateway/config"
)

func main() {
    cfg := config.Load()
    
    r := gin.Default()
    
    // Global middleware
    r.Use(middleware.CORS())
    r.Use(middleware.RequestLogger())
    r.Use(middleware.RateLimit(100, time.Minute))
    
    // Health check
    r.GET("/health", handlers.HealthCheck)
    
    // Authentication routes
    auth := r.Group("/api/v1/auth")
    {
        auth.POST("/login", handlers.Login)
        auth.POST("/logout", handlers.Logout)
        auth.POST("/refresh", handlers.RefreshToken)
    }
    
    // Protected routes
    api := r.Group("/api/v1")
    api.Use(middleware.AuthMiddleware(cfg.JWTSecret))
    {
        // Agent management
        agents := api.Group("/agents")
        agents.Use(middleware.AuthorizeMiddleware("agents", "read"))
        {
            agents.GET("", handlers.ListAgents)
            agents.GET("/:id", handlers.GetAgent)
            agents.PUT("/:id/config", middleware.AuthorizeMiddleware("agents", "write"), handlers.UpdateAgentConfig)
            agents.DELETE("/:id", middleware.AuthorizeMiddleware("agents", "delete"), handlers.DeleteAgent)
        }
        
        // Event management
        events := api.Group("/events")
        events.Use(middleware.AuthorizeMiddleware("events", "read"))
        {
            events.GET("", handlers.ListEvents)
            events.GET("/:id", handlers.GetEvent)
            events.POST("/search", handlers.SearchEvents)
        }
        
        // Alert management
        alerts := api.Group("/alerts")
        alerts.Use(middleware.AuthorizeMiddleware("alerts", "read"))
        {
            alerts.GET("", handlers.ListAlerts)
            alerts.PUT("/:id/acknowledge", middleware.AuthorizeMiddleware("alerts", "write"), handlers.AcknowledgeAlert)
            alerts.POST("/:id/investigate", middleware.AuthorizeMiddleware("investigations", "create"), handlers.CreateInvestigation)
        }
        
        // Dashboard and analytics
        dashboard := api.Group("/dashboard")
        dashboard.Use(middleware.AuthorizeMiddleware("dashboard", "read"))
        {
            dashboard.GET("/overview", handlers.GetDashboardOverview)
            dashboard.GET("/threats", handlers.GetThreatLandscape)
        }
        
        analytics := api.Group("/analytics")
        analytics.Use(middleware.AuthorizeMiddleware("analytics", "read"))
        {
            analytics.GET("/trends", handlers.GetSecurityTrends)
            analytics.POST("/query", handlers.ExecuteAnalyticsQuery)
        }
    }
    
    // WebSocket for real-time updates
    r.GET("/ws", middleware.AuthMiddleware(cfg.JWTSecret), handlers.WebSocketHandler)
    
    log.Printf("API Gateway starting on port %s", cfg.Port)
    log.Fatal(r.Run(":" + cfg.Port))
}
```

#### 2. **Agent Manager Service**
```go
// File: backend/agent-manager/service/agent_service.go
package service

import (
    "context"
    "fmt"
    "time"
    
    "gorm.io/gorm"
    "musafir/agent-manager/models"
    pb "musafir/agent-manager/proto"
)

type AgentService struct {
    db    *gorm.DB
    redis *redis.Client
    pb.UnimplementedAgentManagerServer
}

func NewAgentService(db *gorm.DB, redis *redis.Client) *AgentService {
    return &AgentService{
        db:    db,
        redis: redis,
    }
}

func (s *AgentService) RegisterAgent(ctx context.Context, req *pb.RegisterAgentRequest) (*pb.RegisterAgentResponse, error) {
    // Validate request
    if req.Hostname == "" || req.IpAddress == "" {
        return nil, fmt.Errorf("hostname and IP address are required")
    }
    
    // Check if agent already exists
    var existingAgent models.Agent
    if err := s.db.Where("hostname = ? AND ip_address = ?", req.Hostname, req.IpAddress).First(&existingAgent).Error; err == nil {
        // Agent exists, update information
        existingAgent.AgentVersion = req.AgentVersion
        existingAgent.Capabilities = req.Capabilities
        existingAgent.LastHeartbeat = time.Now()
        existingAgent.Status = "online"
        
        if err := s.db.Save(&existingAgent).Error; err != nil {
            return nil, fmt.Errorf("failed to update existing agent: %w", err)
        }
        
        return &pb.RegisterAgentResponse{
            AgentId: existingAgent.AgentID,
            Config:  s.getAgentConfig(existingAgent.ID),
        }, nil
    }
    
    // Create new agent
    agent := models.Agent{
        AgentID:       generateAgentID(),
        Hostname:      req.Hostname,
        IPAddress:     req.IpAddress,
        OSName:        req.OsInfo.Name,
        OSVersion:     req.OsInfo.Version,
        Architecture:  req.OsInfo.Architecture,
        AgentVersion:  req.AgentVersion,
        Capabilities:  req.Capabilities,
        Status:        "online",
        LastHeartbeat: time.Now(),
    }
    
    if err := s.db.Create(&agent).Error; err != nil {
        return nil, fmt.Errorf("failed to create agent: %w", err)
    }
    
    // Cache agent information in Redis
    s.cacheAgentInfo(agent)
    
    return &pb.RegisterAgentResponse{
        AgentId: agent.AgentID,
        Config:  s.getDefaultAgentConfig(),
    }, nil
}

func (s *AgentService) Heartbeat(ctx context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
    // Update agent heartbeat
    if err := s.db.Model(&models.Agent{}).
        Where("agent_id = ?", req.AgentId).
        Updates(map[string]interface{}{
            "last_heartbeat": time.Now(),
            "status":         "online",
        }).Error; err != nil {
        return nil, fmt.Errorf("failed to update heartbeat: %w", err)
    }
    
    // Update Redis cache
    s.redis.Set(ctx, fmt.Sprintf("agent:heartbeat:%s", req.AgentId), time.Now().Unix(), 5*time.Minute)
    
    return &pb.HeartbeatResponse{
        Status: "ok",
        Config: s.getAgentConfig(req.AgentId),
    }, nil
}

func (s *AgentService) GetAgentConfig(agentID string) *pb.AgentConfig {
    // Retrieve agent-specific configuration
    var agent models.Agent
    if err := s.db.Where("agent_id = ?", agentID).First(&agent).Error; err != nil {
        return s.getDefaultAgentConfig()
    }
    
    config := &pb.AgentConfig{
        CollectionInterval: 30, // seconds
        EnabledModules: []string{
            "process_monitor",
            "file_monitor",
            "network_monitor",
            "registry_monitor",
        },
        ThreatDetection: &pb.ThreatDetectionConfig{
            EnableBehaviorAnalysis: true,
            EnableSignatureDetection: true,
            ScanInterval: 60,
        },
        Networking: &pb.NetworkingConfig{
            ServerEndpoint: "grpc://central-server:9090",
            TlsEnabled: true,
            CompressionEnabled: true,
        },
    }
    
    // Apply agent-specific overrides
    if agent.Configuration != nil {
        // Merge with stored configuration
        // Implementation depends on your configuration format
    }
    
    return config
}
```

### Phase 3: Frontend Development (Weeks 7-10)

#### 1. **React Application Structure**
```typescript
// File: frontend/src/App.tsx
import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { Provider } from 'react-redux';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';

import { store } from './store/store';
import { AuthProvider } from './contexts/AuthContext';
import { WebSocketProvider } from './contexts/WebSocketContext';

import Layout from './components/Layout/Layout';
import Dashboard from './pages/Dashboard/Dashboard';
import EDRDashboard from './pages/EDR/EDRDashboard';
import XDRDashboard from './pages/XDR/XDRDashboard';
import SIEMDashboard from './pages/SIEM/SIEMDashboard';
import AgentManagement from './pages/Agents/AgentManagement';
import ThreatIntelligence from './pages/ThreatIntel/ThreatIntelligence';
import Investigations from './pages/Investigations/Investigations';
import Settings from './pages/Settings/Settings';
import Login from './pages/Auth/Login';

import ProtectedRoute from './components/Auth/ProtectedRoute';

const theme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#1976d2',
    },
    secondary: {
      main: '#dc004e',
    },
    background: {
      default: '#0a0e27',
      paper: '#1a1d3a',
    },
  },
  typography: {
    fontFamily: '"Roboto", "Helvetica", "Arial", sans-serif',
  },
});

function App() {
  return (
    <Provider store={store}>
      <ThemeProvider theme={theme}>
        <CssBaseline />
        <AuthProvider>
          <WebSocketProvider>
            <Router>
              <Routes>
                <Route path="/login" element={<Login />} />
                <Route path="/" element={
                  <ProtectedRoute>
                    <Layout />
                  </ProtectedRoute>
                }>
                  <Route index element={<Dashboard />} />
                  <Route path="edr" element={<EDRDashboard />} />
                  <Route path="xdr" element={<XDRDashboard />} />
                  <Route path="siem" element={<SIEMDashboard />} />
                  <Route path="agents" element={<AgentManagement />} />
                  <Route path="threat-intel" element={<ThreatIntelligence />} />
                  <Route path="investigations" element={<Investigations />} />
                  <Route path="settings" element={<Settings />} />
                </Route>
              </Routes>
            </Router>
          </WebSocketProvider>
        </AuthProvider>
      </ThemeProvider>
    </Provider>
  );
}

export default App;
```

#### 2. **Real-time Dashboard Component**
```typescript
// File: frontend/src/pages/Dashboard/Dashboard.tsx
import React, { useEffect, useState } from 'react';
import { Grid, Paper, Typography, Box } from '@mui/material';
import { useSelector, useDispatch } from 'react-redux';

import { RootState } from '../../store/store';
import { fetchDashboardData } from '../../store/slices/dashboardSlice';
import { useWebSocket } from '../../contexts/WebSocketContext';

import ThreatLevelIndicator from '../../components/Dashboard/ThreatLevelIndicator';
import SecurityMetrics from '../../components/Dashboard/SecurityMetrics';
import ThreatMap from '../../components/Dashboard/ThreatMap';
import RecentAlerts from '../../components/Dashboard/RecentAlerts';
import AgentStatus from '../../components/Dashboard/AgentStatus';
import SecurityTimeline from '../../components/Dashboard/SecurityTimeline';

const Dashboard: React.FC = () => {
  const dispatch = useDispatch();
  const { socket } = useWebSocket();
  const { 
    overview, 
    threats, 
    agents, 
    recentAlerts, 
    loading 
  } = useSelector((state: RootState) => state.dashboard);

  useEffect(() => {
    // Fetch initial dashboard data
    dispatch(fetchDashboardData());

    // Set up real-time updates
    if (socket) {
      socket.on('threat_alert', (alert) => {
        // Handle new threat alert
        dispatch(addRealtimeAlert(alert));
      });

      socket.on('agent_status_change', (agentUpdate) => {
        // Handle agent status change
        dispatch(updateAgentStatus(agentUpdate));
      });

      socket.on('security_metrics_update', (metrics) => {
        // Handle metrics update
        dispatch(updateSecurityMetrics(metrics));
      });

      return () => {
        socket.off('threat_alert');
        socket.off('agent_status_change');
        socket.off('security_metrics_update');
      };
    }
  }, [dispatch, socket]);

  if (loading) {
    return <div>Loading dashboard...</div>;
  }

  return (
    <Box sx={{ flexGrow: 1, p: 3 }}>
      <Typography variant="h4" gutterBottom>
        Security Operations Center
      </Typography>
      
      <Grid container spacing={3}>
        {/* Top Row - Key Metrics */}
        <Grid item xs={12} md={3}>
          <ThreatLevelIndicator level={overview.threatLevel} />
        </Grid>
        <Grid item xs={12} md={9}>
          <SecurityMetrics 
            activeAlerts={overview.activeAlerts}
            connectedAgents={overview.connectedAgents}
            eventsPerSecond={overview.eventsPerSecond}
            threatScore={overview.threatScore}
          />
        </Grid>

        {/* Second Row - Threat Visualization */}
        <Grid item xs={12} md={8}>
          <Paper sx={{ p: 2, height: 400 }}>
            <Typography variant="h6" gutterBottom>
              Global Threat Map
            </Typography>
            <ThreatMap threats={threats} />
          </Paper>
        </Grid>
        <Grid item xs={12} md={4}>
          <Paper sx={{ p: 2, height: 400 }}>
            <Typography variant="h6" gutterBottom>
              Recent Alerts
            </Typography>
            <RecentAlerts alerts={recentAlerts} />
          </Paper>
        </Grid>

        {/* Third Row - Agent Status and Timeline */}
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 2, height: 350 }}>
            <Typography variant="h6" gutterBottom>
              Agent Status
            </Typography>
            <AgentStatus agents={agents} />
          </Paper>
        </Grid>
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 2, height: 350 }}>
            <Typography variant="h6" gutterBottom>
              Security Timeline
            </Typography>
            <SecurityTimeline />
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
};

export default Dashboard;
```

### Phase 4: Integration & Testing (Weeks 11-12)

#### 1. **End-to-End Testing Setup**
```typescript
// File: frontend/cypress/integration/dashboard.spec.ts
describe('Security Dashboard', () => {
  beforeEach(() => {
    // Mock authentication
    cy.login('admin', 'password');
    cy.visit('/');
  });

  it('should display security overview', () => {
    cy.get('[data-testid="threat-level-indicator"]').should('be.visible');
    cy.get('[data-testid="security-metrics"]').should('be.visible');
    cy.get('[data-testid="threat-map"]').should('be.visible');
  });

  it('should show real-time alerts', () => {
    // Simulate real-time alert
    cy.mockWebSocketMessage('threat_alert', {
      id: 'alert-123',
      severity: 'high',
      title: 'Suspicious Process Detected',
      timestamp: new Date().toISOString()
    });

    cy.get('[data-testid="recent-alerts"]')
      .should('contain', 'Suspicious Process Detected');
  });

  it('should navigate to EDR dashboard', () => {
    cy.get('[data-testid="nav-edr"]').click();
    cy.url().should('include', '/edr');
    cy.get('[data-testid="endpoint-grid"]').should('be.visible');
  });
});
```

#### 2. **Backend Integration Tests**
```go
// File: backend/tests/integration/agent_test.go
package integration

import (
    "context"
    "testing"
    "time"
    
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/suite"
    pb "musafir/agent-manager/proto"
)

type AgentIntegrationTestSuite struct {
    suite.Suite
    client pb.AgentManagerClient
    ctx    context.Context
}

func (suite *AgentIntegrationTestSuite) SetupSuite() {
    // Set up test environment
    suite.ctx = context.Background()
    // Initialize gRPC client
}

func (suite *AgentIntegrationTestSuite) TestAgentRegistration() {
    req := &pb.RegisterAgentRequest{
        Hostname:     "test-host",
        IpAddress:    "192.168.1.100",
        AgentVersion: "1.0.0",
        OsInfo: &pb.OSInfo{
            Name:         "Windows",
            Version:      "10",
            Architecture: "x64",
        },
        Capabilities: []string{"process_monitor", "file_monitor"},
    }
    
    resp, err := suite.client.RegisterAgent(suite.ctx, req)
    assert.NoError(suite.T(), err)
    assert.NotEmpty(suite.T(), resp.AgentId)
    assert.NotNil(suite.T(), resp.Config)
}

func (suite *AgentIntegrationTestSuite) TestHeartbeat() {
    // First register an agent
    registerReq := &pb.RegisterAgentRequest{
        Hostname:  "test-host-2",
        IpAddress: "192.168.1.101",
    }
    
    registerResp, err := suite.client.RegisterAgent(suite.ctx, registerReq)
    assert.NoError(suite.T(), err)
    
    // Send heartbeat
    heartbeatReq := &pb.HeartbeatRequest{
        AgentId: registerResp.AgentId,
        Status:  "online",
        Metrics: &pb.SystemMetrics{
            CpuUsage:    25.5,
            MemoryUsage: 60.2,
            DiskUsage:   45.8,
        },
    }
    
    heartbeatResp, err := suite.client.Heartbeat(suite.ctx, heartbeatReq)
    assert.NoError(suite.T(), err)
    assert.Equal(suite.T(), "ok", heartbeatResp.Status)
}

func TestAgentIntegrationSuite(t *testing.T) {
    suite.Run(t, new(AgentIntegrationTestSuite))
}
```

---

## 🔍 Monitoring & Alerting

### System Monitoring Setup

#### 1. **Prometheus Metrics Collection**
```go
// File: backend/shared/metrics/metrics.go
package metrics

import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
)

var (
    // Agent metrics
    ConnectedAgents = promauto.NewGauge(prometheus.GaugeOpts{
        Name: "musafir_connected_agents_total",
        Help: "Total number of connected agents",
    })
    
    AgentHeartbeats = promauto.NewCounterVec(prometheus.CounterOpts{
        Name: "musafir_agent_heartbeats_total",
        Help: "Total number of agent heartbeats",
    }, []string{"agent_id", "status"})
    
    // Event processing metrics
    EventsProcessed = promauto.NewCounterVec(prometheus.CounterOpts{
        Name: "musafir_events_processed_total",
        Help: "Total number of events processed",
    }, []string{"event_type", "severity"})
    
    EventProcessingDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
        Name: "musafir_event_processing_duration_seconds",
        Help: "Time spent processing events",
        Buckets: prometheus.DefBuckets,
    }, []string{"event_type"})
    
    // Threat detection metrics
    ThreatsDetected = promauto.NewCounterVec(prometheus.CounterOpts{
        Name: "musafir_threats_detected_total",
        Help: "Total number of threats detected",
    }, []string{"threat_type", "confidence_level"})
    
    // API metrics
    APIRequests = promauto.NewCounterVec(prometheus.CounterOpts{
        Name: "musafir_api_requests_total",
        Help: "Total number of API requests",
    }, []string{"method", "endpoint", "status_code"})
    
    APIRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
        Name: "musafir_api_request_duration_seconds",
        Help: "Time spent processing API requests",
        Buckets: prometheus.DefBuckets,
    }, []string{"method", "endpoint"})
)

// Middleware for API metrics
func PrometheusMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        start := time.Now()
        
        c.Next()
        
        duration := time.Since(start).Seconds()
        statusCode := strconv.Itoa(c.Writer.Status())
        
        APIRequests.WithLabelValues(c.Request.Method, c.FullPath(), statusCode).Inc()
        APIRequestDuration.WithLabelValues(c.Request.Method, c.FullPath()).Observe(duration)
    }
}
```

#### 2. **Grafana Dashboard Configuration**
```json
{
  "dashboard": {
    "title": "MUSAFIR Security Operations Center",
    "panels": [
      {
        "title": "Connected Agents",
        "type": "stat",
        "targets": [
          {
            "expr": "musafir_connected_agents_total",
            "legendFormat": "Connected Agents"
          }
        ]
      },
      {
        "title": "Events Per Second",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(musafir_events_processed_total[5m])",
            "legendFormat": "{{event_type}}"
          }
        ]
      },
      {
        "title": "Threat Detection Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(musafir_threats_detected_total[5m])",
            "legendFormat": "{{threat_type}}"
          }
        ]
      },
      {
        "title": "API Response Times",
        "type": "heatmap",
        "targets": [
          {
            "expr": "rate(musafir_api_request_duration_seconds_bucket[5m])",
            "legendFormat": "{{le}}"
          }
        ]
      }
    ]
  }
}
```

---

This comprehensive documentation provides a complete roadmap for developing the MUSAFIR Central Web UI platform. The architecture supports scalable, real-time security operations with EDR, XDR, and SIEM capabilities, all containerized with Docker for easy deployment and management.
# MUSAFIR Central Web UI - API Specifications & Backend Services

## 📋 Table of Contents
1. [API Gateway Specifications](#api-gateway-specifications)
2. [Agent Management Service](#agent-management-service)
3. [Event Processing Service](#event-processing-service)
4. [Threat Detection Service](#threat-detection-service)
5. [Analytics Service](#analytics-service)
6. [User Management Service](#user-management-service)
7. [gRPC Service Definitions](#grpc-service-definitions)
8. [WebSocket Real-time Events](#websocket-real-time-events)

---

## 🌐 API Gateway Specifications

### Base Configuration
```yaml
# API Gateway Configuration
server:
  host: "0.0.0.0"
  port: 8080
  read_timeout: 30s
  write_timeout: 30s
  idle_timeout: 120s

security:
  jwt_secret: "${JWT_SECRET}"
  jwt_expiry: 24h
  refresh_token_expiry: 168h # 7 days
  rate_limit: 1000 # requests per minute
  cors_origins: ["http://localhost:3000", "https://musafir.security"]

services:
  agent_manager: "agent-manager:9090"
  event_processor: "event-processor:9091"
  threat_detection: "threat-detection:9092"
  analytics: "analytics-service:9093"
  user_management: "user-service:9094"
```

### Authentication Endpoints

#### POST /api/v1/auth/login
```json
{
  "request": {
    "username": "string",
    "password": "string",
    "remember_me": "boolean"
  },
  "response": {
    "access_token": "string",
    "refresh_token": "string",
    "expires_in": "number",
    "user": {
      "id": "string",
      "username": "string",
      "email": "string",
      "roles": ["string"],
      "permissions": ["string"],
      "last_login": "timestamp"
    }
  },
  "errors": {
    "400": "Invalid credentials",
    "401": "Authentication failed",
    "429": "Too many login attempts"
  }
}
```

#### POST /api/v1/auth/refresh
```json
{
  "request": {
    "refresh_token": "string"
  },
  "response": {
    "access_token": "string",
    "expires_in": "number"
  },
  "errors": {
    "401": "Invalid refresh token",
    "403": "Token expired"
  }
}
```

### Agent Management Endpoints

#### GET /api/v1/agents
```json
{
  "query_parameters": {
    "page": "number (default: 1)",
    "limit": "number (default: 50, max: 100)",
    "status": "string (online|offline|error)",
    "os": "string (windows|linux|macos)",
    "search": "string (hostname or IP)"
  },
  "response": {
    "agents": [
      {
        "id": "string",
        "agent_id": "string",
        "hostname": "string",
        "ip_address": "string",
        "os_info": {
          "name": "string",
          "version": "string",
          "architecture": "string"
        },
        "agent_version": "string",
        "capabilities": ["string"],
        "status": "string",
        "last_heartbeat": "timestamp",
        "threat_score": "number",
        "events_count_24h": "number",
        "created_at": "timestamp"
      }
    ],
    "pagination": {
      "page": "number",
      "limit": "number",
      "total": "number",
      "total_pages": "number"
    }
  }
}
```

#### GET /api/v1/agents/{agent_id}
```json
{
  "response": {
    "id": "string",
    "agent_id": "string",
    "hostname": "string",
    "ip_address": "string",
    "os_info": {
      "name": "string",
      "version": "string",
      "architecture": "string",
      "kernel_version": "string"
    },
    "agent_version": "string",
    "capabilities": ["string"],
    "configuration": {
      "collection_interval": "number",
      "enabled_modules": ["string"],
      "threat_detection": {
        "enable_behavior_analysis": "boolean",
        "enable_signature_detection": "boolean",
        "scan_interval": "number"
      },
      "networking": {
        "server_endpoint": "string",
        "tls_enabled": "boolean",
        "compression_enabled": "boolean"
      }
    },
    "status": "string",
    "last_heartbeat": "timestamp",
    "system_info": {
      "cpu_count": "number",
      "memory_total": "number",
      "disk_total": "number",
      "network_interfaces": [
        {
          "name": "string",
          "ip_address": "string",
          "mac_address": "string"
        }
      ]
    },
    "statistics": {
      "events_sent_24h": "number",
      "threats_detected_24h": "number",
      "uptime": "number",
      "cpu_usage": "number",
      "memory_usage": "number"
    },
    "created_at": "timestamp",
    "updated_at": "timestamp"
  }
}
```

#### PUT /api/v1/agents/{agent_id}/config
```json
{
  "request": {
    "collection_interval": "number",
    "enabled_modules": ["string"],
    "threat_detection": {
      "enable_behavior_analysis": "boolean",
      "enable_signature_detection": "boolean",
      "scan_interval": "number"
    },
    "networking": {
      "compression_enabled": "boolean",
      "heartbeat_interval": "number"
    }
  },
  "response": {
    "message": "Configuration updated successfully",
    "config": "object" // Updated configuration
  }
}
```

#### POST /api/v1/agents/{agent_id}/actions
```json
{
  "request": {
    "action": "string", // isolate|unisolate|restart|update_config|collect_forensics
    "parameters": "object" // Action-specific parameters
  },
  "response": {
    "action_id": "string",
    "status": "string", // pending|in_progress|completed|failed
    "message": "string"
  }
}
```

### Event Management Endpoints

#### GET /api/v1/events
```json
{
  "query_parameters": {
    "page": "number",
    "limit": "number",
    "start_time": "timestamp",
    "end_time": "timestamp",
    "agent_id": "string",
    "event_type": "string",
    "severity": "string",
    "search": "string"
  },
  "response": {
    "events": [
      {
        "id": "string",
        "agent_id": "string",
        "timestamp": "timestamp",
        "event_type": "string",
        "severity": "string",
        "title": "string",
        "description": "string",
        "data": "object",
        "enrichment": {
          "geo_location": {
            "country": "string",
            "city": "string",
            "latitude": "number",
            "longitude": "number"
          },
          "threat_intelligence": {
            "iocs": ["object"],
            "mitre_ttps": ["string"]
          }
        },
        "threat_score": "number",
        "tags": ["string"]
      }
    ],
    "pagination": "object",
    "aggregations": {
      "by_severity": "object",
      "by_event_type": "object",
      "by_agent": "object"
    }
  }
}
```

#### POST /api/v1/events/search
```json
{
  "request": {
    "query": {
      "bool": {
        "must": [
          {
            "range": {
              "timestamp": {
                "gte": "timestamp",
                "lte": "timestamp"
              }
            }
          },
          {
            "terms": {
              "event_type": ["process", "network", "file"]
            }
          }
        ],
        "filter": [
          {
            "term": {
              "severity": "high"
            }
          }
        ]
      }
    },
    "aggregations": {
      "severity_breakdown": {
        "terms": {
          "field": "severity"
        }
      }
    },
    "sort": [
      {
        "timestamp": {
          "order": "desc"
        }
      }
    ],
    "size": 100
  },
  "response": {
    "hits": {
      "total": "number",
      "events": ["object"]
    },
    "aggregations": "object"
  }
}
```

### Alert Management Endpoints

#### GET /api/v1/alerts
```json
{
  "query_parameters": {
    "status": "string", // open|acknowledged|investigating|resolved|closed
    "severity": "string",
    "assigned_to": "string",
    "created_after": "timestamp"
  },
  "response": {
    "alerts": [
      {
        "id": "string",
        "title": "string",
        "description": "string",
        "severity": "string",
        "status": "string",
        "threat_type": "string",
        "confidence": "number",
        "mitre_ttps": ["string"],
        "iocs": [
          {
            "type": "string",
            "value": "string",
            "confidence": "number"
          }
        ],
        "affected_assets": [
          {
            "agent_id": "string",
            "hostname": "string",
            "ip_address": "string"
          }
        ],
        "events": ["string"], // Event IDs
        "assigned_to": "string",
        "created_by": "string",
        "created_at": "timestamp",
        "updated_at": "timestamp",
        "timeline": [
          {
            "timestamp": "timestamp",
            "action": "string",
            "user": "string",
            "details": "string"
          }
        ]
      }
    ]
  }
}
```

#### PUT /api/v1/alerts/{alert_id}/acknowledge
```json
{
  "request": {
    "comment": "string"
  },
  "response": {
    "message": "Alert acknowledged successfully",
    "alert": "object"
  }
}
```

#### POST /api/v1/alerts/{alert_id}/investigate
```json
{
  "request": {
    "title": "string",
    "description": "string",
    "assigned_to": "string"
  },
  "response": {
    "investigation_id": "string",
    "message": "Investigation created successfully"
  }
}
```

### Dashboard & Analytics Endpoints

#### GET /api/v1/dashboard/overview
```json
{
  "response": {
    "threat_level": "string", // low|medium|high|critical
    "active_alerts": "number",
    "connected_agents": "number",
    "events_per_second": "number",
    "threat_score": "number",
    "statistics": {
      "events_24h": "number",
      "threats_detected_24h": "number",
      "incidents_resolved_24h": "number",
      "mean_time_to_detection": "number", // seconds
      "mean_time_to_response": "number"   // seconds
    },
    "top_threats": [
      {
        "threat_type": "string",
        "count": "number",
        "trend": "string" // up|down|stable
      }
    ],
    "agent_distribution": {
      "by_os": "object",
      "by_status": "object",
      "by_version": "object"
    }
  }
}
```

#### GET /api/v1/dashboard/threats
```json
{
  "query_parameters": {
    "time_range": "string" // 1h|6h|24h|7d|30d
  },
  "response": {
    "threat_landscape": {
      "geographic_distribution": [
        {
          "country": "string",
          "threat_count": "number",
          "coordinates": {
            "latitude": "number",
            "longitude": "number"
          }
        }
      ],
      "attack_vectors": [
        {
          "vector": "string",
          "count": "number",
          "percentage": "number"
        }
      ],
      "mitre_techniques": [
        {
          "technique_id": "string",
          "technique_name": "string",
          "count": "number",
          "tactic": "string"
        }
      ]
    },
    "timeline": [
      {
        "timestamp": "timestamp",
        "threat_count": "number",
        "severity_breakdown": {
          "low": "number",
          "medium": "number",
          "high": "number",
          "critical": "number"
        }
      }
    ]
  }
}
```

---

## 🔧 Agent Management Service

### gRPC Service Definition
```protobuf
// File: proto/agent_manager.proto
syntax = "proto3";

package musafir.agent_manager;

option go_package = "musafir/agent-manager/proto";

service AgentManager {
  // Agent lifecycle management
  rpc RegisterAgent(RegisterAgentRequest) returns (RegisterAgentResponse);
  rpc Heartbeat(HeartbeatRequest) returns (HeartbeatResponse);
  rpc UpdateConfiguration(UpdateConfigurationRequest) returns (UpdateConfigurationResponse);
  rpc DeregisterAgent(DeregisterAgentRequest) returns (DeregisterAgentResponse);
  
  // Agent actions
  rpc ExecuteAction(ExecuteActionRequest) returns (ExecuteActionResponse);
  rpc GetActionStatus(GetActionStatusRequest) returns (GetActionStatusResponse);
  
  // Data streaming
  rpc StreamEvents(stream EventStreamRequest) returns (stream EventStreamResponse);
  rpc StreamMetrics(stream MetricStreamRequest) returns (stream MetricStreamResponse);
}

message RegisterAgentRequest {
  string hostname = 1;
  string ip_address = 2;
  OSInfo os_info = 3;
  string agent_version = 4;
  repeated string capabilities = 5;
  SystemInfo system_info = 6;
}

message RegisterAgentResponse {
  string agent_id = 1;
  string api_key = 2;
  AgentConfig config = 3;
  string server_certificate = 4;
}

message OSInfo {
  string name = 1;
  string version = 2;
  string architecture = 3;
  string kernel_version = 4;
}

message SystemInfo {
  int32 cpu_count = 1;
  int64 memory_total = 2;
  int64 disk_total = 3;
  repeated NetworkInterface network_interfaces = 4;
}

message NetworkInterface {
  string name = 1;
  string ip_address = 2;
  string mac_address = 3;
  bool is_up = 4;
}

message AgentConfig {
  int32 collection_interval = 1;
  repeated string enabled_modules = 2;
  ThreatDetectionConfig threat_detection = 3;
  NetworkingConfig networking = 4;
  LoggingConfig logging = 5;
}

message ThreatDetectionConfig {
  bool enable_behavior_analysis = 1;
  bool enable_signature_detection = 2;
  int32 scan_interval = 3;
  repeated string yara_rules = 4;
}

message NetworkingConfig {
  string server_endpoint = 1;
  bool tls_enabled = 2;
  bool compression_enabled = 3;
  int32 heartbeat_interval = 4;
  int32 retry_attempts = 5;
}

message LoggingConfig {
  string log_level = 1;
  bool enable_file_logging = 2;
  string log_file_path = 3;
  int64 max_log_size = 4;
}

message HeartbeatRequest {
  string agent_id = 1;
  string status = 2;
  SystemMetrics metrics = 3;
  repeated string active_modules = 4;
}

message HeartbeatResponse {
  string status = 1;
  AgentConfig config = 2;
  repeated AgentAction pending_actions = 3;
}

message SystemMetrics {
  double cpu_usage = 1;
  double memory_usage = 2;
  double disk_usage = 3;
  int64 network_bytes_sent = 4;
  int64 network_bytes_received = 5;
  int32 process_count = 6;
  int32 thread_count = 7;
}

message AgentAction {
  string action_id = 1;
  string action_type = 2; // isolate, collect_forensics, update_config, etc.
  map<string, string> parameters = 3;
  int64 timeout = 4;
}

message ExecuteActionRequest {
  string agent_id = 1;
  string action_type = 2;
  map<string, string> parameters = 3;
  int64 timeout = 4;
}

message ExecuteActionResponse {
  string action_id = 1;
  string status = 2; // pending, in_progress, completed, failed
  string message = 3;
}
```

### Go Service Implementation
```go
// File: backend/agent-manager/service/agent_service.go
package service

import (
    "context"
    "crypto/rand"
    "encoding/hex"
    "fmt"
    "sync"
    "time"
    
    "github.com/go-redis/redis/v8"
    "google.golang.org/grpc/codes"
    "google.golang.org/grpc/status"
    "gorm.io/gorm"
    
    "musafir/agent-manager/models"
    pb "musafir/agent-manager/proto"
    "musafir/shared/logger"
)

type AgentService struct {
    db          *gorm.DB
    redis       *redis.Client
    logger      logger.Logger
    agentStore  map[string]*models.Agent
    actionStore map[string]*models.AgentAction
    mutex       sync.RWMutex
    pb.UnimplementedAgentManagerServer
}

func NewAgentService(db *gorm.DB, redis *redis.Client, logger logger.Logger) *AgentService {
    return &AgentService{
        db:          db,
        redis:       redis,
        logger:      logger,
        agentStore:  make(map[string]*models.Agent),
        actionStore: make(map[string]*models.AgentAction),
    }
}

func (s *AgentService) RegisterAgent(ctx context.Context, req *pb.RegisterAgentRequest) (*pb.RegisterAgentResponse, error) {
    s.logger.Info("Agent registration request", "hostname", req.Hostname, "ip", req.IpAddress)
    
    // Validate request
    if err := s.validateRegistrationRequest(req); err != nil {
        return nil, status.Errorf(codes.InvalidArgument, "Invalid registration request: %v", err)
    }
    
    // Check for existing agent
    var existingAgent models.Agent
    err := s.db.Where("hostname = ? AND ip_address = ?", req.Hostname, req.IpAddress).First(&existingAgent).Error
    
    if err == nil {
        // Agent exists, update and return
        return s.updateExistingAgent(ctx, &existingAgent, req)
    } else if err != gorm.ErrRecordNotFound {
        s.logger.Error("Database error during agent lookup", "error", err)
        return nil, status.Errorf(codes.Internal, "Database error: %v", err)
    }
    
    // Create new agent
    agent := &models.Agent{
        AgentID:       s.generateAgentID(),
        Hostname:      req.Hostname,
        IPAddress:     req.IpAddress,
        OSName:        req.OsInfo.Name,
        OSVersion:     req.OsInfo.Version,
        Architecture:  req.OsInfo.Architecture,
        KernelVersion: req.OsInfo.KernelVersion,
        AgentVersion:  req.AgentVersion,
        Capabilities:  req.Capabilities,
        Status:        "online",
        LastHeartbeat: time.Now(),
        SystemInfo:    s.convertSystemInfo(req.SystemInfo),
    }
    
    // Generate API key
    apiKey, err := s.generateAPIKey()
    if err != nil {
        return nil, status.Errorf(codes.Internal, "Failed to generate API key: %v", err)
    }
    
    agent.APIKeyHash = s.hashAPIKey(apiKey)
    
    // Save to database
    if err := s.db.Create(agent).Error; err != nil {
        s.logger.Error("Failed to create agent", "error", err)
        return nil, status.Errorf(codes.Internal, "Failed to register agent: %v", err)
    }
    
    // Cache agent information
    s.cacheAgent(agent)
    
    // Get default configuration
    config := s.getDefaultAgentConfig()
    
    s.logger.Info("Agent registered successfully", "agent_id", agent.AgentID, "hostname", agent.Hostname)
    
    return &pb.RegisterAgentResponse{
        AgentId:           agent.AgentID,
        ApiKey:            apiKey,
        Config:            config,
        ServerCertificate: s.getServerCertificate(),
    }, nil
}

func (s *AgentService) Heartbeat(ctx context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
    // Validate agent exists
    agent, err := s.getAgent(req.AgentId)
    if err != nil {
        return nil, status.Errorf(codes.NotFound, "Agent not found: %v", err)
    }
    
    // Update heartbeat and metrics
    now := time.Now()
    updates := map[string]interface{}{
        "last_heartbeat": now,
        "status":         req.Status,
    }
    
    if req.Metrics != nil {
        updates["cpu_usage"] = req.Metrics.CpuUsage
        updates["memory_usage"] = req.Metrics.MemoryUsage
        updates["disk_usage"] = req.Metrics.DiskUsage
    }
    
    if err := s.db.Model(&models.Agent{}).Where("agent_id = ?", req.AgentId).Updates(updates).Error; err != nil {
        s.logger.Error("Failed to update agent heartbeat", "agent_id", req.AgentId, "error", err)
        return nil, status.Errorf(codes.Internal, "Failed to update heartbeat: %v", err)
    }
    
    // Update cache
    s.updateAgentCache(req.AgentId, updates)
    
    // Store metrics in Redis for real-time monitoring
    s.storeMetricsInCache(req.AgentId, req.Metrics)
    
    // Get pending actions
    pendingActions := s.getPendingActions(req.AgentId)
    
    // Get current configuration
    config := s.getAgentConfig(req.AgentId)
    
    return &pb.HeartbeatResponse{
        Status:         "ok",
        Config:         config,
        PendingActions: pendingActions,
    }, nil
}

func (s *AgentService) ExecuteAction(ctx context.Context, req *pb.ExecuteActionRequest) (*pb.ExecuteActionResponse, error) {
    // Validate agent exists
    _, err := s.getAgent(req.AgentId)
    if err != nil {
        return nil, status.Errorf(codes.NotFound, "Agent not found: %v", err)
    }
    
    // Create action record
    action := &models.AgentAction{
        ID:         s.generateActionID(),
        AgentID:    req.AgentId,
        ActionType: req.ActionType,
        Parameters: req.Parameters,
        Status:     "pending",
        Timeout:    req.Timeout,
        CreatedAt:  time.Now(),
    }
    
    // Save to database
    if err := s.db.Create(action).Error; err != nil {
        return nil, status.Errorf(codes.Internal, "Failed to create action: %v", err)
    }
    
    // Cache action for quick retrieval
    s.mutex.Lock()
    s.actionStore[action.ID] = action
    s.mutex.Unlock()
    
    // Notify agent via Redis pub/sub
    s.notifyAgentAction(req.AgentId, action)
    
    s.logger.Info("Action created for agent", "agent_id", req.AgentId, "action_id", action.ID, "action_type", req.ActionType)
    
    return &pb.ExecuteActionResponse{
        ActionId: action.ID,
        Status:   "pending",
        Message:  "Action queued for execution",
    }, nil
}

// Helper methods
func (s *AgentService) generateAgentID() string {
    bytes := make([]byte, 16)
    rand.Read(bytes)
    return "agent-" + hex.EncodeToString(bytes)[:16]
}

func (s *AgentService) generateAPIKey() (string, error) {
    bytes := make([]byte, 32)
    if _, err := rand.Read(bytes); err != nil {
        return "", err
    }
    return hex.EncodeToString(bytes), nil
}

func (s *AgentService) hashAPIKey(apiKey string) string {
    // Implement secure hashing (bcrypt, scrypt, etc.)
    // This is a simplified example
    return fmt.Sprintf("hashed_%s", apiKey)
}

func (s *AgentService) getDefaultAgentConfig() *pb.AgentConfig {
    return &pb.AgentConfig{
        CollectionInterval: 30,
        EnabledModules: []string{
            "process_monitor",
            "file_monitor",
            "network_monitor",
            "registry_monitor",
        },
        ThreatDetection: &pb.ThreatDetectionConfig{
            EnableBehaviorAnalysis:    true,
            EnableSignatureDetection:  true,
            ScanInterval:             60,
        },
        Networking: &pb.NetworkingConfig{
            ServerEndpoint:      "grpc://central-server:9090",
            TlsEnabled:         true,
            CompressionEnabled: true,
            HeartbeatInterval:  30,
            RetryAttempts:      3,
        },
        Logging: &pb.LoggingConfig{
            LogLevel:          "INFO",
            EnableFileLogging: true,
            LogFilePath:       "/var/log/musafir-agent.log",
            MaxLogSize:        100 * 1024 * 1024, // 100MB
        },
    }
}

func (s *AgentService) cacheAgent(agent *models.Agent) {
    s.mutex.Lock()
    defer s.mutex.Unlock()
    s.agentStore[agent.AgentID] = agent
    
    // Also cache in Redis for cross-service access
    agentData := map[string]interface{}{
        "hostname":       agent.Hostname,
        "ip_address":     agent.IPAddress,
        "status":         agent.Status,
        "last_heartbeat": agent.LastHeartbeat.Unix(),
    }
    
    s.redis.HMSet(context.Background(), fmt.Sprintf("agent:%s", agent.AgentID), agentData)
    s.redis.Expire(context.Background(), fmt.Sprintf("agent:%s", agent.AgentID), 24*time.Hour)
}

func (s *AgentService) storeMetricsInCache(agentID string, metrics *pb.SystemMetrics) {
    if metrics == nil {
        return
    }
    
    metricsData := map[string]interface{}{
        "cpu_usage":    metrics.CpuUsage,
        "memory_usage": metrics.MemoryUsage,
        "disk_usage":   metrics.DiskUsage,
        "timestamp":    time.Now().Unix(),
    }
    
    // Store latest metrics
    s.redis.HMSet(context.Background(), fmt.Sprintf("agent:metrics:%s", agentID), metricsData)
    s.redis.Expire(context.Background(), fmt.Sprintf("agent:metrics:%s", agentID), time.Hour)
    
    // Add to time series for historical data
    s.redis.ZAdd(context.Background(), fmt.Sprintf("agent:metrics:history:%s", agentID), &redis.Z{
        Score:  float64(time.Now().Unix()),
        Member: fmt.Sprintf("%.2f,%.2f,%.2f", metrics.CpuUsage, metrics.MemoryUsage, metrics.DiskUsage),
    })
    
    // Keep only last 24 hours of metrics
    s.redis.ZRemRangeByScore(context.Background(), fmt.Sprintf("agent:metrics:history:%s", agentID), 
        "0", fmt.Sprintf("%.0f", float64(time.Now().Add(-24*time.Hour).Unix())))
}
```

---

## 📊 Event Processing Service

### Event Stream Processing
```go
// File: backend/event-processor/service/event_processor.go
package service

import (
    "context"
    "encoding/json"
    "fmt"
    "time"
    
    "github.com/confluentinc/confluent-kafka-go/kafka"
    influxdb2 "github.com/influxdata/influxdb-client-go/v2"
    "go.mongodb.org/mongo-driver/mongo"
    
    "musafir/event-processor/models"
    "musafir/shared/logger"
)

type EventProcessor struct {
    kafkaConsumer *kafka.Consumer
    influxClient  influxdb2.Client
    mongoClient   *mongo.Client
    ruleEngine    *RuleEngine
    enricher      *EventEnricher
    logger        logger.Logger
}

func NewEventProcessor(kafkaConsumer *kafka.Consumer, influxClient influxdb2.Client, 
                      mongoClient *mongo.Client, logger logger.Logger) *EventProcessor {
    return &EventProcessor{
        kafkaConsumer: kafkaConsumer,
        influxClient:  influxClient,
        mongoClient:   mongoClient,
        ruleEngine:    NewRuleEngine(),
        enricher:      NewEventEnricher(),
        logger:        logger,
    }
}

func (ep *EventProcessor) Start(ctx context.Context) error {
    ep.logger.Info("Starting event processor")
    
    // Subscribe to Kafka topics
    topics := []string{"raw-events", "agent-metrics", "system-logs"}
    if err := ep.kafkaConsumer.SubscribeTopics(topics, nil); err != nil {
        return fmt.Errorf("failed to subscribe to topics: %w", err)
    }
    
    // Start processing loop
    go ep.processEvents(ctx)
    
    return nil
}

func (ep *EventProcessor) processEvents(ctx context.Context) {
    for {
        select {
        case <-ctx.Done():
            ep.logger.Info("Event processor shutting down")
            return
        default:
            msg, err := ep.kafkaConsumer.ReadMessage(100 * time.Millisecond)
            if err != nil {
                if err.(kafka.Error).Code() != kafka.ErrTimedOut {
                    ep.logger.Error("Error reading message", "error", err)
                }
                continue
            }
            
            if err := ep.handleMessage(ctx, msg); err != nil {
                ep.logger.Error("Error processing message", "error", err, "topic", *msg.TopicPartition.Topic)
            }
        }
    }
}

func (ep *EventProcessor) handleMessage(ctx context.Context, msg *kafka.Message) error {
    switch *msg.TopicPartition.Topic {
    case "raw-events":
        return ep.processSecurityEvent(ctx, msg.Value)
    case "agent-metrics":
        return ep.processMetrics(ctx, msg.Value)
    case "system-logs":
        return ep.processSystemLogs(ctx, msg.Value)
    default:
        return fmt.Errorf("unknown topic: %s", *msg.TopicPartition.Topic)
    }
}

func (ep *EventProcessor) processSecurityEvent(ctx context.Context, data []byte) error {
    var rawEvent models.RawSecurityEvent
    if err := json.Unmarshal(data, &rawEvent); err != nil {
        return fmt.Errorf("failed to unmarshal event: %w", err)
    }
    
    // 1. Validate event
    if err := ep.validateEvent(&rawEvent); err != nil {
        ep.logger.Warn("Invalid event received", "error", err, "agent_id", rawEvent.AgentID)
        return nil // Don't return error for invalid events, just log and continue
    }
    
    // 2. Enrich event with additional context
    enrichedEvent, err := ep.enricher.EnrichEvent(ctx, &rawEvent)
    if err != nil {
        ep.logger.Error("Failed to enrich event", "error", err)
        // Continue processing even if enrichment fails
        enrichedEvent = ep.convertToSecurityEvent(&rawEvent)
    }
    
    // 3. Apply detection rules
    threats := ep.ruleEngine.AnalyzeEvent(enrichedEvent)
    
    // 4. Store event in time-series database
    if err := ep.storeEventInInflux(enrichedEvent); err != nil {
        ep.logger.Error("Failed to store event in InfluxDB", "error", err)
    }
    
    // 5. Store detailed event in MongoDB
    if err := ep.storeEventInMongo(ctx, enrichedEvent); err != nil {
        ep.logger.Error("Failed to store event in MongoDB", "error", err)
    }
    
    // 6. Generate alerts for detected threats
    for _, threat := range threats {
        if err := ep.generateThreatAlert(ctx, enrichedEvent, threat); err != nil {
            ep.logger.Error("Failed to generate threat alert", "error", err)
        }
    }
    
    // 7. Forward to real-time dashboard
    ep.forwardToRealtime(enrichedEvent)
    
    return nil
}

func (ep *EventProcessor) storeEventInInflux(event *models.SecurityEvent) error {
    writeAPI := ep.influxClient.WriteAPIBlocking("musafir", "events")
    
    // Create InfluxDB point
    point := influxdb2.NewPoint("security_events",
        map[string]string{
            "agent_id":    event.AgentID,
            "event_type":  event.EventType,
            "severity":    event.Severity,
            "hostname":    event.Hostname,
        },
        map[string]interface{}{
            "threat_score":    event.ThreatScore,
            "process_name":    event.GetProcessName(),
            "file_path":       event.GetFilePath(),
            "network_dest":    event.GetNetworkDestination(),
            "user_name":       event.GetUserName(),
        },
        event.Timestamp)
    
    return writeAPI.WritePoint(context.Background(), point)
}

func (ep *EventProcessor) storeEventInMongo(ctx context.Context, event *models.SecurityEvent) error {
    collection := ep.mongoClient.Database("musafir").Collection("security_events")
    
    // Convert to MongoDB document
    doc := bson.M{
        "_id":         event.ID,
        "agent_id":    event.AgentID,
        "timestamp":   event.Timestamp,
        "event_type":  event.EventType,
        "severity":    event.Severity,
        "title":       event.Title,
        "description": event.Description,
        "data":        event.Data,
        "enrichment":  event.Enrichment,
        "threat_score": event.ThreatScore,
        "tags":        event.Tags,
        "created_at":  time.Now(),
    }
    
    _, err := collection.InsertOne(ctx, doc)
    return err
}

// Event enrichment service
type EventEnricher struct {
    geoIPService    *GeoIPService
    threatIntelAPI  *ThreatIntelligenceAPI
    assetDatabase   *AssetDatabase
}

func (ee *EventEnricher) EnrichEvent(ctx context.Context, rawEvent *models.RawSecurityEvent) (*models.SecurityEvent, error) {
    event := ee.convertToSecurityEvent(rawEvent)
    
    // Geo-location enrichment
    if ipAddress := event.GetIPAddress(); ipAddress != "" {
        if geoInfo, err := ee.geoIPService.Lookup(ipAddress); err == nil {
            event.Enrichment.GeoLocation = geoInfo
        }
    }
    
    // Threat intelligence enrichment
    iocs := ee.extractIOCs(event)
    for _, ioc := range iocs {
        if threatInfo, err := ee.threatIntelAPI.Lookup(ctx, ioc); err == nil {
            event.Enrichment.ThreatIntelligence.IOCs = append(event.Enrichment.ThreatIntelligence.IOCs, threatInfo)
        }
    }
    
    // Asset information enrichment
    if assetInfo, err := ee.assetDatabase.GetAssetInfo(event.AgentID); err == nil {
        event.Enrichment.AssetInfo = assetInfo
    }
    
    // Calculate threat score based on enrichment
    event.ThreatScore = ee.calculateThreatScore(event)
    
    return event, nil
}

// Rule engine for threat detection
type RuleEngine struct {
    yaraRules       *YaraRuleSet
    behaviorRules   []BehaviorRule
    signatureRules  []SignatureRule
}

func (re *RuleEngine) AnalyzeEvent(event *models.SecurityEvent) []models.ThreatDetection {
    var threats []models.ThreatDetection
    
    // Apply YARA rules for file-based events
    if event.EventType == "file" {
        if matches := re.yaraRules.ScanEvent(event); len(matches) > 0 {
            for _, match := range matches {
                threats = append(threats, models.ThreatDetection{
                    Type:       "malware",
                    Confidence: 0.9,
                    Rule:       match.Rule,
                    Details:    match.Details,
                })
            }
        }
    }
    
    // Apply behavior-based detection
    for _, rule := range re.behaviorRules {
        if rule.Matches(event) {
            threats = append(threats, models.ThreatDetection{
                Type:       rule.ThreatType,
                Confidence: rule.Confidence,
                Rule:       rule.Name,
                Details:    rule.Description,
            })
        }
    }
    
    // Apply signature-based detection
    for _, rule := range re.signatureRules {
        if rule.Matches(event) {
            threats = append(threats, models.ThreatDetection{
                Type:       rule.ThreatType,
                Confidence: rule.Confidence,
                Rule:       rule.Name,
                Details:    rule.Description,
            })
        }
    }
    
    return threats
}

// Behavior rule example
type BehaviorRule struct {
    Name        string
    ThreatType  string
    Confidence  float64
    Description string
    Conditions  []Condition
}

func (br *BehaviorRule) Matches(event *models.SecurityEvent) bool {
    for _, condition := range br.Conditions {
        if !condition.Evaluate(event) {
            return false
        }
    }
    return true
}

// Example behavior rules
var DefaultBehaviorRules = []BehaviorRule{
    {
        Name:        "Suspicious Process Injection",
        ThreatType:  "process_injection",
        Confidence:  0.8,
        Description: "Detected potential process injection technique",
        Conditions: []Condition{
            {Field: "event_type", Operator: "equals", Value: "process"},
            {Field: "data.technique", Operator: "contains", Value: "injection"},
            {Field: "data.parent_process", Operator: "not_in", Value: []string{"explorer.exe", "cmd.exe"}},
        },
    },
    {
        Name:        "Lateral Movement Detection",
        ThreatType:  "lateral_movement",
        Confidence:  0.7,
        Description: "Detected potential lateral movement activity",
        Conditions: []Condition{
            {Field: "event_type", Operator: "equals", Value: "network"},
            {Field: "data.destination_port", Operator: "in", Value: []int{445, 139, 3389}},
            {Field: "data.connection_count", Operator: "greater_than", Value: 10},
        },
    },
}
```

This comprehensive API specification and backend service documentation provides the foundation for building a robust, scalable MUSAFIR Central Web UI platform. The architecture supports real-time event processing, threat detection, and comprehensive security monitoring capabilities.
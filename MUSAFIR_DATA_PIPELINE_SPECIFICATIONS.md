# MUSAFIR Data Pipeline Specifications

## Overview
This document outlines the data pipeline architecture for the MUSAFIR central web UI platform, detailing how data flows from agents to the central platform for EDR, XDR, and SIEM capabilities.

## Data Flow Architecture

```
[MUSAFIR Agents] → [Message Queue] → [Data Processors] → [Storage Layer] → [API Layer] → [Web UI]
```

## 1. Data Sources (Agent Events)

### 1.1 Event Types from Agent
Based on the agent codebase analysis, the following event types are generated:

```go
// Event types from agent
type EventType string

const (
    ProcessEvent        EventType = "process"
    NetworkEvent        EventType = "network"
    FileEvent          EventType = "file"
    RegistryEvent      EventType = "registry"
    ThreatEvent        EventType = "threat"
    ComplianceEvent    EventType = "compliance"
    SystemEvent        EventType = "system"
    RansomwareEvent    EventType = "ransomware"
    SyslogEvent        EventType = "syslog"
    SNMPEvent          EventType = "snmp"
)
```

### 1.2 Event Structure
```go
type AgentEvent struct {
    ID          string                 `json:"id"`
    AgentID     string                 `json:"agent_id"`
    Timestamp   time.Time             `json:"timestamp"`
    EventType   EventType             `json:"event_type"`
    Severity    string                `json:"severity"`
    Source      string                `json:"source"`
    Data        map[string]interface{} `json:"data"`
    Metadata    EventMetadata         `json:"metadata"`
}

type EventMetadata struct {
    Hostname    string            `json:"hostname"`
    OS          string            `json:"os"`
    Version     string            `json:"version"`
    Tags        []string          `json:"tags"`
    Enrichment  map[string]string `json:"enrichment"`
}
```

## 2. Data Ingestion Layer

### 2.1 Message Queue (Apache Kafka)

#### Kafka Configuration
```yaml
# docker-compose.yml - Kafka Service
kafka:
  image: confluentinc/cp-kafka:latest
  environment:
    KAFKA_BROKER_ID: 1
    KAFKA_ZOOKEEPER_CONNECT: zookeeper:2181
    KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://kafka:9092
    KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR: 1
    KAFKA_AUTO_CREATE_TOPICS_ENABLE: true
  volumes:
    - kafka_data:/var/lib/kafka/data
```

#### Topic Structure
```go
// Kafka topics for different event types
var KafkaTopics = map[EventType]string{
    ProcessEvent:     "musafir.events.process",
    NetworkEvent:     "musafir.events.network",
    FileEvent:        "musafir.events.file",
    RegistryEvent:    "musafir.events.registry",
    ThreatEvent:      "musafir.events.threat",
    ComplianceEvent:  "musafir.events.compliance",
    SystemEvent:      "musafir.events.system",
    RansomwareEvent:  "musafir.events.ransomware",
    SyslogEvent:      "musafir.events.syslog",
    SNMPEvent:        "musafir.events.snmp",
}
```

### 2.2 Event Ingestion Service

```go
// cmd/ingestion-service/main.go
package main

import (
    "context"
    "encoding/json"
    "log"
    "net/http"
    
    "github.com/gorilla/mux"
    "github.com/segmentio/kafka-go"
)

type IngestionService struct {
    kafkaWriter *kafka.Writer
}

func NewIngestionService() *IngestionService {
    return &IngestionService{
        kafkaWriter: &kafka.Writer{
            Addr:     kafka.TCP("kafka:9092"),
            Balancer: &kafka.LeastBytes{},
        },
    }
}

func (s *IngestionService) HandleAgentEvents(w http.ResponseWriter, r *http.Request) {
    var events []AgentEvent
    if err := json.NewDecoder(r.Body).Decode(&events); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    for _, event := range events {
        topic := KafkaTopics[event.EventType]
        message, _ := json.Marshal(event)
        
        err := s.kafkaWriter.WriteMessages(context.Background(),
            kafka.Message{
                Topic: topic,
                Key:   []byte(event.AgentID),
                Value: message,
            },
        )
        
        if err != nil {
            log.Printf("Failed to write message: %v", err)
            http.Error(w, "Failed to process event", http.StatusInternalServerError)
            return
        }
    }
    
    w.WriteHeader(http.StatusAccepted)
}
```

## 3. Data Processing Layer

### 3.1 Event Processors

#### Base Event Processor
```go
// internal/processors/base.go
package processors

import (
    "context"
    "encoding/json"
    "log"
    
    "github.com/segmentio/kafka-go"
)

type EventProcessor interface {
    Process(ctx context.Context, event AgentEvent) error
    GetEventType() EventType
}

type BaseProcessor struct {
    eventType EventType
    storage   StorageInterface
    enricher  EnrichmentService
}

func (p *BaseProcessor) StartConsumer(ctx context.Context) {
    reader := kafka.NewReader(kafka.ReaderConfig{
        Brokers: []string{"kafka:9092"},
        Topic:   KafkaTopics[p.eventType],
        GroupID: fmt.Sprintf("processor-%s", p.eventType),
    })
    
    for {
        message, err := reader.ReadMessage(ctx)
        if err != nil {
            log.Printf("Error reading message: %v", err)
            continue
        }
        
        var event AgentEvent
        if err := json.Unmarshal(message.Value, &event); err != nil {
            log.Printf("Error unmarshaling event: %v", err)
            continue
        }
        
        if err := p.Process(ctx, event); err != nil {
            log.Printf("Error processing event: %v", err)
        }
    }
}
```

#### Threat Event Processor
```go
// internal/processors/threat.go
package processors

import (
    "context"
    "time"
)

type ThreatProcessor struct {
    BaseProcessor
    alertManager AlertManager
    ruleEngine   RuleEngine
}

func NewThreatProcessor(storage StorageInterface) *ThreatProcessor {
    return &ThreatProcessor{
        BaseProcessor: BaseProcessor{
            eventType: ThreatEvent,
            storage:   storage,
        },
        alertManager: NewAlertManager(),
        ruleEngine:   NewRuleEngine(),
    }
}

func (p *ThreatProcessor) Process(ctx context.Context, event AgentEvent) error {
    // Enrich event with threat intelligence
    enrichedEvent := p.enricher.EnrichThreatEvent(event)
    
    // Apply detection rules
    alerts := p.ruleEngine.EvaluateRules(enrichedEvent)
    
    // Store processed event
    if err := p.storage.StoreEvent(ctx, enrichedEvent); err != nil {
        return err
    }
    
    // Generate alerts if needed
    for _, alert := range alerts {
        if err := p.alertManager.CreateAlert(ctx, alert); err != nil {
            log.Printf("Failed to create alert: %v", err)
        }
    }
    
    return nil
}
```

### 3.2 Data Enrichment Service

```go
// internal/enrichment/service.go
package enrichment

import (
    "context"
    "net"
    "strings"
)

type EnrichmentService struct {
    geoIP       GeoIPService
    threatIntel ThreatIntelService
    assetDB     AssetDatabase
}

func (e *EnrichmentService) EnrichNetworkEvent(event AgentEvent) AgentEvent {
    if srcIP, ok := event.Data["source_ip"].(string); ok {
        if geoInfo := e.geoIP.Lookup(srcIP); geoInfo != nil {
            event.Data["geo_country"] = geoInfo.Country
            event.Data["geo_city"] = geoInfo.City
        }
        
        if reputation := e.threatIntel.CheckReputation(srcIP); reputation != nil {
            event.Data["ip_reputation"] = reputation.Score
            event.Data["threat_categories"] = reputation.Categories
        }
    }
    
    return event
}

func (e *EnrichmentService) EnrichProcessEvent(event AgentEvent) AgentEvent {
    if processPath, ok := event.Data["process_path"].(string); ok {
        if asset := e.assetDB.GetAssetByProcess(processPath); asset != nil {
            event.Data["asset_criticality"] = asset.Criticality
            event.Data["asset_owner"] = asset.Owner
        }
    }
    
    return event
}
```

## 4. Storage Layer

### 4.1 Time-Series Database (InfluxDB)

#### InfluxDB Configuration
```yaml
# docker-compose.yml - InfluxDB Service
influxdb:
  image: influxdb:2.0
  environment:
    INFLUXDB_DB: musafir
    INFLUXDB_ADMIN_USER: admin
    INFLUXDB_ADMIN_PASSWORD: password
    INFLUXDB_HTTP_AUTH_ENABLED: true
  volumes:
    - influxdb_data:/var/lib/influxdb2
```

#### Time-Series Storage Implementation
```go
// internal/storage/timeseries.go
package storage

import (
    "context"
    "fmt"
    "time"
    
    influxdb2 "github.com/influxdata/influxdb-client-go/v2"
    "github.com/influxdata/influxdb-client-go/v2/api"
)

type TimeSeriesStorage struct {
    client   influxdb2.Client
    writeAPI api.WriteAPIBlocking
    queryAPI api.QueryAPI
}

func NewTimeSeriesStorage() *TimeSeriesStorage {
    client := influxdb2.NewClient("http://influxdb:8086", "admin:password")
    
    return &TimeSeriesStorage{
        client:   client,
        writeAPI: client.WriteAPIBlocking("musafir", "events"),
        queryAPI: client.QueryAPI("musafir"),
    }
}

func (ts *TimeSeriesStorage) StoreEvent(ctx context.Context, event AgentEvent) error {
    point := influxdb2.NewPointWithMeasurement(string(event.EventType)).
        AddTag("agent_id", event.AgentID).
        AddTag("severity", event.Severity).
        AddTag("hostname", event.Metadata.Hostname).
        SetTime(event.Timestamp)
    
    // Add event data as fields
    for key, value := range event.Data {
        point = point.AddField(key, value)
    }
    
    return ts.writeAPI.WritePoint(ctx, point)
}

func (ts *TimeSeriesStorage) QueryEvents(ctx context.Context, query string) ([]AgentEvent, error) {
    result, err := ts.queryAPI.Query(ctx, query)
    if err != nil {
        return nil, err
    }
    
    var events []AgentEvent
    for result.Next() {
        // Parse InfluxDB result into AgentEvent
        event := parseInfluxRecord(result.Record())
        events = append(events, event)
    }
    
    return events, nil
}
```

### 4.2 Document Database (MongoDB)

#### MongoDB Configuration
```yaml
# docker-compose.yml - MongoDB Service
mongodb:
  image: mongo:5.0
  environment:
    MONGO_INITDB_ROOT_USERNAME: admin
    MONGO_INITDB_ROOT_PASSWORD: password
    MONGO_INITDB_DATABASE: musafir
  volumes:
    - mongodb_data:/data/db
```

#### Document Storage Implementation
```go
// internal/storage/document.go
package storage

import (
    "context"
    "time"
    
    "go.mongodb.org/mongo-driver/mongo"
    "go.mongodb.org/mongo-driver/mongo/options"
)

type DocumentStorage struct {
    client     *mongo.Client
    database   *mongo.Database
    collection *mongo.Collection
}

func NewDocumentStorage() *DocumentStorage {
    client, _ := mongo.Connect(context.Background(), 
        options.Client().ApplyURI("mongodb://admin:password@mongodb:27017"))
    
    database := client.Database("musafir")
    collection := database.Collection("events")
    
    return &DocumentStorage{
        client:     client,
        database:   database,
        collection: collection,
    }
}

func (ds *DocumentStorage) StoreAlert(ctx context.Context, alert Alert) error {
    _, err := ds.collection.InsertOne(ctx, alert)
    return err
}

func (ds *DocumentStorage) GetAlerts(ctx context.Context, filter interface{}) ([]Alert, error) {
    cursor, err := ds.collection.Find(ctx, filter)
    if err != nil {
        return nil, err
    }
    
    var alerts []Alert
    if err := cursor.All(ctx, &alerts); err != nil {
        return nil, err
    }
    
    return alerts, nil
}
```

## 5. Real-time Data Streaming

### 5.1 WebSocket Service

```go
// internal/websocket/hub.go
package websocket

import (
    "encoding/json"
    "log"
    "net/http"
    
    "github.com/gorilla/websocket"
)

type Hub struct {
    clients    map[*Client]bool
    broadcast  chan []byte
    register   chan *Client
    unregister chan *Client
}

type Client struct {
    hub  *Hub
    conn *websocket.Conn
    send chan []byte
}

func NewHub() *Hub {
    return &Hub{
        clients:    make(map[*Client]bool),
        broadcast:  make(chan []byte),
        register:   make(chan *Client),
        unregister: make(chan *Client),
    }
}

func (h *Hub) Run() {
    for {
        select {
        case client := <-h.register:
            h.clients[client] = true
            log.Println("Client connected")
            
        case client := <-h.unregister:
            if _, ok := h.clients[client]; ok {
                delete(h.clients, client)
                close(client.send)
                log.Println("Client disconnected")
            }
            
        case message := <-h.broadcast:
            for client := range h.clients {
                select {
                case client.send <- message:
                default:
                    close(client.send)
                    delete(h.clients, client)
                }
            }
        }
    }
}

func (h *Hub) BroadcastEvent(event AgentEvent) {
    message, _ := json.Marshal(event)
    h.broadcast <- message
}
```

## 6. Data Aggregation and Analytics

### 6.1 Analytics Engine

```go
// internal/analytics/engine.go
package analytics

import (
    "context"
    "time"
)

type AnalyticsEngine struct {
    storage     StorageInterface
    aggregator  DataAggregator
    calculator  MetricsCalculator
}

func (ae *AnalyticsEngine) GenerateDashboardMetrics(ctx context.Context, timeRange TimeRange) (*DashboardMetrics, error) {
    metrics := &DashboardMetrics{
        TimeRange: timeRange,
        Generated: time.Now(),
    }
    
    // Calculate threat metrics
    threatMetrics, err := ae.calculateThreatMetrics(ctx, timeRange)
    if err != nil {
        return nil, err
    }
    metrics.ThreatMetrics = threatMetrics
    
    // Calculate network metrics
    networkMetrics, err := ae.calculateNetworkMetrics(ctx, timeRange)
    if err != nil {
        return nil, err
    }
    metrics.NetworkMetrics = networkMetrics
    
    // Calculate compliance metrics
    complianceMetrics, err := ae.calculateComplianceMetrics(ctx, timeRange)
    if err != nil {
        return nil, err
    }
    metrics.ComplianceMetrics = complianceMetrics
    
    return metrics, nil
}

type DashboardMetrics struct {
    TimeRange         TimeRange         `json:"time_range"`
    Generated         time.Time         `json:"generated"`
    ThreatMetrics     ThreatMetrics     `json:"threat_metrics"`
    NetworkMetrics    NetworkMetrics    `json:"network_metrics"`
    ComplianceMetrics ComplianceMetrics `json:"compliance_metrics"`
}
```

## 7. Data Retention and Archival

### 7.1 Retention Policies

```go
// internal/retention/policy.go
package retention

import (
    "context"
    "time"
)

type RetentionPolicy struct {
    EventType     EventType     `json:"event_type"`
    HotStorage    time.Duration `json:"hot_storage"`    // Fast access
    WarmStorage   time.Duration `json:"warm_storage"`   // Medium access
    ColdStorage   time.Duration `json:"cold_storage"`   // Archive
    DeleteAfter   time.Duration `json:"delete_after"`   // Permanent deletion
}

var DefaultRetentionPolicies = map[EventType]RetentionPolicy{
    ThreatEvent: {
        EventType:   ThreatEvent,
        HotStorage:  30 * 24 * time.Hour,  // 30 days
        WarmStorage: 90 * 24 * time.Hour,  // 90 days
        ColdStorage: 365 * 24 * time.Hour, // 1 year
        DeleteAfter: 7 * 365 * 24 * time.Hour, // 7 years
    },
    ProcessEvent: {
        EventType:   ProcessEvent,
        HotStorage:  7 * 24 * time.Hour,   // 7 days
        WarmStorage: 30 * 24 * time.Hour,  // 30 days
        ColdStorage: 90 * 24 * time.Hour,  // 90 days
        DeleteAfter: 365 * 24 * time.Hour, // 1 year
    },
}

type RetentionManager struct {
    policies map[EventType]RetentionPolicy
    storage  StorageInterface
}

func (rm *RetentionManager) ApplyRetentionPolicies(ctx context.Context) error {
    for eventType, policy := range rm.policies {
        if err := rm.archiveOldEvents(ctx, eventType, policy); err != nil {
            return err
        }
        
        if err := rm.deleteExpiredEvents(ctx, eventType, policy); err != nil {
            return err
        }
    }
    
    return nil
}
```

## 8. Performance Optimization

### 8.1 Data Partitioning Strategy

```go
// internal/partitioning/strategy.go
package partitioning

import (
    "fmt"
    "time"
)

type PartitionStrategy interface {
    GetPartitionKey(event AgentEvent) string
    GetPartitionTable(timestamp time.Time) string
}

type TimeBasedPartitioning struct {
    interval time.Duration
}

func (tbp *TimeBasedPartitioning) GetPartitionTable(timestamp time.Time) string {
    partition := timestamp.Truncate(tbp.interval)
    return fmt.Sprintf("events_%s", partition.Format("2006_01_02"))
}

type AgentBasedPartitioning struct{}

func (abp *AgentBasedPartitioning) GetPartitionKey(event AgentEvent) string {
    return fmt.Sprintf("agent_%s", event.AgentID)
}
```

### 8.2 Caching Layer

```go
// internal/cache/redis.go
package cache

import (
    "context"
    "encoding/json"
    "time"
    
    "github.com/go-redis/redis/v8"
)

type RedisCache struct {
    client *redis.Client
}

func NewRedisCache() *RedisCache {
    return &RedisCache{
        client: redis.NewClient(&redis.Options{
            Addr: "redis:6379",
        }),
    }
}

func (rc *RedisCache) CacheMetrics(ctx context.Context, key string, metrics interface{}, ttl time.Duration) error {
    data, err := json.Marshal(metrics)
    if err != nil {
        return err
    }
    
    return rc.client.Set(ctx, key, data, ttl).Err()
}

func (rc *RedisCache) GetCachedMetrics(ctx context.Context, key string, result interface{}) error {
    data, err := rc.client.Get(ctx, key).Result()
    if err != nil {
        return err
    }
    
    return json.Unmarshal([]byte(data), result)
}
```

## 9. Monitoring and Observability

### 9.1 Pipeline Metrics

```go
// internal/monitoring/metrics.go
package monitoring

import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
)

var (
    EventsProcessed = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "musafir_events_processed_total",
            Help: "Total number of events processed",
        },
        []string{"event_type", "status"},
    )
    
    ProcessingLatency = promauto.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "musafir_processing_latency_seconds",
            Help: "Event processing latency",
        },
        []string{"event_type"},
    )
    
    StorageOperations = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "musafir_storage_operations_total",
            Help: "Total storage operations",
        },
        []string{"operation", "status"},
    )
)
```

This comprehensive data pipeline documentation covers all aspects of data flow from the MUSAFIR agents to the central web UI platform, ensuring efficient processing, storage, and real-time delivery of security events for EDR, XDR, and SIEM capabilities.
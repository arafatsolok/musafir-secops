package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"strings"
	"time"

	ch "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/segmentio/kafka-go"
)

type TenantEvent struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	TenantID    string                 `json:"tenant_id"`
	EventType   string                 `json:"event_type"`
	Resource    string                 `json:"resource"`
	Action      string                 `json:"action"`
	UserID      string                 `json:"user_id"`
	SourceIP    string                 `json:"source_ip"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type TenantConfig struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Status          string            `json:"status"`
	Region          string            `json:"region"`
	DataRetention   int               `json:"data_retention_days"`
	EncryptionKey   string            `json:"encryption_key"`
	KafkaTopics     []string          `json:"kafka_topics"`
	DatabaseSchema  string            `json:"database_schema"`
	Quotas          map[string]int    `json:"quotas"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
}

type TenantIsolation struct {
	TenantID        string   `json:"tenant_id"`
	KafkaTopics     []string `json:"kafka_topics"`
	DatabaseSchema  string   `json:"database_schema"`
	EncryptionKey   string   `json:"encryption_key"`
	NetworkSegment  string   `json:"network_segment"`
	StorageBucket   string   `json:"storage_bucket"`
	ComputePool     string   `json:"compute_pool"`
}

func main() {
	kbrokers := os.Getenv("KAFKA_BROKERS")
	if kbrokers == "" { kbrokers = "localhost:9092" }
	group := os.Getenv("KAFKA_GROUP")
	if group == "" { group = "tenant" }

	chDsn := os.Getenv("CLICKHOUSE_DSN")
	if chDsn == "" { chDsn = "tcp://localhost:9000?database=default" }

	ctx := context.Background()
	conn, err := ch.Open(&ch.Options{Addr: []string{"localhost:9000"}})
	if err != nil { log.Fatalf("clickhouse connect: %v", err) }
	defer conn.Close()

	// Ensure tenant tables exist
	createTenantTables(conn, ctx)

	writer := kafka.NewWriter(kafka.WriterConfig{
		Brokers: strings.Split(kbrokers, ","),
		Topic:   "musafir.tenant_events",
	})

	log.Printf("tenant management starting brokers=%s", kbrokers)

	// Simulate tenant operations
	go simulateTenantOperations(writer, ctx)

	// Keep running
	select {}
}

func createTenantTables(conn ch.Conn, ctx context.Context) {
	// Tenant events table
	ddl := `CREATE TABLE IF NOT EXISTS musafir_tenant_events (
  id String,
  timestamp DateTime,
  tenant_id String,
  event_type String,
  resource String,
  action String,
  user_id String,
  source_ip String,
  metadata String
) ENGINE = MergeTree ORDER BY timestamp`
	
	if err := conn.Exec(ctx, ddl); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}

	// Tenant configs table
	ddl2 := `CREATE TABLE IF NOT EXISTS musafir_tenant_configs (
  id String,
  name String,
  status String,
  region String,
  data_retention_days Int32,
  encryption_key String,
  kafka_topics Array(String),
  database_schema String,
  quotas String,
  created_at DateTime,
  updated_at DateTime
) ENGINE = MergeTree ORDER BY created_at`
	
	if err := conn.Exec(ctx, ddl2); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}

	// Tenant isolation table
	ddl3 := `CREATE TABLE IF NOT EXISTS musafir_tenant_isolation (
  tenant_id String,
  kafka_topics Array(String),
  database_schema String,
  encryption_key String,
  network_segment String,
  storage_bucket String,
  compute_pool String,
  created_at DateTime,
  updated_at DateTime
) ENGINE = MergeTree ORDER BY created_at`
	
	if err := conn.Exec(ctx, ddl3); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}
}

func simulateTenantOperations(writer *kafka.Writer, ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	tenants := []string{"tenant-001", "tenant-002", "tenant-003"}
	eventTypes := []string{"tenant_created", "tenant_updated", "resource_accessed", "quota_exceeded"}
	resources := []string{"kafka_topic", "database", "storage", "compute", "network"}

	for {
		select {
		case <-ticker.C:
			// Generate sample tenant events
			for i := 0; i < 2; i++ {
				tenantID := tenants[time.Now().Second()%len(tenants)]
				eventType := eventTypes[time.Now().Second()%len(eventTypes)]
				resource := resources[time.Now().Second()%len(resources)]

				event := TenantEvent{
					ID:        generateTenantEventID(),
					Timestamp: time.Now(),
					TenantID:  tenantID,
					EventType: eventType,
					Resource:  resource,
					Action:    getAction(eventType),
					UserID:    "user-" + time.Now().Format("20060102150405"),
					SourceIP:  "192.168.1." + string(rune(100+i)),
					Metadata: map[string]interface{}{
						"region":        "us-east-1",
						"data_classification": "confidential",
						"compliance":    []string{"iso27001", "soc2"},
					},
				}

				sendTenantEvent(event, writer, ctx)
			}
		}
	}
}

func sendTenantEvent(event TenantEvent, writer *kafka.Writer, ctx context.Context) {
	eventData, _ := json.Marshal(event)
	if err := writer.WriteMessages(ctx, kafka.Message{Value: eventData}); err != nil {
		log.Printf("write tenant event: %v", err)
	} else {
		log.Printf("TENANT EVENT: %s - %s (%s)", event.TenantID, event.EventType, event.Resource)
	}
}

func generateTenantEventID() string {
	return "tenant-" + time.Now().Format("20060102150405")
}

func getAction(eventType string) string {
	actions := map[string]string{
		"tenant_created":    "create",
		"tenant_updated":    "update",
		"resource_accessed": "read",
		"quota_exceeded":    "limit",
	}

	if action, exists := actions[eventType]; exists {
		return action
	}
	return "unknown"
}

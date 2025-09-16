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

type SPIFFEEvent struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	SPIFFEID    string                 `json:"spiffe_id"`
	TrustDomain string                 `json:"trust_domain"`
	WorkloadID  string                 `json:"workload_id"`
	AgentID     string                 `json:"agent_id"`
	EventType   string                 `json:"event_type"`
	Status      string                 `json:"status"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type WorkloadIdentity struct {
	ID          string    `json:"id"`
	SPIFFEID    string    `json:"spiffe_id"`
	TrustDomain string    `json:"trust_domain"`
	WorkloadID  string    `json:"workload_id"`
	AgentID     string    `json:"agent_id"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Status      string    `json:"status"`
	CertData    string    `json:"cert_data"`
	KeyData     string    `json:"key_data"`
}

type SPIREConfig struct {
	TrustDomain string            `json:"trust_domain"`
	ServerAddr  string            `json:"server_addr"`
	Workloads   []WorkloadConfig  `json:"workloads"`
}

type WorkloadConfig struct {
	ID          string   `json:"id"`
	SPIFFEID    string   `json:"spiffe_id"`
	Selectors   []string `json:"selectors"`
	TTL         int      `json:"ttl"`
	DNSNames    []string `json:"dns_names"`
}

func main() {
	kbrokers := os.Getenv("KAFKA_BROKERS")
	if kbrokers == "" { kbrokers = "localhost:9092" }
	group := os.Getenv("KAFKA_GROUP")
	if group == "" { group = "spire" }

	chDsn := os.Getenv("CLICKHOUSE_DSN")
	if chDsn == "" { chDsn = "tcp://localhost:9000?database=default" }

	ctx := context.Background()
	conn, err := ch.Open(&ch.Options{Addr: []string{"localhost:9000"}})
	if err != nil { log.Fatalf("clickhouse connect: %v", err) }
	defer conn.Close()

	// Ensure SPIFFE tables exist
	createSPIFFETables(conn, ctx)

	writer := kafka.NewWriter(kafka.WriterConfig{
		Brokers: strings.Split(kbrokers, ","),
		Topic:   "musafir.spire_events",
	})

	log.Printf("SPIRE identity management starting brokers=%s", kbrokers)

	// Simulate SPIFFE/SPIRE operations
	go simulateSPIFFEOperations(writer, ctx)

	// Keep running
	select {}
}

func createSPIFFETables(conn ch.Conn, ctx context.Context) {
	// SPIFFE events table
	ddl := `CREATE TABLE IF NOT EXISTS musafir_spire_events (
  id String,
  timestamp DateTime,
  spiffe_id String,
  trust_domain String,
  workload_id String,
  agent_id String,
  event_type String,
  status String,
  metadata String
) ENGINE = MergeTree ORDER BY timestamp`
	
	if err := conn.Exec(ctx, ddl); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}

	// Workload identities table
	ddl2 := `CREATE TABLE IF NOT EXISTS musafir_workload_identities (
  id String,
  spiffe_id String,
  trust_domain String,
  workload_id String,
  agent_id String,
  created_at DateTime,
  expires_at DateTime,
  status String,
  cert_data String,
  key_data String
) ENGINE = MergeTree ORDER BY created_at`
	
	if err := conn.Exec(ctx, ddl2); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}
}

func simulateSPIFFEOperations(writer *kafka.Writer, ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	workloads := []string{
		"musafir://musafir.local/agent",
		"musafir://musafir.local/gateway",
		"musafir://musafir.local/ingester",
		"musafir://musafir.local/detector",
		"musafir://musafir.local/responder",
	}

	eventTypes := []string{
		"workload_registered",
		"workload_attested",
		"certificate_issued",
		"certificate_renewed",
		"workload_unregistered",
	}

	for {
		select {
		case <-ticker.C:
			// Generate sample SPIFFE events
			for i := 0; i < 2; i++ {
				workload := workloads[time.Now().Second()%len(workloads)]
				eventType := eventTypes[time.Now().Second()%len(eventTypes)]

				event := SPIFFEEvent{
					ID:          generateSPIFFEEventID(),
					Timestamp:   time.Now(),
					SPIFFEID:    workload,
					TrustDomain: "musafir.local",
					WorkloadID:  extractWorkloadID(workload),
					AgentID:     "agent-" + time.Now().Format("20060102150405"),
					EventType:   eventType,
					Status:      "success",
					Metadata: map[string]interface{}{
						"ttl": 3600,
						"dns_names": []string{"localhost", "musafir.local"},
						"selectors": []string{"unix:uid:1000", "unix:gid:1000"},
					},
				}

				sendSPIFFEEvent(event, writer, ctx)
			}
		}
	}
}

func sendSPIFFEEvent(event SPIFFEEvent, writer *kafka.Writer, ctx context.Context) {
	eventData, _ := json.Marshal(event)
	if err := writer.WriteMessages(ctx, kafka.Message{Value: eventData}); err != nil {
		log.Printf("write spire event: %v", err)
	} else {
		log.Printf("SPIRE EVENT: %s - %s (%s)", event.SPIFFEID, event.EventType, event.Status)
	}
}

func generateSPIFFEEventID() string {
	return "spire-" + time.Now().Format("20060102150405")
}

func extractWorkloadID(spiffeID string) string {
	parts := strings.Split(spiffeID, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return spiffeID
}

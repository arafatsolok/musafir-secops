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

type SLSAEvent struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	BuildID     string                 `json:"build_id"`
	Artifact    string                 `json:"artifact"`
	Level       int                    `json:"level"` // 0-4
	Provenance  SLSAProvenance         `json:"provenance"`
	Attestation SLSAAttestation        `json:"attestation"`
	Status      string                 `json:"status"` // valid, invalid, pending
	Metadata    map[string]interface{} `json:"metadata"`
}

type SLSAProvenance struct {
	Builder     string            `json:"builder"`
	BuildType   string            `json:"build_type"`
	Invocation  map[string]string `json:"invocation"`
	BuildConfig map[string]string `json:"build_config"`
	Materials   []SLSAMaterial    `json:"materials"`
}

type SLSAMaterial struct {
	URI    string            `json:"uri"`
	Digest map[string]string `json:"digest"`
}

type SLSAAttestation struct {
	PredicateType string            `json:"predicate_type"`
	Predicate     map[string]string `json:"predicate"`
	Signature     string            `json:"signature"`
	PublicKey     string            `json:"public_key"`
}

type SLSAVerification struct {
	ID        string    `json:"id"`
	Artifact  string    `json:"artifact"`
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
	Error     string    `json:"error,omitempty"`
}

func main() {
	kbrokers := os.Getenv("KAFKA_BROKERS")
	if kbrokers == "" { kbrokers = "localhost:9092" }
	group := os.Getenv("KAFKA_GROUP")
	if group == "" { group = "slsa" }

	chDsn := os.Getenv("CLICKHOUSE_DSN")
	if chDsn == "" { chDsn = "tcp://localhost:9000?database=default" }

	ctx := context.Background()
	conn, err := ch.Open(&ch.Options{Addr: []string{"localhost:9000"}})
	if err != nil { log.Fatalf("clickhouse connect: %v", err) }
	defer conn.Close()

	// Ensure SLSA tables exist
	createSLSATables(conn, ctx)

	writer := kafka.NewWriter(kafka.WriterConfig{
		Brokers: strings.Split(kbrokers, ","),
		Topic:   "musafir.slsa_events",
	})

	log.Printf("SLSA pipeline starting brokers=%s", kbrokers)

	// Simulate SLSA L3 pipeline
	go simulateSLSAPipeline(writer, ctx)

	// Keep running
	select {}
}

func createSLSATables(conn ch.Conn, ctx context.Context) {
	// SLSA events table
	ddl := `CREATE TABLE IF NOT EXISTS musafir_slsa_events (
  id String,
  timestamp DateTime,
  build_id String,
  artifact String,
  level Int32,
  provenance String,
  attestation String,
  status String,
  metadata String
) ENGINE = MergeTree ORDER BY timestamp`
	
	if err := conn.Exec(ctx, ddl); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}

	// SLSA verifications table
	ddl2 := `CREATE TABLE IF NOT EXISTS musafir_slsa_verifications (
  id String,
  artifact String,
  status String,
  timestamp DateTime,
  error String
) ENGINE = MergeTree ORDER BY timestamp`
	
	if err := conn.Exec(ctx, ddl2); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}
}

func simulateSLSAPipeline(writer *kafka.Writer, ctx context.Context) {
	ticker := time.NewTicker(120 * time.Second)
	defer ticker.Stop()

	artifacts := []string{
		"musafir-agent-windows.exe",
		"musafir-agent-linux",
		"musafir-agent-darwin",
		"musafir-gateway.exe",
		"musafir-ingest.exe",
		"musafir-detect.exe",
	}

	builders := []string{
		"musafir-ci/cd-pipeline",
		"musafir-github-actions",
		"musafir-gitlab-ci",
		"musafir-jenkins",
	}

	for {
		select {
		case <-ticker.C:
			// Generate sample SLSA events
			for i := 0; i < 2; i++ {
				artifact := artifacts[time.Now().Second()%len(artifacts)]
				builder := builders[time.Now().Second()%len(builders)]

				event := SLSAEvent{
					ID:        generateSLSAEventID(),
					Timestamp: time.Now(),
					BuildID:   "build-" + time.Now().Format("20060102150405"),
					Artifact:  artifact,
					Level:     3, // SLSA L3
					Provenance: SLSAProvenance{
						Builder:   builder,
						BuildType: "https://github.com/Attestations/GitHubActionsWorkflow@v1",
						Invocation: map[string]string{
							"config_source": "https://github.com/musafirsec/musafir/.github/workflows/build.yml@refs/heads/main",
							"parameters":    "{\"build_target\":\"musafir-agent\"}",
						},
						BuildConfig: map[string]string{
							"compiler": "go1.22",
							"os":       "linux",
							"arch":     "amd64",
						},
						Materials: []SLSAMaterial{
							{
								URI: "git+https://github.com/musafirsec/musafir@refs/heads/main",
								Digest: map[string]string{
									"sha1": "abc123def456",
								},
							},
						},
					},
					Attestation: SLSAAttestation{
						PredicateType: "https://slsa.dev/provenance/v0.2",
						Predicate: map[string]string{
							"buildType": "https://github.com/Attestations/GitHubActionsWorkflow@v1",
							"builder":   builder,
						},
						Signature: "MEUCIQDx+...", // Truncated for brevity
						PublicKey: "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----",
					},
					Status: "valid",
					Metadata: map[string]interface{}{
						"tenant_id": "tenant-123",
						"pipeline":  "musafir-ci",
						"version":   "1.0.0",
					},
				}

				sendSLSAEvent(event, writer, ctx)
			}
		}
	}
}

func sendSLSAEvent(event SLSAEvent, writer *kafka.Writer, ctx context.Context) {
	eventData, _ := json.Marshal(event)
	if err := writer.WriteMessages(ctx, kafka.Message{Value: eventData}); err != nil {
		log.Printf("write slsa event: %v", err)
	} else {
		log.Printf("SLSA EVENT: %s - Level %d (%s)", event.Artifact, event.Level, event.Status)
	}
}

func generateSLSAEventID() string {
	return "slsa-" + time.Now().Format("20060102150405")
}

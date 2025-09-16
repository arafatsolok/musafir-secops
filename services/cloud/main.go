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

type CloudEvent struct {
	ID          string                 `json:"id"`
	Provider    string                 `json:"provider"` // aws, azure, gcp
	Service     string                 `json:"service"`  // ec2, s3, iam, etc.
	EventType   string                 `json:"event_type"`
	ResourceID  string                 `json:"resource_id"`
	Region      string                 `json:"region"`
	AccountID   string                 `json:"account_id"`
	UserID      string                 `json:"user_id"`
	SourceIP    string                 `json:"source_ip"`
	UserAgent   string                 `json:"user_agent"`
	Timestamp   time.Time              `json:"timestamp"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	Details     map[string]interface{} `json:"details"`
	RawEvent    map[string]interface{} `json:"raw_event"`
}

type CloudConnector struct {
	Provider string
	Config   map[string]string
	Enabled  bool
}

func main() {
	kbrokers := os.Getenv("KAFKA_BROKERS")
	if kbrokers == "" { kbrokers = "localhost:9092" }
	group := os.Getenv("KAFKA_GROUP")
	if group == "" { group = "cloud" }

	chDsn := os.Getenv("CLICKHOUSE_DSN")
	if chDsn == "" { chDsn = "tcp://localhost:9000?database=default" }

	ctx := context.Background()
	conn, err := ch.Open(&ch.Options{Addr: []string{"localhost:9000"}})
	if err != nil { log.Fatalf("clickhouse connect: %v", err) }
	defer conn.Close()

	// Ensure cloud tables exist
	createCloudTables(conn, ctx)

	// Initialize cloud connectors
	connectors := initializeCloudConnectors()

	writer := kafka.NewWriter(kafka.WriterConfig{
		Brokers: strings.Split(kbrokers, ","),
		Topic:   "musafir.cloud_events",
	})

	log.Printf("cloud connectors starting brokers=%s", kbrokers)

	// Start each cloud connector
	for _, connector := range connectors {
		if connector.Enabled {
			go startCloudConnector(connector, writer, ctx)
		}
	}

	// Keep running
	select {}
}

func createCloudTables(conn ch.Conn, ctx context.Context) {
	// Cloud events table
	ddl := `CREATE TABLE IF NOT EXISTS musafir_cloud_events (
  id String,
  provider String,
  service String,
  event_type String,
  resource_id String,
  region String,
  account_id String,
  user_id String,
  source_ip String,
  user_agent String,
  timestamp DateTime,
  severity String,
  description String,
  details String,
  raw_event String
) ENGINE = MergeTree ORDER BY timestamp`
	
	if err := conn.Exec(ctx, ddl); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}
}

func initializeCloudConnectors() []CloudConnector {
	connectors := []CloudConnector{}

	// AWS Connector
	if os.Getenv("AWS_ACCESS_KEY_ID") != "" {
		connectors = append(connectors, CloudConnector{
			Provider: "aws",
			Config: map[string]string{
				"access_key": os.Getenv("AWS_ACCESS_KEY_ID"),
				"secret_key": os.Getenv("AWS_SECRET_ACCESS_KEY"),
				"region":     os.Getenv("AWS_REGION"),
			},
			Enabled: true,
		})
	}

	// Azure Connector
	if os.Getenv("AZURE_CLIENT_ID") != "" {
		connectors = append(connectors, CloudConnector{
			Provider: "azure",
			Config: map[string]string{
				"client_id":     os.Getenv("AZURE_CLIENT_ID"),
				"client_secret": os.Getenv("AZURE_CLIENT_SECRET"),
				"tenant_id":     os.Getenv("AZURE_TENANT_ID"),
				"subscription":  os.Getenv("AZURE_SUBSCRIPTION_ID"),
			},
			Enabled: true,
		})
	}

	// GCP Connector
	if os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") != "" {
		connectors = append(connectors, CloudConnector{
			Provider: "gcp",
			Config: map[string]string{
				"credentials_file": os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"),
				"project_id":       os.Getenv("GOOGLE_CLOUD_PROJECT"),
			},
			Enabled: true,
		})
	}

	return connectors
}

func startCloudConnector(connector CloudConnector, writer *kafka.Writer, ctx context.Context) {
	log.Printf("Starting %s cloud connector", connector.Provider)

	switch connector.Provider {
	case "aws":
		startAWSConnector(connector, writer, ctx)
	case "azure":
		startAzureConnector(connector, writer, ctx)
	case "gcp":
		startGCPConnector(connector, writer, ctx)
	}
}

func startAWSConnector(connector CloudConnector, writer *kafka.Writer, ctx context.Context) {
	// Simulate AWS CloudTrail events
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Generate sample AWS events
			events := generateAWSEvents()
			for _, event := range events {
				sendCloudEvent(event, writer, ctx)
			}
		case <-ctx.Done():
			return
		}
	}
}

func startAzureConnector(connector CloudConnector, writer *kafka.Writer, ctx context.Context) {
	// Simulate Azure Activity Log events
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Generate sample Azure events
			events := generateAzureEvents()
			for _, event := range events {
				sendCloudEvent(event, writer, ctx)
			}
		case <-ctx.Done():
			return
		}
	}
}

func startGCPConnector(connector CloudConnector, writer *kafka.Writer, ctx context.Context) {
	// Simulate GCP Cloud Audit Logs
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Generate sample GCP events
			events := generateGCPEvents()
			for _, event := range events {
				sendCloudEvent(event, writer, ctx)
			}
		case <-ctx.Done():
			return
		}
	}
}

func generateAWSEvents() []CloudEvent {
	events := []CloudEvent{
		{
			ID:          generateEventID(),
			Provider:    "aws",
			Service:     "ec2",
			EventType:   "RunInstances",
			ResourceID:  "i-1234567890abcdef0",
			Region:      "us-east-1",
			AccountID:   "123456789012",
			UserID:      "arn:aws:iam::123456789012:user/admin",
			SourceIP:    "203.0.113.12",
			UserAgent:   "aws-cli/2.0.0",
			Timestamp:   time.Now(),
			Severity:    "medium",
			Description: "EC2 instance launched",
			Details: map[string]interface{}{
				"instance_type": "t3.micro",
				"image_id":      "ami-12345678",
				"key_name":      "my-key-pair",
			},
		},
		{
			ID:          generateEventID(),
			Provider:    "aws",
			Service:     "s3",
			EventType:   "PutObject",
			ResourceID:  "my-bucket",
			Region:      "us-east-1",
			AccountID:   "123456789012",
			UserID:      "arn:aws:iam::123456789012:user/admin",
			SourceIP:    "203.0.113.12",
			UserAgent:   "aws-cli/2.0.0",
			Timestamp:   time.Now(),
			Severity:    "low",
			Description: "Object uploaded to S3",
			Details: map[string]interface{}{
				"object_key": "documents/important.pdf",
				"size":       1024000,
				"content_type": "application/pdf",
			},
		},
		{
			ID:          generateEventID(),
			Provider:    "aws",
			Service:     "iam",
			EventType:   "CreateUser",
			ResourceID:  "new-user",
			Region:      "us-east-1",
			AccountID:   "123456789012",
			UserID:      "arn:aws:iam::123456789012:user/admin",
			SourceIP:    "203.0.113.12",
			UserAgent:   "aws-cli/2.0.0",
			Timestamp:   time.Now(),
			Severity:    "high",
			Description: "New IAM user created",
			Details: map[string]interface{}{
				"user_name": "new-user",
				"path":      "/",
			},
		},
	}

	return events
}

func generateAzureEvents() []CloudEvent {
	events := []CloudEvent{
		{
			ID:          generateEventID(),
			Provider:    "azure",
			Service:     "compute",
			EventType:   "Microsoft.Compute/virtualMachines/write",
			ResourceID:  "/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/myRG/providers/Microsoft.Compute/virtualMachines/myVM",
			Region:      "eastus",
			AccountID:   "12345678-1234-1234-1234-123456789012",
			UserID:      "admin@company.com",
			SourceIP:    "203.0.113.12",
			UserAgent:   "Azure PowerShell/5.0",
			Timestamp:   time.Now(),
			Severity:    "medium",
			Description: "Virtual machine created",
			Details: map[string]interface{}{
				"vm_size": "Standard_B1s",
				"os_type": "Windows",
			},
		},
		{
			ID:          generateEventID(),
			Provider:    "azure",
			Service:     "storage",
			EventType:   "Microsoft.Storage/storageAccounts/write",
			ResourceID:  "/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/myRG/providers/Microsoft.Storage/storageAccounts/mystorageaccount",
			Region:      "eastus",
			AccountID:   "12345678-1234-1234-1234-123456789012",
			UserID:      "admin@company.com",
			SourceIP:    "203.0.113.12",
			UserAgent:   "Azure Portal",
			Timestamp:   time.Now(),
			Severity:    "low",
			Description: "Storage account created",
			Details: map[string]interface{}{
				"account_type": "Standard_LRS",
				"access_tier":  "Hot",
			},
		},
	}

	return events
}

func generateGCPEvents() []CloudEvent {
	events := []CloudEvent{
		{
			ID:          generateEventID(),
			Provider:    "gcp",
			Service:     "compute",
			EventType:   "google.cloud.compute.v1.Instances.insert",
			ResourceID:  "projects/my-project/zones/us-central1-a/instances/my-instance",
			Region:      "us-central1",
			AccountID:   "my-project",
			UserID:      "admin@company.com",
			SourceIP:    "203.0.113.12",
			UserAgent:   "gcloud/400.0.0",
			Timestamp:   time.Now(),
			Severity:    "medium",
			Description: "Compute instance created",
			Details: map[string]interface{}{
				"machine_type": "e2-micro",
				"image":        "projects/debian-cloud/global/images/debian-11",
			},
		},
		{
			ID:          generateEventID(),
			Provider:    "gcp",
			Service:     "storage",
			EventType:   "google.cloud.storage.v1.Objects.insert",
			ResourceID:  "my-bucket",
			Region:      "us-central1",
			AccountID:   "my-project",
			UserID:      "admin@company.com",
			SourceIP:    "203.0.113.12",
			UserAgent:   "gsutil/5.0",
			Timestamp:   time.Now(),
			Severity:    "low",
			Description: "Object uploaded to Cloud Storage",
			Details: map[string]interface{}{
				"object_name": "documents/file.pdf",
				"size":        1024000,
			},
		},
	}

	return events
}

func sendCloudEvent(event CloudEvent, writer *kafka.Writer, ctx context.Context) {
	eventData, _ := json.Marshal(event)
	if err := writer.WriteMessages(ctx, kafka.Message{Value: eventData}); err != nil {
		log.Printf("write cloud event: %v", err)
	} else {
		log.Printf("CLOUD EVENT: %s - %s (%s)", event.Provider, event.EventType, event.Severity)
	}
}

func generateEventID() string {
	return "cloud-" + time.Now().Format("20060102150405")
}

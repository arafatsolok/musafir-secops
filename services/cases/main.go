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

type Case struct {
	ID          string            `json:"id"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Severity    string            `json:"severity"` // low, medium, high, critical
	Status      string            `json:"status"`   // open, investigating, resolved, closed
	Priority    int               `json:"priority"` // 1-5
	Assignee    string            `json:"assignee"`
	CreatedBy   string            `json:"created_by"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	ResolvedAt  *time.Time        `json:"resolved_at,omitempty"`
	Tags        []string          `json:"tags"`
	Assets      []string          `json:"assets"`
	Users       []string          `json:"users"`
	Alerts      []string          `json:"alerts"`
	Evidence    []Evidence        `json:"evidence"`
	Timeline    []TimelineEvent   `json:"timeline"`
	Metadata    map[string]string `json:"metadata"`
}

type Evidence struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"` // file, process, network, registry, memory
	Path        string    `json:"path"`
	Hash        string    `json:"hash"`
	Size        int64     `json:"size"`
	Description string    `json:"description"`
	CollectedAt time.Time `json:"collected_at"`
	CollectedBy string    `json:"collected_by"`
	Status      string    `json:"status"` // pending, collected, analyzed, archived
}

type TimelineEvent struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"` // alert, action, comment, status_change
	Title     string    `json:"title"`
	Content   string    `json:"content"`
	Author    string    `json:"author"`
	Timestamp time.Time `json:"timestamp"`
	Metadata  map[string]string `json:"metadata"`
}

type CaseUpdate struct {
	CaseID    string            `json:"case_id"`
	Action    string            `json:"action"` // create, update, comment, assign, resolve, close
	Data      map[string]string `json:"data"`
	Author    string            `json:"author"`
	Timestamp time.Time         `json:"timestamp"`
}

func main() {
	kbrokers := os.Getenv("KAFKA_BROKERS")
	if kbrokers == "" { kbrokers = "localhost:9092" }
	group := os.Getenv("KAFKA_GROUP")
	if group == "" { group = "cases" }

	chDsn := os.Getenv("CLICKHOUSE_DSN")
	if chDsn == "" { chDsn = "tcp://localhost:9000?database=default" }

	ctx := context.Background()
	conn, err := ch.Open(&ch.Options{Addr: []string{"localhost:9000"}})
	if err != nil { log.Fatalf("clickhouse connect: %v", err) }
	defer conn.Close()

	// Ensure case management tables exist
	createCaseTables(conn, ctx)

	// Listen for case updates
	updateReader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:  strings.Split(kbrokers, ","),
		Topic:    "musafir.case_updates",
		GroupID:  group + "_updates",
		MinBytes: 1, MaxBytes: 10e6,
	})
	defer updateReader.Close()

	// Listen for correlated alerts to auto-create cases
	alertReader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:  strings.Split(kbrokers, ","),
		Topic:    "musafir.correlated_alerts",
		GroupID:  group + "_alerts",
		MinBytes: 1, MaxBytes: 10e6,
	})
	defer alertReader.Close()

	// Case update writer
	caseWriter := kafka.NewWriter(kafka.WriterConfig{
		Brokers: strings.Split(kbrokers, ","),
		Topic:   "musafir.cases",
	})

	log.Printf("case management consuming updates brokers=%s", kbrokers)

	// Process case updates
	go processCaseUpdates(updateReader, conn, ctx)

	// Process alerts for auto-case creation
	go processAlertsForCases(alertReader, caseWriter, conn, ctx)

	// Keep running
	select {}
}

func createCaseTables(conn ch.Conn, ctx context.Context) {
	// Cases table
	ddl := `CREATE TABLE IF NOT EXISTS musafir_cases (
  id String,
  title String,
  description String,
  severity String,
  status String,
  priority Int32,
  assignee String,
  created_by String,
  created_at DateTime,
  updated_at DateTime,
  resolved_at Nullable(DateTime),
  tags Array(String),
  assets Array(String),
  users Array(String),
  alerts Array(String),
  evidence String,
  timeline String,
  metadata String
) ENGINE = MergeTree ORDER BY created_at`
	
	if err := conn.Exec(ctx, ddl); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}

	// Case updates table
	ddl2 := `CREATE TABLE IF NOT EXISTS musafir_case_updates (
  case_id String,
  action String,
  data String,
  author String,
  timestamp DateTime
) ENGINE = MergeTree ORDER BY timestamp`
	
	if err := conn.Exec(ctx, ddl2); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}
}

func processCaseUpdates(reader *kafka.Reader, conn ch.Conn, ctx context.Context) {
	for {
		m, err := reader.ReadMessage(ctx)
		if err != nil { log.Printf("kafka read case update: %v", err); continue }

		var update CaseUpdate
		if err := json.Unmarshal(m.Value, &update); err != nil {
			log.Printf("unmarshal case update: %v", err)
			continue
		}

		// Process case update
		if err := processCaseUpdate(update, conn, ctx); err != nil {
			log.Printf("process case update: %v", err)
		}
	}
}

func processAlertsForCases(reader *kafka.Reader, writer *kafka.Writer, conn ch.Conn, ctx context.Context) {
	for {
		m, err := reader.ReadMessage(ctx)
		if err != nil { log.Printf("kafka read alert: %v", err); continue }

		var alert map[string]interface{}
		if err := json.Unmarshal(m.Value, &alert); err != nil {
			log.Printf("unmarshal alert: %v", err)
			continue
		}

		// Check if alert should create a case
		if shouldCreateCase(alert) {
			caseData := createCaseFromAlert(alert)
			caseJSON, _ := json.Marshal(caseData)
			
			if err := writer.WriteMessages(ctx, kafka.Message{Value: caseJSON}); err != nil {
				log.Printf("write case: %v", err)
			} else {
				log.Printf("CASE CREATED: %s - %s", caseData.ID, caseData.Title)
			}
		}
	}
}

func processCaseUpdate(update CaseUpdate, conn ch.Conn, ctx context.Context) error {
	// Update case in database
	query := `INSERT INTO musafir_case_updates (case_id, action, data, author, timestamp) VALUES (?, ?, ?, ?, ?)`
	
	dataJSON, _ := json.Marshal(update.Data)
	
	return conn.Exec(ctx, query,
		update.CaseID,
		update.Action,
		string(dataJSON),
		update.Author,
		update.Timestamp,
	)
}

func shouldCreateCase(alert map[string]interface{}) bool {
	// Create case for high-severity correlated alerts
	if severity, ok := alert["severity"].(string); ok {
		return severity == "critical" || severity == "high"
	}
	
	// Create case for specific alert types
	if alertType, ok := alert["type"].(string); ok {
		criticalTypes := []string{"ransomware_attack", "credential_theft", "lateral_movement", "data_exfiltration"}
		for _, t := range criticalTypes {
			if strings.Contains(strings.ToLower(alertType), t) {
				return true
			}
		}
	}
	
	return false
}

func createCaseFromAlert(alert map[string]interface{}) Case {
	caseID := generateCaseID()
	now := time.Now()
	
	// Extract alert information
	title := "Security Incident"
	if alertTitle, ok := alert["title"].(string); ok {
		title = alertTitle
	}
	
	severity := "medium"
	if alertSeverity, ok := alert["severity"].(string); ok {
		severity = alertSeverity
	}
	
	description := "Automatically created case from security alert"
	if alertDesc, ok := alert["description"].(string); ok {
		description = alertDesc
	}
	
	// Determine priority based on severity
	priority := 3
	switch severity {
	case "critical":
		priority = 1
	case "high":
		priority = 2
	case "medium":
		priority = 3
	case "low":
		priority = 4
	}
	
	// Extract assets and users
	var assets, users []string
	if assetID, ok := alert["asset_id"].(string); ok {
		assets = append(assets, assetID)
	}
	if userID, ok := alert["user_id"].(string); ok {
		users = append(users, userID)
	}
	
	// Create tags
	tags := []string{"auto-created", "security-alert"}
	if alertType, ok := alert["type"].(string); ok {
		tags = append(tags, alertType)
	}
	
	// Create initial timeline event
	timeline := []TimelineEvent{
		{
			ID:        generateTimelineID(),
			Type:      "alert",
			Title:     "Alert Generated",
			Content:   "Security alert triggered case creation",
			Author:    "system",
			Timestamp: now,
			Metadata: map[string]string{
				"alert_id": alert["id"].(string),
			},
		},
	}
	
	return Case{
		ID:          caseID,
		Title:       title,
		Description: description,
		Severity:    severity,
		Status:      "open",
		Priority:    priority,
		Assignee:    "",
		CreatedBy:   "system",
		CreatedAt:   now,
		UpdatedAt:   now,
		Tags:        tags,
		Assets:      assets,
		Users:       users,
		Alerts:      []string{alert["id"].(string)},
		Evidence:    []Evidence{},
		Timeline:    timeline,
		Metadata: map[string]string{
			"auto_created": "true",
			"alert_id":     alert["id"].(string),
		},
	}
}

func generateCaseID() string {
	return "case-" + time.Now().Format("20060102150405")
}

func generateTimelineID() string {
	return "timeline-" + time.Now().Format("20060102150405")
}

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

type EmailEvent struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	Provider    string                 `json:"provider"` // m365, gmail
	MessageID   string                 `json:"message_id"`
	Subject     string                 `json:"subject"`
	From        string                 `json:"from"`
	To          []string               `json:"to"`
	CC          []string               `json:"cc"`
	BCC         []string               `json:"bcc"`
	Body        string                 `json:"body"`
	BodyType    string                 `json:"body_type"` // html, text
	Attachments []EmailAttachment      `json:"attachments"`
	Headers     map[string]string      `json:"headers"`
	Size        int64                  `json:"size"`
	Priority    string                 `json:"priority"`
	ReadStatus  string                 `json:"read_status"`
	Folder      string                 `json:"folder"`
	ThreadID    string                 `json:"thread_id"`
	ConversationID string              `json:"conversation_id"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type EmailAttachment struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Size     int64  `json:"size"`
	MimeType string `json:"mime_type"`
	Hash     string `json:"hash"`
}

type EmailRule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Conditions  []string `json:"conditions"`
	Actions     []string `json:"actions"`
	Enabled     bool     `json:"enabled"`
	Priority    int      `json:"priority"`
}

type EmailConnector struct {
	Provider string
	Config   map[string]string
	Enabled  bool
}

func main() {
	kbrokers := os.Getenv("KAFKA_BROKERS")
	if kbrokers == "" { kbrokers = "localhost:9092" }
	group := os.Getenv("KAFKA_GROUP")
	if group == "" { group = "email" }

	chDsn := os.Getenv("CLICKHOUSE_DSN")
	if chDsn == "" { chDsn = "tcp://localhost:9000?database=default" }

	ctx := context.Background()
	conn, err := ch.Open(&ch.Options{Addr: []string{"localhost:9000"}})
	if err != nil { log.Fatalf("clickhouse connect: %v", err) }
	defer conn.Close()

	// Ensure email tables exist
	createEmailTables(conn, ctx)

	// Initialize email connectors
	connectors := initializeEmailConnectors()

	writer := kafka.NewWriter(kafka.WriterConfig{
		Brokers: strings.Split(kbrokers, ","),
		Topic:   "musafir.email_events",
	})

	log.Printf("email connectors starting brokers=%s", kbrokers)

	// Start each email connector
	for _, connector := range connectors {
		if connector.Enabled {
			go startEmailConnector(connector, writer, ctx)
		}
	}

	// Keep running
	select {}
}

func createEmailTables(conn ch.Conn, ctx context.Context) {
	// Email events table
	ddl := `CREATE TABLE IF NOT EXISTS musafir_email_events (
  id String,
  timestamp DateTime,
  provider String,
  message_id String,
  subject String,
  from_addr String,
  to_addrs Array(String),
  cc_addrs Array(String),
  bcc_addrs Array(String),
  body String,
  body_type String,
  attachments String,
  headers String,
  size Int64,
  priority String,
  read_status String,
  folder String,
  thread_id String,
  conversation_id String,
  metadata String
) ENGINE = MergeTree ORDER BY timestamp`
	
	if err := conn.Exec(ctx, ddl); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}

	// Email rules table
	ddl2 := `CREATE TABLE IF NOT EXISTS musafir_email_rules (
  id String,
  name String,
  description String,
  conditions String,
  actions String,
  enabled UInt8,
  priority Int32,
  created_at DateTime,
  updated_at DateTime
) ENGINE = MergeTree ORDER BY created_at`
	
	if err := conn.Exec(ctx, ddl2); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}
}

func initializeEmailConnectors() []EmailConnector {
	connectors := []EmailConnector{}

	// Microsoft 365 Connector
	if os.Getenv("M365_CLIENT_ID") != "" {
		connectors = append(connectors, EmailConnector{
			Provider: "m365",
			Config: map[string]string{
				"client_id":     os.Getenv("M365_CLIENT_ID"),
				"client_secret": os.Getenv("M365_CLIENT_SECRET"),
				"tenant_id":     os.Getenv("M365_TENANT_ID"),
				"scope":         "https://graph.microsoft.com/.default",
			},
			Enabled: true,
		})
	}

	// Gmail Connector
	if os.Getenv("GMAIL_CLIENT_ID") != "" {
		connectors = append(connectors, EmailConnector{
			Provider: "gmail",
			Config: map[string]string{
				"client_id":     os.Getenv("GMAIL_CLIENT_ID"),
				"client_secret": os.Getenv("GMAIL_CLIENT_SECRET"),
				"refresh_token": os.Getenv("GMAIL_REFRESH_TOKEN"),
				"scope":         "https://www.googleapis.com/auth/gmail.readonly",
			},
			Enabled: true,
		})
	}

	return connectors
}

func startEmailConnector(connector EmailConnector, writer *kafka.Writer, ctx context.Context) {
	log.Printf("Starting %s email connector", connector.Provider)

	switch connector.Provider {
	case "m365":
		startM365Connector(connector, writer, ctx)
	case "gmail":
		startGmailConnector(connector, writer, ctx)
	}
}

func startM365Connector(connector EmailConnector, writer *kafka.Writer, ctx context.Context) {
	// Simulate Microsoft 365 email events
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Generate sample M365 events
			events := generateM365Events()
			for _, event := range events {
				sendEmailEvent(event, writer, ctx)
			}
		case <-ctx.Done():
			return
		}
	}
}

func startGmailConnector(connector EmailConnector, writer *kafka.Writer, ctx context.Context) {
	// Simulate Gmail events
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Generate sample Gmail events
			events := generateGmailEvents()
			for _, event := range events {
				sendEmailEvent(event, writer, ctx)
			}
		case <-ctx.Done():
			return
		}
	}
}

func generateM365Events() []EmailEvent {
	events := []EmailEvent{
		{
			ID:        generateEmailEventID(),
			Timestamp: time.Now(),
			Provider:  "m365",
			MessageID: "m365-" + time.Now().Format("20060102150405"),
			Subject:   "Important Security Update Required",
			From:      "security@company.com",
			To:        []string{"admin@company.com", "it@company.com"},
			CC:        []string{},
			BCC:       []string{},
			Body:      "Please update your security software immediately.",
			BodyType:  "text",
			Attachments: []EmailAttachment{
				{
					ID:       "att1",
					Name:     "security_patch.exe",
					Size:     1024000,
					MimeType: "application/octet-stream",
					Hash:     "sha256:abc123...",
				},
			},
			Headers: map[string]string{
				"X-Microsoft-Exchange-Organization": "true",
				"X-MS-Exchange-Organization":        "true",
			},
			Size:           2048000,
			Priority:       "high",
			ReadStatus:     "unread",
			Folder:         "Inbox",
			ThreadID:       "thread-123",
			ConversationID: "conv-456",
			Metadata: map[string]interface{}{
				"tenant_id": "tenant-123",
				"user_id":   "user-456",
			},
		},
		{
			ID:        generateEmailEventID(),
			Timestamp: time.Now(),
			Provider:  "m365",
			MessageID: "m365-" + time.Now().Format("20060102150406"),
			Subject:   "Suspicious Email Detected",
			From:      "noreply@suspicious-domain.com",
			To:        []string{"user@company.com"},
			CC:        []string{},
			BCC:       []string{},
			Body:      "Click here to verify your account: http://fake-bank.com/verify",
			BodyType:  "html",
			Attachments: []EmailAttachment{},
			Headers: map[string]string{
				"X-Spam-Score": "8.5",
				"X-Spam-Flag":  "YES",
			},
			Size:           512000,
			Priority:       "normal",
			ReadStatus:     "unread",
			Folder:         "Inbox",
			ThreadID:       "thread-124",
			ConversationID: "conv-457",
			Metadata: map[string]interface{}{
				"tenant_id": "tenant-123",
				"user_id":   "user-789",
				"spam_score": 8.5,
			},
		},
	}

	return events
}

func generateGmailEvents() []EmailEvent {
	events := []EmailEvent{
		{
			ID:        generateEmailEventID(),
			Timestamp: time.Now(),
			Provider:  "gmail",
			MessageID: "gmail-" + time.Now().Format("20060102150405"),
			Subject:   "Meeting Reminder",
			From:      "calendar@company.com",
			To:        []string{"team@company.com"},
			CC:        []string{},
			BCC:       []string{},
			Body:      "Don't forget about our team meeting at 2 PM today.",
			BodyType:  "text",
			Attachments: []EmailAttachment{},
			Headers: map[string]string{
				"X-Gmail-Labels": "Important,Meeting",
			},
			Size:           1024,
			Priority:       "normal",
			ReadStatus:     "read",
			Folder:         "Inbox",
			ThreadID:       "thread-gmail-123",
			ConversationID: "conv-gmail-456",
			Metadata: map[string]interface{}{
				"labels": []string{"Important", "Meeting"},
			},
		},
		{
			ID:        generateEmailEventID(),
			Timestamp: time.Now(),
			Provider:  "gmail",
			MessageID: "gmail-" + time.Now().Format("20060102150406"),
			Subject:   "URGENT: Account Verification Required",
			From:      "noreply@phishing-site.com",
			To:        []string{"victim@company.com"},
			CC:        []string{},
			BCC:       []string{},
			Body:      "Your account will be suspended unless you verify immediately: http://fake-verification.com",
			BodyType:  "html",
			Attachments: []EmailAttachment{
				{
					ID:       "att2",
					Name:     "verification_form.pdf",
					Size:     512000,
					MimeType: "application/pdf",
					Hash:     "sha256:def456...",
				},
			},
			Headers: map[string]string{
				"X-Gmail-Labels": "Spam",
			},
			Size:           1024000,
			Priority:       "high",
			ReadStatus:     "unread",
			Folder:         "Spam",
			ThreadID:       "thread-gmail-124",
			ConversationID: "conv-gmail-457",
			Metadata: map[string]interface{}{
				"labels":    []string{"Spam"},
				"phishing":  true,
				"risk_score": 9.2,
			},
		},
	}

	return events
}

func sendEmailEvent(event EmailEvent, writer *kafka.Writer, ctx context.Context) {
	eventData, _ := json.Marshal(event)
	if err := writer.WriteMessages(ctx, kafka.Message{Value: eventData}); err != nil {
		log.Printf("write email event: %v", err)
	} else {
		log.Printf("EMAIL EVENT: %s - %s (%s)", event.Provider, event.Subject, event.From)
	}
}

func generateEmailEventID() string {
	return "email-" + time.Now().Format("20060102150405")
}

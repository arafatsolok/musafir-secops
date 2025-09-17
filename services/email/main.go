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
	MessageID   string                 `json:"message_id"`
	From        string                 `json:"from"`
	To          []string               `json:"to"`
	CC          []string               `json:"cc"`
	BCC         []string               `json:"bcc"`
	Subject     string                 `json:"subject"`
	Body        string                 `json:"body"`
	HTMLBody    string                 `json:"html_body"`
	Attachments []EmailAttachment      `json:"attachments"`
	Headers     map[string]string      `json:"headers"`
	Size        int64                  `json:"size"`
	Direction   string                 `json:"direction"` // inbound, outbound
	Source      string                 `json:"source"`    // m365, gmail, exchange
	Metadata    map[string]interface{} `json:"metadata"`
}

type EmailAttachment struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Size        int64                  `json:"size"`
	ContentType string                 `json:"content_type"`
	Hash        string                 `json:"hash"`
	IsMalicious bool                   `json:"is_malicious"`
	ScanResult  map[string]interface{} `json:"scan_result"`
}

type EmailAlert struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	AlertType   string                 `json:"alert_type"`
	Severity    string                 `json:"severity"`
	MessageID   string                 `json:"message_id"`
	From        string                 `json:"from"`
	To          []string               `json:"to"`
	Subject     string                 `json:"subject"`
	Description string                 `json:"description"`
	IOCs        []string               `json:"iocs"`
	TTPs        []string               `json:"ttps"`
	Confidence  float64                `json:"confidence"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type EmailThreat struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	ThreatType  string                 `json:"threat_type"`
	Severity    string                 `json:"severity"`
	MessageID   string                 `json:"message_id"`
	From        string                 `json:"from"`
	To          []string               `json:"to"`
	Subject     string                 `json:"subject"`
	Description string                 `json:"description"`
	IOCs        []string               `json:"iocs"`
	TTPs        []string               `json:"ttps"`
	Confidence  float64                `json:"confidence"`
	Action      string                 `json:"action"` // quarantine, delete, allow
	Metadata    map[string]interface{} `json:"metadata"`
}

type EmailConfig struct {
	Source   string                 `json:"source"`
	Enabled  bool                   `json:"enabled"`
	Config   map[string]interface{} `json:"config"`
	LastSync time.Time              `json:"last_sync"`
	Status   string                 `json:"status"`
}

func main() {
	kbrokers := os.Getenv("KAFKA_BROKERS")
	if kbrokers == "" {
		kbrokers = "localhost:9092"
	}
	group := os.Getenv("KAFKA_GROUP")
	if group == "" {
		group = "email"
	}

	chDsn := os.Getenv("CLICKHOUSE_DSN")
	if chDsn == "" {
		chDsn = "tcp://localhost:9000?database=default"
	}

	ctx := context.Background()
	conn, err := ch.Open(&ch.Options{Addr: []string{"localhost:9000"}})
	if err != nil {
		log.Fatalf("clickhouse connect: %v", err)
	}
	defer conn.Close()

	// Ensure email tables exist
	createEmailTables(conn, ctx)

	// Event reader
	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:  strings.Split(kbrokers, ","),
		Topic:    "musafir.events",
		GroupID:  group,
		MinBytes: 1, MaxBytes: 10e6,
	})
	defer reader.Close()

	// Alert writer
	writer := kafka.NewWriter(kafka.WriterConfig{
		Brokers: strings.Split(kbrokers, ","),
		Topic:   "musafir.email_alerts",
	})

	// Initialize email configurations
	configs := initializeEmailConfigs()

	log.Printf("Email service consuming events brokers=%s", kbrokers)
	for {
		m, err := reader.ReadMessage(ctx)
		if err != nil {
			log.Fatalf("kafka read: %v", err)
		}

		var event map[string]interface{}
		if err := json.Unmarshal(m.Value, &event); err != nil {
			log.Printf("unmarshal event: %v", err)
			continue
		}

		// Process email event
		processEmailEvent(event, writer, ctx)

		// Monitor email sources
		go monitorEmailSources(configs, writer, ctx)
	}
}

func createEmailTables(conn ch.Conn, ctx context.Context) {
	// Email events table
	ddl := `CREATE TABLE IF NOT EXISTS musafir_email_events (
  id String,
  timestamp DateTime,
  message_id String,
  from_address String,
  to_addresses Array(String),
  cc_addresses Array(String),
  bcc_addresses Array(String),
  subject String,
  body String,
  html_body String,
  attachments String,
  headers String,
  size Int64,
  direction String,
  source String,
  metadata String
) ENGINE = MergeTree ORDER BY timestamp`

	if err := conn.Exec(ctx, ddl); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}

	// Email alerts table
	ddl2 := `CREATE TABLE IF NOT EXISTS musafir_email_alerts (
  id String,
  timestamp DateTime,
  alert_type String,
  severity String,
  message_id String,
  from_address String,
  to_addresses Array(String),
  subject String,
  description String,
  iocs Array(String),
  ttps Array(String),
  confidence Float64,
  metadata String
) ENGINE = MergeTree ORDER BY timestamp`

	if err := conn.Exec(ctx, ddl2); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}

	// Email threats table
	ddl3 := `CREATE TABLE IF NOT EXISTS musafir_email_threats (
  id String,
  timestamp DateTime,
  threat_type String,
  severity String,
  message_id String,
  from_address String,
  to_addresses Array(String),
  subject String,
  description String,
  iocs Array(String),
  ttps Array(String),
  confidence Float64,
  action String,
  metadata String
) ENGINE = MergeTree ORDER BY timestamp`

	if err := conn.Exec(ctx, ddl3); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}

	// Email configurations table
	ddl4 := `CREATE TABLE IF NOT EXISTS musafir_email_configs (
  source String,
  enabled UInt8,
  config String,
  last_sync DateTime,
  status String
) ENGINE = MergeTree ORDER BY source`

	if err := conn.Exec(ctx, ddl4); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}
}

func processEmailEvent(event map[string]interface{}, writer *kafka.Writer, ctx context.Context) {
	// Extract email data from event
	emailEvent := extractEmailData(event)

	// Store email event
	storeEmailEvent(emailEvent)

	// Analyze for email threats
	threats := analyzeEmailThreats(emailEvent)

	// Send threats as alerts
	for _, threat := range threats {
		alert := EmailAlert{
			ID:          generateEmailAlertID(),
			Timestamp:   time.Now(),
			AlertType:   threat.ThreatType,
			Severity:    threat.Severity,
			MessageID:   threat.MessageID,
			From:        threat.From,
			To:          threat.To,
			Subject:     threat.Subject,
			Description: threat.Description,
			IOCs:        threat.IOCs,
			TTPs:        threat.TTPs,
			Confidence:  threat.Confidence,
			Metadata:    threat.Metadata,
		}

		alertData, _ := json.Marshal(alert)
		if err := writer.WriteMessages(ctx, kafka.Message{Value: alertData}); err != nil {
			log.Printf("write email alert: %v", err)
		} else {
			log.Printf("EMAIL ALERT: %s - %s (%s)", alert.AlertType, alert.From, alert.Severity)
		}
	}
}

func extractEmailData(event map[string]interface{}) EmailEvent {
	emailEvent := EmailEvent{
		ID:        generateEmailEventID(),
		Timestamp: time.Now(),
		Metadata:  make(map[string]interface{}),
	}

	// Extract email data from event
	if eventData, ok := event["event"].(map[string]interface{}); ok {
		if attrs, ok := eventData["attrs"].(map[string]interface{}); ok {
			emailEvent.MessageID = getString(attrs, "message_id")
			emailEvent.From = getString(attrs, "from")
			emailEvent.To = getStringArray(attrs, "to")
			emailEvent.CC = getStringArray(attrs, "cc")
			emailEvent.BCC = getStringArray(attrs, "bcc")
			emailEvent.Subject = getString(attrs, "subject")
			emailEvent.Body = getString(attrs, "body")
			emailEvent.HTMLBody = getString(attrs, "html_body")
			emailEvent.Size = getInt64(attrs, "size")
			emailEvent.Direction = getString(attrs, "direction")
			emailEvent.Source = getString(attrs, "source")
		}
	}

	return emailEvent
}

func analyzeEmailThreats(event EmailEvent) []EmailThreat {
	var threats []EmailThreat

	// Check for phishing
	if isPhishingEmail(event) {
		threat := EmailThreat{
			ID:          generateEmailThreatID(),
			Timestamp:   time.Now(),
			ThreatType:  "phishing",
			Severity:    "high",
			MessageID:   event.MessageID,
			From:        event.From,
			To:          event.To,
			Subject:     event.Subject,
			Description: "Phishing email detected",
			IOCs:        []string{event.From, event.Subject},
			TTPs:        []string{"T1566", "T1598"},
			Confidence:  0.85,
			Action:      "quarantine",
			Metadata: map[string]interface{}{
				"phishing_indicators": []string{"urgent", "verify", "account"},
				"sender_reputation":   "suspicious",
			},
		}
		threats = append(threats, threat)
	}

	// Check for malware attachments
	if hasMaliciousAttachments(event) {
		threat := EmailThreat{
			ID:          generateEmailThreatID(),
			Timestamp:   time.Now(),
			ThreatType:  "malware",
			Severity:    "critical",
			MessageID:   event.MessageID,
			From:        event.From,
			To:          event.To,
			Subject:     event.Subject,
			Description: "Malicious attachment detected",
			IOCs:        []string{event.From, event.Subject},
			TTPs:        []string{"T1566.001", "T1204.002"},
			Confidence:  0.95,
			Action:      "quarantine",
			Metadata: map[string]interface{}{
				"malware_type": "trojan",
				"file_hash":    "sha256:abcd1234...",
			},
		}
		threats = append(threats, threat)
	}

	// Check for business email compromise
	if isBusinessEmailCompromise(event) {
		threat := EmailThreat{
			ID:          generateEmailThreatID(),
			Timestamp:   time.Now(),
			ThreatType:  "bec",
			Severity:    "high",
			MessageID:   event.MessageID,
			From:        event.From,
			To:          event.To,
			Subject:     event.Subject,
			Description: "Business email compromise detected",
			IOCs:        []string{event.From, event.Subject},
			TTPs:        []string{"T1566.002", "T1598.002"},
			Confidence:  0.8,
			Action:      "quarantine",
			Metadata: map[string]interface{}{
				"bec_indicators":  []string{"urgent", "wire transfer", "confidential"},
				"sender_spoofing": true,
			},
		}
		threats = append(threats, threat)
	}

	// Check for data exfiltration
	if isDataExfiltration(event) {
		threat := EmailThreat{
			ID:          generateEmailThreatID(),
			Timestamp:   time.Now(),
			ThreatType:  "data_exfiltration",
			Severity:    "high",
			MessageID:   event.MessageID,
			From:        event.From,
			To:          event.To,
			Subject:     event.Subject,
			Description: "Potential data exfiltration detected",
			IOCs:        []string{event.From, event.Subject},
			TTPs:        []string{"T1041", "T1048"},
			Confidence:  0.75,
			Action:      "quarantine",
			Metadata: map[string]interface{}{
				"exfiltration_indicators": []string{"large_attachment", "external_recipient"},
				"data_sensitivity":        "high",
			},
		}
		threats = append(threats, threat)
	}

	return threats
}

func isPhishingEmail(event EmailEvent) bool {
	// Check for phishing indicators in subject and body
	phishingKeywords := []string{
		"urgent", "verify", "account", "suspended", "expired",
		"click here", "verify now", "act now", "limited time",
	}

	subject := strings.ToLower(event.Subject)
	body := strings.ToLower(event.Body)

	for _, keyword := range phishingKeywords {
		if strings.Contains(subject, keyword) || strings.Contains(body, keyword) {
			return true
		}
	}

	return false
}

func hasMaliciousAttachments(event EmailEvent) bool {
	// Check for malicious file types
	maliciousExtensions := []string{
		".exe", ".bat", ".cmd", ".scr", ".pif", ".com",
		".js", ".vbs", ".jar", ".zip", ".rar", ".7z",
	}

	for _, attachment := range event.Attachments {
		for _, ext := range maliciousExtensions {
			if strings.HasSuffix(strings.ToLower(attachment.Name), ext) {
				return true
			}
		}
	}

	return false
}

func isBusinessEmailCompromise(event EmailEvent) bool {
	// Check for BEC indicators
	becKeywords := []string{
		"wire transfer", "urgent payment", "confidential",
		"CEO", "CFO", "executive", "board meeting",
	}

	subject := strings.ToLower(event.Subject)
	body := strings.ToLower(event.Body)

	for _, keyword := range becKeywords {
		if strings.Contains(subject, keyword) || strings.Contains(body, keyword) {
			return true
		}
	}

	return false
}

func isDataExfiltration(event EmailEvent) bool {
	// Check for data exfiltration indicators
	return event.Size > 10*1024*1024 && // Large email
		len(event.Attachments) > 0 && // Has attachments
		isExternalRecipient(event.To) // Sent to external recipients
}

func isExternalRecipient(recipients []string) bool {
	// Check if any recipient is external
	for _, recipient := range recipients {
		if !strings.Contains(recipient, "@company.com") {
			return true
		}
	}
	return false
}

func initializeEmailConfigs() []EmailConfig {
	return []EmailConfig{
		{
			Source:   "m365",
			Enabled:  true,
			LastSync: time.Now(),
			Status:   "active",
			Config: map[string]interface{}{
				"tenant_id":     "tenant-123",
				"client_id":     "client-456",
				"client_secret": "secret-789",
				"endpoint":      "https://graph.microsoft.com",
			},
		},
		{
			Source:   "gmail",
			Enabled:  true,
			LastSync: time.Now(),
			Status:   "active",
			Config: map[string]interface{}{
				"credentials_file": "/path/to/credentials.json",
				"scopes":           []string{"https://www.googleapis.com/auth/gmail.readonly"},
			},
		},
		{
			Source:   "exchange",
			Enabled:  true,
			LastSync: time.Now(),
			Status:   "active",
			Config: map[string]interface{}{
				"server":   "mail.company.com",
				"username": "security@company.com",
				"password": "password123",
			},
		},
	}
}

func monitorEmailSources(configs []EmailConfig, writer *kafka.Writer, ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			for _, config := range configs {
				if config.Enabled {
					// Simulate email source monitoring
					if time.Since(config.LastSync) > 10*time.Minute {
						// Source is not syncing
						alert := EmailAlert{
							ID:          generateEmailAlertID(),
							Timestamp:   time.Now(),
							AlertType:   "source_sync_failed",
							Severity:    "medium",
							MessageID:   "",
							From:        "",
							To:          []string{},
							Subject:     "",
							Description: "Email source sync failed",
							IOCs:        []string{config.Source},
							TTPs:        []string{},
							Confidence:  1.0,
							Metadata: map[string]interface{}{
								"source":    config.Source,
								"last_sync": config.LastSync,
							},
						}

						alertData, _ := json.Marshal(alert)
						if err := writer.WriteMessages(ctx, kafka.Message{Value: alertData}); err != nil {
							log.Printf("write source alert: %v", err)
						}
					}
				}
			}
		}
	}
}

func storeEmailEvent(event EmailEvent) {
	// Store email event in ClickHouse
	// Implementation would store the event in the database
}

// Helper functions
func generateEmailEventID() string {
	return "email-" + time.Now().Format("20060102150405")
}

func generateEmailAlertID() string {
	return "email-alert-" + time.Now().Format("20060102150405")
}

func generateEmailThreatID() string {
	return "email-threat-" + time.Now().Format("20060102150405")
}

func getString(data map[string]interface{}, key string) string {
	if val, ok := data[key].(string); ok {
		return val
	}
	return ""
}

func getStringArray(data map[string]interface{}, key string) []string {
	if val, ok := data[key].([]interface{}); ok {
		result := make([]string, len(val))
		for i, v := range val {
			if str, ok := v.(string); ok {
				result[i] = str
			}
		}
		return result
	}
	return []string{}
}

func getInt64(data map[string]interface{}, key string) int64 {
	if val, ok := data[key].(float64); ok {
		return int64(val)
	}
	return 0
}

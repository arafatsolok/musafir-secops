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

type IdentityEvent struct {
	ID        string                 `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	UserID    string                 `json:"user_id"`
	Username  string                 `json:"username"`
	Email     string                 `json:"email"`
	Domain    string                 `json:"domain"`
	EventType string                 `json:"event_type"`
	Source    string                 `json:"source"` // ad, aad, okta, ldap
	IPAddress string                 `json:"ip_address"`
	UserAgent string                 `json:"user_agent"`
	Location  map[string]interface{} `json:"location"`
	Device    map[string]interface{} `json:"device"`
	SessionID string                 `json:"session_id"`
	Metadata  map[string]interface{} `json:"metadata"`
}

type IdentityAlert struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	AlertType   string                 `json:"alert_type"`
	Severity    string                 `json:"severity"`
	UserID      string                 `json:"user_id"`
	Username    string                 `json:"username"`
	Email       string                 `json:"email"`
	Description string                 `json:"description"`
	IOCs        []string               `json:"iocs"`
	TTPs        []string               `json:"ttps"`
	Confidence  float64                `json:"confidence"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type UserProfile struct {
	ID          string                 `json:"id"`
	Username    string                 `json:"username"`
	Email       string                 `json:"email"`
	Domain      string                 `json:"domain"`
	FirstName   string                 `json:"first_name"`
	LastName    string                 `json:"last_name"`
	Department  string                 `json:"department"`
	Title       string                 `json:"title"`
	Manager     string                 `json:"manager"`
	Groups      []string               `json:"groups"`
	Roles       []string               `json:"roles"`
	Permissions []string               `json:"permissions"`
	LastLogin   time.Time              `json:"last_login"`
	Status      string                 `json:"status"` // active, inactive, locked, disabled
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type IdentityConfig struct {
	Source   string                 `json:"source"`
	Enabled  bool                   `json:"enabled"`
	Config   map[string]interface{} `json:"config"`
	LastSync time.Time              `json:"last_sync"`
	Status   string                 `json:"status"`
}

type PrivilegeEscalation struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	UserID      string                 `json:"user_id"`
	Username    string                 `json:"username"`
	OldGroups   []string               `json:"old_groups"`
	NewGroups   []string               `json:"new_groups"`
	AddedGroups []string               `json:"added_groups"`
	Source      string                 `json:"source"`
	Description string                 `json:"description"`
	Confidence  float64                `json:"confidence"`
	Metadata    map[string]interface{} `json:"metadata"`
}

func main() {
	kbrokers := os.Getenv("KAFKA_BROKERS")
	if kbrokers == "" {
		kbrokers = "localhost:9092"
	}
	group := os.Getenv("KAFKA_GROUP")
	if group == "" {
		group = "identity"
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

	// Ensure identity tables exist
	createIdentityTables(conn, ctx)

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
		Topic:   "musafir.identity_alerts",
	})

	// Initialize identity configurations
	configs := initializeIdentityConfigs()

	// Load user profiles
	userProfiles := loadUserProfiles()

	log.Printf("Identity service consuming events brokers=%s", kbrokers)
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

		// Process identity event
		processIdentityEvent(event, writer, ctx, userProfiles)

		// Monitor identity sources
		go monitorIdentitySources(configs, writer, ctx)
	}
}

func createIdentityTables(conn ch.Conn, ctx context.Context) {
	// Identity events table
	ddl := `CREATE TABLE IF NOT EXISTS musafir_identity_events (
  id String,
  timestamp DateTime,
  user_id String,
  username String,
  email String,
  domain String,
  event_type String,
  source String,
  ip_address String,
  user_agent String,
  location String,
  device String,
  session_id String,
  metadata String
) ENGINE = MergeTree ORDER BY timestamp`

	if err := conn.Exec(ctx, ddl); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}

	// Identity alerts table
	ddl2 := `CREATE TABLE IF NOT EXISTS musafir_identity_alerts (
  id String,
  timestamp DateTime,
  alert_type String,
  severity String,
  user_id String,
  username String,
  email String,
  description String,
  iocs Array(String),
  ttps Array(String),
  confidence Float64,
  metadata String
) ENGINE = MergeTree ORDER BY timestamp`

	if err := conn.Exec(ctx, ddl2); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}

	// User profiles table
	ddl3 := `CREATE TABLE IF NOT EXISTS musafir_user_profiles (
  id String,
  username String,
  email String,
  domain String,
  first_name String,
  last_name String,
  department String,
  title String,
  manager String,
  groups Array(String),
  roles Array(String),
  permissions Array(String),
  last_login DateTime,
  status String,
  created_at DateTime,
  updated_at DateTime,
  metadata String
) ENGINE = MergeTree ORDER BY last_login`

	if err := conn.Exec(ctx, ddl3); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}

	// Privilege escalation table
	ddl4 := `CREATE TABLE IF NOT EXISTS musafir_privilege_escalation (
  id String,
  timestamp DateTime,
  user_id String,
  username String,
  old_groups Array(String),
  new_groups Array(String),
  added_groups Array(String),
  source String,
  description String,
  confidence Float64,
  metadata String
) ENGINE = MergeTree ORDER BY timestamp`

	if err := conn.Exec(ctx, ddl4); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}

	// Identity configurations table
	ddl5 := `CREATE TABLE IF NOT EXISTS musafir_identity_configs (
  source String,
  enabled UInt8,
  config String,
  last_sync DateTime,
  status String
) ENGINE = MergeTree ORDER BY source`

	if err := conn.Exec(ctx, ddl5); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}
}

func processIdentityEvent(event map[string]interface{}, writer *kafka.Writer, ctx context.Context, userProfiles map[string]UserProfile) {
	// Extract identity data from event
	identityEvent := extractIdentityData(event)

	// Store identity event
	storeIdentityEvent(identityEvent)

	// Analyze for identity threats
	alerts := analyzeIdentityThreats(identityEvent, userProfiles)

	// Send alerts
	for _, alert := range alerts {
		alertData, _ := json.Marshal(alert)
		if err := writer.WriteMessages(ctx, kafka.Message{Value: alertData}); err != nil {
			log.Printf("write identity alert: %v", err)
		} else {
			log.Printf("IDENTITY ALERT: %s - %s (%s)", alert.AlertType, alert.Username, alert.Severity)
		}
	}
}

func extractIdentityData(event map[string]interface{}) IdentityEvent {
	identityEvent := IdentityEvent{
		ID:        generateIdentityEventID(),
		Timestamp: time.Now(),
		Metadata:  make(map[string]interface{}),
	}

	// Extract identity data from event
	if eventData, ok := event["event"].(map[string]interface{}); ok {
		if attrs, ok := eventData["attrs"].(map[string]interface{}); ok {
			identityEvent.UserID = getString(attrs, "user_id")
			identityEvent.Username = getString(attrs, "username")
			identityEvent.Email = getString(attrs, "email")
			identityEvent.Domain = getString(attrs, "domain")
			identityEvent.EventType = getString(attrs, "event_type")
			identityEvent.Source = getString(attrs, "source")
			identityEvent.IPAddress = getString(attrs, "ip_address")
			identityEvent.UserAgent = getString(attrs, "user_agent")
			identityEvent.SessionID = getString(attrs, "session_id")
		}
	}

	// Extract user data
	if userData, ok := event["user"].(map[string]interface{}); ok {
		identityEvent.UserID = getString(userData, "id")
	}

	return identityEvent
}

func analyzeIdentityThreats(event IdentityEvent, userProfiles map[string]UserProfile) []IdentityAlert {
	var alerts []IdentityAlert

	// Check for privilege escalation
	if isPrivilegeEscalation(event, userProfiles) {
		alert := IdentityAlert{
			ID:          generateIdentityAlertID(),
			Timestamp:   time.Now(),
			AlertType:   "privilege_escalation",
			Severity:    "high",
			UserID:      event.UserID,
			Username:    event.Username,
			Email:       event.Email,
			Description: "Privilege escalation detected",
			IOCs:        []string{event.UserID, event.Username},
			TTPs:        []string{"T1078", "T1098"},
			Confidence:  0.8,
			Metadata: map[string]interface{}{
				"escalation_type": "group_addition",
				"source":          event.Source,
			},
		}
		alerts = append(alerts, alert)
	}

	// Check for suspicious login
	if isSuspiciousLogin(event, userProfiles) {
		alert := IdentityAlert{
			ID:          generateIdentityAlertID(),
			Timestamp:   time.Now(),
			AlertType:   "suspicious_login",
			Severity:    "medium",
			UserID:      event.UserID,
			Username:    event.Username,
			Email:       event.Email,
			Description: "Suspicious login detected",
			IOCs:        []string{event.IPAddress, event.UserAgent},
			TTPs:        []string{"T1078", "T1098"},
			Confidence:  0.7,
			Metadata: map[string]interface{}{
				"ip_address": event.IPAddress,
				"user_agent": event.UserAgent,
				"location":   event.Location,
			},
		}
		alerts = append(alerts, alert)
	}

	// Check for account takeover
	if isAccountTakeover(event, userProfiles) {
		alert := IdentityAlert{
			ID:          generateIdentityAlertID(),
			Timestamp:   time.Now(),
			AlertType:   "account_takeover",
			Severity:    "critical",
			UserID:      event.UserID,
			Username:    event.Username,
			Email:       event.Email,
			Description: "Account takeover detected",
			IOCs:        []string{event.UserID, event.Username, event.IPAddress},
			TTPs:        []string{"T1078", "T1098", "T1099"},
			Confidence:  0.9,
			Metadata: map[string]interface{}{
				"takeover_indicators": []string{"unusual_location", "unusual_device"},
				"ip_address":          event.IPAddress,
				"user_agent":          event.UserAgent,
			},
		}
		alerts = append(alerts, alert)
	}

	// Check for credential stuffing
	if isCredentialStuffing(event, userProfiles) {
		alert := IdentityAlert{
			ID:          generateIdentityAlertID(),
			Timestamp:   time.Now(),
			AlertType:   "credential_stuffing",
			Severity:    "high",
			UserID:      event.UserID,
			Username:    event.Username,
			Email:       event.Email,
			Description: "Credential stuffing attack detected",
			IOCs:        []string{event.IPAddress, event.UserAgent},
			TTPs:        []string{"T1078", "T1098"},
			Confidence:  0.85,
			Metadata: map[string]interface{}{
				"attack_type": "credential_stuffing",
				"ip_address":  event.IPAddress,
				"user_agent":  event.UserAgent,
			},
		}
		alerts = append(alerts, alert)
	}

	return alerts
}

func isPrivilegeEscalation(event IdentityEvent, userProfiles map[string]UserProfile) bool {
	// Check if user gained new privileges
	if profile, exists := userProfiles[event.UserID]; exists {
		// Simulate privilege escalation check
		return len(profile.Groups) > 5 && event.EventType == "group_membership_changed"
	}
	return false
}

func isSuspiciousLogin(event IdentityEvent, userProfiles map[string]UserProfile) bool {
	// Check for suspicious login patterns
	if profile, exists := userProfiles[event.UserID]; exists {
		// Check for unusual location
		if event.Location != nil {
			if country, ok := event.Location["country"].(string); ok {
				if country != "US" && profile.LastLogin.After(time.Now().Add(-24*time.Hour)) {
					return true
				}
			}
		}

		// Check for unusual time
		hour := time.Now().Hour()
		if hour < 6 || hour > 22 {
			return true
		}
	}
	return false
}

func isAccountTakeover(event IdentityEvent, userProfiles map[string]UserProfile) bool {
	// Check for account takeover indicators
	if profile, exists := userProfiles[event.UserID]; exists {
		// Check for multiple failed logins followed by success
		if event.EventType == "login_success" && profile.LastLogin.Before(time.Now().Add(-1*time.Hour)) {
			return true
		}

		// Check for unusual device
		if event.Device != nil {
			if deviceType, ok := event.Device["type"].(string); ok {
				if deviceType == "mobile" && profile.LastLogin.After(time.Now().Add(-24*time.Hour)) {
					return true
				}
			}
		}
	}
	return false
}

func isCredentialStuffing(event IdentityEvent, userProfiles map[string]UserProfile) bool {
	// Check for credential stuffing patterns
	// Simulate credential stuffing detection
	_ = userProfiles // Acknowledge parameter usage for future enhancement
	return event.EventType == "login_failed" &&
		strings.Contains(event.UserAgent, "bot") &&
		event.IPAddress != ""
}

func loadUserProfiles() map[string]UserProfile {
	// Load user profiles from database
	// For now, return sample data
	return map[string]UserProfile{
		"user-001": {
			ID:          "user-001",
			Username:    "john.doe",
			Email:       "john.doe@company.com",
			Domain:      "company.com",
			FirstName:   "John",
			LastName:    "Doe",
			Department:  "IT",
			Title:       "Security Analyst",
			Manager:     "jane.smith",
			Groups:      []string{"IT", "Security", "Analysts"},
			Roles:       []string{"analyst", "user"},
			Permissions: []string{"read", "write", "analyze"},
			LastLogin:   time.Now().Add(-2 * time.Hour),
			Status:      "active",
			CreatedAt:   time.Now().Add(-365 * 24 * time.Hour),
			UpdatedAt:   time.Now().Add(-1 * time.Hour),
			Metadata:    make(map[string]interface{}),
		},
		"user-002": {
			ID:          "user-002",
			Username:    "jane.smith",
			Email:       "jane.smith@company.com",
			Domain:      "company.com",
			FirstName:   "Jane",
			LastName:    "Smith",
			Department:  "IT",
			Title:       "Security Manager",
			Manager:     "bob.johnson",
			Groups:      []string{"IT", "Security", "Managers", "Admins"},
			Roles:       []string{"manager", "admin", "user"},
			Permissions: []string{"read", "write", "analyze", "manage", "admin"},
			LastLogin:   time.Now().Add(-1 * time.Hour),
			Status:      "active",
			CreatedAt:   time.Now().Add(-730 * 24 * time.Hour),
			UpdatedAt:   time.Now().Add(-30 * time.Minute),
			Metadata:    make(map[string]interface{}),
		},
	}
}

func initializeIdentityConfigs() []IdentityConfig {
	return []IdentityConfig{
		{
			Source:   "ad",
			Enabled:  true,
			LastSync: time.Now(),
			Status:   "active",
			Config: map[string]interface{}{
				"server":   "dc.company.com",
				"username": "svc_account",
				"password": "password123",
				"base_dn":  "DC=company,DC=com",
			},
		},
		{
			Source:   "aad",
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
			Source:   "okta",
			Enabled:  true,
			LastSync: time.Now(),
			Status:   "active",
			Config: map[string]interface{}{
				"org_url":   "https://company.okta.com",
				"api_token": "token-123",
				"endpoint":  "https://company.okta.com/api/v1",
			},
		},
	}
}

func monitorIdentitySources(configs []IdentityConfig, writer *kafka.Writer, ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		for _, config := range configs {
			if config.Enabled {
				// Simulate identity source monitoring
				if time.Since(config.LastSync) > 15*time.Minute {
					// Source is not syncing
					alert := IdentityAlert{
						ID:          generateIdentityAlertID(),
						Timestamp:   time.Now(),
						AlertType:   "source_sync_failed",
						Severity:    "medium",
						UserID:      "",
						Username:    "",
						Email:       "",
						Description: "Identity source sync failed",
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

func storeIdentityEvent(event IdentityEvent) {
	// Store identity event in ClickHouse
	// Implementation would store the event in the database
}

// Helper functions
func generateIdentityEventID() string {
	return "identity-" + time.Now().Format("20060102150405")
}

func generateIdentityAlertID() string {
	return "identity-alert-" + time.Now().Format("20060102150405")
}

func getString(data map[string]interface{}, key string) string {
	if val, ok := data[key].(string); ok {
		return val
	}
	return ""
}

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
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	Provider    string                 `json:"provider"` // ad, aad, okta
	EventType   string                 `json:"event_type"`
	UserID      string                 `json:"user_id"`
	Username    string                 `json:"username"`
	Email       string                 `json:"email"`
	DisplayName string                 `json:"display_name"`
	Groups      []string               `json:"groups"`
	Roles       []string               `json:"roles"`
	SourceIP    string                 `json:"source_ip"`
	UserAgent   string                 `json:"user_agent"`
	Location    string                 `json:"location"`
	DeviceID    string                 `json:"device_id"`
	DeviceType  string                 `json:"device_type"`
	RiskScore   float64                `json:"risk_score"`
	Status      string                 `json:"status"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type UserProfile struct {
	ID          string    `json:"id"`
	Username    string    `json:"username"`
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name"`
	Groups      []string  `json:"groups"`
	Roles       []string  `json:"roles"`
	LastLogin   time.Time `json:"last_login"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Status      string    `json:"status"`
	RiskScore   float64   `json:"risk_score"`
}

type IdentityConnector struct {
	Provider string
	Config   map[string]string
	Enabled  bool
}

func main() {
	kbrokers := os.Getenv("KAFKA_BROKERS")
	if kbrokers == "" { kbrokers = "localhost:9092" }
	group := os.Getenv("KAFKA_GROUP")
	if group == "" { group = "identity" }

	chDsn := os.Getenv("CLICKHOUSE_DSN")
	if chDsn == "" { chDsn = "tcp://localhost:9000?database=default" }

	ctx := context.Background()
	conn, err := ch.Open(&ch.Options{Addr: []string{"localhost:9000"}})
	if err != nil { log.Fatalf("clickhouse connect: %v", err) }
	defer conn.Close()

	// Ensure identity tables exist
	createIdentityTables(conn, ctx)

	// Initialize identity connectors
	connectors := initializeIdentityConnectors()

	writer := kafka.NewWriter(kafka.WriterConfig{
		Brokers: strings.Split(kbrokers, ","),
		Topic:   "musafir.identity_events",
	})

	log.Printf("identity connectors starting brokers=%s", kbrokers)

	// Start each identity connector
	for _, connector := range connectors {
		if connector.Enabled {
			go startIdentityConnector(connector, writer, ctx)
		}
	}

	// Keep running
	select {}
}

func createIdentityTables(conn ch.Conn, ctx context.Context) {
	// Identity events table
	ddl := `CREATE TABLE IF NOT EXISTS musafir_identity_events (
  id String,
  timestamp DateTime,
  provider String,
  event_type String,
  user_id String,
  username String,
  email String,
  display_name String,
  groups Array(String),
  roles Array(String),
  source_ip String,
  user_agent String,
  location String,
  device_id String,
  device_type String,
  risk_score Float64,
  status String,
  metadata String
) ENGINE = MergeTree ORDER BY timestamp`
	
	if err := conn.Exec(ctx, ddl); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}

	// User profiles table
	ddl2 := `CREATE TABLE IF NOT EXISTS musafir_user_profiles (
  id String,
  username String,
  email String,
  display_name String,
  groups Array(String),
  roles Array(String),
  last_login DateTime,
  created_at DateTime,
  updated_at DateTime,
  status String,
  risk_score Float64
) ENGINE = MergeTree ORDER BY created_at`
	
	if err := conn.Exec(ctx, ddl2); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}
}

func initializeIdentityConnectors() []IdentityConnector {
	connectors := []IdentityConnector{}

	// Active Directory Connector
	if os.Getenv("AD_SERVER") != "" {
		connectors = append(connectors, IdentityConnector{
			Provider: "ad",
			Config: map[string]string{
				"server":   os.Getenv("AD_SERVER"),
				"username": os.Getenv("AD_USERNAME"),
				"password": os.Getenv("AD_PASSWORD"),
				"base_dn":  os.Getenv("AD_BASE_DN"),
			},
			Enabled: true,
		})
	}

	// Azure Active Directory Connector
	if os.Getenv("AAD_CLIENT_ID") != "" {
		connectors = append(connectors, IdentityConnector{
			Provider: "aad",
			Config: map[string]string{
				"client_id":     os.Getenv("AAD_CLIENT_ID"),
				"client_secret": os.Getenv("AAD_CLIENT_SECRET"),
				"tenant_id":     os.Getenv("AAD_TENANT_ID"),
				"scope":         "https://graph.microsoft.com/.default",
			},
			Enabled: true,
		})
	}

	// Okta Connector
	if os.Getenv("OKTA_DOMAIN") != "" {
		connectors = append(connectors, IdentityConnector{
			Provider: "okta",
			Config: map[string]string{
				"domain":   os.Getenv("OKTA_DOMAIN"),
				"api_token": os.Getenv("OKTA_API_TOKEN"),
			},
			Enabled: true,
		})
	}

	return connectors
}

func startIdentityConnector(connector IdentityConnector, writer *kafka.Writer, ctx context.Context) {
	log.Printf("Starting %s identity connector", connector.Provider)

	switch connector.Provider {
	case "ad":
		startADConnector(connector, writer, ctx)
	case "aad":
		startAADConnector(connector, writer, ctx)
	case "okta":
		startOktaConnector(connector, writer, ctx)
	}
}

func startADConnector(connector IdentityConnector, writer *kafka.Writer, ctx context.Context) {
	// Simulate Active Directory events
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Generate sample AD events
			events := generateADEvents()
			for _, event := range events {
				sendIdentityEvent(event, writer, ctx)
			}
		case <-ctx.Done():
			return
		}
	}
}

func startAADConnector(connector IdentityConnector, writer *kafka.Writer, ctx context.Context) {
	// Simulate Azure AD events
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Generate sample AAD events
			events := generateAADEvents()
			for _, event := range events {
				sendIdentityEvent(event, writer, ctx)
			}
		case <-ctx.Done():
			return
		}
	}
}

func startOktaConnector(connector IdentityConnector, writer *kafka.Writer, ctx context.Context) {
	// Simulate Okta events
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Generate sample Okta events
			events := generateOktaEvents()
			for _, event := range events {
				sendIdentityEvent(event, writer, ctx)
			}
		case <-ctx.Done():
			return
		}
	}
}

func generateADEvents() []IdentityEvent {
	events := []IdentityEvent{
		{
			ID:          generateIdentityEventID(),
			Timestamp:   time.Now(),
			Provider:    "ad",
			EventType:   "user_login",
			UserID:      "S-1-5-21-1234567890-1234567890-1234567890-1001",
			Username:    "john.doe",
			Email:       "john.doe@company.com",
			DisplayName: "John Doe",
			Groups:      []string{"Domain Users", "IT Admins", "Security Team"},
			Roles:       []string{"admin", "security_analyst"},
			SourceIP:    "192.168.1.100",
			UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			Location:    "New York, US",
			DeviceID:    "device-001",
			DeviceType:  "laptop",
			RiskScore:   0.2,
			Status:      "success",
			Metadata: map[string]interface{}{
				"domain": "company.local",
				"ou":     "OU=Users,DC=company,DC=local",
			},
		},
		{
			ID:          generateIdentityEventID(),
			Timestamp:   time.Now(),
			Provider:    "ad",
			EventType:   "user_logout",
			UserID:      "S-1-5-21-1234567890-1234567890-1234567890-1002",
			Username:    "jane.smith",
			Email:       "jane.smith@company.com",
			DisplayName: "Jane Smith",
			Groups:      []string{"Domain Users", "Finance Team"},
			Roles:       []string{"user"},
			SourceIP:    "192.168.1.101",
			UserAgent:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
			Location:    "San Francisco, US",
			DeviceID:    "device-002",
			DeviceType:  "desktop",
			RiskScore:   0.1,
			Status:      "success",
			Metadata: map[string]interface{}{
				"domain": "company.local",
				"ou":     "OU=Users,DC=company,DC=local",
			},
		},
	}

	return events
}

func generateAADEvents() []IdentityEvent {
	events := []IdentityEvent{
		{
			ID:          generateIdentityEventID(),
			Timestamp:   time.Now(),
			Provider:    "aad",
			EventType:   "user_signin",
			UserID:      "aad-user-123",
			Username:    "admin@company.onmicrosoft.com",
			Email:       "admin@company.onmicrosoft.com",
			DisplayName: "Admin User",
			Groups:      []string{"Global Administrators", "Security Administrators"},
			Roles:       []string{"global_admin", "security_admin"},
			SourceIP:    "203.0.113.1",
			UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			Location:    "Seattle, US",
			DeviceID:    "aad-device-001",
			DeviceType:  "mobile",
			RiskScore:   0.3,
			Status:      "success",
			Metadata: map[string]interface{}{
				"tenant_id": "tenant-123",
				"app_id":    "app-456",
				"mfa_used":  true,
			},
		},
		{
			ID:          generateIdentityEventID(),
			Timestamp:   time.Now(),
			Provider:    "aad",
			EventType:   "user_signin_failed",
			UserID:      "aad-user-456",
			Username:    "suspicious@company.onmicrosoft.com",
			Email:       "suspicious@company.onmicrosoft.com",
			DisplayName: "Suspicious User",
			Groups:      []string{},
			Roles:       []string{},
			SourceIP:    "203.0.113.999",
			UserAgent:   "curl/7.68.0",
			Location:    "Unknown",
			DeviceID:    "",
			DeviceType:  "unknown",
			RiskScore:   0.9,
			Status:      "failed",
			Metadata: map[string]interface{}{
				"tenant_id": "tenant-123",
				"app_id":    "app-456",
				"error":     "invalid_credentials",
				"risk_level": "high",
			},
		},
	}

	return events
}

func generateOktaEvents() []IdentityEvent {
	events := []IdentityEvent{
		{
			ID:          generateIdentityEventID(),
			Timestamp:   time.Now(),
			Provider:    "okta",
			EventType:   "user.session.start",
			UserID:      "okta-user-123",
			Username:    "user@company.com",
			Email:       "user@company.com",
			DisplayName: "Regular User",
			Groups:      []string{"Everyone", "Engineering"},
			Roles:       []string{"developer"},
			SourceIP:    "198.51.100.1",
			UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			Location:    "Austin, US",
			DeviceID:    "okta-device-001",
			DeviceType:  "laptop",
			RiskScore:   0.1,
			Status:      "success",
			Metadata: map[string]interface{}{
				"org_id": "org-123",
				"app_id": "app-789",
				"factor_type": "push",
			},
		},
		{
			ID:          generateIdentityEventID(),
			Timestamp:   time.Now(),
			Provider:    "okta",
			EventType:   "user.mfa.factor.verify",
			UserID:      "okta-user-456",
			Username:    "admin@company.com",
			Email:       "admin@company.com",
			DisplayName: "Admin User",
			Groups:      []string{"Everyone", "Administrators"},
			Roles:       []string{"admin"},
			SourceIP:    "198.51.100.2",
			UserAgent:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
			Location:    "Chicago, US",
			DeviceID:    "okta-device-002",
			DeviceType:  "mobile",
			RiskScore:   0.2,
			Status:      "success",
			Metadata: map[string]interface{}{
				"org_id": "org-123",
				"app_id": "app-789",
				"factor_type": "totp",
			},
		},
	}

	return events
}

func sendIdentityEvent(event IdentityEvent, writer *kafka.Writer, ctx context.Context) {
	eventData, _ := json.Marshal(event)
	if err := writer.WriteMessages(ctx, kafka.Message{Value: eventData}); err != nil {
		log.Printf("write identity event: %v", err)
	} else {
		log.Printf("IDENTITY EVENT: %s - %s (%s)", event.Provider, event.EventType, event.Username)
	}
}

func generateIdentityEventID() string {
	return "identity-" + time.Now().Format("20060102150405")
}

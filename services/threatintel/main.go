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

type Event struct {
	Ts       string                 `json:"ts"`
	TenantID string                 `json:"tenant_id"`
	Asset    map[string]string      `json:"asset"`
	User     map[string]string      `json:"user"`
	Event    map[string]interface{} `json:"event"`
	Ingest   map[string]string      `json:"ingest"`
}

type ThreatIntelAlert struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Indicator   string    `json:"indicator"`
	IndicatorType string  `json:"indicator_type"`
	Source      string    `json:"source"`
	Confidence  float64   `json:"confidence"`
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
	Event       Event     `json:"event"`
	MatchType   string    `json:"match_type"`
}

type ThreatIndicator struct {
	Value     string  `json:"value"`
	Type      string  `json:"type"`
	Source    string  `json:"source"`
	Confidence float64 `json:"confidence"`
	Description string `json:"description"`
	LastSeen  time.Time `json:"last_seen"`
}

func main() {
	kbrokers := os.Getenv("KAFKA_BROKERS")
	if kbrokers == "" { kbrokers = "localhost:9092" }
	topic := os.Getenv("KAFKA_TOPIC")
	if topic == "" { topic = "musafir.events" }
	group := os.Getenv("KAFKA_GROUP")
	if group == "" { group = "threatintel" }

	chDsn := os.Getenv("CLICKHOUSE_DSN")
	if chDsn == "" { chDsn = "tcp://localhost:9000?database=default" }

	ctx := context.Background()
	conn, err := ch.Open(&ch.Options{Addr: []string{"localhost:9000"}})
	if err != nil { log.Fatalf("clickhouse connect: %v", err) }
	defer conn.Close()

	// Ensure threat intel tables exist
	createThreatIntelTables(conn, ctx)

	// Load threat indicators
	indicators := loadThreatIndicators()

	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:  strings.Split(kbrokers, ","),
		Topic:    topic,
		GroupID:  group,
		MinBytes: 1, MaxBytes: 10e6,
	})
	defer reader.Close()

	writer := kafka.NewWriter(kafka.WriterConfig{
		Brokers: strings.Split(kbrokers, ","),
		Topic:   "musafir.ti_alerts",
	})

	log.Printf("threat intel consuming topic=%s brokers=%s", topic, kbrokers)
	for {
		m, err := reader.ReadMessage(ctx)
		if err != nil { log.Fatalf("kafka read: %v", err) }

		var event Event
		if err := json.Unmarshal(m.Value, &event); err != nil {
			log.Printf("unmarshal event: %v", err)
			continue
		}

		// Check against threat indicators
		if alert := checkThreatIndicators(indicators, event); alert != nil {
			alertData, _ := json.Marshal(alert)
			if err := writer.WriteMessages(ctx, kafka.Message{Value: alertData}); err != nil {
				log.Printf("write TI alert: %v", err)
			} else {
				log.Printf("TI ALERT: %s - %s (confidence: %.2f)", alert.IndicatorType, alert.Indicator, alert.Confidence)
			}
		}
	}
}

func createThreatIntelTables(conn ch.Conn, ctx context.Context) {
	// Threat indicators table
	ddl := `CREATE TABLE IF NOT EXISTS musafir_threat_indicators (
  value String,
  type String,
  source String,
  confidence Float64,
  description String,
  last_seen DateTime,
  created_at DateTime DEFAULT now()
) ENGINE = MergeTree ORDER BY value`
	
	if err := conn.Exec(ctx, ddl); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}

	// TI alerts table
	ddl2 := `CREATE TABLE IF NOT EXISTS musafir_ti_alerts (
  id String,
  type String,
  indicator String,
  indicator_type String,
  source String,
  confidence Float64,
  description String,
  timestamp DateTime,
  event String,
  match_type String
) ENGINE = MergeTree ORDER BY timestamp`
	
	if err := conn.Exec(ctx, ddl2); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}
}

func loadThreatIndicators() []ThreatIndicator {
	// Sample threat indicators - in production, load from STIX/TAXII feeds
	indicators := []ThreatIndicator{
		{
			Value:       "evil.com",
			Type:        "domain",
			Source:      "sample_feed",
			Confidence:  0.9,
			Description: "Known malicious domain",
			LastSeen:    time.Now(),
		},
		{
			Value:       "192.168.1.100",
			Type:        "ip",
			Source:      "sample_feed",
			Confidence:  0.8,
			Description: "Suspicious IP address",
			LastSeen:    time.Now(),
		},
		{
			Value:       "a1b2c3d4e5f6",
			Type:        "hash",
			Source:      "sample_feed",
			Confidence:  0.95,
			Description: "Malware hash",
			LastSeen:    time.Now(),
		},
		{
			Value:       "powershell.exe",
			Type:        "process",
			Source:      "sample_feed",
			Confidence:  0.7,
			Description: "Suspicious process name",
			LastSeen:    time.Now(),
		},
	}

	log.Printf("loaded %d threat indicators", len(indicators))
	return indicators
}

func checkThreatIndicators(indicators []ThreatIndicator, event Event) *ThreatIntelAlert {
	// Check IP addresses
	if ip, ok := event.Asset["ip"]; ok {
		if match := findIndicatorMatch(indicators, ip, "ip"); match != nil {
			return createTIAlert(match, event, "asset_ip")
		}
	}

	// Check process names
	if attrs, ok := event.Event["attrs"].(map[string]interface{}); ok {
		if image, ok := attrs["image"].(string); ok {
			if match := findIndicatorMatch(indicators, image, "process"); match != nil {
				return createTIAlert(match, event, "process_image")
			}
		}
	}

	// Check command lines
	if attrs, ok := event.Event["attrs"].(map[string]interface{}); ok {
		if cmd, ok := attrs["cmd"].(string); ok {
			// Check for domain matches in command
			for _, indicator := range indicators {
				if indicator.Type == "domain" && strings.Contains(strings.ToLower(cmd), strings.ToLower(indicator.Value)) {
					return createTIAlert(&indicator, event, "command_domain")
				}
			}
		}
	}

	// Check file hashes (if available)
	if attrs, ok := event.Event["attrs"].(map[string]interface{}); ok {
		if hash, ok := attrs["hash"].(string); ok {
			if match := findIndicatorMatch(indicators, hash, "hash"); match != nil {
				return createTIAlert(match, event, "file_hash")
			}
		}
	}

	return nil
}

func findIndicatorMatch(indicators []ThreatIndicator, value, indicatorType string) *ThreatIndicator {
	for _, indicator := range indicators {
		if indicator.Type == indicatorType && strings.EqualFold(indicator.Value, value) {
			return &indicator
		}
	}
	return nil
}

func createTIAlert(indicator *ThreatIndicator, event Event, matchType string) *ThreatIntelAlert {
	return &ThreatIntelAlert{
		ID:            generateAlertID(),
		Type:          "threat_intel",
		Indicator:     indicator.Value,
		IndicatorType: indicator.Type,
		Source:        indicator.Source,
		Confidence:    indicator.Confidence,
		Description:   indicator.Description,
		Timestamp:     time.Now(),
		Event:         event,
		MatchType:     matchType,
	}
}

func generateAlertID() string {
	return "ti-" + time.Now().Format("20060102150405")
}

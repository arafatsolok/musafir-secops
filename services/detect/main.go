package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"strings"
	"time"

	"github.com/segmentio/kafka-go"
	"gopkg.in/yaml.v3"
)

type SigmaRule struct {
	Title    string `yaml:"title"`
	ID       string `yaml:"id"`
	Status   string `yaml:"status"`
	Level    string `yaml:"level"`
	LogSource struct {
		Product string `yaml:"product"`
		Service string `yaml:"service"`
	} `yaml:"logsource"`
	Detection struct {
		Selection map[string]interface{} `yaml:"sel"`
		Condition string                 `yaml:"condition"`
	} `yaml:"detection"`
}

type Event struct {
	Ts       string                 `json:"ts"`
	TenantID string                 `json:"tenant_id"`
	Asset    map[string]string      `json:"asset"`
	User     map[string]string      `json:"user"`
	Event    map[string]interface{} `json:"event"`
	Ingest   map[string]string      `json:"ingest"`
}

type Alert struct {
	ID        string    `json:"id"`
	RuleID    string    `json:"rule_id"`
	Title     string    `json:"title"`
	Level     string    `json:"level"`
	Timestamp time.Time `json:"timestamp"`
	Event     Event     `json:"event"`
	Message   string    `json:"message"`
}

func main() {
	kbrokers := os.Getenv("KAFKA_BROKERS")
	if kbrokers == "" { kbrokers = "localhost:9092" }
	topic := os.Getenv("KAFKA_TOPIC")
	if topic == "" { topic = "musafir.events" }
	group := os.Getenv("KAFKA_GROUP")
	if group == "" { group = "detect" }

	// Load Sigma rules
	rules := loadSigmaRules()
	log.Printf("loaded %d sigma rules", len(rules))

	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:  strings.Split(kbrokers, ","),
		Topic:    topic,
		GroupID:  group,
		MinBytes: 1, MaxBytes: 10e6,
	})
	defer reader.Close()

	writer := kafka.NewWriter(kafka.WriterConfig{
		Brokers: strings.Split(kbrokers, ","),
		Topic:   "musafir.alerts",
	})

	log.Printf("detect consuming topic=%s brokers=%s", topic, kbrokers)
	for {
		m, err := reader.ReadMessage(context.Background())
		if err != nil { log.Fatalf("kafka read: %v", err) }

		var event Event
		if err := json.Unmarshal(m.Value, &event); err != nil {
			log.Printf("unmarshal event: %v", err)
			continue
		}

		// Check against rules
		for _, rule := range rules {
			if matchesRule(event, rule) {
				alert := Alert{
					ID:        generateAlertID(),
					RuleID:    rule.ID,
					Title:     rule.Title,
					Level:     rule.Level,
					Timestamp: time.Now(),
					Event:     event,
					Message:   "Event matched rule: " + rule.Title,
				}

				alertData, _ := json.Marshal(alert)
				if err := writer.WriteMessages(context.Background(), kafka.Message{Value: alertData}); err != nil {
					log.Printf("write alert: %v", err)
				} else {
					log.Printf("ALERT: %s - %s", rule.Level, rule.Title)
				}
			}
		}
	}
}

func loadSigmaRules() []SigmaRule {
	// Load the rapid high entropy rule
	ruleYAML := `title: Rapid High-Entropy File Writes
id: e4a6cfc1-6b0a-4d3a-9f3e-9e5b5a77c9f9
status: experimental
logsource:
  product: endpoint
  service: file
level: high
detection:
  sel:
    event.name: file_write
    event.attrs.entropy: ">=7.5"
  condition: sel | count() by asset.id over 60s >= 200`

	var rule SigmaRule
	if err := yaml.Unmarshal([]byte(ruleYAML), &rule); err != nil {
		log.Fatalf("unmarshal rule: %v", err)
	}
	return []SigmaRule{rule}
}

func matchesRule(event Event, rule SigmaRule) bool {
	// Simple rule matching - check if event matches selection criteria
	eventData := event.Event
	if eventData["name"] == "file_write" {
		// Check for high entropy (simplified)
		if attrs, ok := eventData["attrs"].(map[string]interface{}); ok {
			if entropy, ok := attrs["entropy"].(float64); ok && entropy >= 7.5 {
				return true
			}
		}
	}
	return false
}

func generateAlertID() string {
	return "alert-" + time.Now().Format("20060102150405")
}

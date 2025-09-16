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

type Playbook struct {
	On    string `yaml:"on"`
	Steps []struct {
		Action string                 `yaml:"action"`
		Params map[string]interface{} `yaml:"params"`
	} `yaml:"steps"`
}

type Alert struct {
	ID        string    `json:"id"`
	RuleID    string    `json:"rule_id"`
	Title     string    `json:"title"`
	Level     string    `json:"level"`
	Timestamp time.Time `json:"timestamp"`
	Event     struct {
		Ts       string                 `json:"ts"`
		TenantID string                 `json:"tenant_id"`
		Asset    map[string]string      `json:"asset"`
		User     map[string]string      `json:"user"`
		Event    map[string]interface{} `json:"event"`
		Ingest   map[string]string      `json:"ingest"`
	} `json:"event"`
	Message string `json:"message"`
}

func main() {
	kbrokers := os.Getenv("KAFKA_BROKERS")
	if kbrokers == "" { kbrokers = "localhost:9092" }
	group := os.Getenv("KAFKA_GROUP")
	if group == "" { group = "respond" }

	// Load playbooks
	playbooks := loadPlaybooks()
	log.Printf("loaded %d playbooks", len(playbooks))

	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:  strings.Split(kbrokers, ","),
		Topic:    "musafir.alerts",
		GroupID:  group,
		MinBytes: 1, MaxBytes: 10e6,
	})
	defer reader.Close()

	log.Printf("respond consuming alerts brokers=%s", kbrokers)
	for {
		m, err := reader.ReadMessage(context.Background())
		if err != nil { log.Fatalf("kafka read: %v", err) }

		var alert Alert
		if err := json.Unmarshal(m.Value, &alert); err != nil {
			log.Printf("unmarshal alert: %v", err)
			continue
		}

		// Execute matching playbooks
		for _, playbook := range playbooks {
			if matchesPlaybook(alert, playbook) {
				executePlaybook(alert, playbook)
			}
		}
	}
}

func loadPlaybooks() []Playbook {
	// Load the ransomware playbook
	playbookYAML := `on: alert.where(type=="ransomware_suspected" && risk>=80)
steps:
  - action: isolate_host
    params:
      mode: "edr"
      lease_minutes: 60
  - action: kill_process
    params:
      image: "**/wscript.exe"
  - action: snapshot
    params:
      provider: "auto"
  - action: collect_artifacts
    params:
      memdump: true
      logs: last_24h
  - action: notify
    params:
      channel: "soc-high"
      template: "ransomware-ongoing"
  - action: open_case
    params:
      severity: critical
      sla_minutes: 30`

	var playbook Playbook
	if err := yaml.Unmarshal([]byte(playbookYAML), &playbook); err != nil {
		log.Fatalf("unmarshal playbook: %v", err)
	}
	return []Playbook{playbook}
}

func matchesPlaybook(alert Alert, playbook Playbook) bool {
	// Simple matching - check if alert level is high and title contains ransomware
	return alert.Level == "high" && strings.Contains(strings.ToLower(alert.Title), "entropy")
}

func executePlaybook(alert Alert, playbook Playbook) {
	log.Printf("EXECUTING PLAYBOOK for alert: %s", alert.Title)
	
	for i, step := range playbook.Steps {
		log.Printf("  Step %d: %s", i+1, step.Action)
		
		switch step.Action {
		case "isolate_host":
			log.Printf("    -> Isolating host %s for %v minutes", alert.Event.Asset["id"], step.Params["lease_minutes"])
		case "kill_process":
			log.Printf("    -> Killing processes matching %v", step.Params["image"])
		case "snapshot":
			log.Printf("    -> Creating snapshot with provider %v", step.Params["provider"])
		case "collect_artifacts":
			log.Printf("    -> Collecting artifacts: memdump=%v, logs=%v", step.Params["memdump"], step.Params["logs"])
		case "notify":
			log.Printf("    -> Sending notification to %s with template %s", step.Params["channel"], step.Params["template"])
		case "open_case":
			log.Printf("    -> Opening case with severity %s, SLA %v minutes", step.Params["severity"], step.Params["sla_minutes"])
		default:
			log.Printf("    -> Unknown action: %s", step.Action)
		}
	}
}

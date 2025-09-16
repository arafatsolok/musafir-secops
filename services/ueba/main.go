package main

import (
	"context"
	"encoding/json"
	"log"
	"math"
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

type UEBAAlert struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	UserID      string    `json:"user_id"`
	AssetID     string    `json:"asset_id"`
	Score       float64   `json:"score"`
	Reason      string    `json:"reason"`
	Timestamp   time.Time `json:"timestamp"`
	Event       Event     `json:"event"`
	Baseline    map[string]interface{} `json:"baseline"`
	Anomalies   []string  `json:"anomalies"`
}

type UserBaseline struct {
	UserID           string    `json:"user_id"`
	LoginTimes       []int     `json:"login_times"`        // Hour of day
	CommonProcesses  []string  `json:"common_processes"`
	CommonIPs        []string  `json:"common_ips"`
	CommonDestinations []string `json:"common_destinations"`
	LastUpdated      time.Time `json:"last_updated"`
	EventCount       int       `json:"event_count"`
}

func main() {
	kbrokers := os.Getenv("KAFKA_BROKERS")
	if kbrokers == "" { kbrokers = "localhost:9092" }
	topic := os.Getenv("KAFKA_TOPIC")
	if topic == "" { topic = "musafir.events" }
	group := os.Getenv("KAFKA_GROUP")
	if group == "" { group = "ueba" }

	chDsn := os.Getenv("CLICKHOUSE_DSN")
	if chDsn == "" { chDsn = "tcp://localhost:9000?database=default" }

	ctx := context.Background()
	conn, err := ch.Open(&ch.Options{Addr: []string{"localhost:9000"}})
	if err != nil { log.Fatalf("clickhouse connect: %v", err) }
	defer conn.Close()

	// Ensure UEBA tables exist
	createUEBATables(conn, ctx)

	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:  strings.Split(kbrokers, ","),
		Topic:    topic,
		GroupID:  group,
		MinBytes: 1, MaxBytes: 10e6,
	})
	defer reader.Close()

	writer := kafka.NewWriter(kafka.WriterConfig{
		Brokers: strings.Split(kbrokers, ","),
		Topic:   "musafir.ueba_alerts",
	})

	// User baselines cache
	baselines := make(map[string]*UserBaseline)

	log.Printf("UEBA consuming topic=%s brokers=%s", topic, kbrokers)
	for {
		m, err := reader.ReadMessage(ctx)
		if err != nil { log.Fatalf("kafka read: %v", err) }

		var event Event
		if err := json.Unmarshal(m.Value, &event); err != nil {
			log.Printf("unmarshal event: %v", err)
			continue
		}

		// Update baseline
		updateBaseline(baselines, event)

		// Check for anomalies
		if alert := checkAnomalies(baselines, event); alert != nil {
			alertData, _ := json.Marshal(alert)
			if err := writer.WriteMessages(ctx, kafka.Message{Value: alertData}); err != nil {
				log.Printf("write UEBA alert: %v", err)
			} else {
				log.Printf("UEBA ALERT: %s - %s (score: %.2f)", alert.Type, alert.Reason, alert.Score)
			}
		}
	}
}

func createUEBATables(conn ch.Conn, ctx context.Context) {
	// User baselines table
	ddl := `CREATE TABLE IF NOT EXISTS musafir_user_baselines (
  user_id String,
  login_times Array(Int8),
  common_processes Array(String),
  common_ips Array(String),
  common_destinations Array(String),
  last_updated DateTime,
  event_count UInt32
) ENGINE = MergeTree ORDER BY user_id`
	
	if err := conn.Exec(ctx, ddl); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}

	// UEBA alerts table
	ddl2 := `CREATE TABLE IF NOT EXISTS musafir_ueba_alerts (
  id String,
  type String,
  user_id String,
  asset_id String,
  score Float64,
  reason String,
  timestamp DateTime,
  event String,
  baseline String,
  anomalies Array(String)
) ENGINE = MergeTree ORDER BY timestamp`
	
	if err := conn.Exec(ctx, ddl2); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}
}

func updateBaseline(baselines map[string]*UserBaseline, event Event) {
	userID := event.User["id"]
	if userID == "" { return }

	baseline, exists := baselines[userID]
	if !exists {
		baseline = &UserBaseline{
			UserID:            userID,
			LoginTimes:        []int{},
			CommonProcesses:   []string{},
			CommonIPs:         []string{},
			CommonDestinations: []string{},
			LastUpdated:       time.Now(),
			EventCount:        0,
		}
		baselines[userID] = baseline
	}

	// Update login time if auth event
	if event.Event["class"] == "auth" {
		now := time.Now()
		baseline.LoginTimes = append(baseline.LoginTimes, now.Hour())
		// Keep only last 100 login times
		if len(baseline.LoginTimes) > 100 {
			baseline.LoginTimes = baseline.LoginTimes[len(baseline.LoginTimes)-100:]
		}
	}

	// Update common processes
	if attrs, ok := event.Event["attrs"].(map[string]interface{}); ok {
		if image, ok := attrs["image"].(string); ok {
			baseline.CommonProcesses = append(baseline.CommonProcesses, image)
		}
	}

	// Update common IPs
	if ip, ok := event.Asset["ip"]; ok {
		baseline.CommonIPs = append(baseline.CommonIPs, ip)
	}

	baseline.EventCount++
	baseline.LastUpdated = time.Now()
}

func checkAnomalies(baselines map[string]*UserBaseline, event Event) *UEBAAlert {
	userID := event.User["id"]
	if userID == "" { return nil }

	baseline, exists := baselines[userID]
	if !exists || baseline.EventCount < 10 { return nil } // Need minimum data

	var anomalies []string
	var score float64

	// Check login time anomaly
	if event.Event["class"] == "auth" {
		now := time.Now()
		if isAnomalousLoginTime(baseline.LoginTimes, now.Hour()) {
			anomalies = append(anomalies, "unusual_login_time")
			score += 0.3
		}
	}

	// Check process anomaly
	if attrs, ok := event.Event["attrs"].(map[string]interface{}); ok {
		if image, ok := attrs["image"].(string); ok {
			if isAnomalousProcess(baseline.CommonProcesses, image) {
				anomalies = append(anomalies, "unusual_process")
				score += 0.4
			}
		}
	}

	// Check IP anomaly
	if ip, ok := event.Asset["ip"]; ok {
		if isAnomalousIP(baseline.CommonIPs, ip) {
			anomalies = append(anomalies, "unusual_ip")
			score += 0.3
		}
	}

	// Check for rapid event generation
	if baseline.EventCount > 0 {
		timeSinceLastUpdate := time.Since(baseline.LastUpdated)
		if timeSinceLastUpdate < time.Minute && baseline.EventCount > 50 {
			anomalies = append(anomalies, "rapid_event_generation")
			score += 0.2
		}
	}

	if len(anomalies) > 0 && score > 0.5 {
		return &UEBAAlert{
			ID:        generateAlertID(),
			Type:      "ueba_anomaly",
			UserID:    userID,
			AssetID:   event.Asset["id"],
			Score:     score,
			Reason:    strings.Join(anomalies, ", "),
			Timestamp: time.Now(),
			Event:     event,
			Baseline: map[string]interface{}{
				"login_times":        baseline.LoginTimes,
				"common_processes":   baseline.CommonProcesses,
				"common_ips":         baseline.CommonIPs,
				"event_count":        baseline.EventCount,
			},
			Anomalies: anomalies,
		}
	}

	return nil
}

func isAnomalousLoginTime(loginTimes []int, currentHour int) bool {
	if len(loginTimes) < 5 { return false }
	
	// Calculate mean and std dev
	var sum int
	for _, hour := range loginTimes {
		sum += hour
	}
	mean := float64(sum) / float64(len(loginTimes))
	
	var variance float64
	for _, hour := range loginTimes {
		variance += math.Pow(float64(hour) - mean, 2)
	}
	stdDev := math.Sqrt(variance / float64(len(loginTimes)))
	
	// Anomalous if more than 2 standard deviations from mean
	return math.Abs(float64(currentHour) - mean) > 2*stdDev
}

func isAnomalousProcess(commonProcesses []string, currentProcess string) bool {
	if len(commonProcesses) < 5 { return false }
	
	// Count occurrences
	count := 0
	for _, proc := range commonProcesses {
		if proc == currentProcess {
			count++
		}
	}
	
	// Anomalous if process appears in less than 5% of events
	return float64(count)/float64(len(commonProcesses)) < 0.05
}

func isAnomalousIP(commonIPs []string, currentIP string) bool {
	if len(commonIPs) < 5 { return false }
	
	// Count occurrences
	count := 0
	for _, ip := range commonIPs {
		if ip == currentIP {
			count++
		}
	}
	
	// Anomalous if IP appears in less than 10% of events
	return float64(count)/float64(len(commonIPs)) < 0.1
}

func generateAlertID() string {
	return "ueba-" + time.Now().Format("20060102150405")
}

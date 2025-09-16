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

type Alert struct {
	ID        string    `json:"id"`
	RuleID    string    `json:"rule_id"`
	Title     string    `json:"title"`
	Level     string    `json:"level"`
	Timestamp time.Time `json:"timestamp"`
	Event     Event     `json:"event"`
	Message   string    `json:"message"`
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

type CorrelatedAlert struct {
	ID            string    `json:"id"`
	Type          string    `json:"type"`
	Title         string    `json:"title"`
	Severity      string    `json:"severity"`
	Score         float64   `json:"score"`
	Timestamp     time.Time `json:"timestamp"`
	AssetID       string    `json:"asset_id"`
	UserID        string    `json:"user_id"`
	Description   string    `json:"description"`
	SourceAlerts  []string  `json:"source_alerts"`
	AttackChain   []string  `json:"attack_chain"`
	Recommendations []string `json:"recommendations"`
}

func main() {
	kbrokers := os.Getenv("KAFKA_BROKERS")
	if kbrokers == "" { kbrokers = "localhost:9092" }
	group := os.Getenv("KAFKA_GROUP")
	if group == "" { group = "correlate" }

	chDsn := os.Getenv("CLICKHOUSE_DSN")
	if chDsn == "" { chDsn = "tcp://localhost:9000?database=default" }

	ctx := context.Background()
	conn, err := ch.Open(&ch.Options{Addr: []string{"localhost:9000"}})
	if err != nil { log.Fatalf("clickhouse connect: %v", err) }
	defer conn.Close()

	// Ensure correlation tables exist
	createCorrelationTables(conn, ctx)

	// Create readers for different alert types
	sigmaReader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:  strings.Split(kbrokers, ","),
		Topic:    "musafir.alerts",
		GroupID:  group + "_sigma",
		MinBytes: 1, MaxBytes: 10e6,
	})
	defer sigmaReader.Close()

	uebaReader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:  strings.Split(kbrokers, ","),
		Topic:    "musafir.ueba_alerts",
		GroupID:  group + "_ueba",
		MinBytes: 1, MaxBytes: 10e6,
	})
	defer uebaReader.Close()

	tiReader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:  strings.Split(kbrokers, ","),
		Topic:    "musafir.ti_alerts",
		GroupID:  group + "_ti",
		MinBytes: 1, MaxBytes: 10e6,
	})
	defer tiReader.Close()

	writer := kafka.NewWriter(kafka.WriterConfig{
		Brokers: strings.Split(kbrokers, ","),
		Topic:   "musafir.correlated_alerts",
	})

	// Alert correlation cache
	alertCache := make(map[string]interface{})
	correlationWindow := 5 * time.Minute

	log.Printf("correlate consuming alerts brokers=%s", kbrokers)

	// Process alerts from all sources
	go processAlerts(sigmaReader, "sigma", alertCache, writer, correlationWindow)
	go processAlerts(uebaReader, "ueba", alertCache, writer, correlationWindow)
	go processAlerts(tiReader, "ti", alertCache, writer, correlationWindow)

	// Keep main thread alive
	select {}
}

func processAlerts(reader *kafka.Reader, source string, alertCache map[string]interface{}, writer *kafka.Writer, window time.Duration) {
	for {
		m, err := reader.ReadMessage(context.Background())
		if err != nil { log.Printf("kafka read %s: %v", source, err); continue }

		var alert interface{}
		switch source {
		case "sigma":
			var sigmaAlert Alert
			if err := json.Unmarshal(m.Value, &sigmaAlert); err != nil {
				log.Printf("unmarshal sigma alert: %v", err)
				continue
			}
			alert = sigmaAlert
		case "ueba":
			var uebaAlert UEBAAlert
			if err := json.Unmarshal(m.Value, &uebaAlert); err != nil {
				log.Printf("unmarshal ueba alert: %v", err)
				continue
			}
			alert = uebaAlert
		case "ti":
			var tiAlert ThreatIntelAlert
			if err := json.Unmarshal(m.Value, &tiAlert); err != nil {
				log.Printf("unmarshal ti alert: %v", err)
				continue
			}
			alert = tiAlert
		}

		// Store in cache
		alertID := getAlertID(alert)
		alertCache[alertID] = alert

		// Clean old alerts
		cleanOldAlerts(alertCache, window)

		// Check for correlations
		if correlatedAlert := checkCorrelations(alertCache, alert); correlatedAlert != nil {
			alertData, _ := json.Marshal(correlatedAlert)
			if err := writer.WriteMessages(context.Background(), kafka.Message{Value: alertData}); err != nil {
				log.Printf("write correlated alert: %v", err)
			} else {
				log.Printf("CORRELATED ALERT: %s - %s (score: %.2f)", correlatedAlert.Type, correlatedAlert.Title, correlatedAlert.Score)
			}
		}
	}
}

func createCorrelationTables(conn ch.Conn, ctx context.Context) {
	// Correlated alerts table
	ddl := `CREATE TABLE IF NOT EXISTS musafir_correlated_alerts (
  id String,
  type String,
  title String,
  severity String,
  score Float64,
  timestamp DateTime,
  asset_id String,
  user_id String,
  description String,
  source_alerts Array(String),
  attack_chain Array(String),
  recommendations Array(String)
) ENGINE = MergeTree ORDER BY timestamp`
	
	if err := conn.Exec(ctx, ddl); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}
}

func getAlertID(alert interface{}) string {
	switch a := alert.(type) {
	case Alert:
		return a.ID
	case UEBAAlert:
		return a.ID
	case ThreatIntelAlert:
		return a.ID
	}
	return ""
}

func cleanOldAlerts(alertCache map[string]interface{}, window time.Duration) {
	cutoff := time.Now().Add(-window)
	for id, alert := range alertCache {
		var timestamp time.Time
		switch a := alert.(type) {
		case Alert:
			timestamp = a.Timestamp
		case UEBAAlert:
			timestamp = a.Timestamp
		case ThreatIntelAlert:
			timestamp = a.Timestamp
		}
		if timestamp.Before(cutoff) {
			delete(alertCache, id)
		}
	}
}

func checkCorrelations(alertCache map[string]interface{}, newAlert interface{}) *CorrelatedAlert {
	// Look for attack patterns
	var correlations []string
	var score float64
	var attackChain []string

	// Check for ransomware pattern: high entropy + unusual process + TI match
	if isRansomwarePattern(alertCache, newAlert) {
		correlations = append(correlations, "ransomware_attack")
		score += 0.9
		attackChain = []string{"initial_access", "execution", "impact"}
	}

	// Check for credential theft: auth anomaly + unusual process
	if isCredentialTheftPattern(alertCache, newAlert) {
		correlations = append(correlations, "credential_theft")
		score += 0.8
		attackChain = []string{"initial_access", "credential_access", "lateral_movement"}
	}

	// Check for lateral movement: multiple assets + unusual processes
	if isLateralMovementPattern(alertCache, newAlert) {
		correlations = append(correlations, "lateral_movement")
		score += 0.7
		attackChain = []string{"credential_access", "lateral_movement", "discovery"}
	}

	if len(correlations) > 0 && score > 0.6 {
		return &CorrelatedAlert{
			ID:            generateAlertID(),
			Type:          "correlated_attack",
			Title:         strings.Join(correlations, " + "),
			Severity:      getSeverityFromScore(score),
			Score:         score,
			Timestamp:     time.Now(),
			AssetID:       getAssetID(newAlert),
			UserID:        getUserID(newAlert),
			Description:   "Correlated attack pattern detected",
			SourceAlerts:  getSourceAlerts(alertCache),
			AttackChain:   attackChain,
			Recommendations: getRecommendations(correlations),
		}
	}

	return nil
}

func isRansomwarePattern(alertCache map[string]interface{}, newAlert interface{}) bool {
	hasHighEntropy := false
	hasUnusualProcess := false
	hasTIMatch := false

	for _, alert := range alertCache {
		switch a := alert.(type) {
		case Alert:
			if strings.Contains(strings.ToLower(a.Title), "entropy") {
				hasHighEntropy = true
			}
		case UEBAAlert:
			if strings.Contains(a.Reason, "unusual_process") {
				hasUnusualProcess = true
			}
		case ThreatIntelAlert:
			if a.Type == "threat_intel" {
				hasTIMatch = true
			}
		}
	}

	return hasHighEntropy && hasUnusualProcess && hasTIMatch
}

func isCredentialTheftPattern(alertCache map[string]interface{}, newAlert interface{}) bool {
	hasAuthAnomaly := false
	hasUnusualProcess := false

	for _, alert := range alertCache {
		switch a := alert.(type) {
		case UEBAAlert:
			if strings.Contains(a.Reason, "unusual_login_time") {
				hasAuthAnomaly = true
			}
			if strings.Contains(a.Reason, "unusual_process") {
				hasUnusualProcess = true
			}
		}
	}

	return hasAuthAnomaly && hasUnusualProcess
}

func isLateralMovementPattern(alertCache map[string]interface{}, newAlert interface{}) bool {
	assetCount := make(map[string]int)
	processCount := 0

	for _, alert := range alertCache {
		switch a := alert.(type) {
		case Alert:
			if assetID := getAssetID(a); assetID != "" {
				assetCount[assetID]++
			}
		case UEBAAlert:
			if strings.Contains(a.Reason, "unusual_process") {
				processCount++
			}
		}
	}

	return len(assetCount) > 1 && processCount > 2
}

func getAssetID(alert interface{}) string {
	switch a := alert.(type) {
	case Alert:
		return a.Event.Asset["id"]
	case UEBAAlert:
		return a.AssetID
	case ThreatIntelAlert:
		return a.Event.Asset["id"]
	}
	return ""
}

func getUserID(alert interface{}) string {
	switch a := alert.(type) {
	case Alert:
		return a.Event.User["id"]
	case UEBAAlert:
		return a.UserID
	case ThreatIntelAlert:
		return a.Event.User["id"]
	}
	return ""
}

func getSeverityFromScore(score float64) string {
	if score >= 0.9 { return "critical" }
	if score >= 0.7 { return "high" }
	if score >= 0.5 { return "medium" }
	return "low"
}

func getSourceAlerts(alertCache map[string]interface{}) []string {
	var sources []string
	for id := range alertCache {
		sources = append(sources, id)
	}
	return sources
}

func getRecommendations(correlations []string) []string {
	var recommendations []string
	for _, correlation := range correlations {
		switch correlation {
		case "ransomware_attack":
			recommendations = append(recommendations, "Isolate affected systems immediately")
			recommendations = append(recommendations, "Check backup integrity")
			recommendations = append(recommendations, "Notify incident response team")
		case "credential_theft":
			recommendations = append(recommendations, "Reset compromised credentials")
			recommendations = append(recommendations, "Review authentication logs")
			recommendations = append(recommendations, "Enable MFA if not already")
		case "lateral_movement":
			recommendations = append(recommendations, "Isolate affected network segments")
			recommendations = append(recommendations, "Review network access controls")
			recommendations = append(recommendations, "Check for additional compromised accounts")
		}
	}
	return recommendations
}

func generateAlertID() string {
	return "corr-" + time.Now().Format("20060102150405")
}

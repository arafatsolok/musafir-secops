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

type AIInsight struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	Type        string                 `json:"type"` // threat_prediction, behavior_analysis, risk_assessment, attack_simulation
	Confidence  float64                `json:"confidence"`
	Severity    string                 `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Recommendations []string           `json:"recommendations"`
	Entities    []AIEntity             `json:"entities"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type AIEntity struct {
	ID       string  `json:"id"`
	Type     string  `json:"type"` // user, device, network, process, file
	Name     string  `json:"name"`
	Risk     float64 `json:"risk_score"`
	Behavior string  `json:"behavior_pattern"`
	Anomaly  bool    `json:"is_anomaly"`
}

type ThreatPrediction struct {
	ID              string    `json:"id"`
	Timestamp       time.Time `json:"timestamp"`
	ThreatType      string    `json:"threat_type"`
	Probability     float64   `json:"probability"`
	TimeToImpact    int       `json:"time_to_impact_hours"`
	AffectedAssets  []string  `json:"affected_assets"`
	AttackVector    string    `json:"attack_vector"`
	MitigationSteps []string  `json:"mitigation_steps"`
}

type BehaviorAnalysis struct {
	ID           string    `json:"id"`
	Timestamp    time.Time `json:"timestamp"`
	EntityID     string    `json:"entity_id"`
	EntityType   string    `json:"entity_type"`
	Behavior     string    `json:"behavior"`
	AnomalyScore float64   `json:"anomaly_score"`
	Baseline     string    `json:"baseline_behavior"`
	Deviation    string    `json:"deviation_reason"`
}

func main() {
	kbrokers := os.Getenv("KAFKA_BROKERS")
	if kbrokers == "" { kbrokers = "localhost:9092" }
	group := os.Getenv("KAFKA_GROUP")
	if group == "" { group = "ai" }

	chDsn := os.Getenv("CLICKHOUSE_DSN")
	if chDsn == "" { chDsn = "tcp://localhost:9000?database=default" }

	ctx := context.Background()
	conn, err := ch.Open(&ch.Options{Addr: []string{"localhost:9000"}})
	if err != nil { log.Fatalf("clickhouse connect: %v", err) }
	defer conn.Close()

	// Ensure AI tables exist
	createAITables(conn, ctx)

	writer := kafka.NewWriter(kafka.WriterConfig{
		Brokers: strings.Split(kbrokers, ","),
		Topic:   "musafir.ai_insights",
	})

	log.Printf("AI service starting brokers=%s", kbrokers)

	// Simulate AI analysis
	go simulateAIAnalysis(writer, ctx)

	// Keep running
	select {}
}

func createAITables(conn ch.Conn, ctx context.Context) {
	// AI insights table
	ddl := `CREATE TABLE IF NOT EXISTS musafir_ai_insights (
  id String,
  timestamp DateTime,
  type String,
  confidence Float64,
  severity String,
  title String,
  description String,
  recommendations Array(String),
  entities String,
  metadata String
) ENGINE = MergeTree ORDER BY timestamp`
	
	if err := conn.Exec(ctx, ddl); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}

	// Threat predictions table
	ddl2 := `CREATE TABLE IF NOT EXISTS musafir_threat_predictions (
  id String,
  timestamp DateTime,
  threat_type String,
  probability Float64,
  time_to_impact_hours Int32,
  affected_assets Array(String),
  attack_vector String,
  mitigation_steps Array(String)
) ENGINE = MergeTree ORDER BY timestamp`
	
	if err := conn.Exec(ctx, ddl2); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}

	// Behavior analysis table
	ddl3 := `CREATE TABLE IF NOT EXISTS musafir_behavior_analysis (
  id String,
  timestamp DateTime,
  entity_id String,
  entity_type String,
  behavior String,
  anomaly_score Float64,
  baseline_behavior String,
  deviation_reason String
) ENGINE = MergeTree ORDER BY timestamp`
	
	if err := conn.Exec(ctx, ddl3); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}
}

func simulateAIAnalysis(writer *kafka.Writer, ctx context.Context) {
	ticker := time.NewTicker(45 * time.Second)
	defer ticker.Stop()

	insightTypes := []string{"threat_prediction", "behavior_analysis", "risk_assessment", "attack_simulation"}
	threatTypes := []string{"ransomware", "apt", "insider_threat", "ddos", "phishing", "malware"}
	behaviors := []string{"unusual_login", "data_exfiltration", "privilege_escalation", "lateral_movement", "persistence"}

	for {
		select {
		case <-ticker.C:
			// Generate AI insights
			for i := 0; i < 3; i++ {
				insightType := insightTypes[time.Now().Second()%len(insightTypes)]
				
				var insight AIInsight
				switch insightType {
				case "threat_prediction":
					insight = generateThreatPrediction(threatTypes)
				case "behavior_analysis":
					insight = generateBehaviorAnalysis(behaviors)
				case "risk_assessment":
					insight = generateRiskAssessment()
				case "attack_simulation":
					insight = generateAttackSimulation()
				}

				sendAIInsight(insight, writer, ctx)
			}
		}
	}
}

func generateThreatPrediction(threatTypes []string) AIInsight {
	threatType := threatTypes[time.Now().Second()%len(threatTypes)]
	
	return AIInsight{
		ID:          generateAIInsightID(),
		Timestamp:   time.Now(),
		Type:        "threat_prediction",
		Confidence:  0.85 + float64(time.Now().Second()%15)/100.0,
		Severity:    getSeverity(0.85),
		Title:       "AI Threat Prediction: " + strings.Title(threatType),
		Description: "Advanced AI analysis predicts potential " + threatType + " attack within 24-48 hours based on current network patterns and threat intelligence.",
		Recommendations: []string{
			"Increase monitoring on high-value assets",
			"Review and update security policies",
			"Conduct security awareness training",
			"Implement additional network segmentation",
		},
		Entities: []AIEntity{
			{ID: "user-123", Type: "user", Name: "john.doe", Risk: 0.75, Behavior: "unusual_access_patterns", Anomaly: true},
			{ID: "device-456", Type: "device", Name: "workstation-01", Risk: 0.60, Behavior: "network_anomalies", Anomaly: true},
		},
		Metadata: map[string]interface{}{
			"model_version": "v2.1.0",
			"data_sources":  []string{"network_logs", "user_behavior", "threat_intel"},
			"accuracy":      0.92,
		},
	}
}

func generateBehaviorAnalysis(behaviors []string) AIInsight {
	behavior := behaviors[time.Now().Second()%len(behaviors)]
	
	return AIInsight{
		ID:          generateAIInsightID(),
		Timestamp:   time.Now(),
		Type:        "behavior_analysis",
		Confidence:  0.90 + float64(time.Now().Second()%10)/100.0,
		Severity:    getSeverity(0.90),
		Title:       "Behavioral Anomaly Detected: " + strings.Title(behavior),
		Description: "AI detected unusual behavioral patterns that deviate significantly from established baselines. This may indicate potential security threats or policy violations.",
		Recommendations: []string{
			"Investigate user activities immediately",
			"Review access permissions",
			"Consider additional authentication",
			"Monitor for data exfiltration",
		},
		Entities: []AIEntity{
			{ID: "user-789", Type: "user", Name: "jane.smith", Risk: 0.80, Behavior: behavior, Anomaly: true},
		},
		Metadata: map[string]interface{}{
			"baseline_period": "30_days",
			"deviation_score": 0.85,
			"confidence":      0.92,
		},
	}
}

func generateRiskAssessment() AIInsight {
	return AIInsight{
		ID:          generateAIInsightID(),
		Timestamp:   time.Now(),
		Type:        "risk_assessment",
		Confidence:  0.88,
		Severity:    "high",
		Title:       "AI Risk Assessment: Critical Vulnerabilities Detected",
		Description: "Comprehensive AI analysis identified multiple high-risk vulnerabilities and misconfigurations that could lead to security breaches.",
		Recommendations: []string{
			"Patch critical vulnerabilities immediately",
			"Review and harden system configurations",
			"Implement additional security controls",
			"Conduct penetration testing",
		},
		Entities: []AIEntity{
			{ID: "system-001", Type: "system", Name: "web-server-01", Risk: 0.95, Behavior: "vulnerable_services", Anomaly: true},
			{ID: "network-002", Type: "network", Name: "dmz-segment", Risk: 0.70, Behavior: "open_ports", Anomaly: true},
		},
		Metadata: map[string]interface{}{
			"vulnerability_count": 15,
			"critical_count":      3,
			"assessment_date":     time.Now().Format("2006-01-02"),
		},
	}
}

func generateAttackSimulation() AIInsight {
	return AIInsight{
		ID:          generateAIInsightID(),
		Timestamp:   time.Now(),
		Type:        "attack_simulation",
		Confidence:  0.82,
		Severity:    "medium",
		Title:       "AI Attack Simulation: Ransomware Scenario",
		Description: "AI-powered attack simulation shows how ransomware could spread through the network based on current security posture and attack patterns.",
		Recommendations: []string{
			"Implement network segmentation",
			"Deploy endpoint detection and response",
			"Create incident response playbooks",
			"Conduct regular security training",
		},
		Entities: []AIEntity{
			{ID: "sim-001", Type: "simulation", Name: "ransomware-sim", Risk: 0.85, Behavior: "lateral_movement", Anomaly: false},
		},
		Metadata: map[string]interface{}{
			"simulation_type": "ransomware",
			"affected_assets": 25,
			"time_to_compromise": "2_hours",
		},
	}
}

func sendAIInsight(insight AIInsight, writer *kafka.Writer, ctx context.Context) {
	insightData, _ := json.Marshal(insight)
	if err := writer.WriteMessages(ctx, kafka.Message{Value: insightData}); err != nil {
		log.Printf("write AI insight: %v", err)
	} else {
		log.Printf("AI INSIGHT: %s - %s (confidence: %.2f)", insight.Type, insight.Title, insight.Confidence)
	}
}

func generateAIInsightID() string {
	return "ai-" + time.Now().Format("20060102150405")
}

func getSeverity(confidence float64) string {
	if confidence >= 0.9 {
		return "critical"
	} else if confidence >= 0.8 {
		return "high"
	} else if confidence >= 0.6 {
		return "medium"
	}
	return "low"
}

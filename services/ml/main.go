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
	"github.com/sjwhitworth/golearn/base"
	"github.com/sjwhitworth/golearn/evaluation"
	"github.com/sjwhitworth/golearn/knn"
)

type Event struct {
	Ts       string                 `json:"ts"`
	TenantID string                 `json:"tenant_id"`
	Asset    map[string]string      `json:"asset"`
	User     map[string]string      `json:"user"`
	Event    map[string]interface{} `json:"event"`
	Ingest   map[string]string      `json:"ingest"`
}

type MLFeature struct {
	EventID     string    `json:"event_id"`
	Timestamp   time.Time `json:"timestamp"`
	UserID      string    `json:"user_id"`
	AssetID     string    `json:"asset_id"`
	EventType   string    `json:"event_type"`
	ProcessName string    `json:"process_name"`
	Command     string    `json:"command"`
	IPAddress   string    `json:"ip_address"`
	Port        int       `json:"port"`
	FileSize    int64     `json:"file_size"`
	Entropy     float64   `json:"entropy"`
	HourOfDay   int       `json:"hour_of_day"`
	DayOfWeek   int       `json:"day_of_week"`
	IsWeekend   bool      `json:"is_weekend"`
	RiskScore   float64   `json:"risk_score"`
}

type MLPrediction struct {
	EventID       string    `json:"event_id"`
	Prediction    string    `json:"prediction"` // normal, suspicious, malicious
	Confidence    float64   `json:"confidence"`
	Features      MLFeature `json:"features"`
	AnomalyScore  float64   `json:"anomaly_score"`
	Timestamp     time.Time `json:"timestamp"`
	ModelVersion  string    `json:"model_version"`
}

type MLModel struct {
	Version     string    `json:"version"`
	Type        string    `json:"type"`
	Accuracy    float64   `json:"accuracy"`
	LastTrained time.Time `json:"last_trained"`
	Features    []string  `json:"features"`
}

func main() {
	kbrokers := os.Getenv("KAFKA_BROKERS")
	if kbrokers == "" { kbrokers = "localhost:9092" }
	topic := os.Getenv("KAFKA_TOPIC")
	if topic == "" { topic = "musafir.events" }
	group := os.Getenv("KAFKA_GROUP")
	if group == "" { group = "ml" }

	chDsn := os.Getenv("CLICKHOUSE_DSN")
	if chDsn == "" { chDsn = "tcp://localhost:9000?database=default" }

	ctx := context.Background()
	conn, err := ch.Open(&ch.Options{Addr: []string{"localhost:9000"}})
	if err != nil { log.Fatalf("clickhouse connect: %v", err) }
	defer conn.Close()

	// Ensure ML tables exist
	createMLTables(conn, ctx)

	// Load or train ML model
	model := loadOrTrainModel(conn, ctx)

	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:  strings.Split(kbrokers, ","),
		Topic:    topic,
		GroupID:  group,
		MinBytes: 1, MaxBytes: 10e6,
	})
	defer reader.Close()

	writer := kafka.NewWriter(kafka.WriterConfig{
		Brokers: strings.Split(kbrokers, ","),
		Topic:   "musafir.ml_predictions",
	})

	log.Printf("ML service consuming topic=%s brokers=%s", topic, kbrokers)
	for {
		m, err := reader.ReadMessage(ctx)
		if err != nil { log.Fatalf("kafka read: %v", err) }

		var event Event
		if err := json.Unmarshal(m.Value, &event); err != nil {
			log.Printf("unmarshal event: %v", err)
			continue
		}

		// Extract features
		features := extractFeatures(event)

		// Make prediction
		prediction := makePrediction(model, features)

		// Send prediction
		predData, _ := json.Marshal(prediction)
		if err := writer.WriteMessages(ctx, kafka.Message{Value: predData}); err != nil {
			log.Printf("write ML prediction: %v", err)
		} else {
			log.Printf("ML PREDICTION: %s - %s (confidence: %.2f)", features.EventID, prediction.Prediction, prediction.Confidence)
		}
	}
}

func createMLTables(conn ch.Conn, ctx context.Context) {
	// ML features table
	ddl := `CREATE TABLE IF NOT EXISTS musafir_ml_features (
  event_id String,
  timestamp DateTime,
  user_id String,
  asset_id String,
  event_type String,
  process_name String,
  command String,
  ip_address String,
  port Int32,
  file_size Int64,
  entropy Float64,
  hour_of_day Int8,
  day_of_week Int8,
  is_weekend UInt8,
  risk_score Float64,
  created_at DateTime DEFAULT now()
) ENGINE = MergeTree ORDER BY timestamp`
	
	if err := conn.Exec(ctx, ddl); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}

	// ML predictions table
	ddl2 := `CREATE TABLE IF NOT EXISTS musafir_ml_predictions (
  event_id String,
  prediction String,
  confidence Float64,
  features String,
  anomaly_score Float64,
  timestamp DateTime,
  model_version String
) ENGINE = MergeTree ORDER BY timestamp`
	
	if err := conn.Exec(ctx, ddl2); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}

	// ML models table
	ddl3 := `CREATE TABLE IF NOT EXISTS musafir_ml_models (
  version String,
  type String,
  accuracy Float64,
  last_trained DateTime,
  features Array(String),
  model_data String,
  created_at DateTime DEFAULT now()
) ENGINE = MergeTree ORDER BY version`
	
	if err := conn.Exec(ctx, ddl3); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}
}

func loadOrTrainModel(conn ch.Conn, ctx context.Context) *MLModel {
	// Check if model exists
	var model MLModel
	model.Version = "1.0.0"
	model.Type = "anomaly_detection"
	model.LastTrained = time.Now()
	model.Features = []string{"entropy", "hour_of_day", "file_size", "process_name"}

	// In production, load from database or file
	// For now, return a simple model
	return &model
}

func extractFeatures(event Event) MLFeature {
	// Extract basic features from event
	features := MLFeature{
		EventID:   generateEventID(),
		Timestamp: time.Now(),
		UserID:    event.User["id"],
		AssetID:   event.Asset["id"],
		EventType: event.Event["class"].(string),
	}

	// Extract process information
	if attrs, ok := event.Event["attrs"].(map[string]interface{}); ok {
		if image, ok := attrs["image"].(string); ok {
			features.ProcessName = image
		}
		if cmd, ok := attrs["cmd"].(string); ok {
			features.Command = cmd
		}
		if entropy, ok := attrs["entropy"].(float64); ok {
			features.Entropy = entropy
		}
		if size, ok := attrs["size"].(int64); ok {
			features.FileSize = size
		}
	}

	// Extract network information
	features.IPAddress = event.Asset["ip"]

	// Extract temporal features
	now := time.Now()
	features.HourOfDay = now.Hour()
	features.DayOfWeek = int(now.Weekday())
	features.IsWeekend = now.Weekday() == time.Saturday || now.Weekday() == time.Sunday

	// Calculate risk score
	features.RiskScore = calculateRiskScore(features)

	return features
}

func calculateRiskScore(features MLFeature) float64 {
	score := 0.0

	// High entropy indicates potential encryption/obfuscation
	if features.Entropy > 7.0 {
		score += 0.3
	}

	// Unusual hours (late night/early morning)
	if features.HourOfDay < 6 || features.HourOfDay > 22 {
		score += 0.2
	}

	// Weekend activity
	if features.IsWeekend {
		score += 0.1
	}

	// Suspicious process names
	suspiciousProcesses := []string{"wscript", "powershell", "cmd", "rundll32", "regsvr32"}
	for _, proc := range suspiciousProcesses {
		if strings.Contains(strings.ToLower(features.ProcessName), proc) {
			score += 0.2
		}
	}

	// Large file operations
	if features.FileSize > 100*1024*1024 { // 100MB
		score += 0.1
	}

	return math.Min(score, 1.0)
}

func makePrediction(model *MLModel, features MLFeature) MLPrediction {
	// Simple rule-based prediction (in production, use trained ML model)
	prediction := "normal"
	confidence := 0.5
	anomalyScore := 0.0

	// Anomaly detection based on features
	if features.RiskScore > 0.7 {
		prediction = "malicious"
		confidence = 0.9
		anomalyScore = features.RiskScore
	} else if features.RiskScore > 0.4 {
		prediction = "suspicious"
		confidence = 0.7
		anomalyScore = features.RiskScore
	} else {
		anomalyScore = features.RiskScore
	}

	// Additional ML-based features
	if features.Entropy > 7.5 && features.HourOfDay < 6 {
		prediction = "suspicious"
		confidence = 0.8
		anomalyScore = math.Max(anomalyScore, 0.8)
	}

	return MLPrediction{
		EventID:      features.EventID,
		Prediction:   prediction,
		Confidence:   confidence,
		Features:     features,
		AnomalyScore: anomalyScore,
		Timestamp:    time.Now(),
		ModelVersion: model.Version,
	}
}

func generateEventID() string {
	return "ml-" + time.Now().Format("20060102150405")
}

// Train model function (simplified)
func trainModel(conn ch.Conn, ctx context.Context) *MLModel {
	// In production, this would:
	// 1. Load historical data from ClickHouse
	// 2. Extract features
	// 3. Train ML model (Random Forest, Isolation Forest, etc.)
	// 4. Evaluate model performance
	// 5. Save model to database

	// For now, return a simple model
	return &MLModel{
		Version:     "1.0.0",
		Type:        "anomaly_detection",
		Accuracy:    0.85,
		LastTrained: time.Now(),
		Features:    []string{"entropy", "hour_of_day", "file_size", "process_name"},
	}
}

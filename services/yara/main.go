package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	ch "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/hillu/go-yara/v4"
	"github.com/segmentio/kafka-go"
)

type YARAScanRequest struct {
	ID          string            `json:"id"`
	FilePath    string            `json:"file_path"`
	FileHash    string            `json:"file_hash"`
	FileContent []byte            `json:"file_content,omitempty"`
	Rules       []string          `json:"rules"`
	Metadata    map[string]string `json:"metadata"`
}

type YARAScanResult struct {
	ID          string                 `json:"id"`
	FilePath    string                 `json:"file_path"`
	FileHash    string                 `json:"file_hash"`
	Matches     []YARAMatch            `json:"matches"`
	ScanTime    int64                  `json:"scan_time_ms"`
	Error       string                 `json:"error,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type YARAMatch struct {
	RuleName    string            `json:"rule_name"`
	Namespace   string            `json:"namespace"`
	Tags        []string          `json:"tags"`
	Meta        map[string]string `json:"meta"`
	Strings     []YARAString      `json:"strings"`
	Score       int               `json:"score"`
	Description string            `json:"description"`
}

type YARAString struct {
	Name   string `json:"name"`
	Offset int64  `json:"offset"`
	Data   string `json:"data"`
}

type YARAScanner struct {
	compiler *yara.Compiler
	rules    *yara.Rules
}

func main() {
	kbrokers := os.Getenv("KAFKA_BROKERS")
	if kbrokers == "" { kbrokers = "localhost:9092" }
	topic := os.Getenv("YARA_TOPIC")
	if topic == "" { topic = "musafir.yara_requests" }
	group := os.Getenv("KAFKA_GROUP")
	if group == "" { group = "yara" }

	chDsn := os.Getenv("CLICKHOUSE_DSN")
	if chDsn == "" { chDsn = "tcp://localhost:9000?database=default" }

	ctx := context.Background()
	conn, err := ch.Open(&ch.Options{Addr: []string{"localhost:9000"}})
	if err != nil { log.Fatalf("clickhouse connect: %v", err) }
	defer conn.Close()

	// Ensure YARA tables exist
	createYARATables(conn, ctx)

	// Initialize YARA scanner
	scanner, err := NewYARAScanner()
	if err != nil {
		log.Fatalf("failed to initialize YARA scanner: %v", err)
	}
	defer scanner.Close()

	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:  strings.Split(kbrokers, ","),
		Topic:    topic,
		GroupID:  group,
		MinBytes: 1, MaxBytes: 10e6,
	})
	defer reader.Close()

	writer := kafka.NewWriter(kafka.WriterConfig{
		Brokers: strings.Split(kbrokers, ","),
		Topic:   "musafir.yara_results",
	})

	log.Printf("YARA scanner consuming topic=%s brokers=%s", topic, kbrokers)
	for {
		m, err := reader.ReadMessage(ctx)
		if err != nil { log.Fatalf("kafka read: %v", err) }

		var request YARAScanRequest
		if err := json.Unmarshal(m.Value, &request); err != nil {
			log.Printf("unmarshal YARA request: %v", err)
			continue
		}

		// Scan file with YARA
		result := scanner.ScanFile(request)
		
		// Send result
		resultData, _ := json.Marshal(result)
		if err := writer.WriteMessages(ctx, kafka.Message{Value: resultData}); err != nil {
			log.Printf("write YARA result: %v", err)
		} else {
			log.Printf("YARA RESULT: %s - %d matches", request.ID, len(result.Matches))
		}
	}
}

func createYARATables(conn ch.Conn, ctx context.Context) {
	// YARA scan requests table
	ddl := `CREATE TABLE IF NOT EXISTS musafir_yara_requests (
  id String,
  file_path String,
  file_hash String,
  rules Array(String),
  metadata String,
  created_at DateTime DEFAULT now()
) ENGINE = MergeTree ORDER BY created_at`
	
	if err := conn.Exec(ctx, ddl); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}

	// YARA scan results table
	ddl2 := `CREATE TABLE IF NOT EXISTS musafir_yara_results (
  id String,
  file_path String,
  file_hash String,
  matches String,
  scan_time_ms Int64,
  error String,
  timestamp DateTime,
  metadata String
) ENGINE = MergeTree ORDER BY timestamp`
	
	if err := conn.Exec(ctx, ddl2); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}
}

func NewYARAScanner() (*YARAScanner, error) {
	// Create YARA compiler
	compiler, err := yara.NewCompiler()
	if err != nil {
		return nil, err
	}

	// Load default YARA rules
	rulesDir := "content/yara/rules"
	if err := loadYARARules(compiler, rulesDir); err != nil {
		log.Printf("warning: failed to load YARA rules from %s: %v", rulesDir, err)
	}

	// Compile rules
	yaraRules, err := compiler.GetRules()
	if err != nil {
		return nil, err
	}

	return &YARAScanner{
		compiler: compiler,
		rules:    yaraRules,
	}, nil
}

func (s *YARAScanner) Close() {
	if s.rules != nil {
		s.rules.Destroy()
	}
	if s.compiler != nil {
		s.compiler.Destroy()
	}
}

func (s *YARAScanner) ScanFile(request YARAScanRequest) YARAScanResult {
	startTime := time.Now()
	
	result := YARAScanResult{
		ID:        request.ID,
		FilePath:  request.FilePath,
		FileHash:  request.FileHash,
		Timestamp: time.Now(),
		Metadata:  make(map[string]interface{}),
	}

	// Scan file content
	var matches []yara.MatchRule
	var err error

	if len(request.FileContent) > 0 {
		// Scan from memory
		matches, err = s.rules.ScanMem(request.FileContent, 0, 0)
	} else if request.FilePath != "" {
		// Scan from file
		matches, err = s.rules.ScanFile(request.FilePath, 0, 0)
	} else {
		result.Error = "no file content or path provided"
		return result
	}

	if err != nil {
		result.Error = err.Error()
		return result
	}

	// Convert YARA matches to our format
	for _, match := range matches {
		yaraMatch := YARAMatch{
			RuleName:    match.Rule,
			Namespace:   match.Namespace,
			Tags:        match.Tags,
			Meta:        match.Meta,
			Description: match.Meta["description"],
		}

		// Convert strings
		for _, str := range match.Strings {
			yaraMatch.Strings = append(yaraMatch.Strings, YARAString{
				Name:   str.Name,
				Offset: str.Offset,
				Data:   string(str.Data),
			})
		}

		// Calculate score based on rule severity
		yaraMatch.Score = calculateYARAScore(yaraMatch)
		result.Matches = append(result.Matches, yaraMatch)
	}

	result.ScanTime = time.Since(startTime).Milliseconds()
	result.Metadata["total_matches"] = len(result.Matches)
	result.Metadata["scan_duration_ms"] = result.ScanTime

	return result
}

func loadYARARules(compiler *yara.Compiler, rulesDir string) error {
	// Create rules directory if it doesn't exist
	if err := os.MkdirAll(rulesDir, 0755); err != nil {
		return err
	}

	// Load all .yar files from directory
	return filepath.Walk(rulesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if strings.HasSuffix(path, ".yar") {
			if err := compiler.AddFile(path, ""); err != nil {
				log.Printf("warning: failed to load YARA rule %s: %v", path, err)
			}
		}
		return nil
	})
}

func calculateYARAScore(match YARAMatch) int {
	score := 0

	// Base score
	score += 10

	// Add score based on tags
	for _, tag := range match.Tags {
		switch strings.ToLower(tag) {
		case "malware":
			score += 50
		case "trojan":
			score += 40
		case "backdoor":
			score += 45
		case "keylogger":
			score += 35
		case "ransomware":
			score += 60
		case "exploit":
			score += 30
		case "suspicious":
			score += 20
		}
	}

	// Add score based on meta information
	if severity, ok := match.Meta["severity"]; ok {
		switch strings.ToLower(severity) {
		case "critical":
			score += 40
		case "high":
			score += 30
		case "medium":
			score += 20
		case "low":
			score += 10
		}
	}

	return score
}

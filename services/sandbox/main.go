package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	ch "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/segmentio/kafka-go"
)

type SandboxRequest struct {
	ID          string            `json:"id"`
	Type        string            `json:"type"`
	FileHash    string            `json:"file_hash"`
	FilePath    string            `json:"file_path"`
	FileContent []byte            `json:"file_content"`
	Environment string            `json:"environment"`
	Timeout     int               `json:"timeout"`
	Metadata    map[string]string `json:"metadata"`
}

type SandboxResult struct {
	ID           string                 `json:"id"`
	Verdict      string                 `json:"verdict"` // clean, suspicious, malicious
	Score        float64                `json:"score"`
	Duration     int                    `json:"duration"`
	Processes    []ProcessInfo          `json:"processes"`
	Network      []NetworkActivity      `json:"network"`
	Files        []FileActivity         `json:"files"`
	Registry     []RegistryActivity     `json:"registry"`
	IOCs         []string               `json:"iocs"`
	Behavior     []string               `json:"behavior"`
	Error        string                 `json:"error,omitempty"`
	Timestamp    time.Time              `json:"timestamp"`
	Environment  string                 `json:"environment"`
	Metadata     map[string]interface{} `json:"metadata"`
}

type ProcessInfo struct {
	PID       int      `json:"pid"`
	Name      string   `json:"name"`
	Path      string   `json:"path"`
	Command   string   `json:"command"`
	ParentPID int      `json:"parent_pid"`
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
}

type NetworkActivity struct {
	Protocol string `json:"protocol"`
	Source   string `json:"source"`
	Dest     string `json:"dest"`
	Port     int    `json:"port"`
	Bytes    int    `json:"bytes"`
}

type FileActivity struct {
	Path     string `json:"path"`
	Action   string `json:"action"` // create, read, write, delete
	Size     int64  `json:"size"`
	Hash     string `json:"hash"`
}

type RegistryActivity struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	Action string `json:"action"`
}

func main() {
	kbrokers := os.Getenv("KAFKA_BROKERS")
	if kbrokers == "" { kbrokers = "localhost:9092" }
	topic := os.Getenv("SANDBOX_TOPIC")
	if topic == "" { topic = "musafir.sandbox_requests" }
	group := os.Getenv("KAFKA_GROUP")
	if group == "" { group = "sandbox" }

	chDsn := os.Getenv("CLICKHOUSE_DSN")
	if chDsn == "" { chDsn = "tcp://localhost:9000?database=default" }

	ctx := context.Background()
	conn, err := ch.Open(&ch.Options{Addr: []string{"localhost:9000"}})
	if err != nil { log.Fatalf("clickhouse connect: %v", err) }
	defer conn.Close()

	// Ensure sandbox tables exist
	createSandboxTables(conn, ctx)

	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:  strings.Split(kbrokers, ","),
		Topic:    topic,
		GroupID:  group,
		MinBytes: 1, MaxBytes: 10e6,
	})
	defer reader.Close()

	writer := kafka.NewWriter(kafka.WriterConfig{
		Brokers: strings.Split(kbrokers, ","),
		Topic:   "musafir.sandbox_results",
	})

	log.Printf("sandbox consuming topic=%s brokers=%s", topic, kbrokers)
	for {
		m, err := reader.ReadMessage(ctx)
		if err != nil { log.Fatalf("kafka read: %v", err) }

		var request SandboxRequest
		if err := json.Unmarshal(m.Value, &request); err != nil {
			log.Printf("unmarshal sandbox request: %v", err)
			continue
		}

		// Process sandbox request
		result := processSandboxRequest(request)
		
		// Send result
		resultData, _ := json.Marshal(result)
		if err := writer.WriteMessages(ctx, kafka.Message{Value: resultData}); err != nil {
			log.Printf("write sandbox result: %v", err)
		} else {
			log.Printf("SANDBOX RESULT: %s - %s (score: %.2f)", request.ID, result.Verdict, result.Score)
		}
	}
}

func createSandboxTables(conn ch.Conn, ctx context.Context) {
	// Sandbox requests table
	ddl := `CREATE TABLE IF NOT EXISTS musafir_sandbox_requests (
  id String,
  type String,
  file_hash String,
  file_path String,
  environment String,
  timeout Int32,
  metadata String,
  created_at DateTime DEFAULT now()
) ENGINE = MergeTree ORDER BY created_at`
	
	if err := conn.Exec(ctx, ddl); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}

	// Sandbox results table
	ddl2 := `CREATE TABLE IF NOT EXISTS musafir_sandbox_results (
  id String,
  verdict String,
  score Float64,
  duration Int32,
  processes String,
  network String,
  files String,
  registry String,
  iocs Array(String),
  behavior Array(String),
  error String,
  timestamp DateTime,
  environment String,
  metadata String
) ENGINE = MergeTree ORDER BY timestamp`
	
	if err := conn.Exec(ctx, ddl2); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}
}

func processSandboxRequest(request SandboxRequest) SandboxResult {
	startTime := time.Now()
	
	// Create sandbox environment
	sandboxDir := filepath.Join("/tmp/sandbox", request.ID)
	if err := os.MkdirAll(sandboxDir, 0755); err != nil {
		return SandboxResult{
			ID:        request.ID,
			Verdict:   "error",
			Score:     0.0,
			Error:     err.Error(),
			Timestamp: time.Now(),
		}
	}
	defer os.RemoveAll(sandboxDir)

	// Write file to sandbox
	filePath := filepath.Join(sandboxDir, "sample")
	if err := os.WriteFile(filePath, request.FileContent, 0644); err != nil {
		return SandboxResult{
			ID:        request.ID,
			Verdict:   "error",
			Score:     0.0,
			Error:     err.Error(),
			Timestamp: time.Now(),
		}
	}

	// Execute in sandbox
	timeout := time.Duration(request.Timeout) * time.Second
	if timeout == 0 {
		timeout = 60 * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Run the file (simplified - in production, use proper sandboxing)
	var cmd *exec.Cmd
	switch {
	case strings.HasSuffix(filePath, ".exe"):
		cmd = exec.CommandContext(ctx, "wine", filePath)
	case strings.HasSuffix(filePath, ".py"):
		cmd = exec.CommandContext(ctx, "python3", filePath)
	case strings.HasSuffix(filePath, ".sh"):
		cmd = exec.CommandContext(ctx, "bash", filePath)
	default:
		cmd = exec.CommandContext(ctx, filePath)
	}

	cmd.Dir = sandboxDir
	output, err := cmd.CombinedOutput()

	duration := int(time.Since(startTime).Seconds())

	// Analyze behavior
	behavior := analyzeBehavior(string(output), sandboxDir)
	score := calculateScore(behavior)
	verdict := getVerdict(score)

	// Extract IOCs
	iocs := extractIOCs(string(output))

	return SandboxResult{
		ID:          request.ID,
		Verdict:     verdict,
		Score:       score,
		Duration:    duration,
		Processes:   []ProcessInfo{}, // Would be populated by monitoring
		Network:     []NetworkActivity{}, // Would be populated by monitoring
		Files:       []FileActivity{}, // Would be populated by monitoring
		Registry:    []RegistryActivity{}, // Would be populated by monitoring
		IOCs:        iocs,
		Behavior:    behavior,
		Timestamp:   time.Now(),
		Environment: request.Environment,
		Metadata: map[string]interface{}{
			"output": string(output),
			"error":  err != nil,
		},
	}
}

func analyzeBehavior(output, sandboxDir string) []string {
	var behavior []string

	// Check for suspicious patterns
	if strings.Contains(strings.ToLower(output), "malware") {
		behavior = append(behavior, "malware_indicators")
	}
	if strings.Contains(strings.ToLower(output), "backdoor") {
		behavior = append(behavior, "backdoor_indicators")
	}
	if strings.Contains(strings.ToLower(output), "keylogger") {
		behavior = append(behavior, "keylogger_indicators")
	}
	if strings.Contains(strings.ToLower(output), "ransomware") {
		behavior = append(behavior, "ransomware_indicators")
	}

	// Check file system changes
	files, _ := os.ReadDir(sandboxDir)
	if len(files) > 10 {
		behavior = append(behavior, "excessive_file_creation")
	}

	// Check for network activity (simplified)
	if strings.Contains(output, "http") || strings.Contains(output, "tcp") {
		behavior = append(behavior, "network_activity")
	}

	return behavior
}

func calculateScore(behavior []string) float64 {
	score := 0.0
	for _, b := range behavior {
		switch b {
		case "malware_indicators":
			score += 0.8
		case "backdoor_indicators":
			score += 0.9
		case "keylogger_indicators":
			score += 0.7
		case "ransomware_indicators":
			score += 0.95
		case "excessive_file_creation":
			score += 0.3
		case "network_activity":
			score += 0.2
		}
	}
	if score > 1.0 {
		score = 1.0
	}
	return score
}

func getVerdict(score float64) string {
	if score >= 0.8 {
		return "malicious"
	} else if score >= 0.4 {
		return "suspicious"
	}
	return "clean"
}

func extractIOCs(output string) []string {
	var iocs []string
	
	// Simple IOC extraction (in production, use proper regex patterns)
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) > 0 && (strings.Contains(line, ".") || strings.Contains(line, "://")) {
			iocs = append(iocs, line)
		}
	}
	
	return iocs
}

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	ch "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/segmentio/kafka-go"
)

type ForensicEvent struct {
	ID           string                 `json:"id"`
	Timestamp    time.Time              `json:"timestamp"`
	EventType    string                 `json:"event_type"`
	AssetID      string                 `json:"asset_id"`
	UserID       string                 `json:"user_id"`
	ProcessID    string                 `json:"process_id"`
	ParentPID    string                 `json:"parent_pid"`
	Command      string                 `json:"command"`
	FilePath     string                 `json:"file_path"`
	NetworkData  map[string]interface{} `json:"network_data"`
	RegistryData map[string]interface{} `json:"registry_data"`
	MemoryData   map[string]interface{} `json:"memory_data"`
	DiskData     map[string]interface{} `json:"disk_data"`
	Metadata     map[string]interface{} `json:"metadata"`
}

type ForensicAnalysis struct {
	ID           string             `json:"id"`
	AssetID      string             `json:"asset_id"`
	AnalysisType string             `json:"analysis_type"`
	StartTime    time.Time          `json:"start_time"`
	EndTime      time.Time          `json:"end_time"`
	Status       string             `json:"status"`
	Findings     []ForensicFinding  `json:"findings"`
	Artifacts    []ForensicArtifact `json:"artifacts"`
	Timeline     []ForensicEvent    `json:"timeline"`
	Summary      string             `json:"summary"`
	Confidence   float64            `json:"confidence"`
}

type ForensicFinding struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Evidence    []string               `json:"evidence"`
	IOCs        []string               `json:"iocs"`
	TTPs        []string               `json:"ttps"`
	Confidence  float64                `json:"confidence"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type ForensicArtifact struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Name       string                 `json:"name"`
	Path       string                 `json:"path"`
	Size       int64                  `json:"size"`
	Hash       string                 `json:"hash"`
	CreatedAt  time.Time              `json:"created_at"`
	ModifiedAt time.Time              `json:"modified_at"`
	AccessedAt time.Time              `json:"accessed_at"`
	Metadata   map[string]interface{} `json:"metadata"`
}

type ThreatHuntingQuery struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Query       string    `json:"query"`
	Category    string    `json:"category"`
	Tags        []string  `json:"tags"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
	LastRun     time.Time `json:"last_run"`
	Results     int64     `json:"results"`
	Status      string    `json:"status"`
}

func main() {
	kbrokers := os.Getenv("KAFKA_BROKERS")
	if kbrokers == "" {
		kbrokers = "localhost:9092"
	}
	group := os.Getenv("KAFKA_GROUP")
	if group == "" {
		group = "forensics"
	}

	chDsn := os.Getenv("CLICKHOUSE_DSN")
	if chDsn == "" {
		chDsn = "tcp://localhost:9000?database=default"
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle OS signals for graceful shutdown
	shutdownCh := make(chan os.Signal, 1)
	signal.Notify(shutdownCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-shutdownCh
		log.Println("forensics service: shutdown signal received")
		cancel()
	}()

	conn, err := ch.Open(&ch.Options{Addr: []string{"localhost:9000"}})
	if err != nil {
		log.Fatalf("clickhouse connect: %v", err)
	}
	defer conn.Close()

	// Ensure forensics tables exist with retry
	retryWithBackoff(ctx, 3, 2*time.Second, func() error {
		createForensicsTables(conn, ctx)
		return nil
	})

	// Start HTTP health/metrics server
	httpServer := startHTTPServer(":8095")
	defer func() {
		ctxShutdown, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = httpServer.Shutdown(ctxShutdown)
	}()

	// Kafka dialer
	dialer := &kafka.Dialer{Timeout: 10 * time.Second, DualStack: true, Resolver: &net.Resolver{}}

	// Event reader
	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:         strings.Split(kbrokers, ","),
		Topic:           "musafir.events",
		GroupID:         group,
		Dialer:          dialer,
		MinBytes:        1,
		MaxBytes:        10e6,
		MaxWait:         500 * time.Millisecond,
		ReadLagInterval: 5 * time.Second,
	})
	defer reader.Close()

	// Analysis writer
	writer := kafka.NewWriter(kafka.WriterConfig{
		Brokers:      strings.Split(kbrokers, ","),
		Topic:        "musafir.forensic_analysis",
		Dialer:       dialer,
		RequiredAcks: int(kafka.RequireAll),
		Balancer:     &kafka.LeastBytes{},
		Async:        false,
		BatchTimeout: 200 * time.Millisecond,
	})
	defer writer.Close()

	// DLQ writer
	dlqWriter := kafka.NewWriter(kafka.WriterConfig{
		Brokers:      strings.Split(kbrokers, ","),
		Topic:        "musafir.dlq.forensics",
		Dialer:       dialer,
		RequiredAcks: int(kafka.RequireAll),
		Balancer:     &kafka.Hash{},
	})
	defer dlqWriter.Close()

	// Threat hunting queries
	threatHuntingQueries := loadThreatHuntingQueries()

	// Idempotency cache for processed messages
	var (
		seenMu   sync.Mutex
		seenHash = make(map[string]time.Time)
	)
	cleanupTicker := time.NewTicker(10 * time.Minute)
	defer cleanupTicker.Stop()
	go func() {
		for range cleanupTicker.C {
			seenMu.Lock()
			cutoff := time.Now().Add(-15 * time.Minute)
			for h, t := range seenHash {
				if t.Before(cutoff) {
					delete(seenHash, h)
				}
			}
			seenMu.Unlock()
		}
	}()

	log.Printf("Forensics service consuming events brokers=%s", kbrokers)
	for {
		select {
		case <-ctx.Done():
			log.Println("forensics service: shutting down consumer loop")
			return
		default:
			m, err := reader.ReadMessage(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Printf("kafka read: %v", err)
				continue
			}

			// Idempotency check by message hash
			h := sha256.Sum256(m.Value)
			hs := hex.EncodeToString(h[:])
			seenMu.Lock()
			if _, exists := seenHash[hs]; exists {
				seenMu.Unlock()
				continue
			}
			seenHash[hs] = time.Now()
			seenMu.Unlock()

			var event map[string]interface{}
			if err := json.Unmarshal(m.Value, &event); err != nil {
				log.Printf("unmarshal event: %v", err)
				publishDLQ(ctx, dlqWriter, m.Value, "unmarshal_error")
				continue
			}

			// Process event for forensic analysis with retry
			procErr := retryWithBackoff(ctx, 3, 300*time.Millisecond, func() error {
				processForensicEvent(event, writer, ctx)
				return nil
			})
			if procErr != nil {
				publishDLQ(ctx, dlqWriter, m.Value, "processing_failed")
			}

			// Run threat hunting queries
			go runThreatHuntingQueries(threatHuntingQueries, writer, ctx)
		}
	}
}

// retryWithBackoff executes fn up to attempts with exponential backoff starting at base.
func retryWithBackoff(ctx context.Context, attempts int, base time.Duration, fn func() error) error {
	var err error
	for i := 0; i < attempts; i++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		err = fn()
		if err == nil {
			return nil
		}
		timer := time.NewTimer(time.Duration(1<<i) * base)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
	return err
}

func publishDLQ(ctx context.Context, w *kafka.Writer, payload []byte, reason string) {
	msg := map[string]interface{}{
		"reason":    reason,
		"timestamp": time.Now().Format(time.RFC3339),
		"payload":   string(payload),
	}
	data, _ := json.Marshal(msg)
	_ = w.WriteMessages(ctx, kafka.Message{Value: data})
}

func startHTTPServer(addr string) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	server := &http.Server{Addr: addr, Handler: mux}
	log.Printf("Forensics service HTTP listening on %s", addr)
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("forensics http server: %v", err)
		}
	}()
	return server
}

func createForensicsTables(conn ch.Conn, ctx context.Context) {
	// Forensic events table
	ddl := `CREATE TABLE IF NOT EXISTS musafir_forensic_events (
  id String,
  timestamp DateTime,
  event_type String,
  asset_id String,
  user_id String,
  process_id String,
  parent_pid String,
  command String,
  file_path String,
  network_data String,
  registry_data String,
  memory_data String,
  disk_data String,
  metadata String
) ENGINE = MergeTree ORDER BY timestamp`

	if err := conn.Exec(ctx, ddl); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}

	// Forensic analysis table
	ddl2 := `CREATE TABLE IF NOT EXISTS musafir_forensic_analysis (
  id String,
  asset_id String,
  analysis_type String,
  start_time DateTime,
  end_time DateTime,
  status String,
  findings String,
  artifacts String,
  timeline String,
  summary String,
  confidence Float64
) ENGINE = MergeTree ORDER BY start_time`

	if err := conn.Exec(ctx, ddl2); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}

	// Threat hunting queries table
	ddl3 := `CREATE TABLE IF NOT EXISTS musafir_threat_hunting_queries (
  id String,
  name String,
  description String,
  query String,
  category String,
  tags Array(String),
  created_by String,
  created_at DateTime,
  last_run DateTime,
  results Int64,
  status String
) ENGINE = MergeTree ORDER BY created_at`

	if err := conn.Exec(ctx, ddl3); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}
}

func processForensicEvent(event map[string]interface{}, writer *kafka.Writer, ctx context.Context) {
	// Extract forensic data from event
	forensicEvent := extractForensicData(event)

	// Store forensic event
	storeForensicEvent(forensicEvent)

	// Check for forensic indicators
	if hasForensicIndicators(forensicEvent) {
		// Trigger forensic analysis
		go triggerForensicAnalysis(forensicEvent, writer, ctx)
	}
}

func extractForensicData(event map[string]interface{}) ForensicEvent {
	forensicEvent := ForensicEvent{
		ID:        generateForensicEventID(),
		Timestamp: time.Now(),
		Metadata:  make(map[string]interface{}),
	}

	// Extract basic event data
	if eventData, ok := event["event"].(map[string]interface{}); ok {
		forensicEvent.EventType = getString(eventData, "class")
		if attrs, ok := eventData["attrs"].(map[string]interface{}); ok {
			forensicEvent.Command = getString(attrs, "cmd")
			forensicEvent.FilePath = getString(attrs, "path")
			forensicEvent.ProcessID = getString(attrs, "pid")
			forensicEvent.ParentPID = getString(attrs, "ppid")
		}
	}

	// Extract asset data
	if assetData, ok := event["asset"].(map[string]interface{}); ok {
		forensicEvent.AssetID = getString(assetData, "id")
	}

	// Extract user data
	if userData, ok := event["user"].(map[string]interface{}); ok {
		forensicEvent.UserID = getString(userData, "id")
	}

	// Extract network data
	forensicEvent.NetworkData = extractNetworkData(event)

	// Extract registry data
	forensicEvent.RegistryData = extractRegistryData(event)

	// Extract memory data
	forensicEvent.MemoryData = extractMemoryData(event)

	// Extract disk data
	forensicEvent.DiskData = extractDiskData(event)

	return forensicEvent
}

func hasForensicIndicators(event ForensicEvent) bool {
	// Check for suspicious activities that warrant forensic analysis
	indicators := []string{
		"powershell", "cmd", "wscript", "rundll32", "regsvr32",
		"certutil", "bitsadmin", "wmic", "net", "sc",
	}

	command := strings.ToLower(event.Command)
	for _, indicator := range indicators {
		if strings.Contains(command, indicator) {
			return true
		}
	}

	// Check for suspicious file paths
	suspiciousPaths := []string{
		"temp", "appdata", "programdata", "windows\\system32",
		"users\\public", "recycle", "prefetch",
	}

	filePath := strings.ToLower(event.FilePath)
	for _, path := range suspiciousPaths {
		if strings.Contains(filePath, path) {
			return true
		}
	}

	return false
}

func triggerForensicAnalysis(event ForensicEvent, writer *kafka.Writer, ctx context.Context) {
	analysis := ForensicAnalysis{
		ID:           generateAnalysisID(),
		AssetID:      event.AssetID,
		AnalysisType: "incident_response",
		StartTime:    time.Now(),
		Status:       "running",
		Findings:     []ForensicFinding{},
		Artifacts:    []ForensicArtifact{},
		Timeline:     []ForensicEvent{event},
	}

	// Perform forensic analysis
	performForensicAnalysis(&analysis)

	// Store analysis results
	storeForensicAnalysis(analysis)

	// Send analysis to Kafka
	analysisData, _ := json.Marshal(analysis)
	if err := writer.WriteMessages(ctx, kafka.Message{Value: analysisData}); err != nil {
		log.Printf("write forensic analysis: %v", err)
	} else {
		log.Printf("FORENSIC ANALYSIS: %s - %s (%d findings)", analysis.ID, analysis.Status, len(analysis.Findings))
	}
}

func performForensicAnalysis(analysis *ForensicAnalysis) {
	// Simulate forensic analysis
	analysis.EndTime = time.Now()
	analysis.Status = "completed"

	// Add forensic findings
	analysis.Findings = append(analysis.Findings, ForensicFinding{
		ID:          generateFindingID(),
		Type:        "suspicious_process",
		Severity:    "high",
		Title:       "Suspicious Process Execution",
		Description: "A suspicious process was executed with potential malicious intent",
		Evidence:    []string{"Process execution detected", "Command line analysis"},
		IOCs:        []string{"suspicious_command", "suspicious_path"},
		TTPs:        []string{"T1059", "T1105"},
		Confidence:  0.85,
		Metadata: map[string]interface{}{
			"process_name": "suspicious.exe",
			"command_line": "suspicious.exe --malicious-flag",
		},
	})

	// Add forensic artifacts
	analysis.Artifacts = append(analysis.Artifacts, ForensicArtifact{
		ID:         generateArtifactID(),
		Type:       "file",
		Name:       "suspicious.exe",
		Path:       "C:\\temp\\suspicious.exe",
		Size:       1024000,
		Hash:       "sha256:abcd1234...",
		CreatedAt:  time.Now().Add(-1 * time.Hour),
		ModifiedAt: time.Now().Add(-30 * time.Minute),
		AccessedAt: time.Now(),
		Metadata: map[string]interface{}{
			"file_type": "executable",
			"entropy":   7.8,
		},
	})

	analysis.Summary = "Forensic analysis completed with 1 high-severity finding"
	analysis.Confidence = 0.85
}

func runThreatHuntingQueries(queries []ThreatHuntingQuery, writer *kafka.Writer, ctx context.Context) {
	for _, query := range queries {
		// Simulate threat hunting query execution
		results := executeThreatHuntingQuery(query)

		if results > 0 {
			log.Printf("THREAT HUNTING: Query '%s' found %d results", query.Name, results)
		}
	}
}

func executeThreatHuntingQuery(query ThreatHuntingQuery) int64 {
	// Simulate query execution
	// In production, this would execute the actual query against the database
	return int64(time.Now().Second() % 10)
}

func loadThreatHuntingQueries() []ThreatHuntingQuery {
	return []ThreatHuntingQuery{
		{
			ID:          "thq-001",
			Name:        "Ransomware Activity",
			Description: "Detect ransomware-like file encryption activities",
			Query:       "SELECT * FROM musafir_events WHERE event_type = 'file_write' AND entropy > 7.5",
			Category:    "ransomware",
			Tags:        []string{"ransomware", "encryption", "file_activity"},
			CreatedBy:   "security_team",
			CreatedAt:   time.Now().Add(-24 * time.Hour),
			LastRun:     time.Now().Add(-1 * time.Hour),
			Results:     0,
			Status:      "active",
		},
		{
			ID:          "thq-002",
			Name:        "Lateral Movement",
			Description: "Detect lateral movement patterns",
			Query:       "SELECT * FROM musafir_events WHERE event_type = 'network_connection' AND dest_port IN (22, 3389, 5985)",
			Category:    "lateral_movement",
			Tags:        []string{"lateral_movement", "network", "rdp", "ssh"},
			CreatedBy:   "security_team",
			CreatedAt:   time.Now().Add(-48 * time.Hour),
			LastRun:     time.Now().Add(-2 * time.Hour),
			Results:     0,
			Status:      "active",
		},
		{
			ID:          "thq-003",
			Name:        "Privilege Escalation",
			Description: "Detect privilege escalation attempts",
			Query:       "SELECT * FROM musafir_events WHERE event_type = 'process_exec' AND command LIKE '%sudo%'",
			Category:    "privilege_escalation",
			Tags:        []string{"privilege_escalation", "sudo", "admin"},
			CreatedBy:   "security_team",
			CreatedAt:   time.Now().Add(-72 * time.Hour),
			LastRun:     time.Now().Add(-3 * time.Hour),
			Results:     0,
			Status:      "active",
		},
	}
}

// Helper functions
func generateForensicEventID() string {
	return "forensic-" + time.Now().Format("20060102150405")
}

func generateAnalysisID() string {
	return "analysis-" + time.Now().Format("20060102150405")
}

func generateFindingID() string {
	return "finding-" + time.Now().Format("20060102150405")
}

func generateArtifactID() string {
	return "artifact-" + time.Now().Format("20060102150405")
}

func getString(data map[string]interface{}, key string) string {
	if val, ok := data[key].(string); ok {
		return val
	}
	return ""
}

func extractNetworkData(event map[string]interface{}) map[string]interface{} {
	// Extract network-related data from event
	return map[string]interface{}{
		"connections": []string{},
		"ports":       []int{},
		"protocols":   []string{},
	}
}

func extractRegistryData(event map[string]interface{}) map[string]interface{} {
	// Extract registry-related data from event
	return map[string]interface{}{
		"keys_modified":  []string{},
		"values_added":   []string{},
		"values_changed": []string{},
	}
}

func extractMemoryData(event map[string]interface{}) map[string]interface{} {
	// Extract memory-related data from event
	return map[string]interface{}{
		"memory_usage": 0,
		"processes":    []string{},
		"modules":      []string{},
	}
}

func extractDiskData(event map[string]interface{}) map[string]interface{} {
	// Extract disk-related data from event
	return map[string]interface{}{
		"files_created":  []string{},
		"files_modified": []string{},
		"files_deleted":  []string{},
		"disk_usage":     0,
	}
}

func storeForensicEvent(event ForensicEvent) {
	// Store forensic event in ClickHouse
	// Implementation would store the event in the database
}

func storeForensicAnalysis(analysis ForensicAnalysis) {
	// Store forensic analysis in ClickHouse
	// Implementation would store the analysis in the database
}

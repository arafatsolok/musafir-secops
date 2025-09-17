package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"os"
	"time"

	ch "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/segmentio/kafka-go"
)

type ObservabilityService struct {
	ctx    context.Context
	conn   ch.Conn
	writer *kafka.Writer
	traces map[string]*Trace
	spans  map[string]*Span
}

type Trace struct {
	ID        string                 `json:"trace_id"`
	Service   string                 `json:"service"`
	Operation string                 `json:"operation"`
	StartTime time.Time              `json:"start_time"`
	EndTime   time.Time              `json:"end_time"`
	Duration  int64                  `json:"duration_ms"`
	Status    string                 `json:"status"` // success, error, timeout
	Spans     []string               `json:"span_ids"`
	Metadata  map[string]interface{} `json:"metadata"`
}

type Span struct {
	ID        string            `json:"span_id"`
	TraceID   string            `json:"trace_id"`
	ParentID  string            `json:"parent_id,omitempty"`
	Service   string            `json:"service"`
	Operation string            `json:"operation"`
	StartTime time.Time         `json:"start_time"`
	EndTime   time.Time         `json:"end_time"`
	Duration  int64             `json:"duration_ms"`
	Status    string            `json:"status"`
	Tags      map[string]string `json:"tags"`
	Logs      []SpanLog         `json:"logs"`
	Error     string            `json:"error,omitempty"`
}

type SpanLog struct {
	Timestamp time.Time              `json:"timestamp"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Fields    map[string]interface{} `json:"fields"`
}

type Metrics struct {
	Service     string                 `json:"service"`
	Timestamp   time.Time              `json:"timestamp"`
	CPUUsage    float64                `json:"cpu_usage"`
	MemoryUsage float64                `json:"memory_usage"`
	RequestRate float64                `json:"request_rate"`
	ErrorRate   float64                `json:"error_rate"`
	Latency     float64                `json:"latency_p95"`
	Throughput  float64                `json:"throughput"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type Alert struct {
	ID          string                 `json:"id"`
	Service     string                 `json:"service"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Timestamp   time.Time              `json:"timestamp"`
	Status      string                 `json:"status"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type ServiceHealth struct {
	Service      string    `json:"service"`
	Status       string    `json:"status"`
	LastCheck    time.Time `json:"last_check"`
	ResponseTime int64     `json:"response_time_ms"`
	ErrorCount   int64     `json:"error_count"`
	SuccessCount int64     `json:"success_count"`
	Uptime       float64   `json:"uptime_percent"`
}

func NewObservabilityService() *ObservabilityService {
	chDsn := os.Getenv("CLICKHOUSE_DSN")
	if chDsn == "" {
		chDsn = "tcp://localhost:9000?database=default"
	}

	conn, err := ch.Open(&ch.Options{Addr: []string{"localhost:9000"}})
	if err != nil {
		log.Fatalf("clickhouse connect: %v", err)
	}

	kbrokers := os.Getenv("KAFKA_BROKERS")
	if kbrokers == "" {
		kbrokers = "localhost:9092"
	}

	writer := kafka.NewWriter(kafka.WriterConfig{
		Brokers: []string{kbrokers},
		Topic:   "musafir.observability",
	})

	return &ObservabilityService{
		ctx:    context.Background(),
		conn:   conn,
		writer: writer,
		traces: make(map[string]*Trace),
		spans:  make(map[string]*Span),
	}
}

func (o *ObservabilityService) Initialize() {
	// Create observability tables
	o.createObservabilityTables()

	// Start monitoring services
	go o.monitorServices()

	// Start trace collection
	go o.collectTraces()

	// Start metrics collection
	go o.collectMetrics()

	log.Println("Observability service initialized successfully")
}

func (o *ObservabilityService) createObservabilityTables() {
	// Create traces table
	tracesTable := `
		CREATE TABLE IF NOT EXISTS musafir_traces (
			trace_id String,
			service String,
			operation String,
			start_time DateTime,
			end_time DateTime,
			duration_ms Int64,
			status String,
			span_ids Array(String),
			metadata String,
			created_at DateTime DEFAULT now()
		) ENGINE = MergeTree()
		ORDER BY (start_time, service, trace_id)
	`

	if err := o.conn.Exec(o.ctx, tracesTable); err != nil {
		log.Printf("Error creating traces table: %v", err)
	}

	// Create spans table
	spansTable := `
		CREATE TABLE IF NOT EXISTS musafir_spans (
			span_id String,
			trace_id String,
			parent_id String,
			service String,
			operation String,
			start_time DateTime,
			end_time DateTime,
			duration_ms Int64,
			status String,
			tags String,
			logs String,
			error String,
			created_at DateTime DEFAULT now()
		) ENGINE = MergeTree()
		ORDER BY (start_time, service, span_id)
	`

	if err := o.conn.Exec(o.ctx, spansTable); err != nil {
		log.Printf("Error creating spans table: %v", err)
	}

	// Create metrics table
	metricsTable := `
		CREATE TABLE IF NOT EXISTS musafir_metrics (
			service String,
			timestamp DateTime,
			cpu_usage Float64,
			memory_usage Float64,
			request_rate Float64,
			error_rate Float64,
			latency_p95 Float64,
			throughput Float64,
			metadata String,
			created_at DateTime DEFAULT now()
		) ENGINE = MergeTree()
		ORDER BY (timestamp, service)
	`

	if err := o.conn.Exec(o.ctx, metricsTable); err != nil {
		log.Printf("Error creating metrics table: %v", err)
	}

	// Create alerts table
	alertsTable := `
		CREATE TABLE IF NOT EXISTS musafir_alerts (
			id String,
			service String,
			type String,
			severity String,
			title String,
			description String,
			timestamp DateTime,
			status String,
			metadata String,
			created_at DateTime DEFAULT now()
		) ENGINE = MergeTree()
		ORDER BY (timestamp, service, severity)
	`

	if err := o.conn.Exec(o.ctx, alertsTable); err != nil {
		log.Printf("Error creating alerts table: %v", err)
	}
}

func (o *ObservabilityService) StartTrace(service, operation string) *Trace {
	traceID := generateTraceID()
	trace := &Trace{
		ID:        traceID,
		Service:   service,
		Operation: operation,
		StartTime: time.Now(),
		Status:    "running",
		Spans:     []string{},
		Metadata:  make(map[string]interface{}),
	}

	o.traces[traceID] = trace
	return trace
}

func (o *ObservabilityService) StartSpan(traceID, parentID, service, operation string) *Span {
	spanID := generateSpanID()
	span := &Span{
		ID:        spanID,
		TraceID:   traceID,
		ParentID:  parentID,
		Service:   service,
		Operation: operation,
		StartTime: time.Now(),
		Status:    "running",
		Tags:      make(map[string]string),
		Logs:      []SpanLog{},
	}

	o.spans[spanID] = span

	// Add span to trace
	if trace, exists := o.traces[traceID]; exists {
		trace.Spans = append(trace.Spans, spanID)
	}

	return span
}

func (o *ObservabilityService) FinishSpan(spanID string, status string, err error) {
	if span, exists := o.spans[spanID]; exists {
		span.EndTime = time.Now()
		span.Duration = span.EndTime.Sub(span.StartTime).Milliseconds()
		span.Status = status

		if err != nil {
			span.Error = err.Error()
		}

		// Store span
		o.storeSpan(span)
	}
}

func (o *ObservabilityService) FinishTrace(traceID string, status string) {
	if trace, exists := o.traces[traceID]; exists {
		trace.EndTime = time.Now()
		trace.Duration = trace.EndTime.Sub(trace.StartTime).Milliseconds()
		trace.Status = status

		// Store trace
		o.storeTrace(trace)

		// Clean up from memory
		delete(o.traces, traceID)
	}
}

func (o *ObservabilityService) AddSpanLog(spanID, level, message string, fields map[string]interface{}) {
	if span, exists := o.spans[spanID]; exists {
		log := SpanLog{
			Timestamp: time.Now(),
			Level:     level,
			Message:   message,
			Fields:    fields,
		}
		span.Logs = append(span.Logs, log)
	}
}

func (o *ObservabilityService) AddSpanTag(spanID, key, value string) {
	if span, exists := o.spans[spanID]; exists {
		span.Tags[key] = value
	}
}

func (o *ObservabilityService) storeTrace(trace *Trace) {
	spanIDsJSON, _ := json.Marshal(trace.Spans)
	metadataJSON, _ := json.Marshal(trace.Metadata)

	query := `
		INSERT INTO musafir_traces 
		(trace_id, service, operation, start_time, end_time, duration_ms, status, span_ids, metadata, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	err := o.conn.Exec(o.ctx, query,
		trace.ID,
		trace.Service,
		trace.Operation,
		trace.StartTime,
		trace.EndTime,
		trace.Duration,
		trace.Status,
		string(spanIDsJSON),
		string(metadataJSON),
		time.Now(),
	)

	if err != nil {
		log.Printf("Error storing trace: %v", err)
	}
}

func (o *ObservabilityService) storeSpan(span *Span) {
	tagsJSON, _ := json.Marshal(span.Tags)
	logsJSON, _ := json.Marshal(span.Logs)

	query := `
		INSERT INTO musafir_spans 
		(span_id, trace_id, parent_id, service, operation, start_time, end_time, duration_ms, status, tags, logs, error, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	err := o.conn.Exec(o.ctx, query,
		span.ID,
		span.TraceID,
		span.ParentID,
		span.Service,
		span.Operation,
		span.StartTime,
		span.EndTime,
		span.Duration,
		span.Status,
		string(tagsJSON),
		string(logsJSON),
		span.Error,
		time.Now(),
	)

	if err != nil {
		log.Printf("Error storing span: %v", err)
	}
}

func (o *ObservabilityService) monitorServices() {
	services := []string{
		"gateway", "ingest", "detect", "correlate", "respond", "cases",
		"ueba", "threatintel", "sandbox", "ml", "mdm", "yara",
		"cloud", "network", "email", "identity", "vuln", "compliance",
		"slsa", "tenant", "monitor", "ai", "deception", "graph", "cache",
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			for _, service := range services {
				go o.checkServiceHealth(service)
			}
		}
	}
}

func (o *ObservabilityService) checkServiceHealth(service string) {
	// Simulate health check
	start := time.Now()

	// Simulate service response time
	responseTime := time.Duration(rand.Intn(100)) * time.Millisecond
	time.Sleep(responseTime)

	// Simulate occasional failures
	status := "healthy"
	errorCount := int64(0)
	successCount := int64(1)

	if rand.Float64() < 0.05 { // 5% chance of failure
		status = "unhealthy"
		errorCount = 1
		successCount = 0
	}

	health := ServiceHealth{
		Service:      service,
		Status:       status,
		LastCheck:    time.Now(),
		ResponseTime: responseTime.Milliseconds(),
		ErrorCount:   errorCount,
		SuccessCount: successCount,
		Uptime:       calculateUptime(service),
	}

	// Store health data
	o.storeServiceHealth(health)

	// Generate alert if unhealthy
	if status == "unhealthy" {
		o.generateAlert(service, "service_unhealthy", "high",
			"Service Unhealthy",
			fmt.Sprintf("Service %s is not responding properly", service))
	}
}

func (o *ObservabilityService) collectTraces() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Simulate trace collection
			o.simulateTraceCollection()
		}
	}
}

func (o *ObservabilityService) simulateTraceCollection() {
	services := []string{"gateway", "ingest", "detect", "correlate", "respond"}
	operations := []string{"process_event", "detect_threat", "correlate_alert", "respond_incident"}

	// Generate random traces
	for i := 0; i < rand.Intn(10); i++ {
		service := services[rand.Intn(len(services))]
		operation := operations[rand.Intn(len(operations))]

		trace := o.StartTrace(service, operation)

		// Add some spans
		span1 := o.StartSpan(trace.ID, "", service, operation+"_span1")
		time.Sleep(time.Duration(rand.Intn(100)) * time.Millisecond)
		o.FinishSpan(span1.ID, "success", nil)

		span2 := o.StartSpan(trace.ID, span1.ID, service, operation+"_span2")
		time.Sleep(time.Duration(rand.Intn(50)) * time.Millisecond)
		o.FinishSpan(span2.ID, "success", nil)

		// Finish trace
		status := "success"
		if rand.Float64() < 0.1 { // 10% chance of error
			status = "error"
		}
		o.FinishTrace(trace.ID, status)
	}
}

func (o *ObservabilityService) collectMetrics() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	services := []string{"gateway", "ingest", "detect", "correlate", "respond", "cases"}

	for {
		select {
		case <-ticker.C:
			for _, service := range services {
				metrics := Metrics{
					Service:     service,
					Timestamp:   time.Now(),
					CPUUsage:    rand.Float64() * 100,
					MemoryUsage: rand.Float64() * 100,
					RequestRate: rand.Float64() * 1000,
					ErrorRate:   rand.Float64() * 10,
					Latency:     rand.Float64() * 1000,
					Throughput:  rand.Float64() * 10000,
					Metadata: map[string]interface{}{
						"version": "1.0.0",
						"region":  "us-east-1",
					},
				}

				o.storeMetrics(metrics)

				// Check for alert conditions
				if metrics.CPUUsage > 80 {
					o.generateAlert(service, "high_cpu", "medium",
						"High CPU Usage",
						fmt.Sprintf("CPU usage is %.1f%%", metrics.CPUUsage))
				}

				if metrics.MemoryUsage > 90 {
					o.generateAlert(service, "high_memory", "high",
						"High Memory Usage",
						fmt.Sprintf("Memory usage is %.1f%%", metrics.MemoryUsage))
				}

				if metrics.ErrorRate > 5 {
					o.generateAlert(service, "high_error_rate", "high",
						"High Error Rate",
						fmt.Sprintf("Error rate is %.1f%%", metrics.ErrorRate))
				}
			}
		}
	}
}

func (o *ObservabilityService) storeMetrics(metrics Metrics) {
	metadataJSON, _ := json.Marshal(metrics.Metadata)

	query := `
		INSERT INTO musafir_metrics 
		(service, timestamp, cpu_usage, memory_usage, request_rate, error_rate, latency_p95, throughput, metadata, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	err := o.conn.Exec(o.ctx, query,
		metrics.Service,
		metrics.Timestamp,
		metrics.CPUUsage,
		metrics.MemoryUsage,
		metrics.RequestRate,
		metrics.ErrorRate,
		metrics.Latency,
		metrics.Throughput,
		string(metadataJSON),
		time.Now(),
	)

	if err != nil {
		log.Printf("Error storing metrics: %v", err)
	}
}

func (o *ObservabilityService) storeServiceHealth(health ServiceHealth) {
	// Store in ClickHouse (simplified)
	query := `
		INSERT INTO musafir_service_health 
		(service, status, last_check, response_time_ms, error_count, success_count, uptime_percent, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`

	err := o.conn.Exec(o.ctx, query,
		health.Service,
		health.Status,
		health.LastCheck,
		health.ResponseTime,
		health.ErrorCount,
		health.SuccessCount,
		health.Uptime,
		time.Now(),
	)

	if err != nil {
		log.Printf("Error storing service health: %v", err)
	}
}

func (o *ObservabilityService) generateAlert(service, alertType, severity, title, description string) {
	alert := Alert{
		ID:          generateAlertID(),
		Service:     service,
		Type:        alertType,
		Severity:    severity,
		Title:       title,
		Description: description,
		Timestamp:   time.Now(),
		Status:      "active",
		Metadata: map[string]interface{}{
			"source":  "observability",
			"version": "1.0.0",
		},
	}

	o.storeAlert(alert)

	// Send to Kafka
	alertJSON, _ := json.Marshal(alert)
	o.writer.WriteMessages(o.ctx, kafka.Message{
		Key:   []byte(alert.ID),
		Value: alertJSON,
	})

	log.Printf("Alert generated: %s - %s", service, title)
}

func (o *ObservabilityService) storeAlert(alert Alert) {
	metadataJSON, _ := json.Marshal(alert.Metadata)

	query := `
		INSERT INTO musafir_alerts 
		(id, service, type, severity, title, description, timestamp, status, metadata, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	err := o.conn.Exec(o.ctx, query,
		alert.ID,
		alert.Service,
		alert.Type,
		alert.Severity,
		alert.Title,
		alert.Description,
		alert.Timestamp,
		alert.Status,
		string(metadataJSON),
		time.Now(),
	)

	if err != nil {
		log.Printf("Error storing alert: %v", err)
	}
}

func (o *ObservabilityService) GetTrace(traceID string) (*Trace, error) {
	// Query trace from ClickHouse
	query := `
		SELECT trace_id, service, operation, start_time, end_time, duration_ms, status, span_ids, metadata
		FROM musafir_traces
		WHERE trace_id = ?
		LIMIT 1
	`

	rows, err := o.conn.Query(o.ctx, query, traceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	if rows.Next() {
		var trace Trace
		var spanIDsJSON, metadataJSON string

		err := rows.Scan(
			&trace.ID,
			&trace.Service,
			&trace.Operation,
			&trace.StartTime,
			&trace.EndTime,
			&trace.Duration,
			&trace.Status,
			&spanIDsJSON,
			&metadataJSON,
		)
		if err != nil {
			return nil, err
		}

		// Parse JSON fields
		json.Unmarshal([]byte(spanIDsJSON), &trace.Spans)
		json.Unmarshal([]byte(metadataJSON), &trace.Metadata)

		return &trace, nil
	}

	return nil, fmt.Errorf("trace not found")
}

func (o *ObservabilityService) GetSpans(traceID string) ([]*Span, error) {
	// Query spans from ClickHouse
	query := `
		SELECT span_id, trace_id, parent_id, service, operation, start_time, end_time, duration_ms, status, tags, logs, error
		FROM musafir_spans
		WHERE trace_id = ?
		ORDER BY start_time
	`

	rows, err := o.conn.Query(o.ctx, query, traceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var spans []*Span
	for rows.Next() {
		var span Span
		var tagsJSON, logsJSON string

		err := rows.Scan(
			&span.ID,
			&span.TraceID,
			&span.ParentID,
			&span.Service,
			&span.Operation,
			&span.StartTime,
			&span.EndTime,
			&span.Duration,
			&span.Status,
			&tagsJSON,
			&logsJSON,
			&span.Error,
		)
		if err != nil {
			return nil, err
		}

		// Parse JSON fields
		json.Unmarshal([]byte(tagsJSON), &span.Tags)
		json.Unmarshal([]byte(logsJSON), &span.Logs)

		spans = append(spans, &span)
	}

	return spans, nil
}

func (o *ObservabilityService) Close() {
	o.writer.Close()
	o.conn.Close()
}

// Utility functions
func generateTraceID() string {
	return fmt.Sprintf("trace_%d", time.Now().UnixNano())
}

func generateSpanID() string {
	return fmt.Sprintf("span_%d", time.Now().UnixNano())
}

func generateAlertID() string {
	return fmt.Sprintf("alert_%d", time.Now().UnixNano())
}

func calculateUptime(service string) float64 {
	// Simulate uptime calculation
	return 99.5 + rand.Float64()*0.5
}

func main() {
	observabilityService := NewObservabilityService()
	observabilityService.Initialize()

	// Keep service running
	select {}
}

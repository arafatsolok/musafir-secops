package main

import (
	"context"
	"log"
	"os"
	"time"

	"net/http"

	ch "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type PlatformMetrics struct {
	Timestamp       time.Time              `json:"timestamp"`
	ServiceName     string                 `json:"service_name"`
	Status          string                 `json:"status"` // healthy, degraded, unhealthy
	CPUUsage        float64                `json:"cpu_usage"`
	MemoryUsage     float64                `json:"memory_usage"`
	EventsProcessed int64                  `json:"events_processed"`
	AlertsGenerated int64                  `json:"alerts_generated"`
	ResponseTime    float64                `json:"response_time_ms"`
	ErrorRate       float64                `json:"error_rate"`
	Throughput      float64                `json:"throughput_eps"`
	QueueDepth      int64                  `json:"queue_depth"`
	LastHeartbeat   time.Time              `json:"last_heartbeat"`
	Metadata        map[string]interface{} `json:"metadata"`
}

type ServiceHealth struct {
	ServiceName  string    `json:"service_name"`
	Status       string    `json:"status"`
	LastCheck    time.Time `json:"last_check"`
	ResponseTime float64   `json:"response_time_ms"`
	ErrorCount   int64     `json:"error_count"`
	SuccessCount int64     `json:"success_count"`
	Uptime       float64   `json:"uptime_seconds"`
}

var (
	eventsProcessed = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "musafir_events_processed_total",
			Help: "Total number of events processed",
		},
		[]string{"service", "type"},
	)

	alertsGenerated = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "musafir_alerts_generated_total",
			Help: "Total number of alerts generated",
		},
		[]string{"service", "severity"},
	)

	responseTime = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "musafir_response_time_seconds",
			Help: "Response time in seconds",
		},
		[]string{"service", "endpoint"},
	)

	serviceHealth = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "musafir_service_health",
			Help: "Service health status (1=healthy, 0.5=degraded, 0=unhealthy)",
		},
		[]string{"service"},
	)
)

func init() {
	prometheus.MustRegister(eventsProcessed)
	prometheus.MustRegister(alertsGenerated)
	prometheus.MustRegister(responseTime)
	prometheus.MustRegister(serviceHealth)
}

func main() {
	kbrokers := os.Getenv("KAFKA_BROKERS")
	if kbrokers == "" {
		kbrokers = "localhost:9092"
	}
	group := os.Getenv("KAFKA_GROUP")
	if group == "" {
		group = "monitor"
	}

	chDsn := os.Getenv("CLICKHOUSE_DSN")
	if chDsn == "" {
		chDsn = "tcp://localhost:9000?database=default"
	}

	ctx := context.Background()
	conn, err := ch.Open(&ch.Options{Addr: []string{"localhost:9000"}})
	if err != nil {
		log.Fatalf("clickhouse connect: %v", err)
	}
	defer conn.Close()

	// Ensure monitoring tables exist
	createMonitoringTables(conn, ctx)

	// Start Prometheus metrics server
	go startMetricsServer()

	// Monitor all services
	go monitorAllServices(kbrokers, ctx)

	// Keep running
	select {}
}

func createMonitoringTables(conn ch.Conn, ctx context.Context) {
	// Platform metrics table
	ddl := `CREATE TABLE IF NOT EXISTS musafir_platform_metrics (
  timestamp DateTime,
  service_name String,
  status String,
  cpu_usage Float64,
  memory_usage Float64,
  events_processed Int64,
  alerts_generated Int64,
  response_time Float64,
  error_rate Float64,
  throughput Float64,
  queue_depth Int64,
  last_heartbeat DateTime,
  metadata String
) ENGINE = MergeTree ORDER BY timestamp`

	if err := conn.Exec(ctx, ddl); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}

	// Service health table
	ddl2 := `CREATE TABLE IF NOT EXISTS musafir_service_health (
  service_name String,
  status String,
  last_check DateTime,
  response_time Float64,
  error_count Int64,
  success_count Int64,
  uptime Float64
) ENGINE = MergeTree ORDER BY last_check`

	if err := conn.Exec(ctx, ddl2); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}
}

func startMetricsServer() {
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	log.Println("Starting metrics server on :9090")
	log.Fatal(http.ListenAndServe(":9090", nil))
}

func monitorAllServices(kbrokers string, ctx context.Context) {
	services := []string{
		"gateway", "ingest", "detect", "respond", "ueba", "threatintel",
		"correlate", "sandbox", "ml", "mdm", "yara", "cases", "cloud",
		"network", "email", "identity", "vuln", "compliance", "slsa", "tenant",
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		for _, service := range services {
			go checkServiceHealth(service, kbrokers, ctx)
		}
	}
}

func checkServiceHealth(serviceName, kbrokers string, ctx context.Context) {
	// Check if context is cancelled
	select {
	case <-ctx.Done():
		log.Printf("MONITOR: Context cancelled for %s", serviceName)
		return
	default:
	}

	// Simulate health check
	health := ServiceHealth{
		ServiceName:  serviceName,
		Status:       getServiceStatus(serviceName),
		LastCheck:    time.Now(),
		ResponseTime: getResponseTime(serviceName),
		ErrorCount:   getErrorCount(serviceName),
		SuccessCount: getSuccessCount(serviceName),
		Uptime:       getUptime(serviceName),
	}

	// Update Prometheus metrics
	var statusValue float64
	switch health.Status {
	case "healthy":
		statusValue = 1.0
	case "degraded":
		statusValue = 0.5
	case "unhealthy":
		statusValue = 0.0
	default:
		statusValue = 0.0
	}
	serviceHealth.WithLabelValues(serviceName).Set(statusValue)

	// Generate platform metrics
	metrics := PlatformMetrics{
		Timestamp:       time.Now(),
		ServiceName:     serviceName,
		Status:          health.Status,
		CPUUsage:        getCPUUsage(serviceName),
		MemoryUsage:     getMemoryUsage(serviceName),
		EventsProcessed: getEventsProcessed(serviceName),
		AlertsGenerated: getAlertsGenerated(serviceName),
		ResponseTime:    health.ResponseTime,
		ErrorRate:       getErrorRate(serviceName),
		Throughput:      getThroughput(serviceName),
		QueueDepth:      getQueueDepth(serviceName),
		LastHeartbeat:   time.Now(),
		Metadata: map[string]interface{}{
			"version":       "1.0.0",
			"region":        "us-east-1",
			"kafka_brokers": kbrokers,
		},
	}

	// Update Prometheus counters
	eventsProcessed.WithLabelValues(serviceName, "security").Add(float64(metrics.EventsProcessed))
	alertsGenerated.WithLabelValues(serviceName, "high").Add(float64(metrics.AlertsGenerated))
	responseTime.WithLabelValues(serviceName, "api").Observe(metrics.ResponseTime / 1000)

	// Log comprehensive metrics including health data
	log.Printf("MONITOR: %s - %s (Health: %s, Platform: %s, PlatformStatus: %s, CPU: %.1f%%, Memory: %.1f%%, Events: %d, Alerts: %d, Response: %.1fms, ErrorRate: %.2f%%, Throughput: %.1f, Queue: %d, Errors: %d, Success: %d, Uptime: %.0fs, LastCheck: %s, Timestamp: %s, Heartbeat: %s, Metadata: %v)",
		serviceName, health.Status, health.ServiceName, metrics.ServiceName, metrics.Status, metrics.CPUUsage, metrics.MemoryUsage, metrics.EventsProcessed,
		metrics.AlertsGenerated, metrics.ResponseTime, metrics.ErrorRate*100, metrics.Throughput, metrics.QueueDepth,
		health.ErrorCount, health.SuccessCount, health.Uptime, health.LastCheck.Format("15:04:05"),
		metrics.Timestamp.Format("15:04:05"), metrics.LastHeartbeat.Format("15:04:05"), metrics.Metadata)
}

func getServiceStatus(serviceName string) string {
	statuses := []string{"healthy", "degraded", "unhealthy"}
	// Simulate different statuses based on service
	if serviceName == "gateway" || serviceName == "ingest" {
		return "healthy"
	}
	return statuses[time.Now().Second()%len(statuses)]
}

func getResponseTime(serviceName string) float64 {
	// Simulate response times
	baseTime := 50.0
	if serviceName == "ml" || serviceName == "sandbox" {
		baseTime = 200.0
	}
	return baseTime + float64(time.Now().Second()%100)
}

func getErrorCount(serviceName string) int64 {
	// Simulate different error rates based on service type
	baseErrors := int64(5)
	if serviceName == "ml" || serviceName == "sandbox" {
		baseErrors = 15
	}
	return baseErrors + int64(time.Now().Second()%10)
}

func getSuccessCount(serviceName string) int64 {
	// Simulate different success rates based on service type
	baseSuccess := int64(1000)
	if serviceName == "ingest" {
		baseSuccess = 5000
	}
	return baseSuccess + int64(time.Now().Second()%5000)
}

func getUptime(serviceName string) float64 {
	// Simulate different uptimes based on service type
	baseUptime := float64(time.Now().Unix() - 1640995200) // Since platform start
	if serviceName == "gateway" || serviceName == "ingest" {
		// Core services have been running longer
		baseUptime += 3600 // Add 1 hour
	}
	return baseUptime
}

func getCPUUsage(serviceName string) float64 {
	baseUsage := 20.0
	if serviceName == "ml" || serviceName == "sandbox" {
		baseUsage = 60.0
	}
	return baseUsage + float64(time.Now().Second()%30)
}

func getMemoryUsage(serviceName string) float64 {
	baseUsage := 30.0
	if serviceName == "clickhouse" {
		baseUsage = 70.0
	}
	return baseUsage + float64(time.Now().Second()%20)
}

func getEventsProcessed(serviceName string) int64 {
	baseEvents := int64(1000)
	if serviceName == "ingest" {
		baseEvents = 10000
	}
	return baseEvents + int64(time.Now().Second()%5000)
}

func getAlertsGenerated(serviceName string) int64 {
	baseAlerts := int64(10)
	if serviceName == "detect" || serviceName == "ueba" {
		baseAlerts = 100
	}
	return baseAlerts + int64(time.Now().Second()%50)
}

func getErrorRate(serviceName string) float64 {
	// Simulate different error rates based on service type
	baseRate := float64(time.Now().Second()%5) / 100.0
	if serviceName == "ml" || serviceName == "sandbox" {
		baseRate += 0.02 // Higher error rate for compute-intensive services
	}
	return baseRate
}

func getThroughput(serviceName string) float64 {
	baseThroughput := 100.0
	if serviceName == "ingest" {
		baseThroughput = 1000.0
	}
	return baseThroughput + float64(time.Now().Second()%500)
}

func getQueueDepth(serviceName string) int64 {
	// Simulate different queue depths based on service type
	baseDepth := int64(time.Now().Second() % 100)
	if serviceName == "ingest" || serviceName == "detect" {
		baseDepth += 50 // Higher queue depth for high-throughput services
	}
	return baseDepth
}

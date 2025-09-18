package database

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"
)

// MonitoringManager handles database monitoring and health checks
type MonitoringManager struct {
	dbManager    *DatabaseManager
	metrics      *DatabaseMetrics
	alerts       *AlertManager
	healthChecks map[string]*HealthCheck
	mu           sync.RWMutex
	running      bool
	stopChan     chan struct{}
}

// DatabaseMetrics holds various database performance metrics
type DatabaseMetrics struct {
	ConnectionPool struct {
		Active    int `json:"active"`
		Idle      int `json:"idle"`
		Total     int `json:"total"`
		MaxOpen   int `json:"max_open"`
		MaxIdle   int `json:"max_idle"`
	} `json:"connection_pool"`

	QueryPerformance struct {
		TotalQueries     int64         `json:"total_queries"`
		SuccessfulQueries int64        `json:"successful_queries"`
		FailedQueries    int64         `json:"failed_queries"`
		AverageLatency   time.Duration `json:"average_latency"`
		SlowQueries      int64         `json:"slow_queries"`
	} `json:"query_performance"`

	Storage struct {
		TotalSize     int64            `json:"total_size_bytes"`
		TableSizes    map[string]int64 `json:"table_sizes"`
		PartitionInfo map[string]int   `json:"partition_info"`
	} `json:"storage"`

	System struct {
		Uptime        time.Duration `json:"uptime"`
		Version       string        `json:"version"`
		CPUUsage      float64       `json:"cpu_usage"`
		MemoryUsage   int64         `json:"memory_usage"`
		DiskUsage     float64       `json:"disk_usage"`
	} `json:"system"`

	LastUpdated time.Time `json:"last_updated"`
}

// HealthCheck represents a single health check
type HealthCheck struct {
	Name        string
	Description string
	CheckFunc   func(ctx context.Context) error
	Interval    time.Duration
	Timeout     time.Duration
	LastRun     time.Time
	LastResult  error
	Status      string // "healthy", "warning", "critical"
}

// AlertManager handles database alerts
type AlertManager struct {
	alerts    []Alert
	callbacks map[string]func(Alert)
	mu        sync.RWMutex
}

// Alert represents a database alert
type Alert struct {
	ID          string    `json:"id"`
	Level       string    `json:"level"` // "info", "warning", "critical"
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
	Resolved    bool      `json:"resolved"`
	Source      string    `json:"source"`
}

// NewMonitoringManager creates a new monitoring manager
func NewMonitoringManager(dbManager *DatabaseManager) *MonitoringManager {
	mm := &MonitoringManager{
		dbManager:    dbManager,
		metrics:      &DatabaseMetrics{},
		alerts:       &AlertManager{callbacks: make(map[string]func(Alert))},
		healthChecks: make(map[string]*HealthCheck),
		stopChan:     make(chan struct{}),
	}

	mm.initializeHealthChecks()
	return mm
}

// initializeHealthChecks sets up default health checks
func (mm *MonitoringManager) initializeHealthChecks() {
	// Connection health check
	mm.AddHealthCheck(&HealthCheck{
		Name:        "connection",
		Description: "Database connection health",
		CheckFunc:   mm.checkConnection,
		Interval:    30 * time.Second,
		Timeout:     5 * time.Second,
	})

	// Query performance check
	mm.AddHealthCheck(&HealthCheck{
		Name:        "query_performance",
		Description: "Query performance monitoring",
		CheckFunc:   mm.checkQueryPerformance,
		Interval:    60 * time.Second,
		Timeout:     10 * time.Second,
	})

	// Storage health check
	mm.AddHealthCheck(&HealthCheck{
		Name:        "storage",
		Description: "Storage and disk usage monitoring",
		CheckFunc:   mm.checkStorage,
		Interval:    300 * time.Second, // 5 minutes
		Timeout:     15 * time.Second,
	})

	// Table integrity check
	mm.AddHealthCheck(&HealthCheck{
		Name:        "table_integrity",
		Description: "Table structure and data integrity",
		CheckFunc:   mm.checkTableIntegrity,
		Interval:    3600 * time.Second, // 1 hour
		Timeout:     30 * time.Second,
	})

	// Replication check (if applicable)
	mm.AddHealthCheck(&HealthCheck{
		Name:        "replication",
		Description: "Replication status monitoring",
		CheckFunc:   mm.checkReplication,
		Interval:    120 * time.Second, // 2 minutes
		Timeout:     10 * time.Second,
	})
}

// AddHealthCheck adds a new health check
func (mm *MonitoringManager) AddHealthCheck(check *HealthCheck) {
	mm.mu.Lock()
	defer mm.mu.Unlock()
	mm.healthChecks[check.Name] = check
}

// Start begins monitoring
func (mm *MonitoringManager) Start() {
	mm.mu.Lock()
	if mm.running {
		mm.mu.Unlock()
		return
	}
	mm.running = true
	mm.mu.Unlock()

	log.Println("Starting database monitoring...")

	// Start metrics collection
	go mm.metricsCollector()

	// Start health checks
	for _, check := range mm.healthChecks {
		go mm.runHealthCheck(check)
	}

	// Start alert processor
	go mm.alertProcessor()

	log.Println("Database monitoring started")
}

// Stop stops monitoring
func (mm *MonitoringManager) Stop() {
	mm.mu.Lock()
	if !mm.running {
		mm.mu.Unlock()
		return
	}
	mm.running = false
	mm.mu.Unlock()

	close(mm.stopChan)
	log.Println("Database monitoring stopped")
}

// metricsCollector collects database metrics periodically
func (mm *MonitoringManager) metricsCollector() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			mm.collectMetrics()
		case <-mm.stopChan:
			return
		}
	}
}

// collectMetrics gathers current database metrics
func (mm *MonitoringManager) collectMetrics() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	mm.mu.Lock()
	defer mm.mu.Unlock()

	// Collect connection pool metrics
	mm.collectConnectionMetrics()

	// Collect query performance metrics
	mm.collectQueryMetrics(ctx)

	// Collect storage metrics
	mm.collectStorageMetrics(ctx)

	// Collect system metrics
	mm.collectSystemMetrics(ctx)

	mm.metrics.LastUpdated = time.Now()
}

// collectConnectionMetrics collects connection pool metrics
func (mm *MonitoringManager) collectConnectionMetrics() {
	// Note: ClickHouse driver doesn't expose standard SQL stats
	// We'll track connections through our database manager
	mm.metrics.ConnectionPool.Active = mm.dbManager.activeConns
	mm.metrics.ConnectionPool.Total = mm.dbManager.activeConns
	mm.metrics.ConnectionPool.MaxOpen = 25 // From config
	mm.metrics.ConnectionPool.MaxIdle = 5  // From config
}

// collectQueryMetrics collects query performance metrics
func (mm *MonitoringManager) collectQueryMetrics(ctx context.Context) {
	// Query system tables for performance metrics
	query := `
		SELECT 
			count() as total_queries,
			countIf(exception = '') as successful_queries,
			countIf(exception != '') as failed_queries,
			avg(query_duration_ms) as avg_latency_ms,
			countIf(query_duration_ms > 1000) as slow_queries
		FROM system.query_log 
		WHERE event_time > now() - INTERVAL 5 MINUTE
	`

	rows, err := mm.dbManager.ExecuteQuery(ctx, query)
	if err != nil {
		log.Printf("Failed to collect query metrics: %v", err)
		return
	}
	defer rows.Close()

	if rows.Next() {
		var totalQueries, successfulQueries, failedQueries, slowQueries int64
		var avgLatencyMs float64

		err := rows.Scan(&totalQueries, &successfulQueries, &failedQueries, &avgLatencyMs, &slowQueries)
		if err == nil {
			mm.metrics.QueryPerformance.TotalQueries = totalQueries
			mm.metrics.QueryPerformance.SuccessfulQueries = successfulQueries
			mm.metrics.QueryPerformance.FailedQueries = failedQueries
			mm.metrics.QueryPerformance.AverageLatency = time.Duration(avgLatencyMs) * time.Millisecond
			mm.metrics.QueryPerformance.SlowQueries = slowQueries
		}
	}
}

// collectStorageMetrics collects storage and table size metrics
func (mm *MonitoringManager) collectStorageMetrics(ctx context.Context) {
	// Get table sizes
	query := `
		SELECT 
			table,
			sum(bytes_on_disk) as size_bytes,
			count() as partitions
		FROM system.parts 
		WHERE database = 'default' AND table LIKE 'musafir_%'
		GROUP BY table
	`

	rows, err := mm.dbManager.ExecuteQuery(ctx, query)
	if err != nil {
		log.Printf("Failed to collect storage metrics: %v", err)
		return
	}
	defer rows.Close()

	mm.metrics.Storage.TableSizes = make(map[string]int64)
	mm.metrics.Storage.PartitionInfo = make(map[string]int)
	var totalSize int64

	for rows.Next() {
		var tableName string
		var sizeBytes int64
		var partitions int

		if err := rows.Scan(&tableName, &sizeBytes, &partitions); err == nil {
			mm.metrics.Storage.TableSizes[tableName] = sizeBytes
			mm.metrics.Storage.PartitionInfo[tableName] = partitions
			totalSize += sizeBytes
		}
	}

	mm.metrics.Storage.TotalSize = totalSize
}

// collectSystemMetrics collects system-level metrics
func (mm *MonitoringManager) collectSystemMetrics(ctx context.Context) {
	// Get system information
	query := `
		SELECT 
			version(),
			uptime(),
			(SELECT value FROM system.metrics WHERE metric = 'MemoryTracking'),
			(SELECT value FROM system.asynchronous_metrics WHERE metric = 'jemalloc.resident' LIMIT 1)
	`

	rows, err := mm.dbManager.ExecuteQuery(ctx, query)
	if err != nil {
		log.Printf("Failed to collect system metrics: %v", err)
		return
	}
	defer rows.Close()

	if rows.Next() {
		var version string
		var uptime int64
		var memoryTracking, memoryResident int64

		err := rows.Scan(&version, &uptime, &memoryTracking, &memoryResident)
		if err == nil {
			mm.metrics.System.Version = version
			mm.metrics.System.Uptime = time.Duration(uptime) * time.Second
			mm.metrics.System.MemoryUsage = memoryTracking
		}
	}
}

// runHealthCheck runs a single health check periodically
func (mm *MonitoringManager) runHealthCheck(check *HealthCheck) {
	ticker := time.NewTicker(check.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			mm.executeHealthCheck(check)
		case <-mm.stopChan:
			return
		}
	}
}

// executeHealthCheck executes a single health check
func (mm *MonitoringManager) executeHealthCheck(check *HealthCheck) {
	ctx, cancel := context.WithTimeout(context.Background(), check.Timeout)
	defer cancel()

	check.LastRun = time.Now()
	err := check.CheckFunc(ctx)
	check.LastResult = err

	if err != nil {
		check.Status = "critical"
		mm.createAlert("critical", fmt.Sprintf("Health check failed: %s", check.Name), err.Error(), check.Name)
		log.Printf("Health check failed [%s]: %v", check.Name, err)
	} else {
		if check.Status == "critical" {
			// Health check recovered
			mm.createAlert("info", fmt.Sprintf("Health check recovered: %s", check.Name), "Health check is now passing", check.Name)
		}
		check.Status = "healthy"
	}
}

// Health check implementations
func (mm *MonitoringManager) checkConnection(ctx context.Context) error {
	// Use a simple query to test connection
	_, err := mm.dbManager.ExecuteQuery(ctx, "SELECT 1")
	return err
}

func (mm *MonitoringManager) checkQueryPerformance(ctx context.Context) error {
	start := time.Now()
	_, err := mm.dbManager.ExecuteQuery(ctx, "SELECT 1")
	duration := time.Since(start)

	if err != nil {
		return fmt.Errorf("query failed: %w", err)
	}

	if duration > 5*time.Second {
		return fmt.Errorf("query too slow: %v", duration)
	}

	return nil
}

func (mm *MonitoringManager) checkStorage(ctx context.Context) error {
	// Check disk usage
	query := `
		SELECT 
			sum(bytes_on_disk) as total_size,
			sum(free_space) as free_space
		FROM system.disks
	`

	rows, err := mm.dbManager.ExecuteQuery(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to check storage: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		var totalSize, freeSpace int64
		if err := rows.Scan(&totalSize, &freeSpace); err == nil {
			usagePercent := float64(totalSize-freeSpace) / float64(totalSize) * 100
			if usagePercent > 90 {
				return fmt.Errorf("disk usage too high: %.2f%%", usagePercent)
			}
		}
	}

	return nil
}

func (mm *MonitoringManager) checkTableIntegrity(ctx context.Context) error {
	// Check if all required tables exist
	requiredTables := []string{
		"musafir_agents", "musafir_enroll_tokens", "musafir_events",
		"musafir_telemetry", "musafir_gateway_metrics",
	}

	for _, table := range requiredTables {
		query := fmt.Sprintf("EXISTS TABLE %s", table)
		rows, err := mm.dbManager.ExecuteQuery(ctx, query)
		if err != nil {
			return fmt.Errorf("failed to check table %s: %w", table, err)
		}
		
		var exists int
		if rows.Next() {
			rows.Scan(&exists)
		}
		rows.Close()

		if exists == 0 {
			return fmt.Errorf("required table missing: %s", table)
		}
	}

	return nil
}

func (mm *MonitoringManager) checkReplication(ctx context.Context) error {
	// Check replication status if applicable
	// This is a placeholder for replication monitoring
	return nil
}

// Alert management
func (mm *MonitoringManager) createAlert(level, title, description, source string) {
	alert := Alert{
		ID:          fmt.Sprintf("%d", time.Now().UnixNano()),
		Level:       level,
		Title:       title,
		Description: description,
		Timestamp:   time.Now(),
		Source:      source,
	}

	mm.alerts.mu.Lock()
	mm.alerts.alerts = append(mm.alerts.alerts, alert)
	mm.alerts.mu.Unlock()

	// Trigger callbacks
	for _, callback := range mm.alerts.callbacks {
		go callback(alert)
	}

	log.Printf("Alert created [%s]: %s - %s", level, title, description)
}

// alertProcessor processes and manages alerts
func (mm *MonitoringManager) alertProcessor() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			mm.processAlerts()
		case <-mm.stopChan:
			return
		}
	}
}

// processAlerts processes pending alerts
func (mm *MonitoringManager) processAlerts() {
	mm.alerts.mu.Lock()
	defer mm.alerts.mu.Unlock()

	// Auto-resolve old info alerts
	for i := range mm.alerts.alerts {
		if mm.alerts.alerts[i].Level == "info" && 
		   time.Since(mm.alerts.alerts[i].Timestamp) > 24*time.Hour {
			mm.alerts.alerts[i].Resolved = true
		}
	}
}

// GetMetrics returns current database metrics
func (mm *MonitoringManager) GetMetrics() *DatabaseMetrics {
	mm.mu.RLock()
	defer mm.mu.RUnlock()
	
	// Return a copy to avoid race conditions
	metricsCopy := *mm.metrics
	return &metricsCopy
}

// GetHealthStatus returns the current health status
func (mm *MonitoringManager) GetHealthStatus() map[string]interface{} {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	status := make(map[string]interface{})
	overallHealth := "healthy"

	for name, check := range mm.healthChecks {
		checkStatus := map[string]interface{}{
			"status":      check.Status,
			"last_run":    check.LastRun,
			"description": check.Description,
		}

		if check.LastResult != nil {
			checkStatus["error"] = check.LastResult.Error()
		}

		status[name] = checkStatus

		if check.Status == "critical" {
			overallHealth = "critical"
		} else if check.Status == "warning" && overallHealth == "healthy" {
			overallHealth = "warning"
		}
	}

	status["overall"] = overallHealth
	return status
}

// GetAlerts returns current alerts
func (mm *MonitoringManager) GetAlerts() []Alert {
	mm.alerts.mu.RLock()
	defer mm.alerts.mu.RUnlock()

	// Return unresolved alerts
	var activeAlerts []Alert
	for _, alert := range mm.alerts.alerts {
		if !alert.Resolved {
			activeAlerts = append(activeAlerts, alert)
		}
	}

	return activeAlerts
}

// RegisterAlertCallback registers a callback for alerts
func (mm *MonitoringManager) RegisterAlertCallback(name string, callback func(Alert)) {
	mm.alerts.mu.Lock()
	defer mm.alerts.mu.Unlock()
	mm.alerts.callbacks[name] = callback
}

// GetMetricsJSON returns metrics as JSON
func (mm *MonitoringManager) GetMetricsJSON() ([]byte, error) {
	metrics := mm.GetMetrics()
	return json.MarshalIndent(metrics, "", "  ")
}
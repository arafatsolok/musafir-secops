package database

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// DatabaseManager manages ClickHouse connections and operations
type DatabaseManager struct {
	conn            clickhouse.Conn
	migrationMgr    *MigrationManager
	config          *Config
	healthStatus    *HealthStatus
	mu              sync.RWMutex
	connectionPool  chan clickhouse.Conn
	maxConnections  int
	activeConns     int
}

// Config holds database configuration
type Config struct {
	Host            string
	Port            int
	Database        string
	Username        string
	Password        string
	MaxConnections  int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
	Debug           bool
	Compression     bool
	Settings        map[string]interface{}
}

// HealthStatus represents database health information
type HealthStatus struct {
	IsHealthy        bool
	LastCheck        time.Time
	ConnectionCount  int
	QueryCount       int64
	ErrorCount       int64
	AvgResponseTime  time.Duration
	LastError        error
}

// NewDatabaseManager creates a new database manager
func NewDatabaseManager(config *Config) (*DatabaseManager, error) {
	if config == nil {
		config = getDefaultConfig()
	}

	dm := &DatabaseManager{
		config:         config,
		maxConnections: config.MaxConnections,
		connectionPool: make(chan clickhouse.Conn, config.MaxConnections),
		healthStatus: &HealthStatus{
			IsHealthy: false,
			LastCheck: time.Now(),
		},
	}

	// Initialize primary connection
	if err := dm.connect(); err != nil {
		return nil, fmt.Errorf("failed to establish database connection: %w", err)
	}

	// Initialize migration manager
	dm.migrationMgr = NewMigrationManager(dm.conn)
	if err := dm.migrationMgr.Initialize(); err != nil {
		log.Printf("Warning: Failed to initialize migration manager: %v", err)
	}

	// Start health monitoring
	go dm.startHealthMonitoring()

	// Initialize connection pool
	go dm.initializeConnectionPool()

	return dm, nil
}

// getDefaultConfig returns default database configuration
func getDefaultConfig() *Config {
	return &Config{
		Host:            getEnvOrDefault("CLICKHOUSE_HOST", "localhost"),
		Port:            9000,
		Database:        getEnvOrDefault("CLICKHOUSE_DATABASE", "default"),
		Username:        getEnvOrDefault("CLICKHOUSE_USERNAME", "default"),
		Password:        getEnvOrDefault("CLICKHOUSE_PASSWORD", ""),
		MaxConnections:  10,
		ConnMaxLifetime: 30 * time.Minute,
		ConnMaxIdleTime: 5 * time.Minute,
		Debug:           false,
		Compression:     true,
		Settings: map[string]interface{}{
			"max_execution_time":             300,
			"max_query_size":                 1000000,
			"max_memory_usage":               10000000000,
			"use_uncompressed_cache":         0,
			"load_balancing":                 "random",
			"max_concurrent_queries_for_user": 5,
		},
	}
}

// connect establishes a connection to ClickHouse
func (dm *DatabaseManager) connect() error {
	options := &clickhouse.Options{
		Addr: []string{fmt.Sprintf("%s:%d", dm.config.Host, dm.config.Port)},
		Auth: clickhouse.Auth{
			Database: dm.config.Database,
			Username: dm.config.Username,
			Password: dm.config.Password,
		},
		Debug: dm.config.Debug,
		Debugf: func(format string, v ...interface{}) {
			if dm.config.Debug {
				log.Printf("[ClickHouse Debug] "+format, v...)
			}
		},
		Settings: dm.config.Settings,
		Compression: &clickhouse.Compression{
			Method: clickhouse.CompressionLZ4,
		},
		DialTimeout:      30 * time.Second,
		MaxOpenConns:     dm.config.MaxConnections,
		MaxIdleConns:     dm.config.MaxConnections / 2,
		ConnMaxLifetime:  dm.config.ConnMaxLifetime,
		ConnOpenStrategy: clickhouse.ConnOpenInOrder,
	}

	if !dm.config.Compression {
		options.Compression = &clickhouse.Compression{
			Method: clickhouse.CompressionNone,
		}
	}

	conn, err := clickhouse.Open(options)
	if err != nil {
		return err
	}

	// Test the connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := conn.Ping(ctx); err != nil {
		conn.Close()
		return err
	}

	dm.conn = conn
	dm.healthStatus.IsHealthy = true
	dm.healthStatus.LastCheck = time.Now()

	log.Printf("Successfully connected to ClickHouse at %s:%d", dm.config.Host, dm.config.Port)
	return nil
}

// initializeConnectionPool creates additional connections for the pool
func (dm *DatabaseManager) initializeConnectionPool() {
	for i := 0; i < dm.maxConnections-1; i++ {
		if conn, err := dm.createConnection(); err == nil {
			select {
			case dm.connectionPool <- conn:
				dm.mu.Lock()
				dm.activeConns++
				dm.mu.Unlock()
			default:
				conn.Close()
			}
		}
	}
}

// createConnection creates a new database connection
func (dm *DatabaseManager) createConnection() (clickhouse.Conn, error) {
	options := &clickhouse.Options{
		Addr: []string{fmt.Sprintf("%s:%d", dm.config.Host, dm.config.Port)},
		Auth: clickhouse.Auth{
			Database: dm.config.Database,
			Username: dm.config.Username,
			Password: dm.config.Password,
		},
		Settings:    dm.config.Settings,
		DialTimeout: 10 * time.Second,
	}

	return clickhouse.Open(options)
}

// GetConnection returns a connection from the pool or creates a new one
func (dm *DatabaseManager) GetConnection() (clickhouse.Conn, error) {
	select {
	case conn := <-dm.connectionPool:
		// Test connection before returning
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		
		if err := conn.Ping(ctx); err != nil {
			conn.Close()
			return dm.createConnection()
		}
		return conn, nil
	default:
		return dm.createConnection()
	}
}

// ReturnConnection returns a connection to the pool
func (dm *DatabaseManager) ReturnConnection(conn clickhouse.Conn) {
	if conn == nil {
		return
	}

	select {
	case dm.connectionPool <- conn:
		// Connection returned to pool
	default:
		// Pool is full, close the connection
		conn.Close()
		dm.mu.Lock()
		dm.activeConns--
		dm.mu.Unlock()
	}
}

// ExecuteQuery executes a query with automatic connection management
func (dm *DatabaseManager) ExecuteQuery(ctx context.Context, query string, args ...interface{}) (driver.Rows, error) {
	start := time.Now()
	
	conn, err := dm.GetConnection()
	if err != nil {
		dm.updateHealthStatus(false, err, time.Since(start))
		return nil, err
	}
	defer dm.ReturnConnection(conn)

	rows, err := conn.Query(ctx, query, args...)
	dm.updateHealthStatus(err == nil, err, time.Since(start))
	
	return rows, err
}

// ExecuteCommand executes a command with automatic connection management
func (dm *DatabaseManager) ExecuteCommand(ctx context.Context, query string, args ...interface{}) error {
	start := time.Now()
	
	conn, err := dm.GetConnection()
	if err != nil {
		dm.updateHealthStatus(false, err, time.Since(start))
		return err
	}
	defer dm.ReturnConnection(conn)

	err = conn.Exec(ctx, query, args...)
	dm.updateHealthStatus(err == nil, err, time.Since(start))
	
	return err
}

// updateHealthStatus updates the health status metrics
func (dm *DatabaseManager) updateHealthStatus(success bool, err error, duration time.Duration) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	dm.healthStatus.LastCheck = time.Now()
	dm.healthStatus.QueryCount++
	
	if !success {
		dm.healthStatus.ErrorCount++
		dm.healthStatus.LastError = err
		dm.healthStatus.IsHealthy = false
	} else {
		dm.healthStatus.IsHealthy = true
		dm.healthStatus.LastError = nil
	}

	// Update average response time (simple moving average)
	if dm.healthStatus.AvgResponseTime == 0 {
		dm.healthStatus.AvgResponseTime = duration
	} else {
		dm.healthStatus.AvgResponseTime = (dm.healthStatus.AvgResponseTime + duration) / 2
	}
}

// startHealthMonitoring starts periodic health checks
func (dm *DatabaseManager) startHealthMonitoring() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		dm.performHealthCheck()
	}
}

// performHealthCheck performs a health check on the database
func (dm *DatabaseManager) performHealthCheck() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := time.Now()
	err := dm.conn.Ping(ctx)
	duration := time.Since(start)

	dm.mu.Lock()
	dm.healthStatus.LastCheck = time.Now()
	dm.healthStatus.ConnectionCount = dm.activeConns
	
	if err != nil {
		dm.healthStatus.IsHealthy = false
		dm.healthStatus.LastError = err
		log.Printf("Database health check failed: %v", err)
	} else {
		dm.healthStatus.IsHealthy = true
		dm.healthStatus.LastError = nil
	}
	
	// Update average response time (simple moving average)
	if dm.healthStatus.AvgResponseTime == 0 {
		dm.healthStatus.AvgResponseTime = duration
	} else {
		dm.healthStatus.AvgResponseTime = (dm.healthStatus.AvgResponseTime + duration) / 2
	}
	dm.mu.Unlock()

	// Log health status periodically
	if time.Now().Minute()%5 == 0 && time.Now().Second() < 30 {
		dm.logHealthStatus()
	}
}

// GetHealthStatus returns the current health status
func (dm *DatabaseManager) GetHealthStatus() *HealthStatus {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	// Return a copy to avoid race conditions
	return &HealthStatus{
		IsHealthy:        dm.healthStatus.IsHealthy,
		LastCheck:        dm.healthStatus.LastCheck,
		ConnectionCount:  dm.healthStatus.ConnectionCount,
		QueryCount:       dm.healthStatus.QueryCount,
		ErrorCount:       dm.healthStatus.ErrorCount,
		AvgResponseTime:  dm.healthStatus.AvgResponseTime,
		LastError:        dm.healthStatus.LastError,
	}
}

// logHealthStatus logs the current health status
func (dm *DatabaseManager) logHealthStatus() {
	status := dm.GetHealthStatus()
	log.Printf("Database Health: Healthy=%v, Connections=%d, Queries=%d, Errors=%d, AvgResponseTime=%v",
		status.IsHealthy, status.ConnectionCount, status.QueryCount, status.ErrorCount, status.AvgResponseTime)
}

// RunMigrations runs all pending database migrations
func (dm *DatabaseManager) RunMigrations() error {
	if dm.migrationMgr == nil {
		return fmt.Errorf("migration manager not initialized")
	}

	migrations := GetMigrationDefinitions()
	return dm.migrationMgr.MigrateUp(migrations)
}

// OptimizeDatabase performs database optimization tasks
func (dm *DatabaseManager) OptimizeDatabase() error {
	ctx := context.Background()
	
	log.Println("Starting database optimization...")

	// Optimize tables
	tables := []string{
		"musafir_events",
		"musafir_telemetry", 
		"musafir_agents",
		"musafir_gateway_metrics",
	}

	for _, table := range tables {
		log.Printf("Optimizing table: %s", table)
		if err := dm.ExecuteCommand(ctx, fmt.Sprintf("OPTIMIZE TABLE %s", table)); err != nil {
			log.Printf("Warning: Failed to optimize table %s: %v", table, err)
		}
	}

	log.Println("Database optimization completed")
	return nil
}

// Close closes all database connections
func (dm *DatabaseManager) Close() error {
	log.Println("Closing database connections...")

	// Close connection pool
	close(dm.connectionPool)
	for conn := range dm.connectionPool {
		if err := conn.Close(); err != nil {
			log.Printf("Error closing pooled connection: %v", err)
		}
	}

	// Close primary connection
	if dm.conn != nil {
		return dm.conn.Close()
	}

	return nil
}

// getEnvOrDefault returns environment variable value or default
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
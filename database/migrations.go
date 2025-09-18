package database

import (
	"context"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
)

// Migration represents a database migration
type Migration struct {
	Version     int
	Description string
	Up          string
	Down        string
	AppliedAt   time.Time
}

// MigrationManager handles database migrations
type MigrationManager struct {
	conn clickhouse.Conn
}

// NewMigrationManager creates a new migration manager
func NewMigrationManager(conn clickhouse.Conn) *MigrationManager {
	return &MigrationManager{
		conn: conn,
	}
}

// Initialize creates the migrations table if it doesn't exist
func (m *MigrationManager) Initialize() error {
	ctx := context.Background()
	
	createTable := `
	CREATE TABLE IF NOT EXISTS musafir_migrations (
		version Int32,
		description String,
		applied_at DateTime,
		checksum String
	) ENGINE = MergeTree()
	ORDER BY version`
	
	return m.conn.Exec(ctx, createTable)
}

// GetAppliedMigrations returns all applied migrations
func (m *MigrationManager) GetAppliedMigrations() ([]Migration, error) {
	ctx := context.Background()
	
	rows, err := m.conn.Query(ctx, "SELECT version, description, applied_at FROM musafir_migrations ORDER BY version")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var migrations []Migration
	for rows.Next() {
		var migration Migration
		if err := rows.Scan(&migration.Version, &migration.Description, &migration.AppliedAt); err != nil {
			return nil, err
		}
		migrations = append(migrations, migration)
	}
	
	return migrations, nil
}

// ApplyMigration applies a single migration
func (m *MigrationManager) ApplyMigration(migration Migration) error {
	ctx := context.Background()
	
	// Start transaction (ClickHouse doesn't support transactions, so we'll do best effort)
	log.Printf("Applying migration %d: %s", migration.Version, migration.Description)
	
	// Execute the migration
	if err := m.conn.Exec(ctx, migration.Up); err != nil {
		return fmt.Errorf("failed to apply migration %d: %w", migration.Version, err)
	}
	
	// Record the migration
	insertMigration := `
	INSERT INTO musafir_migrations (version, description, applied_at, checksum) 
	VALUES (?, ?, ?, ?)`
	
	checksum := fmt.Sprintf("%x", migration.Version) // Simple checksum for now
	if err := m.conn.Exec(ctx, insertMigration, migration.Version, migration.Description, time.Now(), checksum); err != nil {
		return fmt.Errorf("failed to record migration %d: %w", migration.Version, err)
	}
	
	log.Printf("Successfully applied migration %d", migration.Version)
	return nil
}

// RollbackMigration rolls back a migration
func (m *MigrationManager) RollbackMigration(migration Migration) error {
	ctx := context.Background()
	
	log.Printf("Rolling back migration %d: %s", migration.Version, migration.Description)
	
	// Execute the rollback
	if err := m.conn.Exec(ctx, migration.Down); err != nil {
		return fmt.Errorf("failed to rollback migration %d: %w", migration.Version, err)
	}
	
	// Remove the migration record
	deleteMigration := "ALTER TABLE musafir_migrations DELETE WHERE version = ?"
	if err := m.conn.Exec(ctx, deleteMigration, migration.Version); err != nil {
		return fmt.Errorf("failed to remove migration record %d: %w", migration.Version, err)
	}
	
	log.Printf("Successfully rolled back migration %d", migration.Version)
	return nil
}

// GetPendingMigrations returns migrations that haven't been applied yet
func (m *MigrationManager) GetPendingMigrations(allMigrations []Migration) ([]Migration, error) {
	applied, err := m.GetAppliedMigrations()
	if err != nil {
		return nil, err
	}
	
	appliedVersions := make(map[int]bool)
	for _, migration := range applied {
		appliedVersions[migration.Version] = true
	}
	
	var pending []Migration
	for _, migration := range allMigrations {
		if !appliedVersions[migration.Version] {
			pending = append(pending, migration)
		}
	}
	
	// Sort by version
	sort.Slice(pending, func(i, j int) bool {
		return pending[i].Version < pending[j].Version
	})
	
	return pending, nil
}

// MigrateUp applies all pending migrations
func (m *MigrationManager) MigrateUp(migrations []Migration) error {
	pending, err := m.GetPendingMigrations(migrations)
	if err != nil {
		return err
	}
	
	if len(pending) == 0 {
		log.Println("No pending migrations to apply")
		return nil
	}
	
	log.Printf("Applying %d pending migrations", len(pending))
	
	for _, migration := range pending {
		if err := m.ApplyMigration(migration); err != nil {
			return err
		}
	}
	
	log.Println("All migrations applied successfully")
	return nil
}

// GetMigrationDefinitions returns all migration definitions
func GetMigrationDefinitions() []Migration {
	return []Migration{
		{
			Version:     1,
			Description: "Create initial agent tables",
			Up: `
			CREATE TABLE IF NOT EXISTS musafir_agents (
				id String,
				token String,
				hmac String,
				hostname String,
				platform String,
				version String,
				ip_address String,
				created_at DateTime,
				last_seen DateTime,
				status Enum8('active' = 1, 'inactive' = 2, 'offline' = 3),
				metadata String
			) ENGINE = MergeTree()
			ORDER BY (id, created_at)
			PARTITION BY toYYYYMM(created_at)
			TTL created_at + INTERVAL 2 YEAR;
			
			CREATE TABLE IF NOT EXISTS musafir_enroll_tokens (
				token String,
				expires_at DateTime,
				created_at DateTime,
				created_by String,
				used_at DateTime DEFAULT '1970-01-01 00:00:00',
				used_by String DEFAULT '',
				status Enum8('active' = 1, 'used' = 2, 'expired' = 3)
			) ENGINE = MergeTree()
			ORDER BY created_at
			PARTITION BY toYYYYMM(created_at)
			TTL created_at + INTERVAL 1 YEAR;`,
			Down: `
			DROP TABLE IF EXISTS musafir_agents;
			DROP TABLE IF EXISTS musafir_enroll_tokens;`,
		},
		{
			Version:     2,
			Description: "Create security events table",
			Up: `
			CREATE TABLE IF NOT EXISTS musafir_events (
				id String,
				agent_id String,
				event_type Enum16(
					'process_start' = 1, 'process_end' = 2, 'file_access' = 3, 
					'network_connection' = 4, 'registry_change' = 5, 'threat_detected' = 6,
					'anomaly_detected' = 7, 'compliance_violation' = 8, 'user_activity' = 9,
					'system_change' = 10, 'malware_detected' = 11, 'vulnerability_found' = 12
				),
				severity Enum8('low' = 1, 'medium' = 2, 'high' = 3, 'critical' = 4),
				timestamp DateTime,
				source_ip String,
				destination_ip String,
				process_name String,
				process_id UInt32,
				user_name String,
				file_path String,
				command_line String,
				hash_sha256 String,
				parent_process String,
				network_protocol String,
				port UInt16,
				raw_data String,
				tags Array(String),
				mitre_tactics Array(String),
				mitre_techniques Array(String)
			) ENGINE = MergeTree()
			ORDER BY (agent_id, timestamp, event_type)
			PARTITION BY toYYYYMM(timestamp)
			TTL timestamp + INTERVAL 1 YEAR;`,
			Down: `DROP TABLE IF EXISTS musafir_events;`,
		},
		{
			Version:     3,
			Description: "Create telemetry and monitoring tables",
			Up: `
			CREATE TABLE IF NOT EXISTS musafir_telemetry (
				agent_id String,
				timestamp DateTime,
				cpu_usage Float32,
				memory_usage Float32,
				disk_usage Float32,
				network_in UInt64,
				network_out UInt64,
				process_count UInt32,
				active_connections UInt32,
				system_uptime UInt64,
				agent_version String,
				os_version String
			) ENGINE = MergeTree()
			ORDER BY (agent_id, timestamp)
			PARTITION BY toYYYYMM(timestamp)
			TTL timestamp + INTERVAL 6 MONTH;
			
			CREATE TABLE IF NOT EXISTS musafir_gateway_metrics (
				timestamp DateTime,
				request_count UInt64,
				error_count UInt64,
				avg_response_time Float32,
				active_connections UInt32,
				memory_usage Float32,
				cpu_usage Float32
			) ENGINE = MergeTree()
			ORDER BY timestamp
			PARTITION BY toYYYYMM(timestamp)
			TTL timestamp + INTERVAL 3 MONTH;`,
			Down: `
			DROP TABLE IF EXISTS musafir_telemetry;
			DROP TABLE IF EXISTS musafir_gateway_metrics;`,
		},
		{
			Version:     4,
			Description: "Create threat intelligence tables",
			Up: `
			CREATE TABLE IF NOT EXISTS musafir_iocs (
				id String,
				ioc_type Enum8('hash' = 1, 'ip' = 2, 'domain' = 3, 'url' = 4, 'email' = 5),
				value String,
				threat_type String,
				confidence Float32,
				source String,
				description String,
				created_at DateTime,
				expires_at DateTime,
				tags Array(String)
			) ENGINE = MergeTree()
			ORDER BY (ioc_type, value)
			PARTITION BY toYYYYMM(created_at)
			TTL expires_at;
			
			CREATE TABLE IF NOT EXISTS musafir_detection_rules (
				id String,
				name String,
				rule_type Enum8('sigma' = 1, 'yara' = 2, 'custom' = 3),
				content String,
				enabled UInt8,
				severity Enum8('low' = 1, 'medium' = 2, 'high' = 3, 'critical' = 4),
				created_at DateTime,
				updated_at DateTime,
				created_by String,
				tags Array(String),
				mitre_tactics Array(String),
				mitre_techniques Array(String)
			) ENGINE = MergeTree()
			ORDER BY (rule_type, id)
			PARTITION BY toYYYYMM(created_at);`,
			Down: `
			DROP TABLE IF EXISTS musafir_iocs;
			DROP TABLE IF EXISTS musafir_detection_rules;`,
		},
		{
			Version:     5,
			Description: "Create asset and vulnerability management tables",
			Up: `
			CREATE TABLE IF NOT EXISTS musafir_assets (
				id String,
				agent_id String,
				asset_type Enum8('server' = 1, 'workstation' = 2, 'mobile' = 3, 'iot' = 4, 'network' = 5),
				hostname String,
				ip_addresses Array(String),
				mac_addresses Array(String),
				os_name String,
				os_version String,
				domain String,
				owner String,
				location String,
				criticality Enum8('low' = 1, 'medium' = 2, 'high' = 3, 'critical' = 4),
				discovered_at DateTime,
				last_seen DateTime,
				metadata String
			) ENGINE = ReplacingMergeTree(last_seen)
			ORDER BY (id, agent_id)
			PARTITION BY toYYYYMM(discovered_at);
			
			CREATE TABLE IF NOT EXISTS musafir_vulnerabilities (
				id String,
				cve_id String,
				asset_id String,
				agent_id String,
				severity Enum8('low' = 1, 'medium' = 2, 'high' = 3, 'critical' = 4),
				cvss_score Float32,
				title String,
				description String,
				affected_software String,
				affected_version String,
				discovered_at DateTime,
				status Enum8('open' = 1, 'patched' = 2, 'mitigated' = 3, 'false_positive' = 4),
				patch_available UInt8,
				exploit_available UInt8
			) ENGINE = MergeTree()
			ORDER BY (severity, cvss_score, discovered_at)
			PARTITION BY toYYYYMM(discovered_at);`,
			Down: `
			DROP TABLE IF EXISTS musafir_assets;
			DROP TABLE IF EXISTS musafir_vulnerabilities;`,
		},
	}
}
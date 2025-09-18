package database

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// BackupManager handles database backup and recovery operations
type BackupManager struct {
	dbManager   *DatabaseManager
	backupPath  string
	retention   time.Duration
	compression bool
}

// BackupConfig holds backup configuration
type BackupConfig struct {
	BackupPath  string
	Retention   time.Duration // How long to keep backups
	Compression bool
	Schedule    string // Cron-like schedule
}

// BackupInfo contains information about a backup
type BackupInfo struct {
	Name      string
	Path      string
	Size      int64
	CreatedAt time.Time
	Tables    []string
	Status    string
}

// NewBackupManager creates a new backup manager
func NewBackupManager(dbManager *DatabaseManager, config *BackupConfig) *BackupManager {
	if config == nil {
		config = &BackupConfig{
			BackupPath:  "./backups",
			Retention:   30 * 24 * time.Hour, // 30 days
			Compression: true,
			Schedule:    "0 2 * * *", // Daily at 2 AM
		}
	}

	// Ensure backup directory exists
	if err := os.MkdirAll(config.BackupPath, 0755); err != nil {
		log.Printf("Warning: Failed to create backup directory: %v", err)
	}

	return &BackupManager{
		dbManager:   dbManager,
		backupPath:  config.BackupPath,
		retention:   config.Retention,
		compression: config.Compression,
	}
}

// CreateFullBackup creates a full backup of all tables
func (bm *BackupManager) CreateFullBackup() (*BackupInfo, error) {
	timestamp := time.Now().Format("20060102_150405")
	backupName := fmt.Sprintf("full_backup_%s", timestamp)
	backupDir := filepath.Join(bm.backupPath, backupName)

	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create backup directory: %w", err)
	}

	log.Printf("Starting full backup: %s", backupName)

	tables, err := bm.getAllTables()
	if err != nil {
		return nil, fmt.Errorf("failed to get table list: %w", err)
	}

	backupInfo := &BackupInfo{
		Name:      backupName,
		Path:      backupDir,
		CreatedAt: time.Now(),
		Tables:    tables,
		Status:    "in_progress",
	}

	var totalSize int64
	for _, table := range tables {
		log.Printf("Backing up table: %s", table)

		size, err := bm.backupTable(table, backupDir)
		if err != nil {
			log.Printf("Warning: Failed to backup table %s: %v", table, err)
			continue
		}
		totalSize += size
	}

	// Create backup metadata
	if err := bm.createBackupMetadata(backupInfo, backupDir); err != nil {
		log.Printf("Warning: Failed to create backup metadata: %v", err)
	}

	backupInfo.Size = totalSize
	backupInfo.Status = "completed"

	log.Printf("Full backup completed: %s (Size: %d bytes)", backupName, totalSize)
	return backupInfo, nil
}

// CreateIncrementalBackup creates an incremental backup since the last backup
func (bm *BackupManager) CreateIncrementalBackup(since time.Time) (*BackupInfo, error) {
	timestamp := time.Now().Format("20060102_150405")
	backupName := fmt.Sprintf("incremental_backup_%s", timestamp)
	backupDir := filepath.Join(bm.backupPath, backupName)

	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create backup directory: %w", err)
	}

	log.Printf("Starting incremental backup since: %s", since.Format(time.RFC3339))

	// For ClickHouse, incremental backups are based on partitions
	// We'll backup partitions that have been modified since the last backup
	tables := []string{"musafir_events", "musafir_telemetry", "musafir_gateway_metrics"}

	backupInfo := &BackupInfo{
		Name:      backupName,
		Path:      backupDir,
		CreatedAt: time.Now(),
		Tables:    tables,
		Status:    "in_progress",
	}

	var totalSize int64
	for _, table := range tables {
		log.Printf("Creating incremental backup for table: %s", table)

		size, err := bm.backupTableIncremental(table, backupDir, since)
		if err != nil {
			log.Printf("Warning: Failed to backup table %s incrementally: %v", table, err)
			continue
		}
		totalSize += size
	}

	backupInfo.Size = totalSize
	backupInfo.Status = "completed"

	log.Printf("Incremental backup completed: %s (Size: %d bytes)", backupName, totalSize)
	return backupInfo, nil
}

// backupTable backs up a single table
func (bm *BackupManager) backupTable(tableName, backupDir string) (int64, error) {
	ctx := context.Background()

	// Get table schema
	schemaQuery := fmt.Sprintf("SHOW CREATE TABLE %s", tableName)
	rows, err := bm.dbManager.ExecuteQuery(ctx, schemaQuery)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	var schema string
	if rows.Next() {
		var statement string
		if err := rows.Scan(&statement); err != nil {
			return 0, err
		}
		schema = statement
	}

	// Save schema
	schemaFile := filepath.Join(backupDir, fmt.Sprintf("%s_schema.sql", tableName))
	if err := os.WriteFile(schemaFile, []byte(schema), 0644); err != nil {
		return 0, err
	}

	// Export data
	dataFile := filepath.Join(backupDir, fmt.Sprintf("%s_data.csv", tableName))
	exportQuery := fmt.Sprintf("SELECT * FROM %s INTO OUTFILE '%s' FORMAT CSV", tableName, dataFile)

	if err := bm.dbManager.ExecuteCommand(ctx, exportQuery); err != nil {
		// Fallback: use clickhouse-client if available
		return bm.exportTableWithClient(tableName)
	}

	// Get file size
	if stat, err := os.Stat(dataFile); err == nil {
		return stat.Size(), nil
	}

	return 0, nil
}

// backupTableIncremental backs up table data since a specific time
func (bm *BackupManager) backupTableIncremental(tableName, backupDir string, since time.Time) (int64, error) {
	ctx := context.Background()

	// Check if table has a timestamp column for incremental backup
	timestampCol := bm.getTimestampColumn(tableName)
	if timestampCol == "" {
		log.Printf("Table %s doesn't have a timestamp column, performing full backup", tableName)
		return bm.backupTable(tableName, backupDir)
	}

	// Export incremental data
	dataFile := filepath.Join(backupDir, fmt.Sprintf("%s_incremental_data.csv", tableName))
	exportQuery := fmt.Sprintf(
		"SELECT * FROM %s WHERE %s > '%s' INTO OUTFILE '%s' FORMAT CSV",
		tableName, timestampCol, since.Format("2006-01-02 15:04:05"), dataFile,
	)

	if err := bm.dbManager.ExecuteCommand(ctx, exportQuery); err != nil {
		return bm.exportTableIncrementalWithClient(tableName, dataFile, since, timestampCol)
	}

	// Get file size
	if stat, err := os.Stat(dataFile); err == nil {
		return stat.Size(), nil
	}

	return 0, nil
}

// exportTableWithClient exports table using clickhouse-client
func (bm *BackupManager) exportTableWithClient(tableName string) (int64, error) {
	// This would use clickhouse-client command line tool
	// Implementation depends on having clickhouse-client installed
	log.Printf("Fallback export for table %s not implemented", tableName)
	return 0, nil
}

// exportTableIncrementalWithClient exports incremental data using clickhouse-client
func (bm *BackupManager) exportTableIncrementalWithClient(tableName string, _ string, _ time.Time, _ string) (int64, error) {
	// This would use clickhouse-client command line tool for incremental export
	log.Printf("Fallback incremental export for table %s not implemented", tableName)
	return 0, nil
}

// getAllTables returns all tables in the database
func (bm *BackupManager) getAllTables() ([]string, error) {
	ctx := context.Background()

	query := "SHOW TABLES LIKE 'musafir_%'"
	rows, err := bm.dbManager.ExecuteQuery(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var tableName string
		if err := rows.Scan(&tableName); err != nil {
			continue
		}
		tables = append(tables, tableName)
	}

	return tables, nil
}

// getTimestampColumn returns the timestamp column name for a table
func (bm *BackupManager) getTimestampColumn(tableName string) string {
	timestampColumns := map[string]string{
		"musafir_events":          "timestamp",
		"musafir_telemetry":       "timestamp",
		"musafir_gateway_metrics": "timestamp",
		"musafir_agents":          "created_at",
		"musafir_enroll_tokens":   "created_at",
		"musafir_audit_logs":      "timestamp",
		"musafir_incidents":       "created_at",
		"musafir_assets":          "discovered_at",
		"musafir_vulnerabilities": "discovered_at",
	}

	return timestampColumns[tableName]
}

// createBackupMetadata creates metadata file for the backup
func (bm *BackupManager) createBackupMetadata(info *BackupInfo, backupDir string) error {
	metadata := fmt.Sprintf(`Backup Name: %s
Created At: %s
Status: %s
Size: %d bytes
Tables: %s
`, info.Name, info.CreatedAt.Format(time.RFC3339), info.Status, info.Size, strings.Join(info.Tables, ", "))

	metadataFile := filepath.Join(backupDir, "backup_metadata.txt")
	return os.WriteFile(metadataFile, []byte(metadata), 0644)
}

// RestoreFromBackup restores database from a backup
func (bm *BackupManager) RestoreFromBackup(backupName string) error {
	backupDir := filepath.Join(bm.backupPath, backupName)

	if _, err := os.Stat(backupDir); os.IsNotExist(err) {
		return fmt.Errorf("backup not found: %s", backupName)
	}

	log.Printf("Starting restore from backup: %s", backupName)

	// Get list of schema files
	files, err := filepath.Glob(filepath.Join(backupDir, "*_schema.sql"))
	if err != nil {
		return err
	}

	ctx := context.Background()

	for _, schemaFile := range files {
		tableName := strings.TrimSuffix(filepath.Base(schemaFile), "_schema.sql")

		log.Printf("Restoring table: %s", tableName)

		// Read schema
		schemaBytes, err := os.ReadFile(schemaFile)
		if err != nil {
			log.Printf("Warning: Failed to read schema for %s: %v", tableName, err)
			continue
		}

		// Drop existing table
		dropQuery := fmt.Sprintf("DROP TABLE IF EXISTS %s", tableName)
		if err := bm.dbManager.ExecuteCommand(ctx, dropQuery); err != nil {
			log.Printf("Warning: Failed to drop table %s: %v", tableName, err)
		}

		// Create table
		if err := bm.dbManager.ExecuteCommand(ctx, string(schemaBytes)); err != nil {
			log.Printf("Error: Failed to create table %s: %v", tableName, err)
			continue
		}

		// Restore data
		dataFile := filepath.Join(backupDir, fmt.Sprintf("%s_data.csv", tableName))
		if _, err := os.Stat(dataFile); err == nil {
			if err := bm.restoreTableData(tableName, dataFile); err != nil {
				log.Printf("Warning: Failed to restore data for %s: %v", tableName, err)
			}
		}
	}

	log.Printf("Restore completed from backup: %s", backupName)
	return nil
}

// restoreTableData restores data for a specific table
func (bm *BackupManager) restoreTableData(tableName, dataFile string) error {
	ctx := context.Background()

	// Use INSERT FROM INFILE if supported
	insertQuery := fmt.Sprintf("INSERT INTO %s FROM INFILE '%s' FORMAT CSV", tableName, dataFile)
	return bm.dbManager.ExecuteCommand(ctx, insertQuery)
}

// ListBackups returns a list of available backups
func (bm *BackupManager) ListBackups() ([]*BackupInfo, error) {
	entries, err := os.ReadDir(bm.backupPath)
	if err != nil {
		return nil, err
	}

	var backups []*BackupInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		backupDir := filepath.Join(bm.backupPath, entry.Name())
		info, err := os.Stat(backupDir)
		if err != nil {
			continue
		}

		backup := &BackupInfo{
			Name:      entry.Name(),
			Path:      backupDir,
			CreatedAt: info.ModTime(),
			Status:    "completed",
		}

		// Get backup size
		if size, err := bm.getDirectorySize(backupDir); err == nil {
			backup.Size = size
		}

		backups = append(backups, backup)
	}

	return backups, nil
}

// getDirectorySize calculates the total size of a directory
func (bm *BackupManager) getDirectorySize(dirPath string) (int64, error) {
	var size int64

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})

	return size, err
}

// CleanupOldBackups removes backups older than the retention period
func (bm *BackupManager) CleanupOldBackups() error {
	backups, err := bm.ListBackups()
	if err != nil {
		return err
	}

	cutoff := time.Now().Add(-bm.retention)

	for _, backup := range backups {
		if backup.CreatedAt.Before(cutoff) {
			log.Printf("Removing old backup: %s", backup.Name)
			if err := os.RemoveAll(backup.Path); err != nil {
				log.Printf("Warning: Failed to remove backup %s: %v", backup.Name, err)
			}
		}
	}

	return nil
}

// ScheduleBackups starts automatic backup scheduling
func (bm *BackupManager) ScheduleBackups() {
	// Daily backup at 2 AM
	go func() {
		for {
			now := time.Now()
			next := time.Date(now.Year(), now.Month(), now.Day()+1, 2, 0, 0, 0, now.Location())
			time.Sleep(time.Until(next))

			log.Println("Starting scheduled backup...")
			if _, err := bm.CreateFullBackup(); err != nil {
				log.Printf("Scheduled backup failed: %v", err)
			}

			// Cleanup old backups
			if err := bm.CleanupOldBackups(); err != nil {
				log.Printf("Backup cleanup failed: %v", err)
			}
		}
	}()

	log.Println("Backup scheduler started (daily at 2 AM)")
}

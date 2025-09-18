# Musafir Security Platform - Database Management

This directory contains the complete database management system for the Musafir Security Platform, providing comprehensive tools for schema management, migrations, monitoring, backup, and recovery.

## Architecture Overview

The database management system is built around **ClickHouse** as the primary database, chosen for its:
- High-performance analytics and time-series data processing
- Excellent compression and storage efficiency
- Horizontal scalability
- Real-time query capabilities
- Optimized for security event processing

## Components

### 1. Database Manager (`manager.go`)
The core database management component providing:
- **Connection Management**: Connection pooling with health checks
- **Query Execution**: Optimized query execution with retry logic
- **Health Monitoring**: Continuous health checks and diagnostics
- **Migration Integration**: Seamless schema migration support

**Key Features:**
- Automatic connection recovery
- Query performance optimization
- Connection pool management
- Health check endpoints

### 2. Schema Management (`schema.sql`)
Comprehensive database schema for the security platform:

**Core Tables:**
- `musafir_agents` - Agent registration and management
- `musafir_enroll_tokens` - Agent enrollment tokens
- `musafir_events` - Security events and alerts
- `musafir_telemetry` - System telemetry data
- `musafir_gateway_metrics` - Gateway performance metrics

**Security Tables:**
- `musafir_iocs` - Indicators of Compromise
- `musafir_threat_intel` - Threat intelligence data
- `musafir_incidents` - Security incident management
- `musafir_audit_logs` - Audit trail and compliance

**Asset Management:**
- `musafir_assets` - Asset inventory
- `musafir_vulnerabilities` - Vulnerability management
- `musafir_compliance_checks` - Compliance monitoring

### 3. Migration System (`migrations.go`)
Robust database migration system featuring:
- **Version Control**: Track schema versions and changes
- **Forward/Backward Migrations**: Apply and rollback changes
- **Dependency Management**: Handle migration dependencies
- **Validation**: Verify migration integrity

**Migration Commands:**
```go
// Apply all pending migrations
migrationManager.ApplyMigrations()

// Rollback to specific version
migrationManager.RollbackToVersion(3)

// Check pending migrations
pending := migrationManager.GetPendingMigrations()
```

### 4. Monitoring System (`monitoring.go`)
Comprehensive database monitoring and alerting:

**Health Checks:**
- Connection health monitoring
- Query performance tracking
- Storage usage monitoring
- Table integrity verification
- Replication status (if applicable)

**Metrics Collection:**
- Connection pool statistics
- Query performance metrics
- Storage utilization
- System resource usage

**Alerting:**
- Real-time alert generation
- Configurable alert thresholds
- Alert callbacks and notifications
- Alert resolution tracking

### 5. Backup & Recovery (`backup.go`)
Enterprise-grade backup and recovery system:

**Backup Types:**
- **Full Backups**: Complete database backup
- **Incremental Backups**: Changes since last backup
- **Scheduled Backups**: Automated backup scheduling

**Features:**
- Compression support
- Retention policy management
- Backup verification
- Point-in-time recovery
- Automated cleanup

## Usage Examples

### Initialize Database Manager
```go
package main

import (
    "log"
    "d:/MW/database"
)

func main() {
    // Initialize database manager
    dbManager, err := database.NewDatabaseManager(&database.Config{
        DSN: "clickhouse://localhost:9000/default",
        MaxOpenConns: 25,
        MaxIdleConns: 5,
        ConnMaxLifetime: 5 * time.Minute,
    })
    if err != nil {
        log.Fatal(err)
    }
    defer dbManager.Close()

    // Initialize and apply migrations
    migrationManager := database.NewMigrationManager(dbManager)
    if err := migrationManager.ApplyMigrations(); err != nil {
        log.Fatal(err)
    }

    // Start monitoring
    monitoringManager := database.NewMonitoringManager(dbManager)
    monitoringManager.Start()
    defer monitoringManager.Stop()

    // Setup backup system
    backupManager := database.NewBackupManager(dbManager, &database.BackupConfig{
        BackupPath: "./backups",
        Retention: 30 * 24 * time.Hour,
        Compression: true,
    })
    
    // Schedule automatic backups
    backupManager.ScheduleBackups()
}
```

### Health Check Integration
```go
// Get current health status
healthStatus := monitoringManager.GetHealthStatus()
if healthStatus["overall"] != "healthy" {
    log.Printf("Database health issues detected: %+v", healthStatus)
}

// Get detailed metrics
metrics := monitoringManager.GetMetrics()
log.Printf("Query performance: %+v", metrics.QueryPerformance)
log.Printf("Storage usage: %+v", metrics.Storage)
```

### Backup Operations
```go
// Create full backup
backupInfo, err := backupManager.CreateFullBackup()
if err != nil {
    log.Printf("Backup failed: %v", err)
} else {
    log.Printf("Backup created: %s (Size: %d bytes)", backupInfo.Name, backupInfo.Size)
}

// List available backups
backups, err := backupManager.ListBackups()
for _, backup := range backups {
    log.Printf("Backup: %s, Created: %s, Size: %d", 
        backup.Name, backup.CreatedAt, backup.Size)
}

// Restore from backup
if err := backupManager.RestoreFromBackup("full_backup_20240115_020000"); err != nil {
    log.Printf("Restore failed: %v", err)
}
```

## Configuration

### Database Connection
```go
config := &database.Config{
    DSN: "clickhouse://localhost:9000/default",
    MaxOpenConns: 25,
    MaxIdleConns: 5,
    ConnMaxLifetime: 5 * time.Minute,
    ConnMaxIdleTime: 10 * time.Minute,
    HealthCheckInterval: 30 * time.Second,
}
```

### Monitoring Configuration
```go
// Register alert callback
monitoringManager.RegisterAlertCallback("email", func(alert database.Alert) {
    // Send email notification
    sendEmailAlert(alert)
})

// Custom health check
monitoringManager.AddHealthCheck(&database.HealthCheck{
    Name: "custom_check",
    Description: "Custom application health check",
    CheckFunc: func(ctx context.Context) error {
        // Custom health check logic
        return nil
    },
    Interval: 60 * time.Second,
    Timeout: 10 * time.Second,
})
```

## Performance Optimization

### Query Optimization
- Use appropriate indexes for time-series queries
- Leverage ClickHouse's columnar storage
- Implement proper partitioning strategies
- Use materialized views for complex aggregations

### Connection Management
- Configure appropriate connection pool sizes
- Monitor connection usage patterns
- Implement connection retry logic
- Use prepared statements for repeated queries

### Storage Optimization
- Regular partition pruning
- Compression settings optimization
- Storage tiering for historical data
- Index optimization

## Monitoring & Alerting

### Key Metrics to Monitor
- **Connection Pool**: Active/idle connections, pool exhaustion
- **Query Performance**: Latency, throughput, slow queries
- **Storage**: Disk usage, table sizes, partition counts
- **System**: CPU, memory, disk I/O

### Alert Thresholds
- Connection pool utilization > 80%
- Query latency > 5 seconds
- Disk usage > 90%
- Failed queries > 5% of total

## Backup Strategy

### Backup Schedule
- **Daily Full Backups**: 2:00 AM local time
- **Incremental Backups**: Every 4 hours (optional)
- **Retention**: 30 days for full backups, 7 days for incremental

### Recovery Procedures
1. Identify the appropriate backup point
2. Stop application services
3. Restore database from backup
4. Verify data integrity
5. Restart services

## Security Considerations

### Access Control
- Use dedicated database users with minimal privileges
- Implement connection encryption (TLS)
- Regular password rotation
- Network-level access restrictions

### Data Protection
- Encrypt sensitive data at rest
- Implement audit logging
- Regular security assessments
- Backup encryption

## Troubleshooting

### Common Issues
1. **Connection Timeouts**: Check network connectivity and server load
2. **Slow Queries**: Analyze query execution plans and indexes
3. **Storage Issues**: Monitor disk space and partition health
4. **Migration Failures**: Check migration logs and dependencies

### Debug Mode
Enable debug logging for detailed troubleshooting:
```go
dbManager.SetLogLevel("debug")
```

## Integration with Gateway and Agent

### Gateway Integration
The gateway uses the database manager for:
- Agent registration and management
- Event storage and retrieval
- Metrics collection
- Health status reporting

### Agent Integration
Agents interact with the database through the gateway:
- Registration and enrollment
- Event submission
- Telemetry reporting
- Configuration updates

## Future Enhancements

### Planned Features
- Multi-region replication support
- Advanced analytics and reporting
- Machine learning integration
- Enhanced security features
- Performance optimization tools

### Scalability Roadmap
- Horizontal scaling support
- Load balancing improvements
- Caching layer integration
- Archive storage implementation

## Support and Maintenance

### Regular Maintenance Tasks
- Monitor system performance
- Review and optimize queries
- Update security configurations
- Validate backup integrity
- Apply security patches

### Performance Tuning
- Regular index analysis
- Query optimization reviews
- Storage configuration updates
- Connection pool tuning

For additional support or questions, please refer to the project documentation or contact the development team.
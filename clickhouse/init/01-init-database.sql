-- Create database
CREATE DATABASE IF NOT EXISTS musafir_secops;

-- Use the database
USE musafir_secops;

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id String,
    username String,
    email String,
    password_hash String,
    first_name Nullable(String),
    last_name Nullable(String),
    role Enum8('admin' = 1, 'operator' = 2, 'analyst' = 3, 'viewer' = 4),
    is_active UInt8 DEFAULT 1,
    last_login Nullable(DateTime),
    failed_login_attempts UInt32 DEFAULT 0,
    account_locked_until Nullable(DateTime),
    password_changed_at Nullable(DateTime),
    created_at DateTime DEFAULT now(),
    updated_at DateTime DEFAULT now(),
    created_by Nullable(String),
    updated_by Nullable(String)
) ENGINE = MergeTree()
ORDER BY id
SETTINGS index_granularity = 8192;

-- Create user_sessions table
CREATE TABLE IF NOT EXISTS user_sessions (
    id String,
    user_id String,
    access_token String,
    refresh_token String,
    ip_address String,
    user_agent String,
    expires_at DateTime,
    created_at DateTime DEFAULT now(),
    last_activity DateTime DEFAULT now(),
    is_active UInt8 DEFAULT 1,
    logged_out_at Nullable(DateTime)
) ENGINE = MergeTree()
ORDER BY id
SETTINGS index_granularity = 8192;

-- Create audit_logs table
CREATE TABLE IF NOT EXISTS audit_logs (
    id String,
    user_id Nullable(String),
    action String,
    resource String,
    details String,
    ip_address String,
    created_at DateTime DEFAULT now()
) ENGINE = MergeTree()
ORDER BY created_at
SETTINGS index_granularity = 8192;

-- Create agents table
CREATE TABLE IF NOT EXISTS agents (
    id String,
    hostname String,
    ip_address String,
    os_type String,
    os_version String,
    agent_version String,
    status Enum8('online' = 1, 'offline' = 2, 'error' = 3),
    last_seen DateTime,
    created_at DateTime DEFAULT now(),
    updated_at DateTime DEFAULT now()
) ENGINE = MergeTree()
ORDER BY id
SETTINGS index_granularity = 8192;

-- Create events table for security events
CREATE TABLE IF NOT EXISTS security_events (
    id String,
    agent_id String,
    event_type String,
    severity Enum8('low' = 1, 'medium' = 2, 'high' = 3, 'critical' = 4),
    title String,
    description String,
    raw_data String,
    timestamp DateTime,
    created_at DateTime DEFAULT now()
) ENGINE = MergeTree()
ORDER BY timestamp
SETTINGS index_granularity = 8192;

-- Create network_events table
CREATE TABLE IF NOT EXISTS network_events (
    id String,
    agent_id String,
    source_ip String,
    destination_ip String,
    source_port UInt16,
    destination_port UInt16,
    protocol String,
    bytes_sent UInt64,
    bytes_received UInt64,
    timestamp DateTime,
    created_at DateTime DEFAULT now()
) ENGINE = MergeTree()
ORDER BY timestamp
SETTINGS index_granularity = 8192;

-- Create process_events table
CREATE TABLE IF NOT EXISTS process_events (
    id String,
    agent_id String,
    process_name String,
    process_id UInt32,
    parent_process_id UInt32,
    command_line String,
    user_name String,
    action Enum8('start' = 1, 'stop' = 2, 'modify' = 3),
    timestamp DateTime,
    created_at DateTime DEFAULT now()
) ENGINE = MergeTree()
ORDER BY timestamp
SETTINGS index_granularity = 8192;

-- Create file_events table
CREATE TABLE IF NOT EXISTS file_events (
    id String,
    agent_id String,
    file_path String,
    file_name String,
    action Enum8('create' = 1, 'modify' = 2, 'delete' = 3, 'access' = 4),
    user_name String,
    process_name String,
    timestamp DateTime,
    created_at DateTime DEFAULT now()
) ENGINE = MergeTree()
ORDER BY timestamp
SETTINGS index_granularity = 8192;

-- ========================================
-- THREAT DETECTION & ANALYSIS TABLES
-- ========================================

-- Create IOC (Indicators of Compromise) table
CREATE TABLE IF NOT EXISTS ioc_indicators (
    id String,
    type Enum8('hash' = 1, 'ip' = 2, 'domain' = 3, 'url' = 4, 'file_path' = 5, 'registry' = 6, 'email' = 7),
    value String,
    description String,
    severity Enum8('low' = 1, 'medium' = 2, 'high' = 3, 'critical' = 4),
    source String,
    first_seen DateTime,
    last_seen DateTime,
    tags Array(String),
    confidence Float32 DEFAULT 0.0,
    is_active UInt8 DEFAULT 1,
    created_at DateTime DEFAULT now(),
    updated_at DateTime DEFAULT now(),
    created_by Nullable(String)
) ENGINE = MergeTree()
ORDER BY (type, value)
SETTINGS index_granularity = 8192;

-- Create threat intelligence feeds table
CREATE TABLE IF NOT EXISTS threat_intel_feeds (
    id String,
    name String,
    description String,
    feed_type Enum8('commercial' = 1, 'open_source' = 2, 'custom' = 3, 'government' = 4),
    url Nullable(String),
    api_key Nullable(String),
    update_frequency UInt32 DEFAULT 3600, -- seconds
    last_updated Nullable(DateTime),
    is_enabled UInt8 DEFAULT 1,
    total_indicators UInt64 DEFAULT 0,
    created_at DateTime DEFAULT now(),
    updated_at DateTime DEFAULT now()
) ENGINE = MergeTree()
ORDER BY id
SETTINGS index_granularity = 8192;

-- Create behavioral analysis rules table
CREATE TABLE IF NOT EXISTS behavior_rules (
    id String,
    name String,
    description String,
    category Enum8('execution' = 1, 'persistence' = 2, 'privilege_escalation' = 3, 'defense_evasion' = 4, 'credential_access' = 5, 'discovery' = 6, 'lateral_movement' = 7, 'collection' = 8, 'command_control' = 9, 'exfiltration' = 10, 'impact' = 11),
    severity Enum8('low' = 1, 'medium' = 2, 'high' = 3, 'critical' = 4),
    conditions String, -- JSON string of conditions
    actions Array(String),
    is_enabled UInt8 DEFAULT 1,
    false_positive_rate Float32 DEFAULT 0.0,
    detection_count UInt64 DEFAULT 0,
    created_at DateTime DEFAULT now(),
    updated_at DateTime DEFAULT now(),
    created_by Nullable(String)
) ENGINE = MergeTree()
ORDER BY id
SETTINGS index_granularity = 8192;

-- Create threat events table (detected threats)
CREATE TABLE IF NOT EXISTS threat_events (
    id String,
    agent_id String,
    event_type Enum8('ioc_match' = 1, 'behavioral_detection' = 2, 'anomaly_detection' = 3, 'signature_match' = 4),
    threat_level Enum8('low' = 1, 'medium' = 2, 'high' = 3, 'critical' = 4),
    title String,
    description String,
    ioc_id Nullable(String),
    rule_id Nullable(String),
    process_info Nullable(String), -- JSON
    network_info Nullable(String), -- JSON
    file_info Nullable(String), -- JSON
    evidence String, -- JSON
    confidence Float32,
    status Enum8('new' = 1, 'investigating' = 2, 'confirmed' = 3, 'false_positive' = 4, 'resolved' = 5),
    assigned_to Nullable(String),
    timestamp DateTime,
    created_at DateTime DEFAULT now(),
    updated_at DateTime DEFAULT now()
) ENGINE = MergeTree()
ORDER BY timestamp
SETTINGS index_granularity = 8192;

-- Create threat alerts table (real-time notifications)
CREATE TABLE IF NOT EXISTS threat_alerts (
    id String,
    threat_event_id String,
    alert_type Enum8('email' = 1, 'sms' = 2, 'webhook' = 3, 'dashboard' = 4, 'syslog' = 5),
    severity Enum8('low' = 1, 'medium' = 2, 'high' = 3, 'critical' = 4),
    title String,
    message String,
    recipients Array(String),
    delivery_status Enum8('pending' = 1, 'sent' = 2, 'delivered' = 3, 'failed' = 4),
    retry_count UInt8 DEFAULT 0,
    metadata String, -- JSON for additional alert data
    created_at DateTime DEFAULT now(),
    sent_at Nullable(DateTime),
    delivered_at Nullable(DateTime)
) ENGINE = MergeTree()
ORDER BY created_at
SETTINGS index_granularity = 8192;

-- Create threat hunting queries table
CREATE TABLE IF NOT EXISTS threat_hunting_queries (
    id String,
    name String,
    description String,
    query_text String,
    query_type Enum8('clickhouse' = 1, 'kql' = 2, 'splunk' = 3, 'elastic' = 4),
    category String,
    severity Enum8('low' = 1, 'medium' = 2, 'high' = 3, 'critical' = 4),
    tags Array(String),
    is_scheduled UInt8 DEFAULT 0,
    schedule_cron Nullable(String),
    last_executed Nullable(DateTime),
    execution_count UInt64 DEFAULT 0,
    created_at DateTime DEFAULT now(),
    updated_at DateTime DEFAULT now(),
    created_by String
) ENGINE = MergeTree()
ORDER BY id
SETTINGS index_granularity = 8192;

-- Create threat intelligence enrichment table
CREATE TABLE IF NOT EXISTS threat_enrichment (
    id String,
    indicator_value String,
    indicator_type String,
    enrichment_source String,
    enrichment_data String, -- JSON with additional context
    reputation_score Float32,
    malware_families Array(String),
    attack_techniques Array(String),
    geolocation String, -- JSON
    whois_data Nullable(String), -- JSON
    created_at DateTime DEFAULT now(),
    updated_at DateTime DEFAULT now()
) ENGINE = MergeTree()
ORDER BY (indicator_type, indicator_value)
SETTINGS index_granularity = 8192;
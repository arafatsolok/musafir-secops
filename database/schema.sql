-- ClickHouse Database Schema for Musafir Security Platform
-- This file contains the complete database schema for all components

-- =====================================================
-- CORE AGENT MANAGEMENT TABLES
-- =====================================================

-- Agents table - stores registered agents
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
    metadata String -- JSON metadata
) ENGINE = MergeTree()
ORDER BY (id, created_at)
PARTITION BY toYYYYMM(created_at)
TTL created_at + INTERVAL 2 YEAR;

-- Enrollment tokens table
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
TTL created_at + INTERVAL 1 YEAR;

-- =====================================================
-- SECURITY EVENTS AND TELEMETRY
-- =====================================================

-- Security events table - main event storage
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
    raw_data String, -- JSON raw event data
    tags Array(String),
    mitre_tactics Array(String),
    mitre_techniques Array(String)
) ENGINE = MergeTree()
ORDER BY (agent_id, timestamp, event_type)
PARTITION BY toYYYYMM(timestamp)
TTL timestamp + INTERVAL 1 YEAR;

-- System telemetry table
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

-- =====================================================
-- THREAT INTELLIGENCE AND DETECTION
-- =====================================================

-- IOC (Indicators of Compromise) table
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

-- Threat detection rules
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
PARTITION BY toYYYYMM(created_at);

-- =====================================================
-- INCIDENT MANAGEMENT
-- =====================================================

-- Incidents table
CREATE TABLE IF NOT EXISTS musafir_incidents (
    id String,
    title String,
    description String,
    severity Enum8('low' = 1, 'medium' = 2, 'high' = 3, 'critical' = 4),
    status Enum8('open' = 1, 'investigating' = 2, 'resolved' = 3, 'closed' = 4),
    assigned_to String,
    created_at DateTime,
    updated_at DateTime,
    resolved_at DateTime DEFAULT '1970-01-01 00:00:00',
    tags Array(String),
    affected_assets Array(String),
    related_events Array(String)
) ENGINE = MergeTree()
ORDER BY (status, severity, created_at)
PARTITION BY toYYYYMM(created_at);

-- =====================================================
-- COMPLIANCE AND AUDIT
-- =====================================================

-- Compliance checks table
CREATE TABLE IF NOT EXISTS musafir_compliance (
    id String,
    agent_id String,
    framework String, -- CIS, NIST, PCI-DSS, etc.
    control_id String,
    control_name String,
    status Enum8('pass' = 1, 'fail' = 2, 'not_applicable' = 3),
    timestamp DateTime,
    details String,
    remediation String
) ENGINE = MergeTree()
ORDER BY (agent_id, framework, timestamp)
PARTITION BY toYYYYMM(timestamp)
TTL timestamp + INTERVAL 3 YEAR;

-- Audit logs table
CREATE TABLE IF NOT EXISTS musafir_audit_logs (
    id String,
    user_id String,
    action String,
    resource String,
    timestamp DateTime,
    ip_address String,
    user_agent String,
    result Enum8('success' = 1, 'failure' = 2),
    details String
) ENGINE = MergeTree()
ORDER BY (user_id, timestamp)
PARTITION BY toYYYYMM(timestamp)
TTL timestamp + INTERVAL 7 YEAR;

-- =====================================================
-- ASSET INVENTORY
-- =====================================================

-- Assets table
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
    metadata String -- JSON metadata
) ENGINE = ReplacingMergeTree(last_seen)
ORDER BY (id, agent_id)
PARTITION BY toYYYYMM(discovered_at);

-- Software inventory
CREATE TABLE IF NOT EXISTS musafir_software (
    asset_id String,
    agent_id String,
    name String,
    version String,
    vendor String,
    install_date DateTime,
    last_seen DateTime,
    file_path String,
    size UInt64,
    hash_sha256 String
) ENGINE = ReplacingMergeTree(last_seen)
ORDER BY (asset_id, name, version)
PARTITION BY toYYYYMM(last_seen);

-- =====================================================
-- VULNERABILITY MANAGEMENT
-- =====================================================

-- Vulnerabilities table
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
PARTITION BY toYYYYMM(discovered_at);

-- =====================================================
-- PERFORMANCE AND MONITORING
-- =====================================================

-- Gateway metrics
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
TTL timestamp + INTERVAL 3 MONTH;

-- Service health status
CREATE TABLE IF NOT EXISTS musafir_service_health (
    service_name String,
    timestamp DateTime,
    status Enum8('healthy' = 1, 'degraded' = 2, 'unhealthy' = 3),
    response_time Float32,
    error_message String
) ENGINE = MergeTree()
ORDER BY (service_name, timestamp)
PARTITION BY toYYYYMM(timestamp)
TTL timestamp + INTERVAL 1 MONTH;
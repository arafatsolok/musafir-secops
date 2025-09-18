-- Enhanced User Management Schema for Musafir Security Platform
-- This file contains additional tables for advanced user management features

-- =====================================================
-- USER MANAGEMENT CORE TABLES
-- =====================================================

-- Users table - enhanced with new fields
CREATE TABLE IF NOT EXISTS musafir_users (
    id String,
    username String,
    email String,
    password_hash String,
    first_name String,
    last_name String,
    department String,
    role_id String,
    status Enum8('active' = 1, 'inactive' = 2, 'locked' = 3, 'suspended' = 4),
    mfa_enabled UInt8 DEFAULT 0,
    mfa_secret String DEFAULT '',
    hardware_token_id String DEFAULT '',
    last_login DateTime DEFAULT '1970-01-01 00:00:00',
    last_password_change DateTime DEFAULT '1970-01-01 00:00:00',
    failed_login_attempts UInt8 DEFAULT 0,
    account_locked_until DateTime DEFAULT '1970-01-01 00:00:00',
    created_at DateTime,
    updated_at DateTime,
    created_by String,
    metadata String -- JSON metadata for additional fields
) ENGINE = MergeTree()
ORDER BY (id, username)
PARTITION BY toYYYYMM(created_at);

-- User Groups/Organizational Units table
CREATE TABLE IF NOT EXISTS musafir_user_groups (
    id String,
    name String,
    description String,
    parent_group_id String DEFAULT '',
    group_type Enum8('department' = 1, 'team' = 2, 'project' = 3, 'custom' = 4),
    created_at DateTime,
    updated_at DateTime,
    created_by String,
    metadata String -- JSON metadata
) ENGINE = MergeTree()
ORDER BY (id, name)
PARTITION BY toYYYYMM(created_at);

-- User Group Memberships table
CREATE TABLE IF NOT EXISTS musafir_user_group_memberships (
    user_id String,
    group_id String,
    role_in_group String DEFAULT 'member',
    assigned_at DateTime,
    assigned_by String,
    expires_at DateTime DEFAULT '2099-12-31 23:59:59'
) ENGINE = MergeTree()
ORDER BY (user_id, group_id)
PARTITION BY toYYYYMM(assigned_at);

-- =====================================================
-- SESSION MANAGEMENT
-- =====================================================

-- User Sessions table
CREATE TABLE IF NOT EXISTS musafir_user_sessions (
    session_id String,
    user_id String,
    ip_address String,
    user_agent String,
    device_fingerprint String,
    location String DEFAULT '',
    created_at DateTime,
    last_activity DateTime,
    expires_at DateTime,
    status Enum8('active' = 1, 'expired' = 2, 'terminated' = 3, 'forced_logout' = 4),
    logout_reason String DEFAULT '',
    metadata String -- JSON metadata for session details
) ENGINE = MergeTree()
ORDER BY (user_id, created_at)
PARTITION BY toYYYYMM(created_at)
TTL expires_at + INTERVAL 30 DAY;

-- Session Activities table
CREATE TABLE IF NOT EXISTS musafir_session_activities (
    session_id String,
    user_id String,
    activity_type Enum16(
        'login' = 1, 'logout' = 2, 'page_view' = 3, 'action' = 4,
        'api_call' = 5, 'file_access' = 6, 'settings_change' = 7,
        'password_change' = 8, 'mfa_challenge' = 9, 'privilege_escalation' = 10
    ),
    timestamp DateTime,
    ip_address String,
    resource String,
    action_details String,
    result Enum8('success' = 1, 'failure' = 2, 'blocked' = 3),
    risk_score Float32 DEFAULT 0.0
) ENGINE = MergeTree()
ORDER BY (user_id, timestamp)
PARTITION BY toYYYYMM(timestamp)
TTL timestamp + INTERVAL 1 YEAR;

-- =====================================================
-- MULTI-FACTOR AUTHENTICATION
-- =====================================================

-- MFA Devices table
CREATE TABLE IF NOT EXISTS musafir_mfa_devices (
    id String,
    user_id String,
    device_type Enum8('totp' = 1, 'sms' = 2, 'email' = 3, 'hardware_token' = 4, 'webauthn' = 5),
    device_name String,
    device_identifier String, -- Phone number, email, or hardware token ID
    secret_key String DEFAULT '', -- For TOTP
    public_key String DEFAULT '', -- For WebAuthn
    credential_id String DEFAULT '', -- For WebAuthn
    is_primary UInt8 DEFAULT 0,
    is_active UInt8 DEFAULT 1,
    created_at DateTime,
    last_used DateTime DEFAULT '1970-01-01 00:00:00',
    metadata String -- JSON metadata for device-specific data
) ENGINE = MergeTree()
ORDER BY (user_id, device_type)
PARTITION BY toYYYYMM(created_at);

-- MFA Challenges table
CREATE TABLE IF NOT EXISTS musafir_mfa_challenges (
    challenge_id String,
    user_id String,
    device_id String,
    challenge_type Enum8('login' = 1, 'transaction' = 2, 'admin_action' = 3),
    challenge_data String, -- Encrypted challenge data
    created_at DateTime,
    expires_at DateTime,
    completed_at DateTime DEFAULT '1970-01-01 00:00:00',
    status Enum8('pending' = 1, 'completed' = 2, 'failed' = 3, 'expired' = 4),
    attempts UInt8 DEFAULT 0,
    ip_address String,
    user_agent String
) ENGINE = MergeTree()
ORDER BY (user_id, created_at)
PARTITION BY toYYYYMM(created_at)
TTL expires_at + INTERVAL 7 DAY;

-- =====================================================
-- USER BEHAVIOR ANALYTICS
-- =====================================================

-- User Behavior Patterns table
CREATE TABLE IF NOT EXISTS musafir_user_behavior_patterns (
    user_id String,
    pattern_type Enum16(
        'login_time' = 1, 'login_location' = 2, 'device_usage' = 3,
        'resource_access' = 4, 'action_frequency' = 5, 'navigation_pattern' = 6,
        'session_duration' = 7, 'api_usage' = 8, 'file_access_pattern' = 9,
        'privilege_usage' = 10
    ),
    pattern_data String, -- JSON data containing pattern details
    confidence_score Float32,
    created_at DateTime,
    updated_at DateTime,
    valid_until DateTime
) ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (user_id, pattern_type)
PARTITION BY toYYYYMM(created_at);

-- Anomaly Detection Results table
CREATE TABLE IF NOT EXISTS musafir_user_anomalies (
    id String,
    user_id String,
    anomaly_type Enum16(
        'unusual_login_time' = 1, 'new_location' = 2, 'new_device' = 3,
        'privilege_escalation' = 4, 'unusual_resource_access' = 5,
        'suspicious_activity' = 6, 'failed_authentication' = 7,
        'concurrent_sessions' = 8, 'data_exfiltration' = 9, 'policy_violation' = 10
    ),
    severity Enum8('low' = 1, 'medium' = 2, 'high' = 3, 'critical' = 4),
    confidence_score Float32,
    description String,
    detected_at DateTime,
    session_id String DEFAULT '',
    ip_address String,
    evidence String, -- JSON evidence data
    status Enum8('new' = 1, 'investigating' = 2, 'resolved' = 3, 'false_positive' = 4),
    resolved_at DateTime DEFAULT '1970-01-01 00:00:00',
    resolved_by String DEFAULT ''
) ENGINE = MergeTree()
ORDER BY (severity, detected_at)
PARTITION BY toYYYYMM(detected_at)
TTL detected_at + INTERVAL 2 YEAR;

-- =====================================================
-- BULK OPERATIONS
-- =====================================================

-- Bulk Import Jobs table
CREATE TABLE IF NOT EXISTS musafir_bulk_import_jobs (
    job_id String,
    job_type Enum8('user_import' = 1, 'user_export' = 2, 'group_import' = 3, 'role_import' = 4),
    filename String,
    file_size UInt64,
    total_records UInt32,
    processed_records UInt32,
    successful_records UInt32,
    failed_records UInt32,
    status Enum8('pending' = 1, 'processing' = 2, 'completed' = 3, 'failed' = 4, 'cancelled' = 5),
    created_at DateTime,
    started_at DateTime DEFAULT '1970-01-01 00:00:00',
    completed_at DateTime DEFAULT '1970-01-01 00:00:00',
    created_by String,
    error_log String DEFAULT '', -- JSON array of errors
    result_file_path String DEFAULT ''
) ENGINE = MergeTree()
ORDER BY (created_at, job_type)
PARTITION BY toYYYYMM(created_at)
TTL created_at + INTERVAL 1 YEAR;

-- =====================================================
-- PASSWORD POLICIES
-- =====================================================

-- Password Policies table
CREATE TABLE IF NOT EXISTS musafir_password_policies (
    id String,
    name String,
    description String,
    min_length UInt8 DEFAULT 8,
    max_length UInt8 DEFAULT 128,
    require_uppercase UInt8 DEFAULT 1,
    require_lowercase UInt8 DEFAULT 1,
    require_numbers UInt8 DEFAULT 1,
    require_special_chars UInt8 DEFAULT 1,
    forbidden_patterns Array(String), -- Common passwords, patterns to avoid
    max_age_days UInt16 DEFAULT 90,
    history_count UInt8 DEFAULT 5, -- Number of previous passwords to remember
    lockout_threshold UInt8 DEFAULT 5,
    lockout_duration_minutes UInt16 DEFAULT 30,
    is_active UInt8 DEFAULT 1,
    applies_to_groups Array(String), -- Group IDs this policy applies to
    created_at DateTime,
    updated_at DateTime,
    created_by String
) ENGINE = MergeTree()
ORDER BY (id, name)
PARTITION BY toYYYYMM(created_at);

-- Password History table
CREATE TABLE IF NOT EXISTS musafir_password_history (
    user_id String,
    password_hash String,
    created_at DateTime,
    expires_at DateTime
) ENGINE = MergeTree()
ORDER BY (user_id, created_at)
PARTITION BY toYYYYMM(created_at)
TTL expires_at;

-- =====================================================
-- INDEXES FOR PERFORMANCE
-- =====================================================

-- Create materialized views for common queries
CREATE MATERIALIZED VIEW IF NOT EXISTS musafir_active_sessions_mv
ENGINE = AggregatingMergeTree()
ORDER BY (user_id, toStartOfHour(last_activity))
AS SELECT
    user_id,
    toStartOfHour(last_activity) as hour,
    count() as session_count,
    uniq(ip_address) as unique_ips,
    max(last_activity) as latest_activity
FROM musafir_user_sessions
WHERE status = 1 -- active sessions only
GROUP BY user_id, toStartOfHour(last_activity);

CREATE MATERIALIZED VIEW IF NOT EXISTS musafir_user_login_stats_mv
ENGINE = AggregatingMergeTree()
ORDER BY (user_id, toDate(timestamp))
AS SELECT
    user_id,
    toDate(timestamp) as date,
    countIf(activity_type = 1 AND result = 1) as successful_logins,
    countIf(activity_type = 1 AND result = 2) as failed_logins,
    uniq(ip_address) as unique_ips,
    min(timestamp) as first_login,
    max(timestamp) as last_login
FROM musafir_session_activities
WHERE activity_type = 1 -- login activities only
GROUP BY user_id, toDate(timestamp);
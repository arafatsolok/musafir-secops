package models

import "time"

// Threat represents a security threat
type Threat struct {
	ID          string    `json:"id" db:"id"`
	Type        string    `json:"type" db:"type"`
	Severity    string    `json:"severity" db:"severity"`
	Status      string    `json:"status" db:"status"`
	Source      string    `json:"source" db:"source"`
	Description string    `json:"description" db:"description"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// IOC represents an Indicator of Compromise
type IOC struct {
	ID          string    `json:"id" db:"id"`
	Type        string    `json:"type" db:"type"`
	Value       string    `json:"value" db:"value"`
	Source      string    `json:"source" db:"source"`
	Confidence  int       `json:"confidence" db:"confidence"`
	Description string    `json:"description" db:"description"`
	Tags        []string  `json:"tags" db:"tags"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// ThreatFeed represents a threat intelligence feed
type ThreatFeed struct {
	ID             string    `json:"id" db:"id"`
	Name           string    `json:"name" db:"name"`
	Description    string    `json:"description" db:"description"`
	URL            string    `json:"url" db:"url"`
	FeedType       string    `json:"feed_type" db:"feed_type"`
	Format         string    `json:"format" db:"format"`
	UpdateInterval int       `json:"update_interval" db:"update_interval"`
	IsActive       bool      `json:"is_active" db:"is_active"`
	LastUpdate     time.Time `json:"last_update" db:"last_update"`
	Status         string    `json:"status" db:"status"`
	RecordCount    int       `json:"record_count" db:"record_count"`
	ErrorMessage   string    `json:"error_message" db:"error_message"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time `json:"updated_at" db:"updated_at"`
}

// Statistics represents system statistics
type Statistics struct {
	TotalThreats     int `json:"total_threats"`
	ActiveThreats    int `json:"active_threats"`
	ResolvedThreats  int `json:"resolved_threats"`
	TotalIOCs        int `json:"total_iocs"`
	TotalThreatFeeds int `json:"total_threat_feeds"`
	ActiveFeeds      int `json:"active_feeds"`
}
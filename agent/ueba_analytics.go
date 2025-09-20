//go:build windows

package main

import (
	"fmt"
	"log"
	"sort"
	"strings"
	"time"
)

// UEBAAnalytics manages User and Entity Behavior Analytics
type UEBAAnalytics struct {
	userProfiles   map[string]*UserProfile
	entityProfiles map[string]*EntityProfile
	behaviorRules  []BehaviorRule
	anomalies      []Anomaly
	riskScores     map[string]float64
	learningPeriod time.Duration
	alertThreshold float64
}

// UserProfile represents a user's behavioral profile
type UserProfile struct {
	UserID          string                 `json:"user_id"`
	Username        string                 `json:"username"`
	Domain          string                 `json:"domain"`
	FirstSeen       time.Time              `json:"first_seen"`
	LastSeen        time.Time              `json:"last_seen"`
	LoginPatterns   LoginPattern           `json:"login_patterns"`
	AccessPatterns  AccessPattern          `json:"access_patterns"`
	NetworkPatterns NetworkPattern         `json:"network_patterns"`
	ProcessPatterns ProcessPattern         `json:"process_patterns"`
	RiskScore       float64                `json:"risk_score"`
	Anomalies       []UserAnomaly          `json:"anomalies"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// EntityProfile represents an entity's (computer/device) behavioral profile
type EntityProfile struct {
	EntityID        string                 `json:"entity_id"`
	EntityName      string                 `json:"entity_name"`
	EntityType      string                 `json:"entity_type"` // workstation, server, mobile, etc.
	FirstSeen       time.Time              `json:"first_seen"`
	LastSeen        time.Time              `json:"last_seen"`
	NetworkPatterns NetworkPattern         `json:"network_patterns"`
	ProcessPatterns ProcessPattern         `json:"process_patterns"`
	FilePatterns    FilePattern            `json:"file_patterns"`
	ServicePatterns ServicePattern         `json:"service_patterns"`
	RiskScore       float64                `json:"risk_score"`
	Anomalies       []EntityAnomaly        `json:"anomalies"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// LoginPattern represents user login behavior patterns
type LoginPattern struct {
	TypicalHours    []int              `json:"typical_hours"`    // Hours of day (0-23)
	TypicalDays     []int              `json:"typical_days"`     // Days of week (0-6)
	LoginFrequency  map[string]int     `json:"login_frequency"`  // Daily login counts
	FailedAttempts  map[string]int     `json:"failed_attempts"`  // Failed login attempts
	LoginSources    map[string]int     `json:"login_sources"`    // Source IPs/machines
	SessionDuration map[string]float64 `json:"session_duration"` // Average session durations
}

// AccessPattern represents user access behavior patterns
type AccessPattern struct {
	FilesAccessed    map[string]int     `json:"files_accessed"`    // File access frequency
	FoldersAccessed  map[string]int     `json:"folders_accessed"`  // Folder access frequency
	ApplicationsUsed map[string]int     `json:"applications_used"` // Application usage frequency
	PermissionsUsed  map[string]int     `json:"permissions_used"`  // Permissions exercised
	DataVolume       map[string]float64 `json:"data_volume"`       // Data transfer volumes
}

// NetworkPattern represents network behavior patterns
type NetworkPattern struct {
	Connections  map[string]int     `json:"connections"`   // Destination connections
	Protocols    map[string]int     `json:"protocols"`     // Protocol usage
	Ports        map[string]int     `json:"ports"`         // Port usage
	DataTransfer map[string]float64 `json:"data_transfer"` // Data transfer patterns
	DNSQueries   map[string]int     `json:"dns_queries"`   // DNS query patterns
	GeoLocations map[string]int     `json:"geo_locations"` // Geographic locations
}

// ProcessPattern represents process execution patterns
type ProcessPattern struct {
	ProcessNames    map[string]int     `json:"process_names"`    // Process execution frequency
	CommandLines    map[string]int     `json:"command_lines"`    // Command line patterns
	ParentProcesses map[string]int     `json:"parent_processes"` // Parent process relationships
	ExecutionTimes  map[string][]int   `json:"execution_times"`  // Execution time patterns
	ResourceUsage   map[string]float64 `json:"resource_usage"`   // CPU/Memory usage patterns
}

// FilePattern represents file operation patterns
type FilePattern struct {
	FilesCreated  map[string]int `json:"files_created"`  // File creation patterns
	FilesModified map[string]int `json:"files_modified"` // File modification patterns
	FilesDeleted  map[string]int `json:"files_deleted"`  // File deletion patterns
	FileTypes     map[string]int `json:"file_types"`     // File type patterns
	FileLocations map[string]int `json:"file_locations"` // File location patterns
}

// ServicePattern represents service operation patterns
type ServicePattern struct {
	ServicesStarted map[string]int `json:"services_started"` // Service start patterns
	ServicesStopped map[string]int `json:"services_stopped"` // Service stop patterns
	ServiceChanges  map[string]int `json:"service_changes"`  // Service configuration changes
}

// Anomaly represents a detected behavioral anomaly
type Anomaly struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	Type        string                 `json:"type"` // user, entity, network, process, file
	Severity    string                 `json:"severity"`
	Score       float64                `json:"score"`
	Subject     string                 `json:"subject"` // User ID or Entity ID
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Evidence    map[string]interface{} `json:"evidence"`
	RuleID      string                 `json:"rule_id"`
	Status      string                 `json:"status"` // new, investigating, resolved, false_positive
	Context     AnomalyContext         `json:"context"`
}

// UserAnomaly represents a user-specific anomaly
type UserAnomaly struct {
	Anomaly
	AnomalyType string `json:"anomaly_type"` // login, access, privilege, behavior
}

// EntityAnomaly represents an entity-specific anomaly
type EntityAnomaly struct {
	Anomaly
	AnomalyType string `json:"anomaly_type"` // network, process, file, service, configuration
}

// AnomalyContext provides additional context for an anomaly
type AnomalyContext struct {
	BaselineValue    interface{} `json:"baseline_value"`
	ObservedValue    interface{} `json:"observed_value"`
	DeviationPercent float64     `json:"deviation_percent"`
	HistoricalData   []float64   `json:"historical_data"`
	PeerComparison   float64     `json:"peer_comparison"`
}

// NewUEBAAnalytics creates a new UEBA analytics engine
func NewUEBAAnalytics() *UEBAAnalytics {
	ueba := &UEBAAnalytics{
		userProfiles:   make(map[string]*UserProfile),
		entityProfiles: make(map[string]*EntityProfile),
		riskScores:     make(map[string]float64),
		learningPeriod: 30 * 24 * time.Hour, // 30 days learning period
		alertThreshold: 0.7,                 // Alert threshold for anomaly scores
	}

	// Initialize default behavior rules
	ueba.initializeDefaultRules()

	return ueba
}

// initializeDefaultRules initializes default behavioral analysis rules
func (ueba *UEBAAnalytics) initializeDefaultRules() {
	ueba.behaviorRules = []BehaviorRule{
		{
			ID:          "UEBA-001",
			Name:        "Unusual Login Time",
			Description: "User logging in at unusual hours compared to their baseline",
			Category:    "Authentication",
			Severity:    "medium",
			Conditions: []BehaviorCondition{
				{Field: "deviation_threshold", Operator: "gt", Value: 2.0, Logic: "AND"},
				{Field: "min_baseline_days", Operator: "gte", Value: 7, Logic: "AND"},
			},
			Actions: []string{"alert", "log"},
			Enabled: true,
		},
		{
			ID:          "UEBA-002",
			Name:        "Excessive Failed Logins",
			Description: "User with unusually high number of failed login attempts",
			Category:    "Authentication",
			Severity:    "high",
			Conditions: []BehaviorCondition{
				{Field: "failed_attempts", Operator: "gt", Value: 10, Logic: "AND"},
				{Field: "time_window", Operator: "lte", Value: 3600, Logic: "AND"},
			},
			Actions: []string{"alert", "block", "log"},
			Enabled: true,
		},
		{
			ID:          "UEBA-003",
			Name:        "Unusual File Access Volume",
			Description: "User accessing unusually large number of files",
			Category:    "Data Access",
			Severity:    "medium",
			Conditions: []BehaviorCondition{
				{Field: "deviation_threshold", Operator: "gt", Value: 2.5, Logic: "AND"},
				{Field: "min_baseline_days", Operator: "gte", Value: 14, Logic: "AND"},
			},
			Actions: []string{"alert", "log"},
			Enabled: true,
		},
		{
			ID:          "UEBA-004",
			Name:        "Privilege Escalation Attempt",
			Description: "User attempting to use privileges not typically used",
			Category:    "Privilege Use",
			Severity:    "high",
			Conditions: []BehaviorCondition{
				{Field: "new_privileges", Operator: "eq", Value: true, Logic: "OR"},
				{Field: "admin_actions", Operator: "eq", Value: true, Logic: "OR"},
			},
			Actions: []string{"alert", "log", "investigate"},
			Enabled: true,
		},
		{
			ID:          "UEBA-005",
			Name:        "Unusual Network Connection",
			Description: "Entity connecting to unusual destinations",
			Category:    "Network",
			Severity:    "medium",
			Conditions: []BehaviorCondition{
				{Field: "new_destinations", Operator: "eq", Value: true, Logic: "AND"},
				{Field: "deviation_threshold", Operator: "gt", Value: 2.0, Logic: "AND"},
			},
			Actions: []string{"alert", "log"},
			Enabled: true,
		},
		{
			ID:          "UEBA-006",
			Name:        "Suspicious Process Execution",
			Description: "Execution of processes not typically run by user/entity",
			Category:    "Process",
			Severity:    "high",
			Conditions: []BehaviorCondition{
				{Field: "new_processes", Operator: "eq", Value: true, Logic: "AND"},
				{Field: "process_name", Operator: "contains", Value: "powershell", Logic: "OR"},
				{Field: "process_name", Operator: "contains", Value: "cmd", Logic: "OR"},
			},
			Actions: []string{"alert", "log", "investigate"},
			Enabled: true,
		},
	}
}

// ProcessEvent processes an event for behavioral analysis
func (ueba *UEBAAnalytics) ProcessEvent(event map[string]interface{}) error {
	// Extract event details
	eventType, _ := event["event_type"].(string)
	timestamp, _ := event["timestamp"].(time.Time)
	userID, _ := event["user_id"].(string)
	entityID, _ := event["entity_id"].(string)

	// Update user profile if user is involved
	if userID != "" {
		ueba.updateUserProfile(userID, eventType, event, timestamp)
	}

	// Update entity profile if entity is involved
	if entityID != "" {
		ueba.updateEntityProfile(entityID, eventType, event, timestamp)
	}

	// Analyze for anomalies
	anomalies := ueba.analyzeEvent(event)
	for _, anomaly := range anomalies {
		ueba.anomalies = append(ueba.anomalies, anomaly)
		log.Printf("UEBA Anomaly detected: %s (Score: %.2f)", anomaly.Title, anomaly.Score)
	}

	return nil
}

// updateUserProfile updates a user's behavioral profile
func (ueba *UEBAAnalytics) updateUserProfile(userID, eventType string, event map[string]interface{}, timestamp time.Time) {
	profile, exists := ueba.userProfiles[userID]
	if !exists {
		profile = &UserProfile{
			UserID:          userID,
			Username:        userID,
			FirstSeen:       timestamp,
			LoginPatterns:   LoginPattern{TypicalHours: []int{}, TypicalDays: []int{}, LoginFrequency: make(map[string]int), FailedAttempts: make(map[string]int), LoginSources: make(map[string]int), SessionDuration: make(map[string]float64)},
			AccessPatterns:  AccessPattern{FilesAccessed: make(map[string]int), FoldersAccessed: make(map[string]int), ApplicationsUsed: make(map[string]int), PermissionsUsed: make(map[string]int), DataVolume: make(map[string]float64)},
			NetworkPatterns: NetworkPattern{Connections: make(map[string]int), Protocols: make(map[string]int), Ports: make(map[string]int), DataTransfer: make(map[string]float64), DNSQueries: make(map[string]int), GeoLocations: make(map[string]int)},
			ProcessPatterns: ProcessPattern{ProcessNames: make(map[string]int), CommandLines: make(map[string]int), ParentProcesses: make(map[string]int), ExecutionTimes: make(map[string][]int), ResourceUsage: make(map[string]float64)},
			Metadata:        make(map[string]interface{}),
		}
		ueba.userProfiles[userID] = profile
	}

	profile.LastSeen = timestamp

	// Update patterns based on event type
	switch eventType {
	case "login":
		ueba.updateLoginPatterns(profile, event, timestamp)
	case "file_access":
		ueba.updateAccessPatterns(profile, event)
	case "network_connection":
		ueba.updateNetworkPatterns(&profile.NetworkPatterns, event)
	case "process_execution":
		ueba.updateProcessPatterns(&profile.ProcessPatterns, event, timestamp)
	}
}

// updateEntityProfile updates an entity's behavioral profile
func (ueba *UEBAAnalytics) updateEntityProfile(entityID, eventType string, event map[string]interface{}, timestamp time.Time) {
	profile, exists := ueba.entityProfiles[entityID]
	if !exists {
		profile = &EntityProfile{
			EntityID:        entityID,
			EntityName:      entityID,
			EntityType:      "workstation",
			FirstSeen:       timestamp,
			NetworkPatterns: NetworkPattern{Connections: make(map[string]int), Protocols: make(map[string]int), Ports: make(map[string]int), DataTransfer: make(map[string]float64), DNSQueries: make(map[string]int), GeoLocations: make(map[string]int)},
			ProcessPatterns: ProcessPattern{ProcessNames: make(map[string]int), CommandLines: make(map[string]int), ParentProcesses: make(map[string]int), ExecutionTimes: make(map[string][]int), ResourceUsage: make(map[string]float64)},
			FilePatterns:    FilePattern{FilesCreated: make(map[string]int), FilesModified: make(map[string]int), FilesDeleted: make(map[string]int), FileTypes: make(map[string]int), FileLocations: make(map[string]int)},
			ServicePatterns: ServicePattern{ServicesStarted: make(map[string]int), ServicesStopped: make(map[string]int), ServiceChanges: make(map[string]int)},
			Metadata:        make(map[string]interface{}),
		}
		ueba.entityProfiles[entityID] = profile
	}

	profile.LastSeen = timestamp

	// Update patterns based on event type
	switch eventType {
	case "network_connection":
		ueba.updateNetworkPatterns(&profile.NetworkPatterns, event)
	case "process_execution":
		ueba.updateProcessPatterns(&profile.ProcessPatterns, event, timestamp)
	case "file_operation":
		ueba.updateFilePatterns(profile, event)
	case "service_change":
		ueba.updateServicePatterns(profile, event)
	}
}

// updateLoginPatterns updates user login patterns
func (ueba *UEBAAnalytics) updateLoginPatterns(profile *UserProfile, event map[string]interface{}, timestamp time.Time) {
	hour := timestamp.Hour()
	day := int(timestamp.Weekday())
	dateKey := timestamp.Format("2006-01-02")

	// Update typical hours
	if !contains(profile.LoginPatterns.TypicalHours, hour) {
		profile.LoginPatterns.TypicalHours = append(profile.LoginPatterns.TypicalHours, hour)
	}

	// Update typical days
	if !contains(profile.LoginPatterns.TypicalDays, day) {
		profile.LoginPatterns.TypicalDays = append(profile.LoginPatterns.TypicalDays, day)
	}

	// Update login frequency
	profile.LoginPatterns.LoginFrequency[dateKey]++

	// Update login sources
	if sourceIP, ok := event["source_ip"].(string); ok {
		profile.LoginPatterns.LoginSources[sourceIP]++
	}

	// Update failed attempts if applicable
	if success, ok := event["success"].(bool); ok && !success {
		profile.LoginPatterns.FailedAttempts[dateKey]++
	}
}

// updateAccessPatterns updates user access patterns
func (ueba *UEBAAnalytics) updateAccessPatterns(profile *UserProfile, event map[string]interface{}) {
	if filePath, ok := event["file_path"].(string); ok {
		profile.AccessPatterns.FilesAccessed[filePath]++

		// Extract folder path
		if lastSlash := strings.LastIndex(filePath, "\\"); lastSlash != -1 {
			folderPath := filePath[:lastSlash]
			profile.AccessPatterns.FoldersAccessed[folderPath]++
		}
	}

	if appName, ok := event["application"].(string); ok {
		profile.AccessPatterns.ApplicationsUsed[appName]++
	}

	if dataSize, ok := event["data_size"].(float64); ok {
		dateKey := time.Now().Format("2006-01-02")
		profile.AccessPatterns.DataVolume[dateKey] += dataSize
	}
}

// updateNetworkPatterns updates network patterns
func (ueba *UEBAAnalytics) updateNetworkPatterns(patterns *NetworkPattern, event map[string]interface{}) {
	if destIP, ok := event["destination_ip"].(string); ok {
		patterns.Connections[destIP]++
	}

	if protocol, ok := event["protocol"].(string); ok {
		patterns.Protocols[protocol]++
	}

	if port, ok := event["destination_port"].(string); ok {
		patterns.Ports[port]++
	}

	if dataSize, ok := event["data_size"].(float64); ok {
		dateKey := time.Now().Format("2006-01-02")
		patterns.DataTransfer[dateKey] += dataSize
	}
}

// updateProcessPatterns updates process patterns
func (ueba *UEBAAnalytics) updateProcessPatterns(patterns *ProcessPattern, event map[string]interface{}, timestamp time.Time) {
	if processName, ok := event["process_name"].(string); ok {
		patterns.ProcessNames[processName]++

		// Update execution times
		hour := timestamp.Hour()
		if _, exists := patterns.ExecutionTimes[processName]; !exists {
			patterns.ExecutionTimes[processName] = []int{}
		}
		patterns.ExecutionTimes[processName] = append(patterns.ExecutionTimes[processName], hour)
	}

	if cmdLine, ok := event["command_line"].(string); ok {
		patterns.CommandLines[cmdLine]++
	}

	if parentProcess, ok := event["parent_process"].(string); ok {
		patterns.ParentProcesses[parentProcess]++
	}
}

// updateFilePatterns updates file operation patterns
func (ueba *UEBAAnalytics) updateFilePatterns(profile *EntityProfile, event map[string]interface{}) {
	operation, _ := event["operation"].(string)
	filePath, _ := event["file_path"].(string)

	switch operation {
	case "create":
		profile.FilePatterns.FilesCreated[filePath]++
	case "modify":
		profile.FilePatterns.FilesModified[filePath]++
	case "delete":
		profile.FilePatterns.FilesDeleted[filePath]++
	}

	// Extract file type
	if lastDot := strings.LastIndex(filePath, "."); lastDot != -1 {
		fileType := filePath[lastDot:]
		profile.FilePatterns.FileTypes[fileType]++
	}

	// Extract file location
	if lastSlash := strings.LastIndex(filePath, "\\"); lastSlash != -1 {
		location := filePath[:lastSlash]
		profile.FilePatterns.FileLocations[location]++
	}
}

// updateServicePatterns updates service operation patterns
func (ueba *UEBAAnalytics) updateServicePatterns(profile *EntityProfile, event map[string]interface{}) {
	serviceName, _ := event["service_name"].(string)
	operation, _ := event["operation"].(string)

	switch operation {
	case "start":
		profile.ServicePatterns.ServicesStarted[serviceName]++
	case "stop":
		profile.ServicePatterns.ServicesStopped[serviceName]++
	case "change":
		profile.ServicePatterns.ServiceChanges[serviceName]++
	}
}

// analyzeEvent analyzes an event for behavioral anomalies
func (ueba *UEBAAnalytics) analyzeEvent(event map[string]interface{}) []Anomaly {
	var anomalies []Anomaly

	for _, rule := range ueba.behaviorRules {
		if !rule.Enabled {
			continue
		}

		anomaly := ueba.evaluateRule(rule, event)
		if anomaly != nil {
			anomalies = append(anomalies, *anomaly)
		}
	}

	return anomalies
}

// evaluateRule evaluates a behavioral rule against an event
func (ueba *UEBAAnalytics) evaluateRule(rule BehaviorRule, event map[string]interface{}) *Anomaly {
	// Evaluate conditions based on rule category
	switch rule.Category {
	case "Authentication":
		return ueba.evaluateAuthenticationRule(rule, event)
	case "Data Access":
		return ueba.evaluateDataAccessRule(rule, event)
	case "Network":
		return ueba.evaluateNetworkRule(rule, event)
	case "Process":
		return ueba.evaluateProcessRule(rule, event)
	default:
		return nil
	}
}

// evaluateAuthenticationRule evaluates authentication-related behavioral rules
func (ueba *UEBAAnalytics) evaluateAuthenticationRule(rule BehaviorRule, event map[string]interface{}) *Anomaly {
	userID, _ := event["user_id"].(string)
	eventType, _ := event["event_type"].(string)
	timestamp, _ := event["timestamp"].(time.Time)

	if userID == "" || eventType != "login" {
		return nil
	}

	profile, exists := ueba.userProfiles[userID]
	if !exists {
		return nil
	}

	// Check baseline requirements for statistical rules
	if rule.ID == "UEBA-001" || rule.ID == "UEBA-003" {
		minDays := 7.0
		for _, condition := range rule.Conditions {
			if condition.Field == "min_baseline_days" {
				if days, ok := condition.Value.(float64); ok {
					minDays = days
				}
			}
		}
		if time.Since(profile.FirstSeen).Hours() < minDays*24 {
			return nil
		}
	}

	// Analyze based on rule ID
	switch rule.ID {
	case "UEBA-001": // Unusual Login Time
		hour := timestamp.Hour()
		if !contains(profile.LoginPatterns.TypicalHours, hour) {
			return &Anomaly{
				ID:          fmt.Sprintf("ANOM-%d", time.Now().Unix()),
				Timestamp:   timestamp,
				Type:        "user",
				Severity:    rule.Severity,
				Score:       0.8,
				Subject:     userID,
				Title:       "Unusual Login Time",
				Description: fmt.Sprintf("User %s logged in at unusual hour %d", userID, hour),
				RuleID:      rule.ID,
				Status:      "new",
				Context: AnomalyContext{
					BaselineValue:    profile.LoginPatterns.TypicalHours,
					ObservedValue:    hour,
					DeviationPercent: 100.0,
				},
			}
		}
	case "UEBA-002": // Excessive Failed Logins
		if success, ok := event["success"].(bool); ok && !success {
			// Count failed attempts in the time window
			threshold := 10.0
			for _, condition := range rule.Conditions {
				if condition.Field == "failed_attempts" {
					if val, ok := condition.Value.(float64); ok {
						threshold = val
					}
				}
			}

			windowStart := timestamp.Add(-time.Hour)
			failedCount := 0

			for dateStr, count := range profile.LoginPatterns.FailedAttempts {
				if date, err := time.Parse("2006-01-02", dateStr); err == nil {
					if date.After(windowStart) {
						failedCount += count
					}
				}
			}

			if float64(failedCount) > threshold {
				return &Anomaly{
					ID:          fmt.Sprintf("ANOM-%d", time.Now().Unix()),
					Timestamp:   timestamp,
					Type:        "user",
					Severity:    rule.Severity,
					Score:       0.9,
					Subject:     userID,
					Title:       "Excessive Failed Logins",
					Description: fmt.Sprintf("User %s has %d failed login attempts", userID, failedCount),
					RuleID:      rule.ID,
					Status:      "new",
					Context: AnomalyContext{
						BaselineValue:    threshold,
						ObservedValue:    failedCount,
						DeviationPercent: (float64(failedCount) - threshold) / threshold * 100,
					},
				}
			}
		}
	}

	return nil
}

// evaluateDataAccessRule evaluates data access behavioral rules
func (ueba *UEBAAnalytics) evaluateDataAccessRule(rule BehaviorRule, event map[string]interface{}) *Anomaly {
	userID, _ := event["user_id"].(string)
	eventType, _ := event["event_type"].(string)
	timestamp, _ := event["timestamp"].(time.Time)

	if userID == "" || eventType != "file_access" {
		return nil
	}

	profile, exists := ueba.userProfiles[userID]
	if !exists {
		return nil
	}

	switch rule.ID {
	case "UEBA-003": // Unusual File Access Volume
		// Calculate daily file access average
		totalAccess := 0
		for _, count := range profile.AccessPatterns.FilesAccessed {
			totalAccess += count
		}

		daysSinceFirst := int(time.Since(profile.FirstSeen).Hours() / 24)
		if daysSinceFirst == 0 {
			daysSinceFirst = 1
		}

		avgDaily := float64(totalAccess) / float64(daysSinceFirst)

		// Get deviation threshold from conditions
		deviationThreshold := 2.5
		for _, condition := range rule.Conditions {
			if condition.Field == "deviation_threshold" {
				if val, ok := condition.Value.(float64); ok {
					deviationThreshold = val
				}
			}
		}

		// Get today's access count
		today := timestamp.Format("2006-01-02")
		todayCount := 0
		for filePath, count := range profile.AccessPatterns.FilesAccessed {
			if strings.Contains(filePath, today) {
				todayCount += count
			}
		}

		if float64(todayCount) > avgDaily*deviationThreshold {
			return &Anomaly{
				ID:          fmt.Sprintf("ANOM-%d", time.Now().Unix()),
				Timestamp:   timestamp,
				Type:        "user",
				Severity:    rule.Severity,
				Score:       0.7,
				Subject:     userID,
				Title:       "Unusual File Access Volume",
				Description: fmt.Sprintf("User %s accessed %d files today, significantly above average of %.1f", userID, todayCount, avgDaily),
				RuleID:      rule.ID,
				Status:      "new",
				Context: AnomalyContext{
					BaselineValue:    avgDaily,
					ObservedValue:    todayCount,
					DeviationPercent: (float64(todayCount) - avgDaily) / avgDaily * 100,
				},
			}
		}
	}

	return nil
}

// evaluateNetworkRule evaluates network behavioral rules
func (ueba *UEBAAnalytics) evaluateNetworkRule(rule BehaviorRule, event map[string]interface{}) *Anomaly {
	userID, _ := event["user_id"].(string)
	eventType, _ := event["event_type"].(string)
	timestamp, _ := event["timestamp"].(time.Time)

	if userID == "" || eventType != "network_connection" {
		return nil
	}

	profile, exists := ueba.userProfiles[userID]
	if !exists {
		return nil
	}

	switch rule.ID {
	case "UEBA-005": // Unusual Network Destinations
		destination, _ := event["destination_ip"].(string)
		if destination != "" {
			// Check if this is a new destination
			if _, exists := profile.NetworkPatterns.Connections[destination]; !exists {
				return &Anomaly{
					ID:          fmt.Sprintf("ANOM-%d", time.Now().Unix()),
					Timestamp:   timestamp,
					Type:        "user",
					Severity:    rule.Severity,
					Score:       0.6,
					Subject:     userID,
					Title:       "Unusual Network Destination",
					Description: fmt.Sprintf("User %s connected to new destination %s", userID, destination),
					RuleID:      rule.ID,
					Status:      "new",
					Context: AnomalyContext{
						BaselineValue:    "Known destinations",
						ObservedValue:    destination,
						DeviationPercent: 100.0,
					},
				}
			}
		}
	}

	return nil
}

// evaluateProcessRule evaluates process behavioral rules
func (ueba *UEBAAnalytics) evaluateProcessRule(rule BehaviorRule, event map[string]interface{}) *Anomaly {
	userID, _ := event["user_id"].(string)
	eventType, _ := event["event_type"].(string)
	timestamp, _ := event["timestamp"].(time.Time)

	if userID == "" || eventType != "process_execution" {
		return nil
	}

	profile, exists := ueba.userProfiles[userID]
	if !exists {
		return nil
	}

	switch rule.ID {
	case "UEBA-006": // Suspicious Process Execution
		processName, _ := event["process_name"].(string)

		// Check if this is a new process for the user
		if _, exists := profile.ProcessPatterns.ProcessNames[processName]; !exists {
			// Check if it matches suspicious patterns from conditions
			for _, condition := range rule.Conditions {
				if condition.Field == "process_name" && condition.Operator == "contains" {
					if suspName, ok := condition.Value.(string); ok {
						if strings.Contains(strings.ToLower(processName), strings.ToLower(suspName)) {
							return &Anomaly{
								ID:          fmt.Sprintf("ANOM-%d", time.Now().Unix()),
								Timestamp:   timestamp,
								Type:        "user",
								Severity:    rule.Severity,
								Score:       0.8,
								Subject:     userID,
								Title:       "Suspicious Process Execution",
								Description: fmt.Sprintf("User %s executed suspicious process %s", userID, processName),
								RuleID:      rule.ID,
								Status:      "new",
								Context: AnomalyContext{
									BaselineValue:    "Process not in user's typical behavior",
									ObservedValue:    processName,
									DeviationPercent: 100.0,
								},
							}
						}
					}
				}
			}
		}
	}

	return nil
}

// CalculateRiskScores calculates risk scores for all users and entities
func (ueba *UEBAAnalytics) CalculateRiskScores() {
	// Calculate user risk scores
	for userID, profile := range ueba.userProfiles {
		riskScore := ueba.calculateUserRiskScore(profile)
		ueba.riskScores[userID] = riskScore
		profile.RiskScore = riskScore
	}

	// Calculate entity risk scores
	for entityID, profile := range ueba.entityProfiles {
		riskScore := ueba.calculateEntityRiskScore(profile)
		ueba.riskScores[entityID] = riskScore
		profile.RiskScore = riskScore
	}
}

// calculateUserRiskScore calculates risk score for a user
func (ueba *UEBAAnalytics) calculateUserRiskScore(profile *UserProfile) float64 {
	riskScore := 0.0

	// Factor in anomalies
	for _, anomaly := range profile.Anomalies {
		switch anomaly.Severity {
		case "critical":
			riskScore += 0.4
		case "high":
			riskScore += 0.3
		case "medium":
			riskScore += 0.2
		case "low":
			riskScore += 0.1
		}
	}

	// Factor in failed login attempts
	totalFailed := 0
	for _, count := range profile.LoginPatterns.FailedAttempts {
		totalFailed += count
	}
	if totalFailed > 10 {
		riskScore += 0.2
	}

	// Factor in unusual access patterns
	if len(profile.AccessPatterns.FilesAccessed) > 1000 {
		riskScore += 0.1
	}

	// Normalize to 0-1 range
	if riskScore > 1.0 {
		riskScore = 1.0
	}

	return riskScore
}

// calculateEntityRiskScore calculates risk score for an entity
func (ueba *UEBAAnalytics) calculateEntityRiskScore(profile *EntityProfile) float64 {
	riskScore := 0.0

	// Factor in anomalies
	for _, anomaly := range profile.Anomalies {
		switch anomaly.Severity {
		case "critical":
			riskScore += 0.4
		case "high":
			riskScore += 0.3
		case "medium":
			riskScore += 0.2
		case "low":
			riskScore += 0.1
		}
	}

	// Factor in unusual network connections
	if len(profile.NetworkPatterns.Connections) > 100 {
		riskScore += 0.1
	}

	// Factor in suspicious processes
	suspiciousProcesses := []string{"powershell", "cmd", "wmic", "net"}
	for processName := range profile.ProcessPatterns.ProcessNames {
		for _, suspName := range suspiciousProcesses {
			if strings.Contains(strings.ToLower(processName), suspName) {
				riskScore += 0.05
				break
			}
		}
	}

	// Normalize to 0-1 range
	if riskScore > 1.0 {
		riskScore = 1.0
	}

	return riskScore
}

// GetTopRiskyUsers returns the top risky users
func (ueba *UEBAAnalytics) GetTopRiskyUsers(limit int) []UserProfile {
	var users []UserProfile
	for _, profile := range ueba.userProfiles {
		users = append(users, *profile)
	}

	// Sort by risk score
	sort.Slice(users, func(i, j int) bool {
		return users[i].RiskScore > users[j].RiskScore
	})

	if limit > len(users) {
		limit = len(users)
	}

	return users[:limit]
}

// GetRecentAnomalies returns recent anomalies
func (ueba *UEBAAnalytics) GetRecentAnomalies(hours int) []Anomaly {
	var recentAnomalies []Anomaly
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)

	for _, anomaly := range ueba.anomalies {
		if anomaly.Timestamp.After(cutoff) {
			recentAnomalies = append(recentAnomalies, anomaly)
		}
	}

	// Sort by timestamp (newest first)
	sort.Slice(recentAnomalies, func(i, j int) bool {
		return recentAnomalies[i].Timestamp.After(recentAnomalies[j].Timestamp)
	})

	return recentAnomalies
}

// GetUserProfile returns a user's behavioral profile
func (ueba *UEBAAnalytics) GetUserProfile(userID string) (*UserProfile, bool) {
	profile, exists := ueba.userProfiles[userID]
	return profile, exists
}

// GetEntityProfile returns an entity's behavioral profile
func (ueba *UEBAAnalytics) GetEntityProfile(entityID string) (*EntityProfile, bool) {
	profile, exists := ueba.entityProfiles[entityID]
	return profile, exists
}

// Helper function to check if slice contains an integer
func contains(slice []int, item int) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

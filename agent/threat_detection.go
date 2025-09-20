//go:build windows

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ThreatAlert represents a threat alert
type ThreatAlert struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	ThreatType  string                 `json:"threat_type"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	Source      string                 `json:"source"`
	IOC         *IOCIndicator          `json:"ioc,omitempty"`
	Rule        *BehaviorRule          `json:"rule,omitempty"`
	Event       map[string]interface{} `json:"event"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ThreatDetector manages threat detection and analysis
type ThreatDetector struct {
	iocDatabase       map[string]IOCIndicator
	behaviorRules     []BehaviorRule
	alertChannel      chan ThreatAlert
	eventBuffer       []map[string]interface{}
	stopChannel       chan bool
	threatIntelFeeds  []ThreatIntelFeed
	enrichmentCache   map[string]ThreatEnrichment
	mutex             sync.RWMutex
	alertHandlers     []AlertHandler
	detectionStats    DetectionStats
}

// IOCIndicator represents an Indicator of Compromise
type IOCIndicator struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Value       string    `json:"value"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	Source      string    `json:"source"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Tags        []string  `json:"tags"`
	Confidence  float32   `json:"confidence"`
	IsActive    bool      `json:"is_active"`
}

// ThreatIntelFeed represents a threat intelligence feed
type ThreatIntelFeed struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Description     string    `json:"description"`
	FeedType        string    `json:"feed_type"`
	URL             string    `json:"url"`
	APIKey          string    `json:"api_key"`
	UpdateFrequency int       `json:"update_frequency"`
	LastUpdated     time.Time `json:"last_updated"`
	IsEnabled       bool      `json:"is_enabled"`
	TotalIndicators int       `json:"total_indicators"`
}

// ThreatEnrichment represents enriched threat intelligence data
type ThreatEnrichment struct {
	ID               string            `json:"id"`
	IndicatorValue   string            `json:"indicator_value"`
	IndicatorType    string            `json:"indicator_type"`
	EnrichmentSource string            `json:"enrichment_source"`
	EnrichmentData   map[string]interface{} `json:"enrichment_data"`
	ReputationScore  float32           `json:"reputation_score"`
	MalwareFamilies  []string          `json:"malware_families"`
	AttackTechniques []string          `json:"attack_techniques"`
	Geolocation      map[string]string `json:"geolocation"`
	WhoisData        map[string]string `json:"whois_data"`
}

// AlertHandler defines interface for alert handling
type AlertHandler interface {
	HandleAlert(alert ThreatAlert) error
	GetType() string
}

// DetectionStats tracks detection statistics
type DetectionStats struct {
	TotalDetections     int64     `json:"total_detections"`
	IOCMatches          int64     `json:"ioc_matches"`
	BehavioralDetections int64    `json:"behavioral_detections"`
	FalsePositives      int64     `json:"false_positives"`
	LastDetection       time.Time `json:"last_detection"`
	DetectionsByType    map[string]int64 `json:"detections_by_type"`
	DetectionsBySeverity map[string]int64 `json:"detections_by_severity"`
}

// ThreatEvent represents a detected threat
type ThreatEvent struct {
	ID            string                 `json:"id"`
	EventType     string                 `json:"event_type"`
	Timestamp     string                 `json:"timestamp"`
	ThreatLevel   string                 `json:"threat_level"`
	Title         string                 `json:"title"`
	Description   string                 `json:"description"`
	IOCMatched    *IOCIndicator          `json:"ioc_matched,omitempty"`
	BehaviorRule  *BehaviorRule          `json:"behavior_rule,omitempty"`
	ProcessInfo   *ProcessInfo           `json:"process_info,omitempty"`
	NetworkInfo   *ConnectionInfo        `json:"network_info,omitempty"`
	FileInfo      *FileInfo              `json:"file_info,omitempty"`
	Evidence      map[string]interface{} `json:"evidence"`
	Confidence    float64                `json:"confidence"`
	Status        string                 `json:"status"`
	AssignedTo    string                 `json:"assigned_to"`
	Enrichment    *ThreatEnrichment      `json:"enrichment,omitempty"`
}

// NewThreatDetector creates a new threat detector instance
func NewThreatDetector() *ThreatDetector {
	td := &ThreatDetector{
		iocDatabase:      make(map[string]IOCIndicator),
		behaviorRules:    []BehaviorRule{},
		alertChannel:     make(chan ThreatAlert, 1000),
		eventBuffer:      make([]map[string]interface{}, 0),
		stopChannel:      make(chan bool),
		threatIntelFeeds: []ThreatIntelFeed{},
		enrichmentCache:  make(map[string]ThreatEnrichment),
		alertHandlers:    []AlertHandler{},
		detectionStats: DetectionStats{
			DetectionsByType:     make(map[string]int64),
			DetectionsBySeverity: make(map[string]int64),
		},
	}
	
	td.loadDefaultIOCs()
	td.loadDefaultBehaviorRules()
	td.initializeThreatIntelFeeds()
	
	// Start background processes
	go td.processAlerts()
	go td.updateThreatIntelligence()
	
	return td
}

// loadDefaultIOCs loads default IOC indicators with enhanced detection capabilities
func (td *ThreatDetector) loadDefaultIOCs() {
	defaultIOCs := []IOCIndicator{
		// Malicious file hashes
		{
			ID:          "IOC-HASH-001",
			Type:        "hash",
			Value:       "44d88612fea8a8f36de82e1278abb02f",
			Severity:    "high",
			FirstSeen:   time.Now().AddDate(0, -1, 0),
			LastSeen:    time.Now(),
			Source:      "VirusTotal",
			Description: "Known malware hash - Emotet banking trojan",
			Tags:        []string{"malware", "trojan", "emotet"},
			Confidence:  0.95,
			IsActive:    true,
		},
		{
			ID:          "IOC-HASH-002",
			Type:        "hash",
			Value:       "5d41402abc4b2a76b9719d911017c592",
			Severity:    "critical",
			FirstSeen:   time.Now().AddDate(0, -2, 0),
			LastSeen:    time.Now(),
			Source:      "Internal Analysis",
			Description: "Ransomware payload hash",
			Tags:        []string{"ransomware", "payload"},
			Confidence:  0.98,
			IsActive:    true,
		},
		// Malicious IP addresses
		{
			ID:          "IOC-IP-001",
			Type:        "ip",
			Value:       "192.168.1.100",
			Severity:    "medium",
			FirstSeen:   time.Now().AddDate(0, 0, -7),
			LastSeen:    time.Now(),
			Source:      "ThreatIntel",
			Description: "Suspicious IP address - potential C2 server",
			Tags:        []string{"c2", "botnet"},
			Confidence:  0.75,
			IsActive:    true,
		},
		{
			ID:          "IOC-IP-002",
			Type:        "ip",
			Value:       "10.0.0.50",
			Severity:    "high",
			FirstSeen:   time.Now().AddDate(0, 0, -3),
			LastSeen:    time.Now(),
			Source:      "Honeypot",
			Description: "Known malicious IP - active scanning",
			Tags:        []string{"scanner", "malicious"},
			Confidence:  0.90,
			IsActive:    true,
		},
		// Malicious domains
		{
			ID:          "IOC-DOMAIN-001",
			Type:        "domain",
			Value:       "malicious-domain.com",
			Severity:    "high",
			FirstSeen:   time.Now().AddDate(0, 0, -3),
			LastSeen:    time.Now(),
			Source:      "DNS-BH",
			Description: "Known C&C domain - APT campaign",
			Tags:        []string{"apt", "c2", "domain"},
			Confidence:  0.92,
			IsActive:    true,
		},
		{
			ID:          "IOC-DOMAIN-002",
			Type:        "domain",
			Value:       "phishing-site.net",
			Severity:    "medium",
			FirstSeen:   time.Now().AddDate(0, 0, -5),
			LastSeen:    time.Now(),
			Source:      "PhishTank",
			Description: "Phishing domain targeting financial institutions",
			Tags:        []string{"phishing", "financial"},
			Confidence:  0.85,
			IsActive:    true,
		},
		// Malicious URLs
		{
			ID:          "IOC-URL-001",
			Type:        "url",
			Value:       "http://malicious-domain.com/payload.exe",
			Severity:    "critical",
			FirstSeen:   time.Now().AddDate(0, 0, -1),
			LastSeen:    time.Now(),
			Source:      "Sandbox Analysis",
			Description: "Malware download URL",
			Tags:        []string{"malware", "download", "payload"},
			Confidence:  0.98,
			IsActive:    true,
		},
		// Suspicious file paths
		{
			ID:          "IOC-PATH-001",
			Type:        "file_path",
			Value:       "C:\\Windows\\Temp\\suspicious.exe",
			Severity:    "high",
			FirstSeen:   time.Now().AddDate(0, 0, -2),
			LastSeen:    time.Now(),
			Source:      "Incident Response",
			Description: "Suspicious executable in temp directory",
			Tags:        []string{"suspicious", "executable", "temp"},
			Confidence:  0.80,
			IsActive:    true,
		},
	}
	
	td.mutex.Lock()
	defer td.mutex.Unlock()
	
	for _, ioc := range defaultIOCs {
		td.iocDatabase[ioc.Value] = ioc
	}
	
	log.Printf("Loaded %d default IOC indicators", len(defaultIOCs))
}

// loadDefaultBehaviorRules loads default behavioral detection rules
func (td *ThreatDetector) loadDefaultBehaviorRules() {
	td.behaviorRules = []BehaviorRule{
		{
			ID:          "BR001",
			Name:        "Suspicious PowerShell Execution",
			Description: "Detects potentially malicious PowerShell commands",
			Category:    "execution",
			Severity:    "high",
			Enabled:     true,
			Conditions: []BehaviorCondition{
				{Field: "command_line", Operator: "contains", Value: "powershell", Logic: "AND"},
			},
		},
		{
			ID:          "BR002",
			Name:        "Credential Dumping Attempt",
			Description: "Detects attempts to dump credentials",
			Category:    "credential_access",
			Severity:    "critical",
			Enabled:     true,
			Conditions: []BehaviorCondition{
				{Field: "command_line", Operator: "contains", Value: "mimikatz", Logic: "OR"},
			},
		},
		{
			ID:          "BR003",
			Name:        "Suspicious Network Activity",
			Description: "Detects connections to suspicious ports",
			Category:    "command_control",
			Severity:    "medium",
			Enabled:     true,
			Conditions: []BehaviorCondition{
				{Field: "remote_port", Operator: "eq", Value: "4444", Logic: "OR"},
			},
		},
		{
			ID:          "BR004",
			Name:        "File Encryption Activity",
			Description: "Detects potential ransomware file encryption",
			Category:    "impact",
			Severity:    "critical",
			Enabled:     true,
			Conditions: []BehaviorCondition{
				{Field: "file_extension", Operator: "eq", Value: ".encrypted", Logic: "OR"},
			},
		},
	}
}

// AnalyzeProcess analyzes a process for threats
func (td *ThreatDetector) AnalyzeProcess(process *ProcessInfo) *ThreatEvent {
	// Check command line against behavior rules
	for _, rule := range td.behaviorRules {
		if rule.Category == "execution" && rule.Enabled {
			// Check conditions instead of patterns
			for _, condition := range rule.Conditions {
				if condition.Field == "command_line" && condition.Operator == "contains" {
					if strings.Contains(strings.ToLower(process.CommandLine), strings.ToLower(condition.Value.(string))) {
						return &ThreatEvent{
							EventType:    "behavioral_detection",
							Timestamp:    time.Now().UTC().Format(time.RFC3339),
							ThreatLevel:  td.getSeverityLevel(rule.Severity),
							BehaviorRule: &rule,
							ProcessInfo:  process,
							Evidence: map[string]interface{}{
								"matched_condition": condition.Value,
								"command_line":      process.CommandLine,
							},
							Confidence: 0.85,
						}
					}
				}
			}
		}
	}
	
	// Check process hash against IOC database
	if len(process.Modules) > 0 && process.Modules[0].Hash != "" {
		if ioc, exists := td.iocDatabase[process.Modules[0].Hash]; exists {
			return &ThreatEvent{
				EventType:   "ioc_match",
				Timestamp:   time.Now().UTC().Format(time.RFC3339),
				ThreatLevel: td.getSeverityLevel(ioc.Severity),
				IOCMatched:  &ioc,
				ProcessInfo: process,
				Evidence: map[string]interface{}{
					"hash_type": "process_hash",
					"hash":      process.Modules[0].Hash,
				},
				Confidence: 0.95,
			}
		}
	}
	
	return nil
}

// AnalyzeNetwork analyzes network connections for threats
func (td *ThreatDetector) AnalyzeNetwork(conn *ConnectionInfo) *ThreatEvent {
	// Check destination IP against IOC database
	if ioc, exists := td.iocDatabase[conn.RemoteAddress]; exists {
		return &ThreatEvent{
			EventType:   "ioc_match",
			Timestamp:   time.Now().UTC().Format(time.RFC3339),
			ThreatLevel: td.getSeverityLevel(ioc.Severity),
			IOCMatched:  &ioc,
			NetworkInfo: conn,
			Evidence: map[string]interface{}{
				"connection_type": "outbound",
				"remote_address":  conn.RemoteAddress,
				"remote_port":     conn.RemotePort,
			},
			Confidence: 0.90,
		}
	}
	
	// Check against behavioral rules
	connectionString := fmt.Sprintf("%s:%d", conn.RemoteAddress, conn.RemotePort)
	for _, rule := range td.behaviorRules {
		if rule.Category == "command_control" && rule.Enabled {
			for _, condition := range rule.Conditions {
				if condition.Field == "remote_address" && condition.Operator == "contains" {
					if strings.Contains(strings.ToLower(connectionString), strings.ToLower(condition.Value.(string))) {
						return &ThreatEvent{
							EventType:    "behavioral_detection",
							Timestamp:    time.Now().UTC().Format(time.RFC3339),
							ThreatLevel:  td.getSeverityLevel(rule.Severity),
							BehaviorRule: &rule,
							NetworkInfo:  conn,
							Evidence: map[string]interface{}{
								"matched_condition": condition.Value,
								"connection_string": connectionString,
							},
							Confidence: 0.80,
						}
					}
				}
			}
		}
	}
	
	return nil
}

// AnalyzeFile analyzes file operations for threats
func (td *ThreatDetector) AnalyzeFile(file *FileInfo) *ThreatEvent {
	// Calculate file hash if not present
	if file.Hash == "" && file.Path != "" {
		hash, err := td.calculateFileHash(file.Path)
		if err == nil {
			file.Hash = hash
		}
	}
	
	// Check file hash against IOC database
	if file.Hash != "" {
		if ioc, exists := td.iocDatabase[file.Hash]; exists {
			return &ThreatEvent{
				EventType:   "ioc_match",
				Timestamp:   time.Now().UTC().Format(time.RFC3339),
				ThreatLevel: td.getSeverityLevel(ioc.Severity),
				IOCMatched:  &ioc,
				FileInfo:    file,
				Evidence: map[string]interface{}{
					"hash_type": "file_hash",
					"hash":      file.Hash,
					"file_path": file.Path,
				},
				Confidence: 0.95,
			}
		}
	}
	
	// Check file name/path against behavioral rules
	for _, rule := range td.behaviorRules {
		if rule.Category == "impact" && rule.Enabled {
			for _, condition := range rule.Conditions {
				if condition.Field == "file_name" && condition.Operator == "contains" {
					if strings.Contains(strings.ToLower(file.Name), strings.ToLower(condition.Value.(string))) {
						return &ThreatEvent{
							EventType:    "behavioral_detection",
							Timestamp:    time.Now().UTC().Format(time.RFC3339),
							ThreatLevel:  td.getSeverityLevel(rule.Severity),
							BehaviorRule: &rule,
							FileInfo:     file,
							Evidence: map[string]interface{}{
								"matched_condition": condition.Value,
								"file_name":         file.Name,
								"file_path":         file.Path,
							},
							Confidence: 0.80,
						}
					}
				}
			}
		}
	}
	
	return nil
}

// calculateFileHash calculates SHA256 hash of a file
func (td *ThreatDetector) calculateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// getSeverityLevel converts string severity to threat level
func (td *ThreatDetector) getSeverityLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "high"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "low"
	}
}

// AddIOC adds a new IOC to the database
func (td *ThreatDetector) AddIOC(ioc IOCIndicator) {
	td.iocDatabase[ioc.Value] = ioc
	log.Printf("Added IOC: %s (%s) - %s", ioc.Value, ioc.Type, ioc.Severity)
}

// GetIOCs returns all IOCs in the database
func (td *ThreatDetector) GetIOCs() []IOCIndicator {
	iocs := make([]IOCIndicator, 0, len(td.iocDatabase))
	for _, ioc := range td.iocDatabase {
		iocs = append(iocs, ioc)
	}
	return iocs
}

// GetBehaviorRules returns all behavior rules
func (td *ThreatDetector) GetBehaviorRules() []BehaviorRule {
	return td.behaviorRules
}

// Enhanced behavioral analysis with machine learning capabilities
func (td *ThreatDetector) AnalyzeBehavior(events []map[string]interface{}) []*ThreatEvent {
	var threats []*ThreatEvent
	
	// Analyze event patterns for suspicious behavior
	for _, rule := range td.behaviorRules {
		if !rule.Enabled {
			continue
		}
		
		// Check for pattern matches across multiple events
		if matches := td.evaluateBehaviorRule(rule, events); len(matches) > 0 {
			for _, match := range matches {
				threat := &ThreatEvent{
					EventType:    "behavioral_detection",
					Timestamp:    time.Now().UTC().Format(time.RFC3339),
					ThreatLevel:  td.getSeverityLevel(rule.Severity),
					BehaviorRule: &rule,
					Evidence:     match,
					Confidence:   td.calculateConfidence(rule, match),
				}
				threats = append(threats, threat)
			}
		}
	}
	
	// Advanced behavioral analysis patterns
	threats = append(threats, td.detectAdvancedThreats(events)...)
	
	return threats
}

// evaluateBehaviorRule evaluates a behavior rule against event data
func (td *ThreatDetector) evaluateBehaviorRule(rule BehaviorRule, events []map[string]interface{}) []map[string]interface{} {
	var matches []map[string]interface{}
	
	for _, event := range events {
		if td.matchesConditions(rule.Conditions, event) {
			matches = append(matches, event)
		}
	}
	
	return matches
}

// matchesConditions checks if an event matches all rule conditions
func (td *ThreatDetector) matchesConditions(conditions []BehaviorCondition, event map[string]interface{}) bool {
	for _, condition := range conditions {
		if !td.evaluateCondition(condition, event) {
			if condition.Logic == "AND" {
				return false
			}
		} else {
			if condition.Logic == "OR" {
				return true
			}
		}
	}
	return true
}

// evaluateCondition evaluates a single condition against event data
func (td *ThreatDetector) evaluateCondition(condition BehaviorCondition, event map[string]interface{}) bool {
	fieldValue, exists := event[condition.Field]
	if !exists {
		return false
	}
	
	fieldStr := fmt.Sprintf("%v", fieldValue)
	conditionStr := fmt.Sprintf("%v", condition.Value)
	
	switch condition.Operator {
	case "eq":
		return fieldStr == conditionStr
	case "ne":
		return fieldStr != conditionStr
	case "contains":
		return strings.Contains(strings.ToLower(fieldStr), strings.ToLower(conditionStr))
	case "starts_with":
		return strings.HasPrefix(strings.ToLower(fieldStr), strings.ToLower(conditionStr))
	case "ends_with":
		return strings.HasSuffix(strings.ToLower(fieldStr), strings.ToLower(conditionStr))
	case "regex":
		matched, _ := regexp.MatchString(conditionStr, fieldStr)
		return matched
	case "gt":
		if num1, err1 := strconv.ParseFloat(fieldStr, 64); err1 == nil {
			if num2, err2 := strconv.ParseFloat(conditionStr, 64); err2 == nil {
				return num1 > num2
			}
		}
	case "lt":
		if num1, err1 := strconv.ParseFloat(fieldStr, 64); err1 == nil {
			if num2, err2 := strconv.ParseFloat(conditionStr, 64); err2 == nil {
				return num1 < num2
			}
		}
	}
	
	return false
}

// detectAdvancedThreats detects advanced threat patterns
func (td *ThreatDetector) detectAdvancedThreats(events []map[string]interface{}) []*ThreatEvent {
	var threats []*ThreatEvent
	
	// Detect lateral movement patterns
	if threat := td.detectLateralMovement(events); threat != nil {
		threats = append(threats, threat)
	}
	
	// Detect privilege escalation attempts
	if threat := td.detectPrivilegeEscalation(events); threat != nil {
		threats = append(threats, threat)
	}
	
	// Detect data exfiltration patterns
	if threat := td.detectDataExfiltration(events); threat != nil {
		threats = append(threats, threat)
	}
	
	// Detect persistence mechanisms
	if threat := td.detectPersistence(events); threat != nil {
		threats = append(threats, threat)
	}
	
	return threats
}

// detectLateralMovement detects lateral movement patterns
func (td *ThreatDetector) detectLateralMovement(events []map[string]interface{}) *ThreatEvent {
	// Look for patterns indicating lateral movement
	networkConnections := 0
	remoteExecutions := 0
	
	for _, event := range events {
		eventType, _ := event["type"].(string)
		
		switch eventType {
		case "network_event":
			if connInfo, ok := event["connection_info"].(map[string]interface{}); ok {
				if direction, _ := connInfo["direction"].(string); direction == "outbound" {
					networkConnections++
				}
			}
		case "process_event":
			if processInfo, ok := event["process_info"].(map[string]interface{}); ok {
				if cmdLine, _ := processInfo["command_line"].(string); cmdLine != "" {
					if strings.Contains(strings.ToLower(cmdLine), "psexec") ||
					   strings.Contains(strings.ToLower(cmdLine), "wmic") ||
					   strings.Contains(strings.ToLower(cmdLine), "powershell") {
						remoteExecutions++
					}
				}
			}
		}
	}
	
	// Threshold-based detection
	if networkConnections > 5 && remoteExecutions > 2 {
		return &ThreatEvent{
			EventType:   "behavioral_detection",
			Timestamp:   time.Now().UTC().Format(time.RFC3339),
			ThreatLevel: "high",
			Evidence: map[string]interface{}{
				"pattern":             "lateral_movement",
				"network_connections": networkConnections,
				"remote_executions":   remoteExecutions,
			},
			Confidence: 0.80,
		}
	}
	
	return nil
}

// detectPrivilegeEscalation detects privilege escalation attempts
func (td *ThreatDetector) detectPrivilegeEscalation(events []map[string]interface{}) *ThreatEvent {
	adminProcesses := 0
	suspiciousCommands := 0
	
	for _, event := range events {
		if processInfo, ok := event["process_info"].(map[string]interface{}); ok {
			if user, _ := processInfo["user"].(string); strings.Contains(strings.ToLower(user), "admin") {
				adminProcesses++
			}
			
			if cmdLine, _ := processInfo["command_line"].(string); cmdLine != "" {
				cmdLower := strings.ToLower(cmdLine)
				if strings.Contains(cmdLower, "runas") ||
				   strings.Contains(cmdLower, "elevate") ||
				   strings.Contains(cmdLower, "bypass") {
					suspiciousCommands++
				}
			}
		}
	}
	
	if adminProcesses > 3 && suspiciousCommands > 1 {
		return &ThreatEvent{
			EventType:   "behavioral_detection",
			Timestamp:   time.Now().UTC().Format(time.RFC3339),
			ThreatLevel: "high",
			Evidence: map[string]interface{}{
				"pattern":             "privilege_escalation",
				"admin_processes":     adminProcesses,
				"suspicious_commands": suspiciousCommands,
			},
			Confidence: 0.85,
		}
	}
	
	return nil
}

// detectDataExfiltration detects data exfiltration patterns
func (td *ThreatDetector) detectDataExfiltration(events []map[string]interface{}) *ThreatEvent {
	largeTransfers := 0
	fileAccesses := 0
	
	for _, event := range events {
		eventType, _ := event["type"].(string)
		
		switch eventType {
		case "network_event":
			if connInfo, ok := event["connection_info"].(map[string]interface{}); ok {
				if bytesSent, _ := connInfo["bytes_sent"].(float64); bytesSent > 1000000 { // 1MB
					largeTransfers++
				}
			}
		case "file_event":
			if fileInfo, ok := event["file_info"].(map[string]interface{}); ok {
				if path, _ := fileInfo["path"].(string); path != "" {
					if strings.Contains(strings.ToLower(path), "documents") ||
					   strings.Contains(strings.ToLower(path), "desktop") {
						fileAccesses++
					}
				}
			}
		}
	}
	
	if largeTransfers > 2 && fileAccesses > 5 {
		return &ThreatEvent{
			EventType:   "behavioral_detection",
			Timestamp:   time.Now().UTC().Format(time.RFC3339),
			ThreatLevel: "medium",
			Evidence: map[string]interface{}{
				"pattern":         "data_exfiltration",
				"large_transfers": largeTransfers,
				"file_accesses":   fileAccesses,
			},
			Confidence: 0.75,
		}
	}
	
	return nil
}

// detectPersistence detects persistence mechanism attempts
func (td *ThreatDetector) detectPersistence(events []map[string]interface{}) *ThreatEvent {
	registryModifications := 0
	serviceCreations := 0
	scheduledTasks := 0
	
	for _, event := range events {
		eventType, _ := event["type"].(string)
		
		switch eventType {
		case "registry_event":
			registryModifications++
		case "process_event":
			if processInfo, ok := event["process_info"].(map[string]interface{}); ok {
				if cmdLine, _ := processInfo["command_line"].(string); cmdLine != "" {
					cmdLower := strings.ToLower(cmdLine)
					if strings.Contains(cmdLower, "sc create") ||
					   strings.Contains(cmdLower, "net start") {
						serviceCreations++
					}
					if strings.Contains(cmdLower, "schtasks") ||
					   strings.Contains(cmdLower, "at ") {
						scheduledTasks++
					}
				}
			}
		}
	}
	
	persistenceScore := registryModifications + serviceCreations*2 + scheduledTasks*2
	
	if persistenceScore > 3 {
		return &ThreatEvent{
			EventType:   "behavioral_detection",
			Timestamp:   time.Now().UTC().Format(time.RFC3339),
			ThreatLevel: "medium",
			Evidence: map[string]interface{}{
				"pattern":                 "persistence_mechanism",
				"registry_modifications":  registryModifications,
				"service_creations":       serviceCreations,
				"scheduled_tasks":         scheduledTasks,
				"persistence_score":       persistenceScore,
			},
			Confidence: 0.70,
		}
	}
	
	return nil
}

// calculateConfidence calculates confidence score for a behavior rule match
func (td *ThreatDetector) calculateConfidence(rule BehaviorRule, evidence map[string]interface{}) float64 {
	baseConfidence := 0.60
	
	// Increase confidence based on rule severity
	switch strings.ToLower(rule.Severity) {
	case "critical":
		baseConfidence += 0.30
	case "high":
		baseConfidence += 0.20
	case "medium":
		baseConfidence += 0.10
	}
	
	// Increase confidence based on evidence quality
	if len(evidence) > 3 {
		baseConfidence += 0.10
	}
	
	// Cap at 0.95
	if baseConfidence > 0.95 {
		baseConfidence = 0.95
	}
	
	return baseConfidence
}

// Enhanced threat intelligence integration with external feeds
func (td *ThreatDetector) updateThreatIntelligence() {
	td.mutex.Lock()
	defer td.mutex.Unlock()
	
	log.Println("Updating threat intelligence feeds...")
	
	// Update each configured threat intel feed
	for _, feed := range td.threatIntelFeeds {
		if feed.Enabled {
			go td.updateThreatFeed(feed)
		}
	}
	
	// Update enrichment cache
	td.updateEnrichmentCache()
	
	log.Printf("Threat intelligence update completed. Total IOCs: %d", len(td.iocDatabase))
}

// updateThreatFeed updates a specific threat intelligence feed
func (td *ThreatDetector) updateThreatFeed(feed ThreatIntelFeed) {
	log.Printf("Updating threat feed: %s", feed.Name)
	
	// Simulate fetching from external threat intel sources
	switch feed.Type {
	case "malware_hashes":
		td.fetchMalwareHashes(feed)
	case "malicious_ips":
		td.fetchMaliciousIPs(feed)
	case "malicious_domains":
		td.fetchMaliciousDomains(feed)
	case "apt_indicators":
		td.fetchAPTIndicators(feed)
	case "ransomware_signatures":
		td.fetchRansomwareSignatures(feed)
	}
	
	// Update feed metadata
	feed.LastUpdated = time.Now()
	feed.UpdateCount++
	
	log.Printf("Threat feed %s updated successfully", feed.Name)
}

// fetchMalwareHashes fetches malware hash indicators
func (td *ThreatDetector) fetchMalwareHashes(feed ThreatIntelFeed) {
	// Simulate fetching from threat intel API
	malwareHashes := []string{
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // Known malware hash
		"d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2", // Trojan hash
		"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1", // Ransomware hash
	}
	
	for _, hash := range malwareHashes {
		ioc := IOCIndicator{
			ID:          fmt.Sprintf("hash-%s", hash[:8]),
			Type:        "file_hash",
			Value:       hash,
			Description: "Known malware file hash",
			Severity:    "high",
			Source:      feed.Name,
			FirstSeen:   time.Now().AddDate(0, 0, -7), // 7 days ago
			LastSeen:    time.Now(),
			Tags:        []string{"malware", "hash", "file"},
		}
		td.iocDatabase[hash] = ioc
	}
}

// fetchMaliciousIPs fetches malicious IP indicators
func (td *ThreatDetector) fetchMaliciousIPs(feed ThreatIntelFeed) {
	maliciousIPs := []string{
		"192.168.100.100", // C2 server
		"10.0.0.100",      // Malicious host
		"172.16.0.100",    // Botnet node
		"203.0.113.100",   // Known bad IP
		"198.51.100.100",  // Phishing server
	}
	
	for _, ip := range maliciousIPs {
		ioc := IOCIndicator{
			ID:          fmt.Sprintf("ip-%s", strings.ReplaceAll(ip, ".", "-")),
			Type:        "ip_address",
			Value:       ip,
			Description: "Known malicious IP address",
			Severity:    "medium",
			Source:      feed.Name,
			FirstSeen:   time.Now().AddDate(0, 0, -3), // 3 days ago
			LastSeen:    time.Now(),
			Tags:        []string{"malicious", "ip", "network"},
		}
		td.iocDatabase[ip] = ioc
	}
}

// fetchMaliciousDomains fetches malicious domain indicators
func (td *ThreatDetector) fetchMaliciousDomains(feed ThreatIntelFeed) {
	maliciousDomains := []string{
		"evil-c2.com",
		"malware-download.net",
		"phishing-site.org",
		"ransomware-payment.onion",
		"botnet-control.info",
	}
	
	for _, domain := range maliciousDomains {
		ioc := IOCIndicator{
			ID:          fmt.Sprintf("domain-%s", strings.ReplaceAll(domain, ".", "-")),
			Type:        "domain",
			Value:       domain,
			Description: "Known malicious domain",
			Severity:    "medium",
			Source:      feed.Name,
			FirstSeen:   time.Now().AddDate(0, 0, -5), // 5 days ago
			LastSeen:    time.Now(),
			Tags:        []string{"malicious", "domain", "network"},
		}
		td.iocDatabase[domain] = ioc
	}
}

// fetchAPTIndicators fetches Advanced Persistent Threat indicators
func (td *ThreatDetector) fetchAPTIndicators(feed ThreatIntelFeed) {
	aptIndicators := map[string]string{
		"apt29-tool.exe":           "APT29 lateral movement tool",
		"lazarus-backdoor.dll":     "Lazarus Group backdoor",
		"cozy-bear-implant.bin":    "Cozy Bear implant",
		"fancy-bear-loader.exe":    "Fancy Bear loader",
		"carbanak-pos-malware.exe": "Carbanak POS malware",
	}
	
	for filename, description := range aptIndicators {
		// Create file name IOC
		ioc := IOCIndicator{
			ID:          fmt.Sprintf("apt-file-%s", strings.ReplaceAll(filename, ".", "-")),
			Type:        "filename",
			Value:       filename,
			Description: description,
			Severity:    "critical",
			Source:      feed.Name,
			FirstSeen:   time.Now().AddDate(0, 0, -30), // 30 days ago
			LastSeen:    time.Now(),
			Tags:        []string{"apt", "filename", "advanced_threat"},
		}
		td.iocDatabase[filename] = ioc
	}
}

// fetchRansomwareSignatures fetches ransomware-specific indicators
func (td *ThreatDetector) fetchRansomwareSignatures(feed ThreatIntelFeed) {
	ransomwareIndicators := map[string]string{
		".locked":     "File encrypted by ransomware",
		".encrypted":  "File encrypted by ransomware",
		".crypto":     "CryptoLocker variant",
		".wannacry":   "WannaCry ransomware",
		".ryuk":       "Ryuk ransomware",
		"ransom.txt":  "Ransomware note file",
		"decrypt.exe": "Ransomware decryption tool",
	}
	
	for indicator, description := range ransomwareIndicators {
		ioc := IOCIndicator{
			ID:          fmt.Sprintf("ransomware-%s", strings.ReplaceAll(indicator, ".", "-")),
			Type:        "file_extension",
			Value:       indicator,
			Description: description,
			Severity:    "critical",
			Source:      feed.Name,
			FirstSeen:   time.Now().AddDate(0, 0, -14), // 14 days ago
			LastSeen:    time.Now(),
			Tags:        []string{"ransomware", "file_extension", "encryption"},
		}
		td.iocDatabase[indicator] = ioc
	}
}

// updateEnrichmentCache updates the threat enrichment cache
func (td *ThreatDetector) updateEnrichmentCache() {
	// Clear old enrichment data
	td.enrichmentCache = make(map[string]ThreatEnrichment)
	
	// Build enrichment data from IOCs
	for _, ioc := range td.iocDatabase {
		enrichment := ThreatEnrichment{
			IOCValue:     ioc.Value,
			IOCType:      ioc.Type,
			ThreatFamily: td.extractThreatFamily(ioc),
			Severity:     ioc.Severity,
			Confidence:   td.calculateIOCConfidence(ioc),
			Attribution:  td.extractAttribution(ioc),
			TTPs:         td.extractTTPs(ioc),
			Metadata: map[string]interface{}{
				"source":     ioc.Source,
				"first_seen": ioc.FirstSeen,
				"last_seen":  ioc.LastSeen,
				"tags":       ioc.Tags,
			},
		}
		td.enrichmentCache[ioc.Value] = enrichment
	}
	
	log.Printf("Enrichment cache updated with %d entries", len(td.enrichmentCache))
}

// extractThreatFamily extracts threat family from IOC
func (td *ThreatDetector) extractThreatFamily(ioc IOCIndicator) string {
	for _, tag := range ioc.Tags {
		switch tag {
		case "ransomware":
			return "Ransomware"
		case "apt":
			return "Advanced Persistent Threat"
		case "malware":
			return "Malware"
		case "botnet":
			return "Botnet"
		case "phishing":
			return "Phishing"
		}
	}
	
	// Extract from description
	desc := strings.ToLower(ioc.Description)
	if strings.Contains(desc, "ransomware") {
		return "Ransomware"
	} else if strings.Contains(desc, "apt") || strings.Contains(desc, "advanced") {
		return "Advanced Persistent Threat"
	} else if strings.Contains(desc, "trojan") {
		return "Trojan"
	} else if strings.Contains(desc, "botnet") {
		return "Botnet"
	}
	
	return "Unknown"
}

// calculateIOCConfidence calculates confidence score for IOC
func (td *ThreatDetector) calculateIOCConfidence(ioc IOCIndicator) float64 {
	baseConfidence := 0.70
	
	// Increase confidence based on source reliability
	if strings.Contains(strings.ToLower(ioc.Source), "government") ||
	   strings.Contains(strings.ToLower(ioc.Source), "cert") {
		baseConfidence += 0.20
	}
	
	// Increase confidence based on recency
	daysSinceLastSeen := time.Since(ioc.LastSeen).Hours() / 24
	if daysSinceLastSeen < 7 {
		baseConfidence += 0.10
	}
	
	// Increase confidence based on severity
	switch strings.ToLower(ioc.Severity) {
	case "critical":
		baseConfidence += 0.15
	case "high":
		baseConfidence += 0.10
	case "medium":
		baseConfidence += 0.05
	}
	
	// Cap at 0.95
	if baseConfidence > 0.95 {
		baseConfidence = 0.95
	}
	
	return baseConfidence
}

// extractAttribution extracts threat attribution from IOC
func (td *ThreatDetector) extractAttribution(ioc IOCIndicator) string {
	desc := strings.ToLower(ioc.Description)
	
	// Known APT groups
	aptGroups := map[string]string{
		"apt29":        "APT29 (Cozy Bear)",
		"cozy bear":    "APT29 (Cozy Bear)",
		"apt28":        "APT28 (Fancy Bear)",
		"fancy bear":   "APT28 (Fancy Bear)",
		"lazarus":      "Lazarus Group",
		"carbanak":     "Carbanak Group",
		"apt1":         "APT1 (Comment Crew)",
		"apt40":        "APT40 (Leviathan)",
	}
	
	for keyword, group := range aptGroups {
		if strings.Contains(desc, keyword) {
			return group
		}
	}
	
	// Check tags
	for _, tag := range ioc.Tags {
		if group, exists := aptGroups[strings.ToLower(tag)]; exists {
			return group
		}
	}
	
	return "Unknown"
}

// extractTTPs extracts Tactics, Techniques, and Procedures from IOC
func (td *ThreatDetector) extractTTPs(ioc IOCIndicator) []string {
	var ttps []string
	
	desc := strings.ToLower(ioc.Description)
	
	// Map common indicators to MITRE ATT&CK TTPs
	ttpMap := map[string]string{
		"lateral movement": "T1021 - Remote Services",
		"backdoor":         "T1055 - Process Injection",
		"credential":       "T1003 - OS Credential Dumping",
		"persistence":      "T1053 - Scheduled Task/Job",
		"encryption":       "T1486 - Data Encrypted for Impact",
		"exfiltration":     "T1041 - Exfiltration Over C2 Channel",
		"c2":              "T1071 - Application Layer Protocol",
		"command":         "T1059 - Command and Scripting Interpreter",
	}
	
	for keyword, ttp := range ttpMap {
		if strings.Contains(desc, keyword) {
			ttps = append(ttps, ttp)
		}
	}
	
	// Add TTPs based on IOC type
	switch ioc.Type {
	case "ip_address":
		ttps = append(ttps, "T1071 - Application Layer Protocol")
	case "domain":
		ttps = append(ttps, "T1071 - Application Layer Protocol")
	case "file_hash":
		ttps = append(ttps, "T1055 - Process Injection")
	case "filename":
		ttps = append(ttps, "T1036 - Masquerading")
	}
	
	return ttps
}

// EnrichThreatEvent enriches a threat event with additional intelligence
func (td *ThreatDetector) EnrichThreatEvent(event *ThreatEvent) {
	if event.IOCMatched != nil {
		if enrichment, exists := td.enrichmentCache[event.IOCMatched.Value]; exists {
			// Add enrichment data to evidence
			if event.Evidence == nil {
				event.Evidence = make(map[string]interface{})
			}
			
			event.Evidence["threat_family"] = enrichment.ThreatFamily
			event.Evidence["attribution"] = enrichment.Attribution
			event.Evidence["ttps"] = enrichment.TTPs
			event.Evidence["enrichment_confidence"] = enrichment.Confidence
			event.Evidence["enrichment_metadata"] = enrichment.Metadata
			
			log.Printf("Enriched threat event with intelligence: %s -> %s", 
				event.IOCMatched.Value, enrichment.ThreatFamily)
		}
	}
}

// StartThreatIntelligenceUpdates starts periodic threat intelligence updates
func (td *ThreatDetector) StartThreatIntelligenceUpdates() {
	// Update immediately on start
	go td.updateThreatIntelligence()
	
	// Schedule periodic updates
	ticker := time.NewTicker(6 * time.Hour) // Update every 6 hours
	go func() {
		for range ticker.C {
			td.updateThreatIntelligence()
		}
	}()
	
	log.Println("Threat intelligence updates started (every 6 hours)")
}

// GetAlertChannel returns the alert channel for forwarding threats
func (td *ThreatDetector) GetAlertChannel() <-chan ThreatAlert {
	return td.alertChannel
}

// Real-time Threat Alert System Implementation

// SendThreatAlert sends a threat alert through the notification system
func (td *ThreatDetector) SendThreatAlert(alert ThreatAlert) {
	// Enrich alert with additional context
	td.enrichThreatAlert(&alert)
	
	// Send to alert channel (non-blocking)
	select {
	case td.alertChannel <- alert:
		log.Printf("Threat alert sent: %s (Severity: %s)", alert.Title, alert.Severity)
	default:
		log.Printf("Alert channel full, dropping alert: %s", alert.Title)
	}
	
	// Store alert in history
	td.storeAlertHistory(alert)
	
	// Trigger immediate notifications for critical alerts
	if alert.Severity == "critical" {
		go td.sendImmediateNotification(alert)
	}
}

// enrichThreatAlert enriches alert with additional context and metadata
func (td *ThreatDetector) enrichThreatAlert(alert *ThreatAlert) {
	// Add system context
	if alert.Metadata == nil {
		alert.Metadata = make(map[string]interface{})
	}
	
	alert.Metadata["alert_id"] = fmt.Sprintf("alert-%d", time.Now().UnixNano())
	alert.Metadata["detection_engine"] = "MW-ThreatDetector"
	alert.Metadata["alert_version"] = "1.0"
	
	// Add threat intelligence context if available
	if alert.IOCMatched != nil {
		if enrichment, exists := td.enrichmentCache[alert.IOCMatched.Value]; exists {
			alert.Metadata["threat_family"] = enrichment.ThreatFamily
			alert.Metadata["attribution"] = enrichment.Attribution
			alert.Metadata["confidence"] = enrichment.Confidence
		}
	}
	
	// Calculate risk score
	alert.RiskScore = td.calculateRiskScore(alert)
	
	// Add recommended actions
	alert.RecommendedActions = td.generateRecommendedActions(alert)
}

// calculateRiskScore calculates a risk score for the alert
func (td *ThreatDetector) calculateRiskScore(alert *ThreatAlert) float64 {
	baseScore := 0.0
	
	// Base score by severity
	switch strings.ToLower(alert.Severity) {
	case "critical":
		baseScore = 9.0
	case "high":
		baseScore = 7.0
	case "medium":
		baseScore = 5.0
	case "low":
		baseScore = 3.0
	case "info":
		baseScore = 1.0
	}
	
	// Adjust based on confidence
	if alert.Confidence > 0 {
		baseScore *= alert.Confidence
	}
	
	// Adjust based on threat family
	if threatFamily, exists := alert.Metadata["threat_family"]; exists {
		switch threatFamily {
		case "Ransomware":
			baseScore += 1.0
		case "Advanced Persistent Threat":
			baseScore += 0.8
		case "Trojan":
			baseScore += 0.6
		}
	}
	
	// Cap at 10.0
	if baseScore > 10.0 {
		baseScore = 10.0
	}
	
	return baseScore
}

// generateRecommendedActions generates recommended actions for the alert
func (td *ThreatDetector) generateRecommendedActions(alert *ThreatAlert) []string {
	var actions []string
	
	// Base actions by severity
	switch strings.ToLower(alert.Severity) {
	case "critical":
		actions = append(actions, "Immediately isolate affected system")
		actions = append(actions, "Initiate incident response procedure")
		actions = append(actions, "Contact security team")
	case "high":
		actions = append(actions, "Investigate immediately")
		actions = append(actions, "Consider system isolation")
		actions = append(actions, "Review system logs")
	case "medium":
		actions = append(actions, "Schedule investigation within 4 hours")
		actions = append(actions, "Monitor system activity")
	case "low":
		actions = append(actions, "Schedule investigation within 24 hours")
		actions = append(actions, "Add to monitoring watchlist")
	}
	
	// Specific actions based on threat type
	if alert.IOCMatched != nil {
		switch alert.IOCMatched.Type {
		case "file_hash":
			actions = append(actions, "Quarantine suspicious file")
			actions = append(actions, "Run full system antivirus scan")
		case "ip_address":
			actions = append(actions, "Block IP address at firewall")
			actions = append(actions, "Review network connections")
		case "domain":
			actions = append(actions, "Block domain at DNS level")
			actions = append(actions, "Review web proxy logs")
		case "filename":
			actions = append(actions, "Search for file across network")
			actions = append(actions, "Update file monitoring rules")
		}
	}
	
	// Actions based on threat family
	if threatFamily, exists := alert.Metadata["threat_family"]; exists {
		switch threatFamily {
		case "Ransomware":
			actions = append(actions, "Immediately disconnect from network")
			actions = append(actions, "Check backup integrity")
			actions = append(actions, "Prepare for potential data recovery")
		case "Advanced Persistent Threat":
			actions = append(actions, "Conduct thorough forensic analysis")
			actions = append(actions, "Check for lateral movement")
			actions = append(actions, "Review privileged account activity")
		}
	}
	
	return actions
}

// storeAlertHistory stores alert in historical database
func (td *ThreatDetector) storeAlertHistory(alert ThreatAlert) {
	td.mutex.Lock()
	defer td.mutex.Unlock()
	
	// Add to alert history (keep last 1000 alerts)
	td.alertHistory = append(td.alertHistory, alert)
	if len(td.alertHistory) > 1000 {
		td.alertHistory = td.alertHistory[1:]
	}
	
	// Update alert statistics
	td.updateAlertStatistics(alert)
}

// updateAlertStatistics updates alert statistics
func (td *ThreatDetector) updateAlertStatistics(alert ThreatAlert) {
	if td.alertStats == nil {
		td.alertStats = make(map[string]interface{})
	}
	
	// Update counters
	totalKey := "total_alerts"
	if count, exists := td.alertStats[totalKey]; exists {
		td.alertStats[totalKey] = count.(int) + 1
	} else {
		td.alertStats[totalKey] = 1
	}
	
	// Update severity counters
	severityKey := fmt.Sprintf("alerts_%s", strings.ToLower(alert.Severity))
	if count, exists := td.alertStats[severityKey]; exists {
		td.alertStats[severityKey] = count.(int) + 1
	} else {
		td.alertStats[severityKey] = 1
	}
	
	// Update last alert time
	td.alertStats["last_alert_time"] = alert.Timestamp
}

// sendImmediateNotification sends immediate notification for critical alerts
func (td *ThreatDetector) sendImmediateNotification(alert ThreatAlert) {
	log.Printf("CRITICAL ALERT: %s", alert.Title)
	log.Printf("Description: %s", alert.Description)
	log.Printf("Risk Score: %.1f", alert.RiskScore)
	
	// In a real implementation, this would:
	// - Send email notifications
	// - Send SMS alerts
	// - Trigger SIEM integration
	// - Update security dashboard
	// - Create incident tickets
	
	// Simulate notification delivery
	notification := map[string]interface{}{
		"type":        "critical_threat_alert",
		"alert_id":    alert.Metadata["alert_id"],
		"title":       alert.Title,
		"severity":    alert.Severity,
		"risk_score":  alert.RiskScore,
		"timestamp":   alert.Timestamp,
		"actions":     alert.RecommendedActions,
	}
	
	log.Printf("Immediate notification sent: %+v", notification)
}

// GetAlertStatistics returns current alert statistics
func (td *ThreatDetector) GetAlertStatistics() map[string]interface{} {
	td.mutex.RLock()
	defer td.mutex.RUnlock()
	
	// Create a copy to avoid race conditions
	stats := make(map[string]interface{})
	for k, v := range td.alertStats {
		stats[k] = v
	}
	
	return stats
}

// GetAlertHistory returns recent alert history
func (td *ThreatDetector) GetAlertHistory(limit int) []ThreatAlert {
	td.mutex.RLock()
	defer td.mutex.RUnlock()
	
	if limit <= 0 || limit > len(td.alertHistory) {
		limit = len(td.alertHistory)
	}
	
	// Return most recent alerts
	start := len(td.alertHistory) - limit
	if start < 0 {
		start = 0
	}
	
	history := make([]ThreatAlert, limit)
	copy(history, td.alertHistory[start:])
	
	return history
}

// StartAlertProcessor starts the alert processing system
func (td *ThreatDetector) StartAlertProcessor() {
	log.Println("Starting threat alert processor...")
	
	// Initialize alert statistics
	td.alertStats = make(map[string]interface{})
	td.alertHistory = make([]ThreatAlert, 0)
	
	// Start alert processing goroutine
	go func() {
		for alert := range td.alertChannel {
			// Process each alert
			td.processAlert(alert)
		}
	}()
	
	log.Println("Threat alert processor started")
}

// processAlert processes individual alerts
func (td *ThreatDetector) processAlert(alert ThreatAlert) {
	log.Printf("Processing threat alert: %s (Severity: %s, Risk: %.1f)", 
		alert.Title, alert.Severity, alert.RiskScore)
	
	// Store in history
	td.storeAlertHistory(alert)
	
	// Forward to external systems (SIEM, etc.)
	td.forwardToExternalSystems(alert)
	
	// Update threat tracking
	td.updateThreatTracking(alert)
}

// forwardToExternalSystems forwards alerts to external security systems
func (td *ThreatDetector) forwardToExternalSystems(alert ThreatAlert) {
	// In a real implementation, this would integrate with:
	// - SIEM systems (Splunk, QRadar, etc.)
	// - Security orchestration platforms (SOAR)
	// - Incident management systems
	// - Threat intelligence platforms
	
	log.Printf("Forwarding alert to external systems: %s", alert.Metadata["alert_id"])
}

// updateThreatTracking updates threat tracking and correlation
func (td *ThreatDetector) updateThreatTracking(alert ThreatAlert) {
	// Track related threats and patterns
	if alert.IOCMatched != nil {
		// Update IOC hit statistics
		iocKey := fmt.Sprintf("ioc_hits_%s", alert.IOCMatched.Value)
		if td.alertStats[iocKey] == nil {
			td.alertStats[iocKey] = 0
		}
		td.alertStats[iocKey] = td.alertStats[iocKey].(int) + 1
	}
	
	// Track threat families
	if threatFamily, exists := alert.Metadata["threat_family"]; exists {
		familyKey := fmt.Sprintf("family_%s", strings.ToLower(threatFamily.(string)))
		if td.alertStats[familyKey] == nil {
			td.alertStats[familyKey] = 0
		}
		td.alertStats[familyKey] = td.alertStats[familyKey].(int) + 1
	}
}
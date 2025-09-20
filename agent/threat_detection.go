//go:build windows

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
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
	iocDatabase    map[string]IOCIndicator
	behaviorRules  []BehaviorRule
	alertChannel   chan ThreatAlert
	eventBuffer    []map[string]interface{}
	stopChannel    chan bool
}

// IOCIndicator represents an Indicator of Compromise
type IOCIndicator struct {
	Type        string    `json:"type"`
	Value       string    `json:"value"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	Source      string    `json:"source"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Tags        []string  `json:"tags"`
}

// ThreatEvent represents a detected threat
type ThreatEvent struct {
	EventType     string                 `json:"event_type"`
	Timestamp     string                 `json:"timestamp"`
	ThreatLevel   string                 `json:"threat_level"`
	IOCMatched    *IOCIndicator          `json:"ioc_matched,omitempty"`
	BehaviorRule  *BehaviorRule          `json:"behavior_rule,omitempty"`
	ProcessInfo   *ProcessInfo           `json:"process_info,omitempty"`
	NetworkInfo   *ConnectionInfo        `json:"network_info,omitempty"`
	FileInfo      *FileInfo              `json:"file_info,omitempty"`
	Evidence      map[string]interface{} `json:"evidence"`
	Confidence    float64                `json:"confidence"`
}

// NewThreatDetector creates a new threat detector instance
func NewThreatDetector() *ThreatDetector {
	td := &ThreatDetector{
		iocDatabase:   make(map[string]IOCIndicator),
		behaviorRules: []BehaviorRule{},
		alertChannel:  make(chan ThreatAlert, 100),
		eventBuffer:   make([]map[string]interface{}, 0),
		stopChannel:   make(chan bool),
	}
	
	td.loadDefaultIOCs()
	td.loadDefaultBehaviorRules()
	
	return td
}

// loadDefaultIOCs loads default IOC indicators
func (td *ThreatDetector) loadDefaultIOCs() {
	defaultIOCs := []IOCIndicator{
		{
			Type:        "hash",
			Value:       "44d88612fea8a8f36de82e1278abb02f",
			Severity:    "high", // Use Severity instead of ThreatLevel
			FirstSeen:   time.Now().AddDate(0, -1, 0),
			LastSeen:    time.Now(),
			Source:      "VirusTotal", // Use Source instead of Sources
			Description: "Known malware hash",
		},
		{
			Type:        "ip",
			Value:       "192.168.1.100",
			Severity:    "medium", // Use Severity instead of ThreatLevel
			FirstSeen:   time.Now().AddDate(0, 0, -7),
			LastSeen:    time.Now(),
			Source:      "ThreatIntel", // Use Source instead of Sources
			Description: "Suspicious IP address",
		},
		{
			Type:        "domain",
			Value:       "malicious-domain.com",
			Severity:    "high", // Use Severity instead of ThreatLevel
			FirstSeen:   time.Now().AddDate(0, 0, -3),
			LastSeen:    time.Now(),
			Source:      "DNS-BH", // Use Source instead of Sources
			Description: "Known C&C domain",
		},
	}
	
	for _, ioc := range defaultIOCs {
		td.iocDatabase[ioc.Value] = ioc
	}
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

// GetAlertChannel returns the alert channel for forwarding threats
func (td *ThreatDetector) GetAlertChannel() <-chan ThreatAlert {
	return td.alertChannel
}
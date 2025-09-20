//go:build windows

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

// ConfigurationMonitor monitors network device configuration changes
type ConfigurationMonitor struct {
	devices         map[string]*MonitoredDevice
	snmpClient      *SNMPClient
	configStore     *ConfigurationStore
	running         bool
	stopChannel     chan bool
	checkInterval   time.Duration
	mutex           sync.RWMutex
	changeDetectors map[string]ConfigChangeDetector
}

// MonitoredDevice represents a device being monitored for configuration changes
type MonitoredDevice struct {
	IP               string                    `json:"ip"`
	Hostname         string                    `json:"hostname"`
	DeviceType       string                    `json:"device_type"`
	Vendor           string                    `json:"vendor"`
	SNMPCommunity    string                    `json:"snmp_community,omitempty"`
	SSHCredentials   *SSHCredentials           `json:"ssh_credentials,omitempty"`
	HTTPCredentials  *HTTPCredentials          `json:"http_credentials,omitempty"`
	LastConfigHash   string                    `json:"last_config_hash"`
	LastConfigCheck  time.Time                 `json:"last_config_check"`
	ConfigHistory    []*ConfigurationSnapshot  `json:"config_history"`
	MonitoringMethod string                    `json:"monitoring_method"`
	Enabled          bool                      `json:"enabled"`
}

// SSHCredentials for SSH-based configuration retrieval
type SSHCredentials struct {
	Username   string `json:"username"`
	Password   string `json:"password,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
	Port       int    `json:"port"`
}

// HTTPCredentials for HTTP/HTTPS-based configuration retrieval
type HTTPCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Port     int    `json:"port"`
	UseHTTPS bool   `json:"use_https"`
}

// ConfigurationSnapshot represents a point-in-time configuration
type ConfigurationSnapshot struct {
	Timestamp     time.Time         `json:"timestamp"`
	ConfigHash    string            `json:"config_hash"`
	ConfigSize    int               `json:"config_size"`
	ConfigData    string            `json:"config_data,omitempty"`
	Changes       []*ConfigChange   `json:"changes"`
	RetrievalMethod string          `json:"retrieval_method"`
	Metadata      map[string]string `json:"metadata"`
}

// ConfigChange represents a specific configuration change
type ConfigChange struct {
	Type        string    `json:"type"`        // added, removed, modified
	Section     string    `json:"section"`     // interface, routing, acl, etc.
	LineNumber  int       `json:"line_number,omitempty"`
	OldValue    string    `json:"old_value,omitempty"`
	NewValue    string    `json:"new_value"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`   // low, medium, high, critical
	Impact      string    `json:"impact"`     // security, performance, availability
}

// ConfigurationStore manages configuration storage and retrieval
type ConfigurationStore struct {
	configurations map[string][]*ConfigurationSnapshot
	mutex          sync.RWMutex
}

// ConfigChangeDetector interface for vendor-specific change detection
type ConfigChangeDetector interface {
	DetectChanges(oldConfig, newConfig string) ([]*ConfigChange, error)
	GetVendor() string
	GetConfigSections(config string) map[string]string
}

// NewConfigurationMonitor creates a new configuration monitor
func NewConfigurationMonitor(snmpClient *SNMPClient) *ConfigurationMonitor {
	cm := &ConfigurationMonitor{
		devices:         make(map[string]*MonitoredDevice),
		snmpClient:      snmpClient,
		configStore:     NewConfigurationStore(),
		running:         false,
		stopChannel:     make(chan bool),
		checkInterval:   15 * time.Minute, // Check every 15 minutes
		changeDetectors: make(map[string]ConfigChangeDetector),
	}

	// Register change detectors
	cm.RegisterChangeDetector(&CiscoChangeDetector{})
	cm.RegisterChangeDetector(&JuniperChangeDetector{})
	cm.RegisterChangeDetector(&PaloAltoChangeDetector{})
	cm.RegisterChangeDetector(&FortinetChangeDetector{})
	cm.RegisterChangeDetector(&GenericChangeDetector{})

	return cm
}

// NewConfigurationStore creates a new configuration store
func NewConfigurationStore() *ConfigurationStore {
	return &ConfigurationStore{
		configurations: make(map[string][]*ConfigurationSnapshot),
	}
}

// RegisterChangeDetector registers a vendor-specific change detector
func (cm *ConfigurationMonitor) RegisterChangeDetector(detector ConfigChangeDetector) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	cm.changeDetectors[detector.GetVendor()] = detector
}

// AddDevice adds a device to monitor
func (cm *ConfigurationMonitor) AddDevice(device *MonitoredDevice) error {
	if device.IP == "" {
		return fmt.Errorf("device IP is required")
	}

	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	device.Enabled = true
	device.ConfigHistory = make([]*ConfigurationSnapshot, 0)
	cm.devices[device.IP] = device

	log.Printf("Added device %s (%s) for configuration monitoring", device.IP, device.Hostname)
	return nil
}

// RemoveDevice removes a device from monitoring
func (cm *ConfigurationMonitor) RemoveDevice(ip string) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	delete(cm.devices, ip)
	log.Printf("Removed device %s from configuration monitoring", ip)
}

// Start starts the configuration monitor
func (cm *ConfigurationMonitor) Start() error {
	if cm.running {
		return fmt.Errorf("configuration monitor already running")
	}

	cm.running = true

	// Perform initial configuration retrieval
	go cm.performInitialScan()

	// Start monitoring loop
	go cm.monitoringLoop()

	log.Println("Configuration monitor started")
	return nil
}

// Stop stops the configuration monitor
func (cm *ConfigurationMonitor) Stop() {
	if !cm.running {
		return
	}

	cm.running = false
	close(cm.stopChannel)
	log.Println("Configuration monitor stopped")
}

// performInitialScan performs initial configuration retrieval for all devices
func (cm *ConfigurationMonitor) performInitialScan() {
	cm.mutex.RLock()
	devices := make([]*MonitoredDevice, 0, len(cm.devices))
	for _, device := range cm.devices {
		if device.Enabled {
			devices = append(devices, device)
		}
	}
	cm.mutex.RUnlock()

	log.Printf("Performing initial configuration scan for %d devices", len(devices))

	for _, device := range devices {
		cm.checkDeviceConfiguration(device)
		time.Sleep(2 * time.Second) // Avoid overwhelming devices
	}
}

// monitoringLoop main monitoring loop
func (cm *ConfigurationMonitor) monitoringLoop() {
	ticker := time.NewTicker(cm.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-cm.stopChannel:
			return
		case <-ticker.C:
			cm.performConfigurationCheck()
		}
	}
}

// performConfigurationCheck checks all devices for configuration changes
func (cm *ConfigurationMonitor) performConfigurationCheck() {
	cm.mutex.RLock()
	devices := make([]*MonitoredDevice, 0, len(cm.devices))
	for _, device := range cm.devices {
		if device.Enabled {
			devices = append(devices, device)
		}
	}
	cm.mutex.RUnlock()

	log.Printf("Checking configuration for %d devices", len(devices))

	// Use goroutines for concurrent checking
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 5) // Limit concurrent checks

	for _, device := range devices {
		wg.Add(1)
		go func(d *MonitoredDevice) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			cm.checkDeviceConfiguration(d)
		}(device)
	}

	wg.Wait()
}

// checkDeviceConfiguration checks a single device for configuration changes
func (cm *ConfigurationMonitor) checkDeviceConfiguration(device *MonitoredDevice) {
	log.Printf("Checking configuration for device %s (%s)", device.IP, device.Hostname)

	// Retrieve current configuration
	config, method, err := cm.retrieveConfiguration(device)
	if err != nil {
		log.Printf("Failed to retrieve configuration from %s: %v", device.IP, err)
		return
	}

	// Calculate configuration hash
	configHash := cm.calculateConfigHash(config)

	// Check if configuration has changed
	if device.LastConfigHash != "" && device.LastConfigHash == configHash {
		device.LastConfigCheck = time.Now()
		return // No changes
	}

	// Configuration has changed, create snapshot
	snapshot := &ConfigurationSnapshot{
		Timestamp:       time.Now(),
		ConfigHash:      configHash,
		ConfigSize:      len(config),
		ConfigData:      config,
		RetrievalMethod: method,
		Metadata:        make(map[string]string),
		Changes:         make([]*ConfigChange, 0),
	}

	// Detect specific changes if we have a previous configuration
	if device.LastConfigHash != "" && len(device.ConfigHistory) > 0 {
		lastSnapshot := device.ConfigHistory[len(device.ConfigHistory)-1]
		changes, err := cm.detectConfigurationChanges(device, lastSnapshot.ConfigData, config)
		if err != nil {
			log.Printf("Failed to detect changes for %s: %v", device.IP, err)
		} else {
			snapshot.Changes = changes
		}
	}

	// Update device
	device.LastConfigHash = configHash
	device.LastConfigCheck = time.Now()
	device.ConfigHistory = append(device.ConfigHistory, snapshot)

	// Limit history size
	if len(device.ConfigHistory) > 50 {
		device.ConfigHistory = device.ConfigHistory[1:]
	}

	// Store configuration
	cm.configStore.StoreConfiguration(device.IP, snapshot)

	// Generate configuration change event
	cm.generateConfigChangeEvent(device, snapshot)

	log.Printf("Configuration change detected for %s (%s) - %d changes", 
		device.IP, device.Hostname, len(snapshot.Changes))
}

// retrieveConfiguration retrieves configuration from a device
func (cm *ConfigurationMonitor) retrieveConfiguration(device *MonitoredDevice) (string, string, error) {
	// Try different methods based on device capabilities
	
	// Try SNMP first (if available)
	if device.SNMPCommunity != "" && cm.snmpClient != nil {
		config, err := cm.retrieveConfigViaSNMP(device)
		if err == nil {
			return config, "snmp", nil
		}
		log.Printf("SNMP config retrieval failed for %s: %v", device.IP, err)
	}

	// Try SSH (if credentials available)
	if device.SSHCredentials != nil {
		config, err := cm.retrieveConfigViaSSH(device)
		if err == nil {
			return config, "ssh", nil
		}
		log.Printf("SSH config retrieval failed for %s: %v", device.IP, err)
	}

	// Try HTTP/HTTPS (if credentials available)
	if device.HTTPCredentials != nil {
		config, err := cm.retrieveConfigViaHTTP(device)
		if err == nil {
			return config, "http", nil
		}
		log.Printf("HTTP config retrieval failed for %s: %v", device.IP, err)
	}

	return "", "", fmt.Errorf("no available method to retrieve configuration")
}

// retrieveConfigViaSNMP retrieves configuration via SNMP
func (cm *ConfigurationMonitor) retrieveConfigViaSNMP(device *MonitoredDevice) (string, error) {
	// This would use the SNMP client to retrieve configuration
	// For now, return a placeholder
	return "", fmt.Errorf("SNMP configuration retrieval not implemented")
}

// retrieveConfigViaSSH retrieves configuration via SSH
func (cm *ConfigurationMonitor) retrieveConfigViaSSH(device *MonitoredDevice) (string, error) {
	// This would use SSH to connect and retrieve configuration
	// Implementation would depend on the specific device type and vendor
	return "", fmt.Errorf("SSH configuration retrieval not implemented")
}

// retrieveConfigViaHTTP retrieves configuration via HTTP/HTTPS
func (cm *ConfigurationMonitor) retrieveConfigViaHTTP(device *MonitoredDevice) (string, error) {
	// This would use HTTP/HTTPS API to retrieve configuration
	// Implementation would depend on the specific device type and vendor
	return "", fmt.Errorf("HTTP configuration retrieval not implemented")
}

// calculateConfigHash calculates a hash of the configuration
func (cm *ConfigurationMonitor) calculateConfigHash(config string) string {
	// Normalize configuration (remove timestamps, etc.)
	normalized := cm.normalizeConfiguration(config)
	
	hash := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(hash[:])
}

// normalizeConfiguration normalizes configuration for comparison
func (cm *ConfigurationMonitor) normalizeConfiguration(config string) string {
	lines := strings.Split(config, "\n")
	var normalized []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "#") {
			continue
		}

		// Remove timestamps and dynamic values
		if strings.Contains(line, "Current configuration") ||
		   strings.Contains(line, "Last configuration change") ||
		   strings.Contains(line, "NVRAM config last updated") {
			continue
		}

		normalized = append(normalized, line)
	}

	return strings.Join(normalized, "\n")
}

// detectConfigurationChanges detects specific changes between configurations
func (cm *ConfigurationMonitor) detectConfigurationChanges(device *MonitoredDevice, oldConfig, newConfig string) ([]*ConfigChange, error) {
	// Try vendor-specific detector first
	if detector, exists := cm.changeDetectors[device.Vendor]; exists {
		return detector.DetectChanges(oldConfig, newConfig)
	}

	// Fall back to generic detector
	if detector, exists := cm.changeDetectors["Generic"]; exists {
		return detector.DetectChanges(oldConfig, newConfig)
	}

	return nil, fmt.Errorf("no change detector available for vendor %s", device.Vendor)
}

// generateConfigChangeEvent generates an event for configuration changes
func (cm *ConfigurationMonitor) generateConfigChangeEvent(device *MonitoredDevice, snapshot *ConfigurationSnapshot) {
	severity := 2 // Default to informational
	
	// Determine severity based on changes
	for _, change := range snapshot.Changes {
		switch change.Severity {
		case "critical":
			severity = 1
		case "high":
			if severity > 1 {
				severity = 1
			}
		case "medium":
			if severity > 2 {
				severity = 2
			}
		}
	}

	envelope := Envelope{
		Ts:       snapshot.Timestamp.UTC().Format(time.RFC3339),
		TenantID: "t-aci",
		Asset: map[string]string{
			"id":   device.IP,
			"type": "network_device",
			"name": device.Hostname,
		},
		Event: map[string]interface{}{
			"class":    "configuration_change",
			"name":     "config_modified",
			"severity": severity,
			"attrs": map[string]interface{}{
				"device_type":       device.DeviceType,
				"vendor":           device.Vendor,
				"config_hash":      snapshot.ConfigHash,
				"config_size":      snapshot.ConfigSize,
				"retrieval_method": snapshot.RetrievalMethod,
				"change_count":     len(snapshot.Changes),
				"changes":          snapshot.Changes,
			},
		},
		Ingest: map[string]string{
			"agent_version": "0.0.2",
			"schema":        "ocsf:1.2",
			"platform":      "config_monitor",
		},
	}

	// Send to gateway
	data, _ := json.Marshal(envelope)
	gatewayURL := "http://localhost:8080"
	go sendEventToGateway(gatewayURL, data)
}

// StoreConfiguration stores a configuration snapshot
func (cs *ConfigurationStore) StoreConfiguration(deviceIP string, snapshot *ConfigurationSnapshot) {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()

	if cs.configurations[deviceIP] == nil {
		cs.configurations[deviceIP] = make([]*ConfigurationSnapshot, 0)
	}

	cs.configurations[deviceIP] = append(cs.configurations[deviceIP], snapshot)

	// Limit stored configurations per device
	if len(cs.configurations[deviceIP]) > 100 {
		cs.configurations[deviceIP] = cs.configurations[deviceIP][1:]
	}
}

// GetConfigurationHistory returns configuration history for a device
func (cs *ConfigurationStore) GetConfigurationHistory(deviceIP string) []*ConfigurationSnapshot {
	cs.mutex.RLock()
	defer cs.mutex.RUnlock()

	if configs, exists := cs.configurations[deviceIP]; exists {
		// Return a copy
		result := make([]*ConfigurationSnapshot, len(configs))
		copy(result, configs)
		return result
	}

	return nil
}

// Change Detectors

// CiscoChangeDetector detects changes in Cisco configurations
type CiscoChangeDetector struct{}

func (d *CiscoChangeDetector) GetVendor() string { return "Cisco" }

func (d *CiscoChangeDetector) GetConfigSections(config string) map[string]string {
	sections := make(map[string]string)
	lines := strings.Split(config, "\n")
	
	currentSection := "global"
	var sectionLines []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "!") {
			continue
		}

		// Detect section changes
		if strings.HasPrefix(line, "interface ") {
			if len(sectionLines) > 0 {
				sections[currentSection] = strings.Join(sectionLines, "\n")
			}
			currentSection = line
			sectionLines = []string{line}
		} else if strings.HasPrefix(line, "router ") || 
				  strings.HasPrefix(line, "access-list ") ||
				  strings.HasPrefix(line, "ip route ") {
			if len(sectionLines) > 0 {
				sections[currentSection] = strings.Join(sectionLines, "\n")
			}
			currentSection = line
			sectionLines = []string{line}
		} else {
			sectionLines = append(sectionLines, line)
		}
	}

	if len(sectionLines) > 0 {
		sections[currentSection] = strings.Join(sectionLines, "\n")
	}

	return sections
}

func (d *CiscoChangeDetector) DetectChanges(oldConfig, newConfig string) ([]*ConfigChange, error) {
	changes := make([]*ConfigChange, 0)

	oldSections := d.GetConfigSections(oldConfig)
	newSections := d.GetConfigSections(newConfig)

	// Find added sections
	for section, content := range newSections {
		if _, exists := oldSections[section]; !exists {
			changes = append(changes, &ConfigChange{
				Type:        "added",
				Section:     section,
				NewValue:    content,
				Description: fmt.Sprintf("Added section: %s", section),
				Severity:    d.determineSeverity(section, "added"),
				Impact:      d.determineImpact(section),
			})
		}
	}

	// Find removed sections
	for section, content := range oldSections {
		if _, exists := newSections[section]; !exists {
			changes = append(changes, &ConfigChange{
				Type:        "removed",
				Section:     section,
				OldValue:    content,
				Description: fmt.Sprintf("Removed section: %s", section),
				Severity:    d.determineSeverity(section, "removed"),
				Impact:      d.determineImpact(section),
			})
		}
	}

	// Find modified sections
	for section, newContent := range newSections {
		if oldContent, exists := oldSections[section]; exists && oldContent != newContent {
			changes = append(changes, &ConfigChange{
				Type:        "modified",
				Section:     section,
				OldValue:    oldContent,
				NewValue:    newContent,
				Description: fmt.Sprintf("Modified section: %s", section),
				Severity:    d.determineSeverity(section, "modified"),
				Impact:      d.determineImpact(section),
			})
		}
	}

	return changes, nil
}

func (d *CiscoChangeDetector) determineSeverity(section, changeType string) string {
	section = strings.ToLower(section)
	
	// Critical changes
	if strings.Contains(section, "access-list") || 
	   strings.Contains(section, "ip route") ||
	   strings.Contains(section, "enable secret") {
		return "critical"
	}

	// High severity changes
	if strings.Contains(section, "interface") && changeType == "removed" {
		return "high"
	}

	// Medium severity changes
	if strings.Contains(section, "router") || strings.Contains(section, "interface") {
		return "medium"
	}

	return "low"
}

func (d *CiscoChangeDetector) determineImpact(section string) string {
	section = strings.ToLower(section)
	
	if strings.Contains(section, "access-list") {
		return "security"
	}
	if strings.Contains(section, "interface") || strings.Contains(section, "ip route") {
		return "availability"
	}
	if strings.Contains(section, "router") {
		return "performance"
	}
	
	return "configuration"
}

// JuniperChangeDetector detects changes in Juniper configurations
type JuniperChangeDetector struct{}

func (d *JuniperChangeDetector) GetVendor() string { return "Juniper" }

func (d *JuniperChangeDetector) GetConfigSections(config string) map[string]string {
	// Juniper uses hierarchical configuration
	sections := make(map[string]string)
	lines := strings.Split(config, "\n")
	
	var currentPath []string
	var sectionLines []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Handle hierarchy
		if strings.HasSuffix(line, " {") {
			// Start of new section
			sectionName := strings.TrimSuffix(line, " {")
			currentPath = append(currentPath, sectionName)
			sectionLines = append(sectionLines, line)
		} else if line == "}" {
			// End of section
			if len(currentPath) > 0 {
				sectionKey := strings.Join(currentPath, " > ")
				sections[sectionKey] = strings.Join(sectionLines, "\n")
				currentPath = currentPath[:len(currentPath)-1]
				sectionLines = []string{}
			}
		} else {
			sectionLines = append(sectionLines, line)
		}
	}

	return sections
}

func (d *JuniperChangeDetector) DetectChanges(oldConfig, newConfig string) ([]*ConfigChange, error) {
	// Similar to Cisco but adapted for Juniper's hierarchical structure
	changes := make([]*ConfigChange, 0)
	
	oldSections := d.GetConfigSections(oldConfig)
	newSections := d.GetConfigSections(newConfig)

	// Compare sections (similar logic to Cisco)
	for section, content := range newSections {
		if _, exists := oldSections[section]; !exists {
			changes = append(changes, &ConfigChange{
				Type:        "added",
				Section:     section,
				NewValue:    content,
				Description: fmt.Sprintf("Added configuration: %s", section),
				Severity:    "medium",
				Impact:      "configuration",
			})
		}
	}

	return changes, nil
}

// PaloAltoChangeDetector detects changes in Palo Alto configurations
type PaloAltoChangeDetector struct{}

func (d *PaloAltoChangeDetector) GetVendor() string { return "Palo Alto Networks" }

func (d *PaloAltoChangeDetector) GetConfigSections(config string) map[string]string {
	// Palo Alto uses XML-based configuration
	sections := make(map[string]string)
	// This would parse XML configuration
	// For now, return basic sections
	sections["global"] = config
	return sections
}

func (d *PaloAltoChangeDetector) DetectChanges(oldConfig, newConfig string) ([]*ConfigChange, error) {
	changes := make([]*ConfigChange, 0)
	
	if oldConfig != newConfig {
		changes = append(changes, &ConfigChange{
			Type:        "modified",
			Section:     "configuration",
			OldValue:    oldConfig,
			NewValue:    newConfig,
			Description: "Configuration modified",
			Severity:    "medium",
			Impact:      "security",
		})
	}

	return changes, nil
}

// FortinetChangeDetector detects changes in Fortinet configurations
type FortinetChangeDetector struct{}

func (d *FortinetChangeDetector) GetVendor() string { return "Fortinet" }

func (d *FortinetChangeDetector) GetConfigSections(config string) map[string]string {
	sections := make(map[string]string)
	lines := strings.Split(config, "\n")
	
	currentSection := "global"
	var sectionLines []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "config ") {
			if len(sectionLines) > 0 {
				sections[currentSection] = strings.Join(sectionLines, "\n")
			}
			currentSection = line
			sectionLines = []string{line}
		} else if line == "end" {
			if len(sectionLines) > 0 {
				sections[currentSection] = strings.Join(sectionLines, "\n")
			}
			currentSection = "global"
			sectionLines = []string{}
		} else {
			sectionLines = append(sectionLines, line)
		}
	}

	return sections
}

func (d *FortinetChangeDetector) DetectChanges(oldConfig, newConfig string) ([]*ConfigChange, error) {
	changes := make([]*ConfigChange, 0)
	
	oldSections := d.GetConfigSections(oldConfig)
	newSections := d.GetConfigSections(newConfig)

	for section, content := range newSections {
		if oldContent, exists := oldSections[section]; !exists {
			changes = append(changes, &ConfigChange{
				Type:        "added",
				Section:     section,
				NewValue:    content,
				Description: fmt.Sprintf("Added configuration section: %s", section),
				Severity:    "medium",
				Impact:      "security",
			})
		} else if oldContent != content {
			changes = append(changes, &ConfigChange{
				Type:        "modified",
				Section:     section,
				OldValue:    oldContent,
				NewValue:    content,
				Description: fmt.Sprintf("Modified configuration section: %s", section),
				Severity:    "medium",
				Impact:      "security",
			})
		}
	}

	return changes, nil
}

// GenericChangeDetector provides basic change detection for unknown vendors
type GenericChangeDetector struct{}

func (d *GenericChangeDetector) GetVendor() string { return "Generic" }

func (d *GenericChangeDetector) GetConfigSections(config string) map[string]string {
	sections := make(map[string]string)
	sections["configuration"] = config
	return sections
}

func (d *GenericChangeDetector) DetectChanges(oldConfig, newConfig string) ([]*ConfigChange, error) {
	changes := make([]*ConfigChange, 0)
	
	if oldConfig != newConfig {
		// Simple line-by-line comparison
		oldLines := strings.Split(oldConfig, "\n")
		newLines := strings.Split(newConfig, "\n")
		
		// Find added/removed lines
		oldLineMap := make(map[string]bool)
		for _, line := range oldLines {
			oldLineMap[line] = true
		}
		
		newLineMap := make(map[string]bool)
		for i, line := range newLines {
			newLineMap[line] = true
			if !oldLineMap[line] {
				changes = append(changes, &ConfigChange{
					Type:        "added",
					Section:     "configuration",
					LineNumber:  i + 1,
					NewValue:    line,
					Description: fmt.Sprintf("Added line: %s", line),
					Severity:    "low",
					Impact:      "configuration",
				})
			}
		}
		
		for i, line := range oldLines {
			if !newLineMap[line] {
				changes = append(changes, &ConfigChange{
					Type:        "removed",
					Section:     "configuration",
					LineNumber:  i + 1,
					OldValue:    line,
					Description: fmt.Sprintf("Removed line: %s", line),
					Severity:    "low",
					Impact:      "configuration",
				})
			}
		}
	}

	return changes, nil
}
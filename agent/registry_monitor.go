//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Registry monitoring structures
type RegistryEvent struct {
	EventType    string         `json:"event_type"`
	Timestamp    string         `json:"timestamp"`
	ProcessInfo  ProcessInfo    `json:"process_info"`
	RegistryInfo RegistryInfo   `json:"registry_info"`
	OldValue     *RegistryValue `json:"old_value,omitempty"`
	NewValue     *RegistryValue `json:"new_value,omitempty"`
}

type RegistryInfo struct {
	Hive     string `json:"hive"`
	KeyPath  string `json:"key_path"`
	FullPath string `json:"full_path"`
	Action   string `json:"action"`
}

type RegistryValue struct {
	Name     string      `json:"name"`
	Type     string      `json:"type"`
	Data     interface{} `json:"data"`
	DataSize uint32      `json:"data_size"`
}

type WatchedRegistryKey struct {
	Hive      registry.Key
	KeyPath   string
	Handle    registry.Key
	EventHandle windows.Handle
	Critical  bool
}

// Registry Monitor manages registry monitoring
type RegistryMonitor struct {
	watchedKeys   map[string]*WatchedRegistryKey
	eventChannel  chan RegistryEvent
	stopChannel   chan bool
	running       bool
	criticalKeys  []string
	startupKeys   []string
	securityKeys  []string
}

// NewRegistryMonitor creates a new registry monitor
func NewRegistryMonitor() *RegistryMonitor {
	return &RegistryMonitor{
		watchedKeys:  make(map[string]*WatchedRegistryKey),
		eventChannel: make(chan RegistryEvent, 1000),
		stopChannel:  make(chan bool),
		running:      false,
		criticalKeys: []string{
			// System critical keys
			"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
			"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
			"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices",
			"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
			"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
			"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
			
			// Security keys
			"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies",
			"SOFTWARE\\Microsoft\\Windows Defender",
			"SYSTEM\\CurrentControlSet\\Services",
			"SYSTEM\\CurrentControlSet\\Control\\SafeBoot",
			"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
			
			// Network and firewall
			"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy",
			"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
			
			// System configuration
			"SYSTEM\\CurrentControlSet\\Control\\Session Manager",
			"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
		},
		startupKeys: []string{
			"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
			"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
			"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
			"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
		},
		securityKeys: []string{
			"SOFTWARE\\Microsoft\\Windows Defender",
			"SOFTWARE\\Policies\\Microsoft\\Windows Defender",
			"SYSTEM\\CurrentControlSet\\Services\\WinDefend",
			"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
		},
	}
}

// Start begins registry monitoring
func (rm *RegistryMonitor) Start() error {
	if rm.running {
		return fmt.Errorf("registry monitor already running")
	}

	rm.running = true
	
	// Start monitoring critical registry keys
	for _, keyPath := range rm.criticalKeys {
		if err := rm.watchRegistryKey(registry.LOCAL_MACHINE, keyPath, true); err != nil {
			log.Printf("Failed to watch registry key HKLM\\%s: %v", keyPath, err)
		}
	}
	
	// Also monitor current user keys
	userKeys := []string{
		"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
		"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
	}
	
	for _, keyPath := range userKeys {
		if err := rm.watchRegistryKey(registry.CURRENT_USER, keyPath, true); err != nil {
			log.Printf("Failed to watch registry key HKCU\\%s: %v", keyPath, err)
		}
	}
	
	// Start periodic scanning goroutine
	go rm.performPeriodicScans()
	
	// Start event processing goroutine
	go rm.processEvents()
	
	// Start registry monitoring goroutine
	go rm.monitorRegistryChanges()
	
	log.Println("Registry monitor started")
	return nil
}

// Stop stops registry monitoring
func (rm *RegistryMonitor) Stop() {
	if !rm.running {
		return
	}

	rm.running = false
	
	// Close all registry handles
	for _, watchedKey := range rm.watchedKeys {
		if watchedKey.Handle != 0 {
			registry.Key(watchedKey.Handle).Close()
		}
		if watchedKey.EventHandle != 0 {
			windows.CloseHandle(watchedKey.EventHandle)
		}
	}
	
	close(rm.stopChannel)
	log.Println("Registry monitor stopped")
}

// GetEventChannel returns the event channel
func (rm *RegistryMonitor) GetEventChannel() <-chan RegistryEvent {
	return rm.eventChannel
}

// watchRegistryKey starts watching a registry key for changes
func (rm *RegistryMonitor) watchRegistryKey(hive registry.Key, keyPath string, critical bool) error {
	// Open the registry key
	key, err := registry.OpenKey(hive, keyPath, registry.NOTIFY|registry.READ)
	if err != nil {
		return err
	}

	// Create event handle for notifications
	eventHandle, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		key.Close()
		return err
	}

	// Create watched key structure
	watchedKey := &WatchedRegistryKey{
		Hive:        hive,
		KeyPath:     keyPath,
		Handle:      key,
		EventHandle: eventHandle,
		Critical:    critical,
	}

	fullPath := rm.getFullRegistryPath(hive, keyPath)
	rm.watchedKeys[fullPath] = watchedKey
	
	// Start watching
	go rm.watchKeyChanges(watchedKey)
	
	return nil
}

// watchKeyChanges monitors changes in a registry key
func (rm *RegistryMonitor) watchKeyChanges(watchedKey *WatchedRegistryKey) {
	for rm.running {
		// Register for change notifications
		err := windows.RegNotifyChangeKeyValue(
			windows.Handle(watchedKey.Handle),
			true, // watch subtree
			windows.REG_NOTIFY_CHANGE_NAME|
				windows.REG_NOTIFY_CHANGE_ATTRIBUTES|
				windows.REG_NOTIFY_CHANGE_LAST_SET|
				windows.REG_NOTIFY_CHANGE_SECURITY,
			watchedKey.EventHandle,
			true, // asynchronous
		)
		
		if err != nil {
			log.Printf("RegNotifyChangeKeyValue failed for %s: %v", watchedKey.KeyPath, err)
			time.Sleep(10 * time.Second)
			continue
		}

		// Wait for change notification
		result, err := windows.WaitForSingleObject(watchedKey.EventHandle, windows.INFINITE)
		if err != nil || result != windows.WAIT_OBJECT_0 {
			log.Printf("WaitForSingleObject failed for %s: %v", watchedKey.KeyPath, err)
			time.Sleep(5 * time.Second)
			continue
		}

		if !rm.running {
			break
		}

		// Process the change
		rm.processRegistryChange(watchedKey)
	}
}

// processRegistryChange processes a registry change notification
func (rm *RegistryMonitor) processRegistryChange(watchedKey *WatchedRegistryKey) {
	fullPath := rm.getFullRegistryPath(watchedKey.Hive, watchedKey.KeyPath)
	
	// Get current values
	currentValues, err := rm.getRegistryKeyValues(watchedKey.Handle)
	if err != nil {
		log.Printf("Failed to get registry values for %s: %v", fullPath, err)
		return
	}

	// Create registry event
	event := RegistryEvent{
		EventType:   "registry_modified",
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		ProcessInfo: rm.getCurrentProcessInfo(),
		RegistryInfo: RegistryInfo{
			Hive:     rm.getHiveName(watchedKey.Hive),
			KeyPath:  watchedKey.KeyPath,
			FullPath: fullPath,
			Action:   "modified",
		},
	}

	// Add value information if available
	if len(currentValues) > 0 {
		// For simplicity, report the first changed value
		for name, value := range currentValues {
			event.NewValue = &RegistryValue{
				Name:     name,
				Type:     value.Type,
				Data:     value.Data,
				DataSize: value.DataSize,
			}
			break
		}
	}

	rm.eventChannel <- event
}

// performPeriodicScans performs periodic scans of critical registry keys
func (rm *RegistryMonitor) performPeriodicScans() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-rm.stopChannel:
			return
		case <-ticker.C:
			rm.scanStartupKeys()
			rm.scanSecurityKeys()
		}
	}
}

// scanStartupKeys scans startup registry keys for suspicious entries
func (rm *RegistryMonitor) scanStartupKeys() {
	for _, keyPath := range rm.startupKeys {
		rm.scanRegistryKey(registry.LOCAL_MACHINE, keyPath, "startup_scan")
		rm.scanRegistryKey(registry.CURRENT_USER, keyPath, "startup_scan")
	}
}

// scanSecurityKeys scans security-related registry keys
func (rm *RegistryMonitor) scanSecurityKeys() {
	for _, keyPath := range rm.securityKeys {
		rm.scanRegistryKey(registry.LOCAL_MACHINE, keyPath, "security_scan")
	}
}

// scanRegistryKey scans a specific registry key
func (rm *RegistryMonitor) scanRegistryKey(hive registry.Key, keyPath, scanType string) {
	key, err := registry.OpenKey(hive, keyPath, registry.READ)
	if err != nil {
		return
	}
	defer key.Close()

	values, err := rm.getRegistryKeyValues(key)
	if err != nil {
		return
	}

	fullPath := rm.getFullRegistryPath(hive, keyPath)

	for name, value := range values {
		// Check for suspicious patterns
		if rm.isSuspiciousRegistryValue(name, value.Data, scanType) {
			event := RegistryEvent{
				EventType:   "suspicious_registry_entry",
				Timestamp:   time.Now().UTC().Format(time.RFC3339),
				ProcessInfo: rm.getCurrentProcessInfo(),
				RegistryInfo: RegistryInfo{
					Hive:     rm.getHiveName(hive),
					KeyPath:  keyPath,
					FullPath: fullPath,
					Action:   scanType,
				},
				NewValue: &RegistryValue{
					Name:     name,
					Type:     value.Type,
					Data:     value.Data,
					DataSize: value.DataSize,
				},
			}
			
			rm.eventChannel <- event
		}
	}
}

// processEvents processes and forwards events
func (rm *RegistryMonitor) processEvents() {
	for {
		select {
		case <-rm.stopChannel:
			return
		case event := <-rm.eventChannel:
			rm.handleRegistryEvent(event)
		}
	}
}

// handleRegistryEvent handles individual registry events
func (rm *RegistryMonitor) handleRegistryEvent(event RegistryEvent) {
	// Create envelope for the event
	envelope := Envelope{
		Ts:       event.Timestamp,
		TenantID: "t-aci",
		Asset: map[string]string{
			"id":   getHostname(),
			"type": "endpoint",
			"os":   "windows",
			"ip":   getLocalIP(),
		},
		User: map[string]string{
			"id":     event.ProcessInfo.User,
			"domain": event.ProcessInfo.Domain,
		},
		Event: map[string]interface{}{
			"class":    "registry",
			"name":     event.EventType,
			"severity": getRegistryEventSeverity(event.EventType, event.RegistryInfo.KeyPath),
			"attrs": map[string]interface{}{
				"process_id":     event.ProcessInfo.PID,
				"process_name":   event.ProcessInfo.Name,
				"registry_hive":  event.RegistryInfo.Hive,
				"registry_key":   event.RegistryInfo.KeyPath,
				"registry_path":  event.RegistryInfo.FullPath,
				"action":         event.RegistryInfo.Action,
			},
		},
		Ingest: map[string]string{
			"agent_version": "0.0.2",
			"schema":        "ocsf:1.2",
			"platform":      "windows",
		},
	}

	// Add value information if available
	if event.NewValue != nil {
		envelope.Event["registry_value"] = map[string]interface{}{
			"name":      event.NewValue.Name,
			"type":      event.NewValue.Type,
			"data":      event.NewValue.Data,
			"data_size": event.NewValue.DataSize,
		}
	}

	if event.OldValue != nil {
		envelope.Event["old_registry_value"] = map[string]interface{}{
			"name":      event.OldValue.Name,
			"type":      event.OldValue.Type,
			"data":      event.OldValue.Data,
			"data_size": event.OldValue.DataSize,
		}
	}

	// Send to gateway
	data, _ := json.Marshal(envelope)
	gatewayURL := os.Getenv("GATEWAY_URL")
	if gatewayURL == "" {
		gatewayURL = "http://localhost:8080"
	}
	
	go sendEventToGateway(gatewayURL, data)
}

// monitorRegistryChanges monitors registry changes
func (rm *RegistryMonitor) monitorRegistryChanges() {
	// This function handles the main registry monitoring loop
	for rm.running {
		time.Sleep(1 * time.Second)
		// Registry monitoring is handled by individual goroutines
		// This is just a keepalive loop
	}
}

// Helper functions

func (rm *RegistryMonitor) getFullRegistryPath(hive registry.Key, keyPath string) string {
	hiveName := rm.getHiveName(hive)
	return fmt.Sprintf("%s\\%s", hiveName, keyPath)
}

func (rm *RegistryMonitor) getHiveName(hive registry.Key) string {
	switch hive {
	case registry.CLASSES_ROOT:
		return "HKEY_CLASSES_ROOT"
	case registry.CURRENT_USER:
		return "HKEY_CURRENT_USER"
	case registry.LOCAL_MACHINE:
		return "HKEY_LOCAL_MACHINE"
	case registry.USERS:
		return "HKEY_USERS"
	case registry.CURRENT_CONFIG:
		return "HKEY_CURRENT_CONFIG"
	default:
		return "UNKNOWN"
	}
}

func (rm *RegistryMonitor) getRegistryKeyValues(key registry.Key) (map[string]RegistryValue, error) {
	values := make(map[string]RegistryValue)
	
	valueNames, err := key.ReadValueNames(-1)
	if err != nil {
		return values, err
	}

	for _, name := range valueNames {
		// Get the value type first
		_, valueType, err := key.GetValue(name, nil)
		if err != nil {
			continue
		}

		regValue := RegistryValue{
			Name: name,
			Type: rm.getRegistryValueTypeName(valueType),
		}

		// Get the actual value based on type
		switch valueType {
		case registry.SZ, registry.EXPAND_SZ:
			if val, _, err := key.GetStringValue(name); err == nil {
				regValue.Data = val
				regValue.DataSize = uint32(len(val))
			}
		case registry.BINARY:
			if val, _, err := key.GetBinaryValue(name); err == nil {
				regValue.Data = val
				regValue.DataSize = uint32(len(val))
			}
		case registry.DWORD:
			if val, _, err := key.GetIntegerValue(name); err == nil {
				regValue.Data = uint32(val)
				regValue.DataSize = 4
			}
		case registry.QWORD:
			if val, _, err := key.GetIntegerValue(name); err == nil {
				regValue.Data = val
				regValue.DataSize = 8
			}
		case registry.MULTI_SZ:
			if val, _, err := key.GetStringsValue(name); err == nil {
				regValue.Data = val
				regValue.DataSize = uint32(len(strings.Join(val, "")))
			}
		default:
			// For unknown types, get as binary
			if val, _, err := key.GetBinaryValue(name); err == nil {
				regValue.Data = val
				regValue.DataSize = uint32(len(val))
			}
		}

		values[name] = regValue
	}

	return values, nil
}

func (rm *RegistryMonitor) getRegistryValueTypeName(valueType uint32) string {
	switch valueType {
	case registry.SZ:
		return "REG_SZ"
	case registry.EXPAND_SZ:
		return "REG_EXPAND_SZ"
	case registry.BINARY:
		return "REG_BINARY"
	case registry.DWORD:
		return "REG_DWORD"
	case registry.DWORD_BIG_ENDIAN:
		return "REG_DWORD_BIG_ENDIAN"
	case registry.LINK:
		return "REG_LINK"
	case registry.MULTI_SZ:
		return "REG_MULTI_SZ"
	case registry.RESOURCE_LIST:
		return "REG_RESOURCE_LIST"
	case registry.QWORD:
		return "REG_QWORD"
	default:
		return "UNKNOWN"
	}
}

func (rm *RegistryMonitor) getCurrentProcessInfo() ProcessInfo {
	return ProcessInfo{
		PID:  os.Getpid(),
		Name: "registry_monitor",
		Path: "",
		User: "SYSTEM",
	}
}

func (rm *RegistryMonitor) isSuspiciousRegistryValue(name string, data interface{}, scanType string) bool {
	if scanType == "startup_scan" {
		// Check for suspicious startup entries
		if dataStr, ok := data.(string); ok {
			dataLower := strings.ToLower(dataStr)
			
			// Suspicious patterns in startup entries
			suspiciousPatterns := []string{
				"powershell",
				"cmd.exe",
				"wscript",
				"cscript",
				"regsvr32",
				"rundll32",
				"mshta",
				"bitsadmin",
				"certutil",
				"temp\\",
				"appdata\\",
				"%temp%",
				"%appdata%",
			}
			
			for _, pattern := range suspiciousPatterns {
				if strings.Contains(dataLower, pattern) {
					return true
				}
			}
			
			// Check for suspicious file extensions
			suspiciousExts := []string{".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar"}
			for _, ext := range suspiciousExts {
				if strings.Contains(dataLower, ext) {
					return true
				}
			}
		}
	}
	
	if scanType == "security_scan" {
		// Check for security-related changes
		nameLower := strings.ToLower(name)
		
		// Security-related value names
		securityValues := []string{
			"disableantispyware",
			"disablerealtimemonitoring",
			"disablebehaviormonitoring",
			"disableioavprotection",
			"disablescriptscanning",
			"enablelua",
			"consentpromptbehavioradmin",
		}
		
		for _, secValue := range securityValues {
			if strings.Contains(nameLower, secValue) {
				return true
			}
		}
	}
	
	return false
}

func getRegistryEventSeverity(eventType, keyPath string) int {
	keyPathLower := strings.ToLower(keyPath)
	
	// High severity for security-related keys
	if strings.Contains(keyPathLower, "windows defender") ||
		strings.Contains(keyPathLower, "firewall") ||
		strings.Contains(keyPathLower, "policies") ||
		strings.Contains(keyPathLower, "winlogon") {
		switch eventType {
		case "registry_modified":
			return 4 // High
		case "suspicious_registry_entry":
			return 5 // Critical
		}
	}
	
	// Medium severity for startup keys
	if strings.Contains(keyPathLower, "run") ||
		strings.Contains(keyPathLower, "services") {
		switch eventType {
		case "registry_modified":
			return 3 // Medium
		case "suspicious_registry_entry":
			return 4 // High
		}
	}
	
	switch eventType {
	case "registry_modified":
		return 2 // Informational
	case "suspicious_registry_entry":
		return 3 // Medium
	default:
		return 1 // Low
	}
}

func init() {
	// Custom implementation of RegNotifyChangeKeyValue
}

// Helper function to check registry value
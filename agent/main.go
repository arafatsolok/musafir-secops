package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"
)

type Envelope struct {
	Ts       string                 `json:"ts"`
	TenantID string                 `json:"tenant_id"`
	Asset    map[string]string      `json:"asset"`
	User     map[string]string      `json:"user"`
	Event    map[string]interface{} `json:"event"`
	Ingest   map[string]string      `json:"ingest"`
}

func main() {
	gatewayURL := os.Getenv("GATEWAY_URL")
	if gatewayURL == "" {
		gatewayURL = "http://localhost:8080"
	}

	evt := Envelope{
		Ts:       time.Now().UTC().Format(time.RFC3339),
		TenantID: "t-aci",
		Asset:    map[string]string{"id": "host-01", "type": "endpoint", "os": "windows", "ip": "10.10.1.15"},
		User:     map[string]string{"id": "aad:arafat", "sid": "S-1-5-21-..."},
		Event: map[string]interface{}{
			"class":    "process",
			"name":     "process_start",
			"severity": 3,
			"attrs": map[string]interface{}{
				"image": "C:/Windows/System32/wscript.exe",
				"cmd":   "wscript script.vbs",
				"ppid":  1024,
			},
		},
		Ingest: map[string]string{"agent_version": "0.0.1", "schema": "ocsf:1.2"},
	}

	data, _ := json.Marshal(evt)
	log.Printf("agent event: %s", string(data))

	req, err := http.NewRequest(http.MethodPost, gatewayURL+"/v1/events", bytes.NewReader(data))
	if err != nil {
		log.Fatalf("build request failed: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("post failed: %v", err)
	}
	defer resp.Body.Close()
	log.Printf("gateway response: %s", resp.Status)
}

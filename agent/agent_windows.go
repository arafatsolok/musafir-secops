//go:build windows

package main

import (
	"encoding/json"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/arafatsolok/musafir-secops/agent/ransomware"
)

// Global monitoring instances
var (
	processMonitor  *ProcessMonitor
	networkMonitor  *NetworkMonitor
	fileMonitor     *FileMonitor
	registryMonitor *RegistryMonitor
	telemetryCollector *WindowsTelemetryCollector
)

// Windows-specific agent capabilities
func init() {
	log.Printf("MUSAFIR Agent starting on Windows %s", runtime.GOARCH)
}

// Enhanced Windows event generation with comprehensive telemetry
func generateEnhancedWindowsEvent() Envelope {
	hostname, _ := os.Hostname()
	
	// Collect comprehensive system information
	systemInfo, err := telemetryCollector.CollectSystemInfo()
	if err != nil {
		log.Printf("Error collecting system info: %v", err)
		return Envelope{}
	}
	
	return Envelope{
		Ts:       time.Now().UTC().Format(time.RFC3339),
		TenantID: "t-aci",
		Asset: map[string]string{
			"id":       hostname,
			"type":     "endpoint",
			"os":       "windows",
			"version":  systemInfo.OS.Version,
			"arch":     systemInfo.OS.Architecture,
			"domain":   systemInfo.Domain,
			"ip":       getLocalIP(),
		},
		User: map[string]string{
			"id":       "aad:" + getCurrentUsername(),
			"sid":      getCurrentUserSID(),
			"domain":   systemInfo.Domain,
		},
		Event: map[string]interface{}{
			"class":    "system",
			"name":     "agent_heartbeat",
			"severity": 1,
			"attrs": map[string]interface{}{
				"system_info":    systemInfo,
				"agent_version":  "1.0.0-enhanced",
				"monitoring":     []string{"process", "network", "file", "registry", "ransomware"},
				"uptime":        getSystemUptime(),
				"cpu_usage":     systemInfo.Performance.CPUUsage,
				"memory_usage":  systemInfo.Performance.MemoryUsage,
			},
		},
		Ingest: map[string]string{
			"agent_version": "1.0.0-enhanced",
			"schema":        "ocsf:1.2",
			"platform":      "windows",
			"capabilities":  "edr,xdr,siem",
		},
	}
}

// Get local IP address
func getCurrentUsername() string {
	username := os.Getenv("USERNAME")
	if username == "" {
		username = "unknown"
	}
	return username
}

func getCurrentUserSID() string {
	// This is a simplified implementation
	// In a real implementation, you would use Windows API to get the actual SID
	return "S-1-5-21-000000000-000000000-000000000-1000"
}

func getLocalIP() string {
	// This is a simplified version - the network monitor has more comprehensive IP detection
	return "10.10.1.15" // Placeholder - would be dynamically detected
}

// Initialize all monitoring components
func initializeMonitoring() error {
	// Initialize telemetry collector
	telemetryCollector = NewWindowsTelemetryCollector()
	
	// Initialize process monitor
	processMonitor = NewProcessMonitor()
	
	// Initialize network monitor
	networkMonitor = NewNetworkMonitor()
	
	// Initialize file monitor
	fileMonitor = NewFileMonitor()
	
	// Initialize registry monitor
	registryMonitor = NewRegistryMonitor()
	
	return nil
}

// Start all monitoring services
func startMonitoring(gatewayURL string) {
	log.Println("Starting comprehensive Windows monitoring...")
	
	// Start process monitoring
	go func() {
		if err := processMonitor.Start(); err != nil {
			log.Printf("Process monitor error: %v", err)
		}
		// Forward process events to gateway
		go forwardProcessEvents(processMonitor.GetEventChannel(), gatewayURL)
	}()
	
	// Start network monitoring
	go func() {
		if err := networkMonitor.Start(); err != nil {
			log.Printf("Network monitor error: %v", err)
		}
		// Forward network events to gateway
		go forwardNetworkEvents(networkMonitor.GetEventChannel(), gatewayURL)
	}()
	
	// Start file monitoring
	go func() {
		if err := fileMonitor.Start(); err != nil {
			log.Printf("File monitor error: %v", err)
		}
		// Forward file events to gateway
		go forwardFileEvents(fileMonitor.GetEventChannel(), gatewayURL)
	}()
	
	// Start registry monitoring
	go func() {
		if err := registryMonitor.Start(); err != nil {
			log.Printf("Registry monitor error: %v", err)
		}
		// Forward registry events to gateway
		go forwardRegistryEvents(registryMonitor.GetEventChannel(), gatewayURL)
	}()
	
	// Start ransomware canary monitoring
	go ransomware.StartCanaryMonitoring()
	
	log.Println("All monitoring services started successfully")
}

// Stop all monitoring services
func stopMonitoring() {
	log.Println("Stopping monitoring services...")
	
	if processMonitor != nil {
		processMonitor.Stop()
	}
	if networkMonitor != nil {
		networkMonitor.Stop()
	}
	if fileMonitor != nil {
		fileMonitor.Stop()
	}
	if registryMonitor != nil {
		registryMonitor.Stop()
	}
	
	log.Println("All monitoring services stopped")
}

// Send periodic heartbeat with system status
func sendHeartbeat(gatewayURL string, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	
	for range ticker.C {
		evt := generateEnhancedWindowsEvent()
		data, err := json.Marshal(evt)
		if err != nil {
			log.Printf("Failed to marshal heartbeat event: %v", err)
			continue
		}
		
		log.Printf("Sending heartbeat with system telemetry")
		sendEventToGateway(gatewayURL, data)
	}
}

func main() {
	gatewayURL := os.Getenv("GATEWAY_URL")
	if gatewayURL == "" {
		gatewayURL = "http://localhost:8080"
	}
	
	log.Printf("MUSAFIR Enhanced EDR/XDR/SIEM Agent starting...")
	log.Printf("Gateway URL: %s", gatewayURL)
	
	// Initialize all monitoring components
	if err := initializeMonitoring(); err != nil {
		log.Fatalf("Failed to initialize monitoring: %v", err)
	}
	
	// Start all monitoring services
	startMonitoring(gatewayURL)
	
	// Send initial enhanced event
	evt := generateEnhancedWindowsEvent()
	data, _ := json.Marshal(evt)
	log.Printf("Sending initial enhanced telemetry event")
	sendEventToGateway(gatewayURL, data)
	
	// Start periodic heartbeat (every 5 minutes)
	go sendHeartbeat(gatewayURL, 5*time.Minute)
	
	// Setup graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	
	log.Println("MUSAFIR Enhanced Agent is running. Press Ctrl+C to stop.")
	
	// Wait for shutdown signal
	<-sigChan
	log.Println("Shutdown signal received, stopping agent...")
	
	// Stop all monitoring services
	stopMonitoring()
	
	log.Println("MUSAFIR Enhanced Agent stopped successfully")
}

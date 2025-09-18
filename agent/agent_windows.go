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
	telemetryCollector *WindowsTelemetryCollector
	processMonitor     *ProcessMonitor
	networkMonitor     *NetworkMonitor
	fileMonitor        *FileMonitor
	registryMonitor    *RegistryMonitor
	threatDetector     *ThreatDetector
	queryEngine        *QueryEngine
	assetInventory     *AssetInventory
	complianceMonitor  *ComplianceMonitor
	uebaAnalytics      *UEBAAnalytics
	forensicsCollector *ForensicsCollector
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
	
	// Initialize threat detector
	threatDetector = NewThreatDetector()
	
	// Initialize query engine
	queryEngine = NewQueryEngine(10000)
	
	// Initialize asset inventory
	assetInventory = NewAssetInventory()
	
	// Initialize compliance monitor
	complianceMonitor = NewComplianceMonitor()
	
	// Initialize UEBA analytics
	uebaAnalytics = NewUEBAAnalytics()
	
	// Initialize forensics collector
	forensicsCollector = NewForensicsCollector("default-collection", "./forensics")
	
	log.Println("All monitoring and analysis modules initialized successfully")
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
		// Enhanced event processing for process monitor
		go func() {
			for event := range processMonitor.GetEventChannel() {
				// Convert event to map for analytics processing
				eventMap := map[string]interface{}{
					"type":        "process_event",
					"event_type":  event.EventType,
					"timestamp":   event.Timestamp,
					"process_info": event.ProcessInfo,
					"parent_info": event.ParentInfo,
					"event_data":  event.EventData,
				}
				
				// Process through all analytics engines
				processEventThroughAllAnalytics(eventMap)
				
				// Forward to gateway
				envelope := generateEnhancedWindowsEvent()
				envelope.Event = eventMap
				data, _ := json.Marshal(envelope)
				sendEventToGateway(gatewayURL, data)
			}
		}()
	}()
	
	// Start network monitoring
	go func() {
		if err := networkMonitor.Start(); err != nil {
			log.Printf("Network monitor error: %v", err)
		}
		// Enhanced event processing for network monitor
		go func() {
			for event := range networkMonitor.GetEventChannel() {
				// Convert event to map for analytics processing
				eventMap := map[string]interface{}{
					"type":           "network_event",
					"event_type":     event.EventType,
					"timestamp":      event.Timestamp,
					"process_info":   event.ProcessInfo,
					"connection_info": event.ConnectionInfo,
					"traffic_info":   event.TrafficInfo,
				}
				
				// Process through all analytics engines
				processEventThroughAllAnalytics(eventMap)
				
				// Forward to gateway
				envelope := generateEnhancedWindowsEvent()
				envelope.Event = eventMap
				data, _ := json.Marshal(envelope)
				sendEventToGateway(gatewayURL, data)
			}
		}()
	}()
	
	// Start file monitoring
	go func() {
		if err := fileMonitor.Start(); err != nil {
			log.Printf("File monitor error: %v", err)
		}
		// Enhanced event processing for file monitor
		go func() {
			for event := range fileMonitor.GetEventChannel() {
				// Convert event to map for analytics processing
				eventMap := map[string]interface{}{
					"type":         "file_event",
					"event_type":   event.EventType,
					"timestamp":    event.Timestamp,
					"process_info": event.ProcessInfo,
					"file_info":    event.FileInfo,
					"old_file_info": event.OldFileInfo,
					"integrity_info": event.IntegrityInfo,
				}
				
				// Process through all analytics engines
				processEventThroughAllAnalytics(eventMap)
				
				// Forward to gateway
				envelope := generateEnhancedWindowsEvent()
				envelope.Event = eventMap
				data, _ := json.Marshal(envelope)
				sendEventToGateway(gatewayURL, data)
			}
		}()
	}()
	
	// Start registry monitoring
	go func() {
		if err := registryMonitor.Start(); err != nil {
			log.Printf("Registry monitor error: %v", err)
		}
		// Enhanced event processing for registry monitor
		go func() {
			for event := range registryMonitor.GetEventChannel() {
				// Convert event to map for analytics processing
				eventMap := map[string]interface{}{
					"type":          "registry_event",
					"event_type":    event.EventType,
					"timestamp":     event.Timestamp,
					"process_info":  event.ProcessInfo,
					"registry_info": event.RegistryInfo,
					"old_value":     event.OldValue,
					"new_value":     event.NewValue,
				}
				
				// Process through all analytics engines
				processEventThroughAllAnalytics(eventMap)
				
				// Forward to gateway
				envelope := generateEnhancedWindowsEvent()
				envelope.Event = eventMap
				data, _ := json.Marshal(envelope)
				sendEventToGateway(gatewayURL, data)
			}
		}()
	}()
	
	// Start threat detection with enhanced forwarding
	if threatDetector != nil {
		alertChannel := make(chan ThreatAlert, 100)
		go forwardThreatAlerts(alertChannel, gatewayURL)
		
		// ThreatDetector doesn't have Start method, it's always running
		log.Println("Threat detection initialized successfully")
	}

	// Start asset discovery with enhanced forwarding
	if assetInventory != nil {
		go func() {
			if err := assetInventory.DiscoverAssets(); err != nil {
				log.Printf("Failed to start asset discovery: %v", err)
			} else {
				log.Println("Asset discovery started successfully")
			}
		}()
		go forwardAssetUpdates(assetInventory, gatewayURL)
	}

	// Start compliance monitoring with enhanced forwarding
	if complianceMonitor != nil {
		go func() {
			if err := complianceMonitor.RunComplianceCheck(); err != nil {
				log.Printf("Failed to start compliance monitoring: %v", err)
			} else {
				log.Println("Compliance monitoring started successfully")
			}
		}()
		go forwardComplianceReports(complianceMonitor, gatewayURL)
	}

	// Start UEBA analytics with enhanced forwarding
	if uebaAnalytics != nil {
		// UEBA analytics is always running and processes events as they come
		log.Println("UEBA analytics initialized successfully")
		go forwardUEBAAnomalies(uebaAnalytics, gatewayURL)
	}

	// Start forensics data forwarding
	if forensicsCollector != nil {
		go forwardForensicsData(forensicsCollector, gatewayURL)
	}

	// Start query results forwarding
	if queryEngine != nil {
		go forwardQueryResults(queryEngine, gatewayURL)
	}
	
	// Start ransomware canary monitoring
	go ransomware.StartCanaryMonitoring()
	
	log.Println("All monitoring and analysis services started successfully")
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
	if threatDetector != nil {
		// ThreatDetector doesn't have a Stop method - it's always running
		log.Println("ThreatDetector shutdown (no explicit stop method)")
	}
	if assetInventory != nil {
		// AssetInventory doesn't have a StopDiscovery method
		log.Println("AssetInventory shutdown (no explicit stop method)")
	}
	if complianceMonitor != nil {
		// ComplianceMonitor doesn't have a StopMonitoring method
		log.Println("ComplianceMonitor shutdown (no explicit stop method)")
	}
	
	log.Println("All monitoring and analysis services stopped")
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
	
	// Start periodic heartbeat (every 30 seconds)
	go sendHeartbeat(gatewayURL, 30*time.Second)
	
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

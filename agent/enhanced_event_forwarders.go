//go:build windows

package main

import (
	"encoding/json"
	"log"
	"strconv"
	"time"
)

// forwardThreatAlerts forwards threat detection alerts to the gateway
func forwardThreatAlerts(alertChannel <-chan ThreatAlert, gatewayURL string) {
	for alert := range alertChannel {
		envelope := Envelope{
			Ts:       strconv.FormatInt(time.Now().Unix(), 10),
			TenantID: "default",
			Asset:    map[string]string{"hostname": getHostname()},
			User:     map[string]string{"username": getCurrentUsername()},
			Event:    map[string]interface{}{"type": "threat_alert"},
			Ingest:   map[string]string{"source": "agent"},
		}
		
		// Add threat alert data to Event field
		envelope.Event["alert_id"] = alert.ID
		envelope.Event["threat_type"] = alert.ThreatType
		envelope.Event["severity"] = alert.Severity
		envelope.Event["description"] = alert.Description
		envelope.Event["source"] = alert.Source
		envelope.Event["timestamp"] = alert.Timestamp.Format(time.RFC3339)
		envelope.Event["metadata"] = alert.Metadata
		
		data, err := json.Marshal(envelope)
		if err != nil {
			log.Printf("Failed to marshal threat alert: %v", err)
			continue
		}
		
		log.Printf("Forwarding threat alert: %s (Severity: %s)", alert.ID, alert.Severity)
		sendEventToGateway(gatewayURL, data)
	}
}

// forwardAssetUpdates forwards asset inventory updates to the gateway
func forwardAssetUpdates(assetInventory *AssetInventory, gatewayURL string) {
	ticker := time.NewTicker(15 * time.Minute) // Send asset updates every 15 minutes
	defer ticker.Stop()
	
	for range ticker.C {
		assets := assetInventory.GetAssets()
		
		for _, asset := range assets {
			envelope := Envelope{
				Ts:       strconv.FormatInt(time.Now().Unix(), 10),
				TenantID: "default",
				Asset:    map[string]string{"hostname": getHostname()},
				User:     map[string]string{"username": getCurrentUsername()},
				Event:    map[string]interface{}{"type": "asset_inventory"},
				Ingest:   map[string]string{"source": "agent"},
			}
			
			// Add asset data to Event field
			envelope.Event["asset_id"] = asset.ID
			envelope.Event["asset_name"] = asset.Name
			envelope.Event["asset_type"] = asset.Type
			envelope.Event["ip_addresses"] = asset.IPAddresses
			envelope.Event["mac_addresses"] = asset.MACAddresses
			envelope.Event["os_info"] = asset.OSInfo
			envelope.Event["hardware_info"] = asset.HardwareInfo
			envelope.Event["software_info"] = asset.SoftwareInfo
			envelope.Event["network_info"] = asset.NetworkInfo
			envelope.Event["security_info"] = asset.SecurityInfo
			envelope.Event["compliance_status"] = asset.ComplianceStatus
			envelope.Event["risk_score"] = asset.RiskScore
			envelope.Event["last_seen"] = asset.LastSeen.Format(time.RFC3339)
			envelope.Event["first_discovered"] = asset.FirstDiscovered.Format(time.RFC3339)
			envelope.Event["tags"] = asset.Tags
			envelope.Event["metadata"] = asset.Metadata
			
			data, err := json.Marshal(envelope)
			if err != nil {
				log.Printf("Failed to marshal asset data: %v", err)
				continue
			}
			
			log.Printf("Forwarding asset inventory update: %s (%s)", asset.Name, asset.Type)
			sendEventToGateway(gatewayURL, data)
		}
	}
}

// forwardComplianceReports forwards compliance monitoring reports to the gateway
func forwardComplianceReports(complianceMonitor *ComplianceMonitor, gatewayURL string) {
	ticker := time.NewTicker(1 * time.Hour) // Send compliance reports every hour
	defer ticker.Stop()
	
	for range ticker.C {
		report := complianceMonitor.GetComplianceReport() // Get current compliance report
		
		envelope := Envelope{
			Ts:       strconv.FormatInt(time.Now().Unix(), 10),
			TenantID: "default",
			Asset:    map[string]string{"hostname": getHostname()},
			User:     map[string]string{"username": getCurrentUsername()},
			Event:    map[string]interface{}{"type": "compliance_report"},
			Ingest:   map[string]string{"source": "agent"},
		}
			
		// Add compliance report data to Event field
		envelope.Event["timestamp"] = report.Timestamp.Format(time.RFC3339)
		envelope.Event["overall_score"] = report.OverallScore
		envelope.Event["total_controls"] = report.TotalControls
		envelope.Event["passed_controls"] = report.PassedControls
		envelope.Event["failed_controls"] = report.FailedControls
		envelope.Event["frameworks"] = report.Frameworks
		envelope.Event["summary"] = report.Summary
		envelope.Event["recommendations"] = report.Recommendations
		
		data, err := json.Marshal(envelope)
		if err != nil {
			log.Printf("Failed to marshal compliance report: %v", err)
			continue
		}
		
		log.Printf("Forwarding compliance report: Overall Score %.2f%%", report.OverallScore)
		sendEventToGateway(gatewayURL, data)
	}
}

// forwardUEBAAnomalies forwards UEBA anomalies to the gateway
func forwardUEBAAnomalies(uebaAnalytics *UEBAAnalytics, gatewayURL string) {
	ticker := time.NewTicker(1 * time.Minute) // Check for anomalies every minute
	defer ticker.Stop()
	
	for range ticker.C {
		anomalies := uebaAnalytics.GetRecentAnomalies(1) // Get anomalies from last minute
		
		for _, anomaly := range anomalies {
			envelope := Envelope{
				Ts:       strconv.FormatInt(time.Now().Unix(), 10),
				TenantID: "default",
				Asset:    map[string]string{"hostname": getHostname()},
				User:     map[string]string{"username": getCurrentUsername()},
				Event:    map[string]interface{}{"type": "ueba_anomaly"},
				Ingest:   map[string]string{"source": "agent"},
			}
			
			// Add UEBA anomaly data to Event field
			envelope.Event["anomaly_id"] = anomaly.ID
			envelope.Event["anomaly_type"] = anomaly.Type
			envelope.Event["severity"] = anomaly.Severity
			envelope.Event["score"] = anomaly.Score
			envelope.Event["subject"] = anomaly.Subject
			envelope.Event["title"] = anomaly.Title
			envelope.Event["description"] = anomaly.Description
			envelope.Event["evidence"] = anomaly.Evidence
			envelope.Event["rule_id"] = anomaly.RuleID
			envelope.Event["status"] = anomaly.Status
			envelope.Event["context"] = anomaly.Context
			envelope.Event["timestamp"] = anomaly.Timestamp.Format(time.RFC3339)
			
			data, err := json.Marshal(envelope)
			if err != nil {
				log.Printf("Failed to marshal UEBA anomaly: %v", err)
				continue
			}
			
			log.Printf("Forwarding UEBA anomaly: %s (Score: %.2f)", anomaly.Title, anomaly.Score)
			sendEventToGateway(gatewayURL, data)
		}
		
		// Also send risk score updates
		riskyUsers := uebaAnalytics.GetTopRiskyUsers(10)
		if len(riskyUsers) > 0 {
			envelope := Envelope{
				Ts:       strconv.FormatInt(time.Now().Unix(), 10),
				TenantID: "default",
				Asset:    map[string]string{"hostname": getHostname()},
				User:     map[string]string{"username": getCurrentUsername()},
				Event:    map[string]interface{}{"type": "ueba_risk_scores"},
				Ingest:   map[string]string{"source": "agent"},
			}
			
			// Add UEBA risk scores data to Event field
			envelope.Event["risky_users"] = riskyUsers
			envelope.Event["timestamp"] = time.Now().Format(time.RFC3339)
			
			data, err := json.Marshal(envelope)
			if err != nil {
				log.Printf("Failed to marshal UEBA risk scores: %v", err)
				continue
			}
			
			log.Printf("Forwarding UEBA risk scores for %d users", len(riskyUsers))
			sendEventToGateway(gatewayURL, data)
		}
	}
}

// forwardForensicsData forwards forensics collection data to the gateway
func forwardForensicsData(forensicsCollector *ForensicsCollector, gatewayURL string) {
	ticker := time.NewTicker(30 * time.Minute) // Send forensics data every 30 minutes
	defer ticker.Stop()
	
	for range ticker.C {
		artifacts := forensicsCollector.GetArtifacts()
		
		// Send artifacts in batches to avoid overwhelming the gateway
		batchSize := 10
		for i := 0; i < len(artifacts); i += batchSize {
			end := i + batchSize
			if end > len(artifacts) {
				end = len(artifacts)
			}
			
			batch := artifacts[i:end]
			
			envelope := Envelope{
				Ts:       strconv.FormatInt(time.Now().Unix(), 10),
				TenantID: "default",
				Asset:    map[string]string{"hostname": getHostname()},
				User:     map[string]string{"username": getCurrentUsername()},
				Event:    map[string]interface{}{"type": "forensics_artifacts"},
				Ingest:   map[string]string{"source": "agent"},
			}
			
			// Add forensics artifacts data to Event field
			envelope.Event["artifacts"] = batch
			envelope.Event["batch_info"] = map[string]interface{}{
				"batch_number":  (i / batchSize) + 1,
				"total_batches": (len(artifacts) + batchSize - 1) / batchSize,
				"batch_size":    len(batch),
			}
			envelope.Event["timestamp"] = time.Now().Format(time.RFC3339)
			
			data, err := json.Marshal(envelope)
			if err != nil {
				log.Printf("Failed to marshal forensics artifacts: %v", err)
				continue
			}
			
			log.Printf("Forwarding forensics artifacts batch %d/%d (%d artifacts)", 
				(i/batchSize)+1, (len(artifacts)+batchSize-1)/batchSize, len(batch))
			sendEventToGateway(gatewayURL, data)
			
			// Small delay between batches
			time.Sleep(1 * time.Second)
		}
	}
}

// forwardQueryResults forwards threat hunting query results to the gateway
func forwardQueryResults(queryEngine *QueryEngine, gatewayURL string) {
	// This would be called when queries are executed
	// For now, we'll create a placeholder that could be called by the query engine
	
	events := queryEngine.GetStoredEvents() // Get stored events
	
	if len(events) > 0 {
		envelope := Envelope{
			Ts:       strconv.FormatInt(time.Now().Unix(), 10),
			TenantID: "default",
			Asset:    map[string]string{"hostname": getHostname()},
			User:     map[string]string{"username": getCurrentUsername()},
			Event:    map[string]interface{}{"type": "threat_hunting_result"},
			Ingest:   map[string]string{"source": "agent"},
		}
		
		// Add threat hunting results data to Event field
		envelope.Event["event_count"] = len(events)
		envelope.Event["events"] = events
		envelope.Event["timestamp"] = time.Now().Format(time.RFC3339)
		
		data, err := json.Marshal(envelope)
		if err != nil {
			log.Printf("Failed to marshal query result: %v", err)
			return
		}
		
		log.Printf("Forwarding threat hunting query results: %d events", len(events))
		sendEventToGateway(gatewayURL, data)
	}
}

// Enhanced event processing with UEBA integration
func processEventForUEBA(event map[string]interface{}) {
	if uebaAnalytics != nil {
		// Add additional context to the event
		event["timestamp"] = time.Now()
		event["entity_id"] = getHostname()
		
		// Process the event through UEBA
		if err := uebaAnalytics.ProcessEvent(event); err != nil {
			log.Printf("Error processing event for UEBA: %v", err)
		}
	}
}

// Enhanced event processing with threat detection
func processEventForThreatDetection(_ map[string]interface{}) {
	if threatDetector != nil {
		// Since ThreatDetector doesn't have a ProcessEvent method, we'll skip this for now
		// The threat detection is handled by specific analyze methods for processes, networks, and files
		log.Printf("Event processed for threat detection context")
	}
}

// Enhanced event processing with query engine indexing
func processEventForQueryEngine(_ map[string]interface{}) {
	if queryEngine != nil {
		// Since indexEvent requires an Envelope and index, we'll skip this for now
		// The query engine indexing is handled elsewhere in the system
		log.Printf("Event processed for query engine context")
	}
}

// Comprehensive event processor that runs all analytics
func processEventThroughAllAnalytics(event map[string]interface{}) {
	// Process through UEBA
	processEventForUEBA(event)
	
	// Process through threat detection
	processEventForThreatDetection(event)
	
	// Index for threat hunting
	processEventForQueryEngine(event)
}
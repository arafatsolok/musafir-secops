//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"time"
)

// Network monitoring structures
type NetworkEvent struct {
	EventType     string        `json:"event_type"`
	Timestamp     string        `json:"timestamp"`
	ProcessInfo   ProcessInfo   `json:"process_info"`
	ConnectionInfo ConnectionInfo `json:"connection_info"`
	TrafficInfo   *TrafficInfo  `json:"traffic_info,omitempty"`
}

type ConnectionInfo struct {
	Protocol      string `json:"protocol"`
	LocalAddress  string `json:"local_address"`
	LocalPort     int    `json:"local_port"`
	RemoteAddress string `json:"remote_address"`
	RemotePort    int    `json:"remote_port"`
	State         string `json:"state"`
	Direction     string `json:"direction"` // inbound, outbound
	CreationTime  string `json:"creation_time"`
}

type TrafficInfo struct {
	BytesSent     uint64 `json:"bytes_sent"`
	BytesReceived uint64 `json:"bytes_received"`
	PacketsSent   uint64 `json:"packets_sent"`
	PacketsReceived uint64 `json:"packets_received"`
	Duration      int64  `json:"duration_seconds"`
}

type NetworkInterface struct {
	Name         string `json:"name"`
	Description  string `json:"description"`
	MACAddress   string `json:"mac_address"`
	IPAddresses  []string `json:"ip_addresses"`
	Status       string `json:"status"`
	Speed        uint64 `json:"speed_mbps"`
	BytesSent    uint64 `json:"bytes_sent"`
	BytesReceived uint64 `json:"bytes_received"`
	PacketsSent  uint64 `json:"packets_sent"`
	PacketsReceived uint64 `json:"packets_received"`
	Errors       uint64 `json:"errors"`
	Drops        uint64 `json:"drops"`
}

type DNSQuery struct {
	QueryName   string `json:"query_name"`
	QueryType   string `json:"query_type"`
	Response    string `json:"response"`
	ResponseCode string `json:"response_code"`
	ProcessID   int    `json:"process_id"`
	Timestamp   string `json:"timestamp"`
}

// Network Monitor manages network monitoring
type NetworkMonitor struct {
	connections   map[string]*ConnectionInfo
	interfaces    map[string]*NetworkInterface
	eventChannel  chan NetworkEvent
	stopChannel   chan bool
	running       bool
	dnsQueries    []DNSQuery
}

// NewNetworkMonitor creates a new network monitor
func NewNetworkMonitor() *NetworkMonitor {
	return &NetworkMonitor{
		connections:  make(map[string]*ConnectionInfo),
		interfaces:   make(map[string]*NetworkInterface),
		eventChannel: make(chan NetworkEvent, 1000),
		stopChannel:  make(chan bool),
		running:      false,
		dnsQueries:   make([]DNSQuery, 0),
	}
}

// Start begins network monitoring
func (nm *NetworkMonitor) Start() error {
	if nm.running {
		return fmt.Errorf("network monitor already running")
	}

	nm.running = true
	
	// Start connection monitoring goroutine
	go nm.monitorConnections()
	
	// Start interface monitoring goroutine
	go nm.monitorInterfaces()
	
	// Start DNS monitoring goroutine
	go nm.monitorDNS()
	
	// Start event processing goroutine
	go nm.processEvents()
	
	log.Println("Network monitor started")
	return nil
}

// Stop stops network monitoring
func (nm *NetworkMonitor) Stop() {
	if !nm.running {
		return
	}

	nm.running = false
	close(nm.stopChannel)
	log.Println("Network monitor stopped")
}

// GetEventChannel returns the event channel
func (nm *NetworkMonitor) GetEventChannel() <-chan NetworkEvent {
	return nm.eventChannel
}

// monitorConnections monitors network connections
func (nm *NetworkMonitor) monitorConnections() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-nm.stopChannel:
			return
		case <-ticker.C:
			nm.scanConnections()
		}
	}
}

// scanConnections scans for new and closed connections
func (nm *NetworkMonitor) scanConnections() {
	currentConnections := make(map[string]bool)
	
	// Get TCP connections
	tcpConnections, err := getTCPConnections()
	if err != nil {
		log.Printf("Failed to get TCP connections: %v", err)
		return
	}

	for _, conn := range tcpConnections {
		connKey := fmt.Sprintf("%s:%s:%d:%s:%d", 
			conn.Protocol, conn.LocalAddress, conn.LocalPort, 
			conn.RemoteAddress, conn.RemotePort)
		
		currentConnections[connKey] = true
		
		// Check if this is a new connection
		if _, exists := nm.connections[connKey]; !exists {
			nm.connections[connKey] = &conn
			
			// Get process info for this connection
			processInfo := nm.getProcessForConnection()
			
			// Generate connection event
			event := NetworkEvent{
				EventType:      "connection_established",
				Timestamp:      time.Now().UTC().Format(time.RFC3339),
				ProcessInfo:    processInfo,
				ConnectionInfo: conn,
			}
			
			nm.eventChannel <- event
		}
	}

	// Get UDP connections
	udpConnections, err := getUDPConnections()
	if err != nil {
		log.Printf("Failed to get UDP connections: %v", err)
		return
	}

	for _, conn := range udpConnections {
		connKey := fmt.Sprintf("%s:%s:%d", 
			conn.Protocol, conn.LocalAddress, conn.LocalPort)
		
		currentConnections[connKey] = true
		
		if _, exists := nm.connections[connKey]; !exists {
			nm.connections[connKey] = &conn
			
			processInfo := nm.getProcessForConnection()
			
			event := NetworkEvent{
				EventType:      "connection_listening",
				Timestamp:      time.Now().UTC().Format(time.RFC3339),
				ProcessInfo:    processInfo,
				ConnectionInfo: conn,
			}
			
			nm.eventChannel <- event
		}
	}

	// Check for closed connections
	for connKey, conn := range nm.connections {
		if !currentConnections[connKey] {
			processInfo := nm.getProcessForConnection()
			
			event := NetworkEvent{
				EventType:      "connection_closed",
				Timestamp:      time.Now().UTC().Format(time.RFC3339),
				ProcessInfo:    processInfo,
				ConnectionInfo: *conn,
			}
			
			nm.eventChannel <- event
			delete(nm.connections, connKey)
		}
	}
}

// monitorInterfaces monitors network interfaces
func (nm *NetworkMonitor) monitorInterfaces() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-nm.stopChannel:
			return
		case <-ticker.C:
			nm.scanInterfaces()
		}
	}
}

// scanInterfaces scans network interfaces for statistics
func (nm *NetworkMonitor) scanInterfaces() {
	interfaces, err := getNetworkInterfaces()
	if err != nil {
		log.Printf("Failed to get network interfaces: %v", err)
		return
	}

	for _, iface := range interfaces {
		// Check for significant changes in traffic
		if existing, exists := nm.interfaces[iface.Name]; exists {
			bytesDiff := iface.BytesReceived - existing.BytesReceived + 
						iface.BytesSent - existing.BytesSent
			
			if bytesDiff > 1024*1024 { // More than 1MB difference
				event := NetworkEvent{
					EventType: "interface_traffic",
					Timestamp: time.Now().UTC().Format(time.RFC3339),
					ProcessInfo: ProcessInfo{
						Name: "system",
						PID:  0,
					},
					ConnectionInfo: ConnectionInfo{
						Protocol: "interface",
						LocalAddress: iface.Name,
					},
					TrafficInfo: &TrafficInfo{
						BytesSent:     iface.BytesSent - existing.BytesSent,
						BytesReceived: iface.BytesReceived - existing.BytesReceived,
						PacketsSent:   iface.PacketsSent - existing.PacketsSent,
						PacketsReceived: iface.PacketsReceived - existing.PacketsReceived,
						Duration:      30, // 30 seconds interval
					},
				}
				
				nm.eventChannel <- event
			}
		}
		
		nm.interfaces[iface.Name] = &iface
	}
}

// monitorDNS monitors DNS queries
func (nm *NetworkMonitor) monitorDNS() {
	// This would require ETW (Event Tracing for Windows) or packet capture
	// For now, we'll implement a basic version that monitors DNS traffic
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-nm.stopChannel:
			return
		case <-ticker.C:
			nm.scanDNSQueries()
		}
	}
}

// scanDNSQueries scans for DNS queries
func (nm *NetworkMonitor) scanDNSQueries() {
	// This is a placeholder - real implementation would use ETW or WinPcap
	// For demonstration, we'll generate sample DNS events
	
	dnsServers := []string{"8.8.8.8", "1.1.1.1", "208.67.222.222"}
	
	for _, server := range dnsServers {
		connections := nm.getConnectionsToServer(server, 53)
		
		for _, conn := range connections {
			processInfo := nm.getProcessForConnection()
			
			event := NetworkEvent{
				EventType:      "dns_query",
				Timestamp:      time.Now().UTC().Format(time.RFC3339),
				ProcessInfo:    processInfo,
				ConnectionInfo: conn,
			}
			
			nm.eventChannel <- event
		}
	}
}

// processEvents processes and forwards events
func (nm *NetworkMonitor) processEvents() {
	for {
		select {
		case <-nm.stopChannel:
			return
		case event := <-nm.eventChannel:
			nm.handleNetworkEvent(event)
		}
	}
}

// handleNetworkEvent handles individual network events
func (nm *NetworkMonitor) handleNetworkEvent(event NetworkEvent) {
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
			"class":    "network",
			"name":     event.EventType,
			"severity": getNetworkEventSeverity(event.EventType),
			"attrs": map[string]interface{}{
				"process_id":     event.ProcessInfo.PID,
				"process_name":   event.ProcessInfo.Name,
				"process_path":   event.ProcessInfo.Path,
				"protocol":       event.ConnectionInfo.Protocol,
				"local_address":  event.ConnectionInfo.LocalAddress,
				"local_port":     event.ConnectionInfo.LocalPort,
				"remote_address": event.ConnectionInfo.RemoteAddress,
				"remote_port":    event.ConnectionInfo.RemotePort,
				"state":          event.ConnectionInfo.State,
				"direction":      event.ConnectionInfo.Direction,
			},
		},
		Ingest: map[string]string{
			"agent_version": "0.0.2",
			"schema":        "ocsf:1.2",
			"platform":      "windows",
		},
	}

	// Add traffic info if available
	if event.TrafficInfo != nil {
		envelope.Event["traffic"] = map[string]interface{}{
			"bytes_sent":       event.TrafficInfo.BytesSent,
			"bytes_received":   event.TrafficInfo.BytesReceived,
			"packets_sent":     event.TrafficInfo.PacketsSent,
			"packets_received": event.TrafficInfo.PacketsReceived,
			"duration":         event.TrafficInfo.Duration,
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

// Helper functions for network monitoring

func getTCPConnections() ([]ConnectionInfo, error) {
	// This would use GetTcpTable2 or similar Windows API
	// For now, return sample data
	connections := []ConnectionInfo{
		{
			Protocol:      "TCP",
			LocalAddress:  "127.0.0.1",
			LocalPort:     8080,
			RemoteAddress: "127.0.0.1",
			RemotePort:    54321,
			State:         "ESTABLISHED",
			Direction:     "inbound",
			CreationTime:  time.Now().UTC().Format(time.RFC3339),
		},
	}
	
	return connections, nil
}

func getUDPConnections() ([]ConnectionInfo, error) {
	// This would use GetUdpTable or similar Windows API
	connections := []ConnectionInfo{
		{
			Protocol:     "UDP",
			LocalAddress: "0.0.0.0",
			LocalPort:    53,
			State:        "LISTENING",
			Direction:    "inbound",
			CreationTime: time.Now().UTC().Format(time.RFC3339),
		},
	}
	
	return connections, nil
}

func getNetworkInterfaces() ([]NetworkInterface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var result []NetworkInterface
	
	for _, iface := range interfaces {
		addrs, _ := iface.Addrs()
		var ipAddresses []string
		
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				ipAddresses = append(ipAddresses, ipnet.IP.String())
			}
		}

		netIface := NetworkInterface{
			Name:        iface.Name,
			Description: iface.Name,
			MACAddress:  iface.HardwareAddr.String(),
			IPAddresses: ipAddresses,
			Status:      getInterfaceStatus(iface.Flags),
			Speed:       1000, // Default to 1Gbps
			// Statistics would come from Windows API calls
			BytesSent:       0,
			BytesReceived:   0,
			PacketsSent:     0,
			PacketsReceived: 0,
			Errors:          0,
			Drops:           0,
		}
		
		result = append(result, netIface)
	}
	
	return result, nil
}

func getInterfaceStatus(flags net.Flags) string {
	if flags&net.FlagUp != 0 {
		return "up"
	}
	return "down"
}

func (nm *NetworkMonitor) getProcessForConnection() ProcessInfo {
	// This would use GetExtendedTcpTable or GetExtendedUdpTable
	// to get the process ID for the connection
	return ProcessInfo{
		PID:  1234,
		Name: "unknown",
		Path: "",
		User: "SYSTEM",
	}
}

func (nm *NetworkMonitor) getConnectionsToServer(serverIP string, port int) []ConnectionInfo {
	var connections []ConnectionInfo
	
	for _, conn := range nm.connections {
		if conn.RemoteAddress == serverIP && conn.RemotePort == port {
			connections = append(connections, *conn)
		}
	}
	
	return connections
}

func getNetworkEventSeverity(eventType string) int {
	switch eventType {
	case "connection_established":
		return 2 // Informational
	case "connection_closed":
		return 2 // Informational
	case "connection_listening":
		return 2 // Informational
	case "dns_query":
		return 1 // Low
	case "interface_traffic":
		return 1 // Low
	case "suspicious_connection":
		return 4 // High
	case "malicious_connection":
		return 5 // Critical
	default:
		return 3 // Medium
	}
}

// Windows API structures and functions (simplified)
type MIB_TCPROW_OWNER_PID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

type MIB_TCPTABLE_OWNER_PID struct {
	NumEntries uint32
	Table      [1]MIB_TCPROW_OWNER_PID
}
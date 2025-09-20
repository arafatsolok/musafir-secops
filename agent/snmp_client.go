//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

// SNMPClient manages SNMP operations for network devices
type SNMPClient struct {
	devices     map[string]*NetworkDevice
	communities map[string]string // IP -> community string
	running     bool
	stopChannel chan bool
}

// NetworkDevice represents a discovered network device
type NetworkDevice struct {
	IP           string                 `json:"ip"`
	Hostname     string                 `json:"hostname"`
	DeviceType   string                 `json:"device_type"` // router, firewall, switch, etc.
	Vendor       string                 `json:"vendor"`
	Model        string                 `json:"model"`
	Version      string                 `json:"version"`
	Uptime       time.Duration          `json:"uptime"`
	Interfaces   []SNMPInterface        `json:"interfaces"`
	SystemInfo   SNMPSystemInfo         `json:"system_info"`
	Performance  DevicePerformance      `json:"performance"`
	LastPolled   time.Time              `json:"last_polled"`
	Status       string                 `json:"status"`
	Capabilities []string               `json:"capabilities"`
	Config       map[string]interface{} `json:"config"`
}

// SNMPInterface represents a network interface on a device
type SNMPInterface struct {
	Index       int    `json:"index"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Type        string `json:"type"`
	Speed       uint64 `json:"speed"`
	MTU         int    `json:"mtu"`
	AdminStatus string `json:"admin_status"`
	OperStatus  string `json:"oper_status"`
	InOctets    uint64 `json:"in_octets"`
	OutOctets   uint64 `json:"out_octets"`
	InPackets   uint64 `json:"in_packets"`
	OutPackets  uint64 `json:"out_packets"`
	InErrors    uint64 `json:"in_errors"`
	OutErrors   uint64 `json:"out_errors"`
	InDiscards  uint64 `json:"in_discards"`
	OutDiscards uint64 `json:"out_discards"`
}

// SNMPSystemInfo contains system information from SNMP
type SNMPSystemInfo struct {
	Description string `json:"description"`
	ObjectID    string `json:"object_id"`
	Contact     string `json:"contact"`
	Name        string `json:"name"`
	Location    string `json:"location"`
	Services    int    `json:"services"`
}

// DevicePerformance contains performance metrics
type DevicePerformance struct {
	CPUUtilization    float64 `json:"cpu_utilization"`
	MemoryUtilization float64 `json:"memory_utilization"`
	Temperature       float64 `json:"temperature"`
	PowerStatus       string  `json:"power_status"`
	FanStatus         string  `json:"fan_status"`
}

// Common SNMP OIDs
var (
	// System OIDs
	OIDSysDescr    = "1.3.6.1.2.1.1.1.0"
	OIDSysObjectID = "1.3.6.1.2.1.1.2.0"
	OIDSysUpTime   = "1.3.6.1.2.1.1.3.0"
	OIDSysContact  = "1.3.6.1.2.1.1.4.0"
	OIDSysName     = "1.3.6.1.2.1.1.5.0"
	OIDSysLocation = "1.3.6.1.2.1.1.6.0"
	OIDSysServices = "1.3.6.1.2.1.1.7.0"

	// Interface OIDs
	OIDIfNumber      = "1.3.6.1.2.1.2.1.0"
	OIDIfTable       = "1.3.6.1.2.1.2.2.1"
	OIDIfIndex       = "1.3.6.1.2.1.2.2.1.1"
	OIDIfDescr       = "1.3.6.1.2.1.2.2.1.2"
	OIDIfType        = "1.3.6.1.2.1.2.2.1.3"
	OIDIfMtu         = "1.3.6.1.2.1.2.2.1.4"
	OIDIfSpeed       = "1.3.6.1.2.1.2.2.1.5"
	OIDIfAdminStatus = "1.3.6.1.2.1.2.2.1.7"
	OIDIfOperStatus  = "1.3.6.1.2.1.2.2.1.8"
	OIDIfInOctets    = "1.3.6.1.2.1.2.2.1.10"
	OIDIfOutOctets   = "1.3.6.1.2.1.2.2.1.16"
	OIDIfInPackets   = "1.3.6.1.2.1.2.2.1.11"
	OIDIfOutPackets  = "1.3.6.1.2.1.2.2.1.17"
	OIDIfInErrors    = "1.3.6.1.2.1.2.2.1.14"
	OIDIfOutErrors   = "1.3.6.1.2.1.2.2.1.20"
	OIDIfInDiscards  = "1.3.6.1.2.1.2.2.1.13"
	OIDIfOutDiscards = "1.3.6.1.2.1.2.2.1.19"

	// Cisco-specific OIDs
	CiscoMemoryPoolUsed = "1.3.6.1.4.1.9.9.48.1.1.1.5"
	CiscoMemoryPoolFree = "1.3.6.1.4.1.9.9.48.1.1.1.6"
	CiscoCPUUtilization = "1.3.6.1.4.1.9.9.109.1.1.1.1.7"
	CiscoTemperature    = "1.3.6.1.4.1.9.9.13.1.3.1.3"
)

// NewSNMPClient creates a new SNMP client
func NewSNMPClient() *SNMPClient {
	return &SNMPClient{
		devices:     make(map[string]*NetworkDevice),
		communities: make(map[string]string),
		running:     false,
		stopChannel: make(chan bool),
	}
}

// AddDevice adds a device to monitor
func (sc *SNMPClient) AddDevice(ip, community string) {
	sc.communities[ip] = community
	log.Printf("Added SNMP device: %s with community: %s", ip, community)
}

// Start begins SNMP monitoring
func (sc *SNMPClient) Start() error {
	if sc.running {
		return fmt.Errorf("SNMP client already running")
	}

	sc.running = true

	// Start device discovery and monitoring
	go sc.monitorDevices()

	log.Println("SNMP client started")
	return nil
}

// Stop stops SNMP monitoring
func (sc *SNMPClient) Stop() {
	if !sc.running {
		return
	}

	sc.running = false
	close(sc.stopChannel)
	log.Println("SNMP client stopped")
}

// monitorDevices continuously monitors all configured devices
func (sc *SNMPClient) monitorDevices() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sc.stopChannel:
			return
		case <-ticker.C:
			for ip, community := range sc.communities {
				go sc.pollDevice(ip, community)
			}
		}
	}
}

// pollDevice polls a single device for information
func (sc *SNMPClient) pollDevice(ip, community string) {
	device, err := sc.queryDevice(ip, community)
	if err != nil {
		log.Printf("Failed to query device %s: %v", ip, err)
		return
	}

	sc.devices[ip] = device

	// Generate SNMP event
	sc.generateSNMPEvent(device)
}

// queryDevice queries a device via SNMP
func (sc *SNMPClient) queryDevice(ip, community string) (*NetworkDevice, error) {
	// Create SNMP connection
	conn := &gosnmp.GoSNMP{
		Target:    ip,
		Port:      161,
		Community: community,
		Version:   gosnmp.Version2c,
		Timeout:   time.Duration(10) * time.Second,
		Retries:   3,
	}

	err := conn.Connect()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %v", ip, err)
	}
	defer conn.Conn.Close()

	device := &NetworkDevice{
		IP:         ip,
		LastPolled: time.Now(),
		Status:     "online",
	}

	// Query system information
	if err := sc.querySystemInfo(conn, device); err != nil {
		log.Printf("Failed to query system info for %s: %v", ip, err)
	}

	// Query interface information
	if err := sc.queryInterfaces(conn, device); err != nil {
		log.Printf("Failed to query interfaces for %s: %v", ip, err)
	}

	// Query performance metrics
	if err := sc.queryPerformance(conn, device); err != nil {
		log.Printf("Failed to query performance for %s: %v", ip, err)
	}

	// Determine device type and vendor
	sc.identifyDevice(device)

	return device, nil
}

// querySystemInfo queries basic system information
func (sc *SNMPClient) querySystemInfo(conn *gosnmp.GoSNMP, device *NetworkDevice) error {
	oids := []string{
		OIDSysDescr, OIDSysObjectID, OIDSysUpTime,
		OIDSysContact, OIDSysName, OIDSysLocation, OIDSysServices,
	}

	result, err := conn.Get(oids)
	if err != nil {
		return err
	}

	sysInfo := SNMPSystemInfo{}

	for _, variable := range result.Variables {
		switch variable.Name {
		case OIDSysDescr:
			sysInfo.Description = string(variable.Value.([]byte))
			device.Hostname = extractHostname(sysInfo.Description)
		case OIDSysObjectID:
			sysInfo.ObjectID = variable.Value.(string)
		case OIDSysUpTime:
			if uptime, ok := variable.Value.(uint32); ok {
				device.Uptime = time.Duration(uptime) * time.Millisecond * 10
			}
		case OIDSysContact:
			sysInfo.Contact = string(variable.Value.([]byte))
		case OIDSysName:
			sysInfo.Name = string(variable.Value.([]byte))
			if device.Hostname == "" {
				device.Hostname = sysInfo.Name
			}
		case OIDSysLocation:
			sysInfo.Location = string(variable.Value.([]byte))
		case OIDSysServices:
			if services, ok := variable.Value.(int); ok {
				sysInfo.Services = services
			}
		}
	}

	device.SystemInfo = sysInfo
	return nil
}

// queryInterfaces queries interface information
func (sc *SNMPClient) queryInterfaces(conn *gosnmp.GoSNMP, device *NetworkDevice) error {
	// First get the number of interfaces
	result, err := conn.Get([]string{OIDIfNumber})
	if err != nil {
		return err
	}

	var ifCount int
	if len(result.Variables) > 0 {
		if count, ok := result.Variables[0].Value.(int); ok {
			ifCount = count
		}
	}

	if ifCount == 0 {
		return nil
	}

	// Query interface table
	interfaces := make([]SNMPInterface, 0)

	for i := 1; i <= ifCount; i++ {
		iface := SNMPInterface{Index: i}

		// Build OIDs for this interface
		oids := []string{
			fmt.Sprintf("%s.%d", OIDIfDescr, i),
			fmt.Sprintf("%s.%d", OIDIfType, i),
			fmt.Sprintf("%s.%d", OIDIfMtu, i),
			fmt.Sprintf("%s.%d", OIDIfSpeed, i),
			fmt.Sprintf("%s.%d", OIDIfAdminStatus, i),
			fmt.Sprintf("%s.%d", OIDIfOperStatus, i),
			fmt.Sprintf("%s.%d", OIDIfInOctets, i),
			fmt.Sprintf("%s.%d", OIDIfOutOctets, i),
			fmt.Sprintf("%s.%d", OIDIfInPackets, i),
			fmt.Sprintf("%s.%d", OIDIfOutPackets, i),
			fmt.Sprintf("%s.%d", OIDIfInErrors, i),
			fmt.Sprintf("%s.%d", OIDIfOutErrors, i),
			fmt.Sprintf("%s.%d", OIDIfInDiscards, i),
			fmt.Sprintf("%s.%d", OIDIfOutDiscards, i),
		}

		result, err := conn.Get(oids)
		if err != nil {
			continue // Skip this interface if we can't query it
		}

		// Parse interface data
		for j, variable := range result.Variables {
			switch j {
			case 0: // Description
				iface.Description = string(variable.Value.([]byte))
				iface.Name = iface.Description
			case 1: // Type
				if ifType, ok := variable.Value.(int); ok {
					iface.Type = getInterfaceType(ifType)
				}
			case 2: // MTU
				if mtu, ok := variable.Value.(int); ok {
					iface.MTU = mtu
				}
			case 3: // Speed
				if speed, ok := variable.Value.(uint32); ok {
					iface.Speed = uint64(speed)
				}
			case 4: // Admin Status
				if status, ok := variable.Value.(int); ok {
					iface.AdminStatus = getSNMPInterfaceStatus(status)
				}
			case 5: // Oper Status
				if status, ok := variable.Value.(int); ok {
					iface.OperStatus = getSNMPInterfaceStatus(status)
				}
			case 6: // In Octets
				if octets, ok := variable.Value.(uint32); ok {
					iface.InOctets = uint64(octets)
				}
			case 7: // Out Octets
				if octets, ok := variable.Value.(uint32); ok {
					iface.OutOctets = uint64(octets)
				}
			case 8: // In Packets
				if packets, ok := variable.Value.(uint32); ok {
					iface.InPackets = uint64(packets)
				}
			case 9: // Out Packets
				if packets, ok := variable.Value.(uint32); ok {
					iface.OutPackets = uint64(packets)
				}
			case 10: // In Errors
				if errors, ok := variable.Value.(uint32); ok {
					iface.InErrors = uint64(errors)
				}
			case 11: // Out Errors
				if errors, ok := variable.Value.(uint32); ok {
					iface.OutErrors = uint64(errors)
				}
			case 12: // In Discards
				if discards, ok := variable.Value.(uint32); ok {
					iface.InDiscards = uint64(discards)
				}
			case 13: // Out Discards
				if discards, ok := variable.Value.(uint32); ok {
					iface.OutDiscards = uint64(discards)
				}
			}
		}

		interfaces = append(interfaces, iface)
	}

	device.Interfaces = interfaces
	return nil
}

// queryPerformance queries performance metrics
func (sc *SNMPClient) queryPerformance(conn *gosnmp.GoSNMP, device *NetworkDevice) error {
	performance := DevicePerformance{}

	// Try Cisco-specific OIDs first
	if strings.Contains(strings.ToLower(device.SystemInfo.Description), "cisco") {
		// Query CPU utilization
		result, err := conn.Get([]string{CiscoCPUUtilization + ".1"})
		if err == nil && len(result.Variables) > 0 {
			if cpu, ok := result.Variables[0].Value.(int); ok {
				performance.CPUUtilization = float64(cpu)
			}
		}

		// Query memory utilization
		usedResult, err1 := conn.Get([]string{CiscoMemoryPoolUsed + ".1"})
		freeResult, err2 := conn.Get([]string{CiscoMemoryPoolFree + ".1"})

		if err1 == nil && err2 == nil && len(usedResult.Variables) > 0 && len(freeResult.Variables) > 0 {
			if used, ok1 := usedResult.Variables[0].Value.(uint32); ok1 {
				if free, ok2 := freeResult.Variables[0].Value.(uint32); ok2 {
					total := used + free
					if total > 0 {
						performance.MemoryUtilization = float64(used) / float64(total) * 100
					}
				}
			}
		}

		// Query temperature
		result, err = conn.Get([]string{CiscoTemperature + ".1"})
		if err == nil && len(result.Variables) > 0 {
			if temp, ok := result.Variables[0].Value.(int); ok {
				performance.Temperature = float64(temp)
			}
		}
	}

	device.Performance = performance
	return nil
}

// identifyDevice identifies device type and vendor
func (sc *SNMPClient) identifyDevice(device *NetworkDevice) {
	desc := strings.ToLower(device.SystemInfo.Description)

	// Identify vendor
	if strings.Contains(desc, "cisco") {
		device.Vendor = "Cisco"
	} else if strings.Contains(desc, "juniper") {
		device.Vendor = "Juniper"
	} else if strings.Contains(desc, "palo alto") {
		device.Vendor = "Palo Alto Networks"
	} else if strings.Contains(desc, "fortinet") {
		device.Vendor = "Fortinet"
	} else if strings.Contains(desc, "checkpoint") {
		device.Vendor = "Check Point"
	} else if strings.Contains(desc, "hp") || strings.Contains(desc, "hewlett") {
		device.Vendor = "HP"
	} else {
		device.Vendor = "Unknown"
	}

	// Identify device type based on services and description
	services := device.SystemInfo.Services

	if strings.Contains(desc, "firewall") || strings.Contains(desc, "asa") || strings.Contains(desc, "palo alto") {
		device.DeviceType = "firewall"
	} else if strings.Contains(desc, "router") || (services&64 != 0) { // Layer 3 forwarding
		device.DeviceType = "router"
	} else if strings.Contains(desc, "switch") || (services&2 != 0) { // Layer 2 bridging
		device.DeviceType = "switch"
	} else if strings.Contains(desc, "access point") || strings.Contains(desc, "wireless") {
		device.DeviceType = "access_point"
	} else {
		device.DeviceType = "unknown"
	}

	// Extract model and version
	parts := strings.Fields(device.SystemInfo.Description)
	for i, part := range parts {
		if strings.Contains(strings.ToLower(part), "version") && i+1 < len(parts) {
			device.Version = parts[i+1]
		}
		if len(part) > 3 && (strings.Contains(part, "-") || strings.Contains(part, "/")) {
			device.Model = part
		}
	}
}

// generateSNMPEvent generates an event for the monitored device
func (sc *SNMPClient) generateSNMPEvent(device *NetworkDevice) {
	envelope := Envelope{
		Ts:       time.Now().UTC().Format(time.RFC3339),
		TenantID: "t-aci",
		Asset: map[string]string{
			"id":   device.IP,
			"type": "network_device",
			"name": device.Hostname,
		},
		Event: map[string]interface{}{
			"class":    "network_infrastructure",
			"name":     "device_status",
			"severity": 2,
			"attrs": map[string]interface{}{
				"device_type":        device.DeviceType,
				"vendor":             device.Vendor,
				"model":              device.Model,
				"version":            device.Version,
				"uptime":             device.Uptime.Seconds(),
				"interface_count":    len(device.Interfaces),
				"cpu_utilization":    device.Performance.CPUUtilization,
				"memory_utilization": device.Performance.MemoryUtilization,
				"temperature":        device.Performance.Temperature,
				"status":             device.Status,
			},
		},
		Ingest: map[string]string{
			"agent_version": "0.0.2",
			"schema":        "ocsf:1.2",
			"platform":      "snmp",
		},
	}

	// Add interface statistics
	var totalInOctets, totalOutOctets uint64
	var activeInterfaces int

	for _, iface := range device.Interfaces {
		if iface.OperStatus == "up" {
			activeInterfaces++
			totalInOctets += iface.InOctets
			totalOutOctets += iface.OutOctets
		}
	}

	envelope.Event["traffic"] = map[string]interface{}{
		"total_in_octets":   totalInOctets,
		"total_out_octets":  totalOutOctets,
		"active_interfaces": activeInterfaces,
	}

	// Send to gateway
	data, _ := json.Marshal(envelope)
	gatewayURL := "http://localhost:8080"
	go sendEventToGateway(gatewayURL, data)
}

// Helper functions

func extractHostname(description string) string {
	// Try to extract hostname from system description
	parts := strings.Fields(description)
	for _, part := range parts {
		if !strings.Contains(part, ".") && len(part) > 2 && len(part) < 64 {
			return part
		}
	}
	return ""
}

func getInterfaceType(ifType int) string {
	types := map[int]string{
		1:   "other",
		6:   "ethernetCsmacd",
		23:  "ppp",
		24:  "softwareLoopback",
		37:  "atm",
		53:  "propVirtual",
		131: "tunnel",
		161: "ieee80211",
	}

	if t, exists := types[ifType]; exists {
		return t
	}
	return fmt.Sprintf("type_%d", ifType)
}

func getSNMPInterfaceStatus(status int) string {
	switch status {
	case 1:
		return "up"
	case 2:
		return "down"
	case 3:
		return "testing"
	default:
		return "unknown"
	}
}

// GetDevices returns all monitored devices
func (sc *SNMPClient) GetDevices() map[string]*NetworkDevice {
	return sc.devices
}

// GetDevice returns a specific device
func (sc *SNMPClient) GetDevice(ip string) (*NetworkDevice, bool) {
	device, exists := sc.devices[ip]
	return device, exists
}

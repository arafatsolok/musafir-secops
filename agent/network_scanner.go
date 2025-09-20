//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

// NetworkScanner discovers network infrastructure devices
type NetworkScanner struct {
	discoveredDevices map[string]*DiscoveredDevice
	scanRanges        []string
	snmpCommunities   []string
	running           bool
	stopChannel       chan bool
	mutex             sync.RWMutex
}

// DiscoveredDevice represents a discovered network device
type DiscoveredDevice struct {
	IP              string            `json:"ip"`
	MAC             string            `json:"mac"`
	Hostname        string            `json:"hostname"`
	Vendor          string            `json:"vendor"`
	DeviceType      string            `json:"device_type"`
	OpenPorts       []int             `json:"open_ports"`
	Services        map[int]string    `json:"services"`
	SNMPEnabled     bool              `json:"snmp_enabled"`
	SNMPCommunity   string            `json:"snmp_community,omitempty"`
	ResponseTime    time.Duration     `json:"response_time"`
	LastSeen        time.Time         `json:"last_seen"`
	FirstDiscovered time.Time         `json:"first_discovered"`
	Confidence      float64           `json:"confidence"`
	Fingerprint     DeviceFingerprint `json:"fingerprint"`
}

// DeviceFingerprint contains device identification information
type DeviceFingerprint struct {
	TTL            int      `json:"ttl"`
	WindowSize     int      `json:"window_size"`
	HTTPBanner     string   `json:"http_banner,omitempty"`
	SSHBanner      string   `json:"ssh_banner,omitempty"`
	TelnetBanner   string   `json:"telnet_banner,omitempty"`
	SNMPSysDescr   string   `json:"snmp_sys_descr,omitempty"`
	DNSName        string   `json:"dns_name,omitempty"`
	OSFingerprint  string   `json:"os_fingerprint,omitempty"`
	ServiceBanners []string `json:"service_banners"`
}

// Common network device ports
var NetworkDevicePorts = []int{
	22,   // SSH
	23,   // Telnet
	53,   // DNS
	80,   // HTTP
	161,  // SNMP
	443,  // HTTPS
	514,  // Syslog
	830,  // NETCONF over SSH
	8080, // HTTP alternate
	8443, // HTTPS alternate
	9100, // HP JetDirect
}

// Router/Firewall specific ports
var SecurityDevicePorts = []int{
	22,    // SSH
	23,    // Telnet
	80,    // HTTP management
	161,   // SNMP
	443,   // HTTPS management
	4786,  // Cisco Smart Install
	8080,  // HTTP alternate
	8443,  // HTTPS alternate
	10000, // Webmin
}

// NewNetworkScanner creates a new network scanner
func NewNetworkScanner() *NetworkScanner {
	return &NetworkScanner{
		discoveredDevices: make(map[string]*DiscoveredDevice),
		scanRanges:        []string{},
		snmpCommunities:   []string{"public", "private", "community"},
		running:           false,
		stopChannel:       make(chan bool),
	}
}

// AddScanRange adds a network range to scan (e.g., "192.168.1.0/24")
func (ns *NetworkScanner) AddScanRange(cidr string) error {
	_, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR range: %v", err)
	}

	ns.scanRanges = append(ns.scanRanges, cidr)
	log.Printf("Added scan range: %s", cidr)
	return nil
}

// AddSNMPCommunity adds an SNMP community string to try
func (ns *NetworkScanner) AddSNMPCommunity(community string) {
	ns.snmpCommunities = append(ns.snmpCommunities, community)
}

// Start begins network scanning
func (ns *NetworkScanner) Start() error {
	if ns.running {
		return fmt.Errorf("network scanner already running")
	}

	ns.running = true

	// Auto-detect local network ranges if none specified
	if len(ns.scanRanges) == 0 {
		ranges, err := ns.detectLocalNetworks()
		if err != nil {
			log.Printf("Failed to detect local networks: %v", err)
		} else {
			ns.scanRanges = ranges
		}
	}

	// Start scanning goroutine
	go ns.scanLoop()

	log.Println("Network scanner started")
	return nil
}

// Stop stops network scanning
func (ns *NetworkScanner) Stop() {
	if !ns.running {
		return
	}

	ns.running = false
	close(ns.stopChannel)
	log.Println("Network scanner stopped")
}

// detectLocalNetworks detects local network ranges to scan
func (ns *NetworkScanner) detectLocalNetworks() ([]string, error) {
	var ranges []string

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				// Convert to /24 network for scanning
				ip := ipnet.IP.To4()
				network := fmt.Sprintf("%d.%d.%d.0/24", ip[0], ip[1], ip[2])
				ranges = append(ranges, network)
			}
		}
	}

	return ranges, nil
}

// scanLoop main scanning loop
func (ns *NetworkScanner) scanLoop() {
	// Initial comprehensive scan
	ns.performFullScan()

	// Periodic rescans
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ns.stopChannel:
			return
		case <-ticker.C:
			ns.performIncrementalScan()
		}
	}
}

// performFullScan performs a comprehensive network scan
func (ns *NetworkScanner) performFullScan() {
	log.Println("Starting comprehensive network scan...")

	for _, cidr := range ns.scanRanges {
		ns.scanNetwork(cidr)
	}

	log.Printf("Network scan completed. Discovered %d devices", len(ns.discoveredDevices))
}

// performIncrementalScan performs a quick rescan of known devices
func (ns *NetworkScanner) performIncrementalScan() {
	log.Println("Performing incremental network scan...")

	ns.mutex.RLock()
	devices := make([]*DiscoveredDevice, 0, len(ns.discoveredDevices))
	for _, device := range ns.discoveredDevices {
		devices = append(devices, device)
	}
	ns.mutex.RUnlock()

	// Rescan known devices
	for _, device := range devices {
		go ns.rescanDevice(device.IP)
	}
}

// scanNetwork scans a network range
func (ns *NetworkScanner) scanNetwork(cidr string) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		log.Printf("Invalid CIDR %s: %v", cidr, err)
		return
	}

	// Generate all IPs in the range
	ips := generateIPRange(ipnet)

	// Limit concurrent scans
	semaphore := make(chan struct{}, 50)
	var wg sync.WaitGroup

	for _, ip := range ips {
		wg.Add(1)
		go func(targetIP string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			ns.scanHost(targetIP)
		}(ip)
	}

	wg.Wait()
}

// scanHost scans a single host
func (ns *NetworkScanner) scanHost(ip string) {
	// Skip scanning our own IP
	if ns.isLocalIP(ip) {
		return
	}

	// Ping test first
	if !ns.pingHost(ip) {
		return
	}

	device := &DiscoveredDevice{
		IP:              ip,
		FirstDiscovered: time.Now(),
		LastSeen:        time.Now(),
		OpenPorts:       []int{},
		Services:        make(map[int]string),
		Fingerprint:     DeviceFingerprint{ServiceBanners: []string{}},
	}

	// Port scan
	ns.scanPorts(device)

	// Service detection
	ns.detectServices(device)

	// SNMP discovery
	ns.testSNMP(device)

	// Device fingerprinting
	ns.fingerprintDevice(device)

	// Device classification
	ns.classifyDevice(device)

	// Only add devices that look like network infrastructure
	if ns.isNetworkDevice(device) {
		ns.mutex.Lock()
		ns.discoveredDevices[ip] = device
		ns.mutex.Unlock()

		// Generate discovery event
		ns.generateDiscoveryEvent(device)

		log.Printf("Discovered %s device at %s (%s)", device.DeviceType, ip, device.Hostname)
	}
}

// rescanDevice rescans a known device
func (ns *NetworkScanner) rescanDevice(ip string) {
	if !ns.pingHost(ip) {
		// Device is offline
		ns.mutex.Lock()
		if device, exists := ns.discoveredDevices[ip]; exists {
			device.LastSeen = time.Now().Add(-time.Hour) // Mark as potentially offline
		}
		ns.mutex.Unlock()
		return
	}

	ns.mutex.RLock()
	device, exists := ns.discoveredDevices[ip]
	ns.mutex.RUnlock()

	if exists {
		device.LastSeen = time.Now()
		// Quick port scan on known ports
		ns.quickPortScan(device)
	}
}

// pingHost tests if a host is reachable
func (ns *NetworkScanner) pingHost(ip string) bool {
	timeout := 2 * time.Second
	conn, err := net.DialTimeout("tcp", ip+":80", timeout)
	if err == nil {
		conn.Close()
		return true
	}

	// Try ICMP ping as fallback
	cmd := exec.Command("ping", "-n", "1", "-w", "2000", ip)
	err = cmd.Run()
	return err == nil
}

// scanPorts scans common network device ports
func (ns *NetworkScanner) scanPorts(device *DiscoveredDevice) {
	ports := append(NetworkDevicePorts, SecurityDevicePorts...)

	// Remove duplicates
	portMap := make(map[int]bool)
	uniquePorts := []int{}
	for _, port := range ports {
		if !portMap[port] {
			portMap[port] = true
			uniquePorts = append(uniquePorts, port)
		}
	}

	var wg sync.WaitGroup
	portChan := make(chan int, len(uniquePorts))

	// Concurrent port scanning
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portChan {
				if ns.isPortOpen(device.IP, port) {
					device.OpenPorts = append(device.OpenPorts, port)
				}
			}
		}()
	}

	for _, port := range uniquePorts {
		portChan <- port
	}
	close(portChan)
	wg.Wait()

	sort.Ints(device.OpenPorts)
}

// quickPortScan performs a quick scan of known open ports
func (ns *NetworkScanner) quickPortScan(device *DiscoveredDevice) {
	newOpenPorts := []int{}

	for _, port := range device.OpenPorts {
		if ns.isPortOpen(device.IP, port) {
			newOpenPorts = append(newOpenPorts, port)
		}
	}

	device.OpenPorts = newOpenPorts
}

// isPortOpen checks if a port is open
func (ns *NetworkScanner) isPortOpen(ip string, port int) bool {
	timeout := 3 * time.Second
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// detectServices detects services running on open ports
func (ns *NetworkScanner) detectServices(device *DiscoveredDevice) {
	for _, port := range device.OpenPorts {
		service := ns.identifyService(device.IP, port)
		if service != "" {
			device.Services[port] = service
		}
	}
}

// identifyService identifies the service running on a port
func (ns *NetworkScanner) identifyService(ip string, port int) string {
	// Common service mappings
	commonServices := map[int]string{
		22:   "SSH",
		23:   "Telnet",
		53:   "DNS",
		80:   "HTTP",
		161:  "SNMP",
		443:  "HTTPS",
		514:  "Syslog",
		830:  "NETCONF",
		8080: "HTTP",
		8443: "HTTPS",
		9100: "JetDirect",
	}

	if service, exists := commonServices[port]; exists {
		return service
	}

	// Try to grab banner
	banner := ns.grabBanner(ip, port)
	if banner != "" {
		return ns.parseServiceFromBanner(banner)
	}

	return "Unknown"
}

// grabBanner attempts to grab a service banner
func (ns *NetworkScanner) grabBanner(ip string, port int) string {
	timeout := 5 * time.Second
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(timeout))

	// Send appropriate probe based on port
	switch port {
	case 80, 8080:
		conn.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
	case 22:
		// SSH banner is sent immediately
	case 23:
		// Telnet banner is usually sent immediately
	default:
		conn.Write([]byte("\r\n"))
	}

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return ""
	}

	return string(buffer[:n])
}

// parseServiceFromBanner parses service information from banner
func (ns *NetworkScanner) parseServiceFromBanner(banner string) string {
	banner = strings.ToLower(banner)

	if strings.Contains(banner, "ssh") {
		return "SSH"
	}
	if strings.Contains(banner, "http") {
		return "HTTP"
	}
	if strings.Contains(banner, "telnet") {
		return "Telnet"
	}
	if strings.Contains(banner, "ftp") {
		return "FTP"
	}

	return "Unknown"
}

// testSNMP tests SNMP connectivity
func (ns *NetworkScanner) testSNMP(device *DiscoveredDevice) {
	for _, community := range ns.snmpCommunities {
		if ns.testSNMPCommunity(device.IP, community) {
			device.SNMPEnabled = true
			device.SNMPCommunity = community

			// Get system description via SNMP
			sysDescr := ns.getSNMPSysDescr(device.IP, community)
			if sysDescr != "" {
				device.Fingerprint.SNMPSysDescr = sysDescr
			}
			break
		}
	}
}

// testSNMPCommunity tests a specific SNMP community
func (ns *NetworkScanner) testSNMPCommunity(ip string, _ string) bool {
	// This is a simplified test - in reality you'd use the gosnmp library
	// For now, just check if port 161 is open
	return ns.isPortOpen(ip, 161)
}

// getSNMPSysDescr gets system description via SNMP
func (ns *NetworkScanner) getSNMPSysDescr(_ string, _ string) string {
	// This would use the SNMP client we created earlier
	// For now, return empty string
	return ""
}

// fingerprintDevice performs OS and device fingerprinting
func (ns *NetworkScanner) fingerprintDevice(device *DiscoveredDevice) {
	// Collect banners from various services
	for _, port := range device.OpenPorts {
		banner := ns.grabBanner(device.IP, port)
		if banner != "" {
			device.Fingerprint.ServiceBanners = append(device.Fingerprint.ServiceBanners, banner)

			switch port {
			case 80, 8080:
				device.Fingerprint.HTTPBanner = banner
			case 22:
				device.Fingerprint.SSHBanner = banner
			case 23:
				device.Fingerprint.TelnetBanner = banner
			}
		}
	}

	// Try reverse DNS lookup
	names, err := net.LookupAddr(device.IP)
	if err == nil && len(names) > 0 {
		device.Hostname = names[0]
		device.Fingerprint.DNSName = names[0]
	}
}

// classifyDevice classifies the device type based on collected information
func (ns *NetworkScanner) classifyDevice(device *DiscoveredDevice) {
	confidence := 0.0
	deviceType := "unknown"
	vendor := "Unknown"

	// Analyze SNMP system description
	if device.Fingerprint.SNMPSysDescr != "" {
		sysDescr := strings.ToLower(device.Fingerprint.SNMPSysDescr)

		// Vendor detection
		if strings.Contains(sysDescr, "cisco") {
			vendor = "Cisco"
			confidence += 0.3
		} else if strings.Contains(sysDescr, "juniper") {
			vendor = "Juniper"
			confidence += 0.3
		} else if strings.Contains(sysDescr, "palo alto") {
			vendor = "Palo Alto Networks"
			confidence += 0.3
		} else if strings.Contains(sysDescr, "fortinet") {
			vendor = "Fortinet"
			confidence += 0.3
		}

		// Device type detection
		if strings.Contains(sysDescr, "router") {
			deviceType = "router"
			confidence += 0.4
		} else if strings.Contains(sysDescr, "firewall") || strings.Contains(sysDescr, "asa") {
			deviceType = "firewall"
			confidence += 0.4
		} else if strings.Contains(sysDescr, "switch") {
			deviceType = "switch"
			confidence += 0.4
		}
	}

	// Analyze open ports
	hasSSH := containsInt(device.OpenPorts, 22)
	hasTelnet := containsInt(device.OpenPorts, 23)
	hasHTTP := containsInt(device.OpenPorts, 80) || containsInt(device.OpenPorts, 8080)
	hasHTTPS := containsInt(device.OpenPorts, 443) || containsInt(device.OpenPorts, 8443)
	hasSNMP := containsInt(device.OpenPorts, 161)

	if hasSSH && (hasHTTP || hasHTTPS) && hasSNMP {
		confidence += 0.3
		if deviceType == "unknown" {
			deviceType = "network_device"
		}
	}

	// Check for legacy protocols
	if hasTelnet {
		confidence += 0.1 // Telnet indicates older network equipment
	}

	// Analyze hostname
	if device.Hostname != "" {
		hostname := strings.ToLower(device.Hostname)
		if strings.Contains(hostname, "router") || strings.Contains(hostname, "rtr") {
			deviceType = "router"
			confidence += 0.2
		} else if strings.Contains(hostname, "firewall") || strings.Contains(hostname, "fw") {
			deviceType = "firewall"
			confidence += 0.2
		} else if strings.Contains(hostname, "switch") || strings.Contains(hostname, "sw") {
			deviceType = "switch"
			confidence += 0.2
		}
	}

	device.DeviceType = deviceType
	device.Vendor = vendor
	device.Confidence = confidence
}

// isNetworkDevice determines if a device is likely network infrastructure
func (ns *NetworkScanner) isNetworkDevice(device *DiscoveredDevice) bool {
	// Must have SNMP or management interface
	hasSNMP := containsInt(device.OpenPorts, 161)
	hasManagement := containsInt(device.OpenPorts, 80) || containsInt(device.OpenPorts, 443) ||
		containsInt(device.OpenPorts, 8080) || containsInt(device.OpenPorts, 8443)
	hasSSH := containsInt(device.OpenPorts, 22)

	// Basic criteria for network device
	if !hasSNMP && !hasManagement && !hasSSH {
		return false
	}

	// High confidence devices
	if device.Confidence > 0.5 {
		return true
	}

	// Known device types
	networkTypes := []string{"router", "firewall", "switch", "access_point", "network_device"}
	for _, t := range networkTypes {
		if device.DeviceType == t {
			return true
		}
	}

	return false
}

// generateDiscoveryEvent generates a device discovery event
func (ns *NetworkScanner) generateDiscoveryEvent(device *DiscoveredDevice) {
	envelope := Envelope{
		Ts:       time.Now().UTC().Format(time.RFC3339),
		TenantID: "t-aci",
		Asset: map[string]string{
			"id":   device.IP,
			"type": "network_device",
			"name": device.Hostname,
		},
		Event: map[string]interface{}{
			"class":    "network_discovery",
			"name":     "device_discovered",
			"severity": 2,
			"attrs": map[string]interface{}{
				"device_type":      device.DeviceType,
				"vendor":           device.Vendor,
				"hostname":         device.Hostname,
				"open_ports":       device.OpenPorts,
				"services":         device.Services,
				"snmp_enabled":     device.SNMPEnabled,
				"confidence":       device.Confidence,
				"first_discovered": device.FirstDiscovered,
			},
		},
		Ingest: map[string]string{
			"agent_version": "0.0.2",
			"schema":        "ocsf:1.2",
			"platform":      "network_scanner",
		},
	}

	// Send to gateway
	data, _ := json.Marshal(envelope)
	gatewayURL := "http://localhost:8080"
	go sendEventToGateway(gatewayURL, data)
}

// Helper functions

func generateIPRange(ipnet *net.IPNet) []string {
	var ips []string

	ip := ipnet.IP.To4()
	if ip == nil {
		return ips // IPv6 not supported in this simple implementation
	}

	mask := ipnet.Mask
	network := ip.Mask(mask)
	broadcast := make(net.IP, len(network))
	copy(broadcast, network)

	for i := range broadcast {
		broadcast[i] |= ^mask[i]
	}

	// Generate all IPs in range
	for ip := network; !ip.Equal(broadcast); incrementIP(ip) {
		ips = append(ips, ip.String())
	}

	return ips
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func (ns *NetworkScanner) isLocalIP(ip string) bool {
	// Get local interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return false
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ipnet.IP.String() == ip {
					return true
				}
			}
		}
	}

	return false
}

func containsInt(slice []int, item int) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// GetDiscoveredDevices returns all discovered devices
func (ns *NetworkScanner) GetDiscoveredDevices() map[string]*DiscoveredDevice {
	ns.mutex.RLock()
	defer ns.mutex.RUnlock()

	devices := make(map[string]*DiscoveredDevice)
	for k, v := range ns.discoveredDevices {
		devices[k] = v
	}
	return devices
}

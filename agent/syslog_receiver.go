//go:build windows

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SyslogReceiver receives and processes syslog messages from network devices
type SyslogReceiver struct {
	udpListener    net.PacketConn
	tcpListener    net.Listener
	port           int
	running        bool
	stopChannel    chan bool
	messageChannel chan *SyslogMessage
	parsers        map[string]DeviceParser
	mutex          sync.RWMutex
}

// SyslogMessage represents a parsed syslog message
type SyslogMessage struct {
	Timestamp    time.Time         `json:"timestamp"`
	Hostname     string            `json:"hostname"`
	SourceIP     string            `json:"source_ip"`
	Facility     int               `json:"facility"`
	Severity     int               `json:"severity"`
	Tag          string            `json:"tag"`
	Content      string            `json:"content"`
	RawMessage   string            `json:"raw_message"`
	DeviceType   string            `json:"device_type"`
	Vendor       string            `json:"vendor"`
	ParsedFields map[string]string `json:"parsed_fields"`
	EventType    string            `json:"event_type"`
	Priority     int               `json:"priority"`
}

// DeviceParser interface for vendor-specific parsing
type DeviceParser interface {
	CanParse(message *SyslogMessage) bool
	Parse(message *SyslogMessage) error
	GetVendor() string
	GetDeviceTypes() []string
}

// Syslog facilities
var SyslogFacilities = map[int]string{
	0:  "kernel",
	1:  "user",
	2:  "mail",
	3:  "daemon",
	4:  "security",
	5:  "syslogd",
	6:  "line_printer",
	7:  "network_news",
	8:  "uucp",
	9:  "clock_daemon",
	10: "security",
	11: "ftp_daemon",
	12: "ntp",
	13: "log_audit",
	14: "log_alert",
	15: "clock_daemon",
	16: "local0",
	17: "local1",
	18: "local2",
	19: "local3",
	20: "local4",
	21: "local5",
	22: "local6",
	23: "local7",
}

// Syslog severities
var SyslogSeverities = map[int]string{
	0: "emergency",
	1: "alert",
	2: "critical",
	3: "error",
	4: "warning",
	5: "notice",
	6: "info",
	7: "debug",
}

// NewSyslogReceiver creates a new syslog receiver
func NewSyslogReceiver(port int) *SyslogReceiver {
	sr := &SyslogReceiver{
		port:           port,
		running:        false,
		stopChannel:    make(chan bool),
		messageChannel: make(chan *SyslogMessage, 1000),
		parsers:        make(map[string]DeviceParser),
	}

	// Register built-in parsers
	sr.RegisterParser(&CiscoParser{})
	sr.RegisterParser(&JuniperParser{})
	sr.RegisterParser(&PaloAltoParser{})
	sr.RegisterParser(&FortinetParser{})
	sr.RegisterParser(&GenericParser{})

	return sr
}

// RegisterParser registers a device-specific parser
func (sr *SyslogReceiver) RegisterParser(parser DeviceParser) {
	sr.mutex.Lock()
	defer sr.mutex.Unlock()
	sr.parsers[parser.GetVendor()] = parser
}

// Start starts the syslog receiver
func (sr *SyslogReceiver) Start() error {
	if sr.running {
		return fmt.Errorf("syslog receiver already running")
	}

	// Start UDP listener
	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", sr.port))
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %v", err)
	}

	sr.udpListener, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to start UDP listener: %v", err)
	}

	// Start TCP listener
	tcpAddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf(":%d", sr.port))
	if err != nil {
		sr.udpListener.Close()
		return fmt.Errorf("failed to resolve TCP address: %v", err)
	}

	sr.tcpListener, err = net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		sr.udpListener.Close()
		return fmt.Errorf("failed to start TCP listener: %v", err)
	}

	sr.running = true

	// Start goroutines
	go sr.handleUDPMessages()
	go sr.handleTCPConnections()
	go sr.processMessages()

	log.Printf("Syslog receiver started on port %d", sr.port)
	return nil
}

// Stop stops the syslog receiver
func (sr *SyslogReceiver) Stop() {
	if !sr.running {
		return
	}

	sr.running = false
	close(sr.stopChannel)

	if sr.udpListener != nil {
		sr.udpListener.Close()
	}
	if sr.tcpListener != nil {
		sr.tcpListener.Close()
	}

	close(sr.messageChannel)
	log.Println("Syslog receiver stopped")
}

// handleUDPMessages handles incoming UDP syslog messages
func (sr *SyslogReceiver) handleUDPMessages() {
	buffer := make([]byte, 4096)

	for sr.running {
		n, addr, err := sr.udpListener.ReadFrom(buffer)
		if err != nil {
			if sr.running {
				log.Printf("UDP read error: %v", err)
			}
			continue
		}

		message := sr.parseSyslogMessage(string(buffer[:n]), addr.String())
		if message != nil {
			select {
			case sr.messageChannel <- message:
			default:
				log.Println("Message channel full, dropping message")
			}
		}
	}
}

// handleTCPConnections handles incoming TCP syslog connections
func (sr *SyslogReceiver) handleTCPConnections() {
	for sr.running {
		conn, err := sr.tcpListener.Accept()
		if err != nil {
			if sr.running {
				log.Printf("TCP accept error: %v", err)
			}
			continue
		}

		go sr.handleTCPConnection(conn)
	}
}

// handleTCPConnection handles a single TCP connection
func (sr *SyslogReceiver) handleTCPConnection(conn net.Conn) {
	defer conn.Close()

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() && sr.running {
		line := scanner.Text()
		if line == "" {
			continue
		}

		message := sr.parseSyslogMessage(line, conn.RemoteAddr().String())
		if message != nil {
			select {
			case sr.messageChannel <- message:
			default:
				log.Println("Message channel full, dropping message")
			}
		}
	}
}

// parseSyslogMessage parses a raw syslog message
func (sr *SyslogReceiver) parseSyslogMessage(rawMessage, sourceAddr string) *SyslogMessage {
	message := &SyslogMessage{
		RawMessage:   rawMessage,
		SourceIP:     strings.Split(sourceAddr, ":")[0],
		Timestamp:    time.Now(),
		ParsedFields: make(map[string]string),
	}

	// Parse RFC3164 format: <priority>timestamp hostname tag: content
	re := regexp.MustCompile(`^<(\d+)>(.*)`)
	matches := re.FindStringSubmatch(rawMessage)
	
	if len(matches) < 3 {
		// No priority found, treat as plain message
		message.Content = rawMessage
		message.Priority = 13 // Default: user.notice
		message.Facility = 1
		message.Severity = 5
		return message
	}

	// Parse priority
	priority, err := strconv.Atoi(matches[1])
	if err != nil {
		priority = 13
	}
	message.Priority = priority
	message.Facility = priority / 8
	message.Severity = priority % 8

	// Parse the rest of the message
	rest := matches[2]
	
	// Try to parse timestamp
	timestampFormats := []string{
		"Jan 2 15:04:05",
		"Jan  2 15:04:05",
		"2006-01-02T15:04:05",
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05-07:00",
	}

	var parsedTime time.Time
	var remainingMessage string

	for _, format := range timestampFormats {
		if len(rest) >= len(format) {
			timeStr := rest[:len(format)]
			if t, err := time.Parse(format, timeStr); err == nil {
				parsedTime = t
				// Adjust year for formats without year
				if format == "Jan 2 15:04:05" || format == "Jan  2 15:04:05" {
					parsedTime = parsedTime.AddDate(time.Now().Year(), 0, 0)
				}
				remainingMessage = strings.TrimSpace(rest[len(format):])
				break
			}
		}
	}

	if !parsedTime.IsZero() {
		message.Timestamp = parsedTime
	}

	if remainingMessage == "" {
		remainingMessage = rest
	}

	// Parse hostname and tag
	parts := strings.Fields(remainingMessage)
	if len(parts) > 0 {
		message.Hostname = parts[0]
		
		if len(parts) > 1 {
			// Look for tag (usually ends with :)
			for i, part := range parts[1:] {
				if strings.HasSuffix(part, ":") {
					message.Tag = strings.TrimSuffix(part, ":")
					if i+2 < len(parts) {
						message.Content = strings.Join(parts[i+2:], " ")
					}
					break
				}
			}
			
			// If no tag found, treat everything after hostname as content
			if message.Tag == "" {
				message.Content = strings.Join(parts[1:], " ")
			}
		}
	}

	return message
}

// processMessages processes parsed syslog messages
func (sr *SyslogReceiver) processMessages() {
	for message := range sr.messageChannel {
		sr.enhanceMessage(message)
		sr.generateSyslogEvent(message)
	}
}

// enhanceMessage enhances the message with vendor-specific parsing
func (sr *SyslogReceiver) enhanceMessage(message *SyslogMessage) {
	sr.mutex.RLock()
	defer sr.mutex.RUnlock()

	// Try each parser
	for _, parser := range sr.parsers {
		if parser.CanParse(message) {
			err := parser.Parse(message)
			if err != nil {
				log.Printf("Parser error for %s: %v", parser.GetVendor(), err)
				continue
			}
			message.Vendor = parser.GetVendor()
			break
		}
	}
}

// generateSyslogEvent generates an event for the syslog message
func (sr *SyslogReceiver) generateSyslogEvent(message *SyslogMessage) {
	envelope := Envelope{
		Ts:       message.Timestamp.UTC().Format(time.RFC3339),
		TenantID: "t-aci",
		Asset: map[string]string{
			"id":   message.SourceIP,
			"type": "network_device",
			"name": message.Hostname,
		},
		Event: map[string]interface{}{
			"class":    "syslog",
			"name":     "syslog_message",
			"severity": message.Severity,
			"attrs": map[string]interface{}{
				"facility":      message.Facility,
				"severity":      message.Severity,
				"priority":      message.Priority,
				"tag":          message.Tag,
				"content":      message.Content,
				"raw_message":  message.RawMessage,
				"device_type":  message.DeviceType,
				"vendor":       message.Vendor,
				"event_type":   message.EventType,
				"parsed_fields": message.ParsedFields,
			},
		},
		Ingest: map[string]string{
			"agent_version": "0.0.2",
			"schema":        "ocsf:1.2",
			"platform":      "syslog_receiver",
		},
	}

	// Send to gateway
	data, _ := json.Marshal(envelope)
	gatewayURL := "http://localhost:8080"
	go sendEventToGateway(gatewayURL, data)
}

// Built-in parsers

// CiscoParser parses Cisco device messages
type CiscoParser struct{}

func (p *CiscoParser) GetVendor() string { return "Cisco" }
func (p *CiscoParser) GetDeviceTypes() []string { return []string{"router", "switch", "firewall", "asa"} }

func (p *CiscoParser) CanParse(message *SyslogMessage) bool {
	content := strings.ToLower(message.Content)
	hostname := strings.ToLower(message.Hostname)
	
	// Check for Cisco-specific patterns
	ciscoPatterns := []string{
		"%", // Cisco messages often start with %
		"asa-", "pix-", "fwsm-", // ASA/PIX patterns
		"sec-", "sys-", "link-", // Common Cisco facility codes
	}

	for _, pattern := range ciscoPatterns {
		if strings.Contains(content, pattern) || strings.Contains(hostname, pattern) {
			return true
		}
	}

	return false
}

func (p *CiscoParser) Parse(message *SyslogMessage) error {
	content := message.Content
	
	// Parse Cisco message format: %FACILITY-SEVERITY-MNEMONIC: description
	re := regexp.MustCompile(`%([A-Z_]+)-(\d+)-([A-Z_]+):\s*(.*)`)
	matches := re.FindStringSubmatch(content)
	
	if len(matches) == 5 {
		message.ParsedFields["facility_code"] = matches[1]
		message.ParsedFields["cisco_severity"] = matches[2]
		message.ParsedFields["mnemonic"] = matches[3]
		message.ParsedFields["description"] = matches[4]
		
		// Determine device type based on facility
		facility := strings.ToLower(matches[1])
		if strings.Contains(facility, "asa") || strings.Contains(facility, "pix") {
			message.DeviceType = "firewall"
		} else if strings.Contains(facility, "sys") || strings.Contains(facility, "link") {
			message.DeviceType = "router"
		}
		
		// Determine event type
		mnemonic := strings.ToLower(matches[3])
		if strings.Contains(mnemonic, "up") || strings.Contains(mnemonic, "down") {
			message.EventType = "interface_status"
		} else if strings.Contains(mnemonic, "login") || strings.Contains(mnemonic, "logout") {
			message.EventType = "authentication"
		} else if strings.Contains(mnemonic, "config") {
			message.EventType = "configuration_change"
		}
	}

	return nil
}

// JuniperParser parses Juniper device messages
type JuniperParser struct{}

func (p *JuniperParser) GetVendor() string { return "Juniper" }
func (p *JuniperParser) GetDeviceTypes() []string { return []string{"router", "switch", "firewall", "srx"} }

func (p *JuniperParser) CanParse(message *SyslogMessage) bool {
	content := strings.ToLower(message.Content)
	hostname := strings.ToLower(message.Hostname)
	
	juniperPatterns := []string{
		"junos", "srx", "mx", "ex", "qfx",
		"rpd", "chassisd", "mgd",
	}

	for _, pattern := range juniperPatterns {
		if strings.Contains(content, pattern) || strings.Contains(hostname, pattern) {
			return true
		}
	}

	return false
}

func (p *JuniperParser) Parse(message *SyslogMessage) error {
	// Juniper format: process[pid]: message
	re := regexp.MustCompile(`(\w+)\[(\d+)\]:\s*(.*)`)
	matches := re.FindStringSubmatch(message.Content)
	
	if len(matches) == 4 {
		message.ParsedFields["process"] = matches[1]
		message.ParsedFields["pid"] = matches[2]
		message.ParsedFields["description"] = matches[3]
		
		process := strings.ToLower(matches[1])
		if process == "rpd" {
			message.EventType = "routing"
		} else if process == "mgd" {
			message.EventType = "management"
		} else if process == "chassisd" {
			message.EventType = "hardware"
		}
	}

	return nil
}

// PaloAltoParser parses Palo Alto Networks messages
type PaloAltoParser struct{}

func (p *PaloAltoParser) GetVendor() string { return "Palo Alto Networks" }
func (p *PaloAltoParser) GetDeviceTypes() []string { return []string{"firewall", "panorama"} }

func (p *PaloAltoParser) CanParse(message *SyslogMessage) bool {
	content := strings.ToLower(message.Content)
	
	paloPatterns := []string{
		"traffic", "threat", "config", "system",
		"panorama", "pa-", "globalprotect",
	}

	for _, pattern := range paloPatterns {
		if strings.Contains(content, pattern) {
			return true
		}
	}

	return false
}

func (p *PaloAltoParser) Parse(message *SyslogMessage) error {
	message.DeviceType = "firewall"
	
	content := strings.ToLower(message.Content)
	if strings.Contains(content, "traffic") {
		message.EventType = "traffic"
	} else if strings.Contains(content, "threat") {
		message.EventType = "threat"
	} else if strings.Contains(content, "config") {
		message.EventType = "configuration_change"
	} else if strings.Contains(content, "system") {
		message.EventType = "system"
	}

	return nil
}

// FortinetParser parses Fortinet messages
type FortinetParser struct{}

func (p *FortinetParser) GetVendor() string { return "Fortinet" }
func (p *FortinetParser) GetDeviceTypes() []string { return []string{"firewall", "fortigate"} }

func (p *FortinetParser) CanParse(message *SyslogMessage) bool {
	content := strings.ToLower(message.Content)
	
	fortiPatterns := []string{
		"fortigate", "fortios", "fortimanager",
		"logid=", "type=", "subtype=",
	}

	for _, pattern := range fortiPatterns {
		if strings.Contains(content, pattern) {
			return true
		}
	}

	return false
}

func (p *FortinetParser) Parse(message *SyslogMessage) error {
	message.DeviceType = "firewall"
	
	// Parse key-value pairs
	re := regexp.MustCompile(`(\w+)=([^\s]+)`)
	matches := re.FindAllStringSubmatch(message.Content, -1)
	
	for _, match := range matches {
		if len(match) == 3 {
			key := match[1]
			value := strings.Trim(match[2], `"`)
			message.ParsedFields[key] = value
		}
	}
	
	// Determine event type
	if logType, exists := message.ParsedFields["type"]; exists {
		message.EventType = logType
	}

	return nil
}

// GenericParser is a fallback parser
type GenericParser struct{}

func (p *GenericParser) GetVendor() string { return "Generic" }
func (p *GenericParser) GetDeviceTypes() []string { return []string{"network_device"} }

func (p *GenericParser) CanParse(message *SyslogMessage) bool {
	return true // Always can parse as fallback
}

func (p *GenericParser) Parse(message *SyslogMessage) error {
	// Basic parsing for generic devices
	content := strings.ToLower(message.Content)
	
	if strings.Contains(content, "interface") || strings.Contains(content, "link") {
		message.EventType = "interface"
	} else if strings.Contains(content, "login") || strings.Contains(content, "auth") {
		message.EventType = "authentication"
	} else if strings.Contains(content, "config") {
		message.EventType = "configuration"
	} else {
		message.EventType = "general"
	}

	return nil
}
//go:build windows

package main

import (
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync"
)

// Enhanced device parsers with more sophisticated parsing capabilities

// CiscoAdvancedParser provides advanced Cisco device parsing
type CiscoAdvancedParser struct {
	patterns map[string]*regexp.Regexp
}

// NewCiscoAdvancedParser creates a new advanced Cisco parser
func NewCiscoAdvancedParser() *CiscoAdvancedParser {
	parser := &CiscoAdvancedParser{
		patterns: make(map[string]*regexp.Regexp),
	}
	
	// Compile common Cisco patterns
	parser.patterns["asa_connection"] = regexp.MustCompile(`%ASA-(\d+)-(\d+): (Built|Teardown) (inbound|outbound) (TCP|UDP|ICMP) connection (\d+) for ([^:]+):(\d+)/(\d+) \(([^)]+)\) to ([^:]+):(\d+)/(\d+) \(([^)]+)\)`)
	parser.patterns["asa_deny"] = regexp.MustCompile(`%ASA-(\d+)-(\d+): Deny (TCP|UDP|ICMP) \(no connection\) from ([^:]+):(\d+) to ([^:]+):(\d+) flags ([^\s]+) on interface ([^\s]+)`)
	parser.patterns["interface_status"] = regexp.MustCompile(`%LINK-(\d+)-(\w+): Interface ([^,]+), changed state to (\w+)`)
	parser.patterns["bgp_neighbor"] = regexp.MustCompile(`%BGP-(\d+)-(\w+): Neighbor ([^\s]+) (\w+)`)
	parser.patterns["ospf_neighbor"] = regexp.MustCompile(`%OSPF-(\d+)-(\w+): Neighbor ([^\s]+) on ([^\s]+) \(([^)]+)\) (\w+)`)
	parser.patterns["config_change"] = regexp.MustCompile(`%SYS-(\d+)-(\w+): Configured from ([^\s]+) by ([^\s]+)`)
	parser.patterns["authentication"] = regexp.MustCompile(`%SEC_LOGIN-(\d+)-(\w+): Login (Success|Failed) \[user: ([^\]]+)\] \[Source: ([^\]]+)\]`)
	
	return parser
}

func (p *CiscoAdvancedParser) GetVendor() string { return "Cisco" }
func (p *CiscoAdvancedParser) GetDeviceTypes() []string { return []string{"router", "switch", "firewall", "asa"} }

func (p *CiscoAdvancedParser) CanParse(message *SyslogMessage) bool {
	content := strings.ToUpper(message.Content)
	
	// Check for Cisco-specific patterns
	ciscoIndicators := []string{
		"%ASA-", "%PIX-", "%FWSM-", "%SEC-", "%SYS-", "%LINK-", 
		"%BGP-", "%OSPF-", "%EIGRP-", "%CDP-", "%SNMP-",
	}

	for _, indicator := range ciscoIndicators {
		if strings.Contains(content, indicator) {
			return true
		}
	}

	return false
}

func (p *CiscoAdvancedParser) Parse(message *SyslogMessage) error {
	content := message.Content
	
	// Try ASA connection patterns
	if matches := p.patterns["asa_connection"].FindStringSubmatch(content); matches != nil {
		message.DeviceType = "firewall"
		message.EventType = "connection"
		message.ParsedFields["severity"] = matches[1]
		message.ParsedFields["message_id"] = matches[2]
		message.ParsedFields["action"] = strings.ToLower(matches[3])
		message.ParsedFields["direction"] = matches[4]
		message.ParsedFields["protocol"] = matches[5]
		message.ParsedFields["connection_id"] = matches[6]
		message.ParsedFields["source_ip"] = matches[7]
		message.ParsedFields["source_port"] = matches[8]
		message.ParsedFields["source_mapped_port"] = matches[9]
		message.ParsedFields["source_interface"] = matches[10]
		message.ParsedFields["dest_ip"] = matches[11]
		message.ParsedFields["dest_port"] = matches[12]
		message.ParsedFields["dest_mapped_port"] = matches[13]
		message.ParsedFields["dest_interface"] = matches[14]
		return nil
	}

	// Try ASA deny patterns
	if matches := p.patterns["asa_deny"].FindStringSubmatch(content); matches != nil {
		message.DeviceType = "firewall"
		message.EventType = "deny"
		message.ParsedFields["severity"] = matches[1]
		message.ParsedFields["message_id"] = matches[2]
		message.ParsedFields["protocol"] = matches[3]
		message.ParsedFields["source_ip"] = matches[4]
		message.ParsedFields["source_port"] = matches[5]
		message.ParsedFields["dest_ip"] = matches[6]
		message.ParsedFields["dest_port"] = matches[7]
		message.ParsedFields["flags"] = matches[8]
		message.ParsedFields["interface"] = matches[9]
		return nil
	}

	// Try interface status patterns
	if matches := p.patterns["interface_status"].FindStringSubmatch(content); matches != nil {
		message.DeviceType = "router"
		message.EventType = "interface_status"
		message.ParsedFields["severity"] = matches[1]
		message.ParsedFields["mnemonic"] = matches[2]
		message.ParsedFields["interface"] = matches[3]
		message.ParsedFields["state"] = matches[4]
		return nil
	}

	// Try BGP neighbor patterns
	if matches := p.patterns["bgp_neighbor"].FindStringSubmatch(content); matches != nil {
		message.DeviceType = "router"
		message.EventType = "bgp"
		message.ParsedFields["severity"] = matches[1]
		message.ParsedFields["mnemonic"] = matches[2]
		message.ParsedFields["neighbor"] = matches[3]
		message.ParsedFields["state"] = matches[4]
		return nil
	}

	// Try authentication patterns
	if matches := p.patterns["authentication"].FindStringSubmatch(content); matches != nil {
		message.EventType = "authentication"
		message.ParsedFields["severity"] = matches[1]
		message.ParsedFields["mnemonic"] = matches[2]
		message.ParsedFields["result"] = strings.ToLower(matches[3])
		message.ParsedFields["user"] = matches[4]
		message.ParsedFields["source"] = matches[5]
		return nil
	}

	return nil
}

// JuniperAdvancedParser provides advanced Juniper device parsing
type JuniperAdvancedParser struct {
	patterns map[string]*regexp.Regexp
}

func NewJuniperAdvancedParser() *JuniperAdvancedParser {
	parser := &JuniperAdvancedParser{
		patterns: make(map[string]*regexp.Regexp),
	}
	
	parser.patterns["interface"] = regexp.MustCompile(`(\w+)\[(\d+)\]: Interface ([^\s]+) is now (\w+)`)
	parser.patterns["bgp"] = regexp.MustCompile(`rpd\[(\d+)\]: BGP_PREFIX_THRESH_EXCEEDED ([^:]+): Configured maximum prefix-limit threshold\((\d+)\) exceeded for ([^,]+), prefix-count\((\d+)\)`)
	parser.patterns["ospf"] = regexp.MustCompile(`rpd\[(\d+)\]: OSPF neighbor ([^\s]+) \(realm ([^)]+)\) state changed from (\w+) to (\w+)`)
	parser.patterns["commit"] = regexp.MustCompile(`mgd\[(\d+)\]: UI_COMMIT: User '([^']+)' performed commit: (.*)`)
	parser.patterns["login"] = regexp.MustCompile(`sshd\[(\d+)\]: (Accepted|Failed) (\w+) for ([^\s]+) from ([^\s]+) port (\d+)`)
	
	return parser
}

func (p *JuniperAdvancedParser) GetVendor() string { return "Juniper" }
func (p *JuniperAdvancedParser) GetDeviceTypes() []string { return []string{"router", "switch", "firewall", "srx"} }

func (p *JuniperAdvancedParser) CanParse(message *SyslogMessage) bool {
	content := strings.ToLower(message.Content)
	hostname := strings.ToLower(message.Hostname)
	
	juniperIndicators := []string{
		"junos", "srx", "mx", "ex", "qfx", "acx",
		"rpd[", "mgd[", "chassisd[", "kmd[", "dcd[",
	}

	for _, indicator := range juniperIndicators {
		if strings.Contains(content, indicator) || strings.Contains(hostname, indicator) {
			return true
		}
	}

	return false
}

func (p *JuniperAdvancedParser) Parse(message *SyslogMessage) error {
	content := message.Content
	
	// Try interface patterns
	if matches := p.patterns["interface"].FindStringSubmatch(content); matches != nil {
		message.EventType = "interface_status"
		message.ParsedFields["process"] = matches[1]
		message.ParsedFields["pid"] = matches[2]
		message.ParsedFields["interface"] = matches[3]
		message.ParsedFields["state"] = matches[4]
		return nil
	}

	// Try BGP patterns
	if matches := p.patterns["bgp"].FindStringSubmatch(content); matches != nil {
		message.DeviceType = "router"
		message.EventType = "bgp"
		message.ParsedFields["pid"] = matches[1]
		message.ParsedFields["peer"] = matches[2]
		message.ParsedFields["threshold"] = matches[3]
		message.ParsedFields["neighbor"] = matches[4]
		message.ParsedFields["prefix_count"] = matches[5]
		return nil
	}

	// Try commit patterns
	if matches := p.patterns["commit"].FindStringSubmatch(content); matches != nil {
		message.EventType = "configuration_change"
		message.ParsedFields["pid"] = matches[1]
		message.ParsedFields["user"] = matches[2]
		message.ParsedFields["commit_info"] = matches[3]
		return nil
	}

	// Try login patterns
	if matches := p.patterns["login"].FindStringSubmatch(content); matches != nil {
		message.EventType = "authentication"
		message.ParsedFields["pid"] = matches[1]
		message.ParsedFields["result"] = strings.ToLower(matches[2])
		message.ParsedFields["method"] = matches[3]
		message.ParsedFields["user"] = matches[4]
		message.ParsedFields["source_ip"] = matches[5]
		message.ParsedFields["source_port"] = matches[6]
		return nil
	}

	return nil
}

// PaloAltoAdvancedParser provides advanced Palo Alto parsing
type PaloAltoAdvancedParser struct {
	patterns map[string]*regexp.Regexp
}

func NewPaloAltoAdvancedParser() *PaloAltoAdvancedParser {
	parser := &PaloAltoAdvancedParser{
		patterns: make(map[string]*regexp.Regexp),
	}
	
	// Palo Alto uses CSV-like format for many logs
	parser.patterns["traffic"] = regexp.MustCompile(`TRAFFIC,([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+)`)
	parser.patterns["threat"] = regexp.MustCompile(`THREAT,([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+)`)
	
	return parser
}

func (p *PaloAltoAdvancedParser) GetVendor() string { return "Palo Alto Networks" }
func (p *PaloAltoAdvancedParser) GetDeviceTypes() []string { return []string{"firewall", "panorama"} }

func (p *PaloAltoAdvancedParser) CanParse(message *SyslogMessage) bool {
	content := strings.ToUpper(message.Content)
	
	paloIndicators := []string{
		"TRAFFIC,", "THREAT,", "CONFIG,", "SYSTEM,",
		"PANORAMA", "PA-", "GLOBALPROTECT",
	}

	for _, indicator := range paloIndicators {
		if strings.Contains(content, indicator) {
			return true
		}
	}

	return false
}

func (p *PaloAltoAdvancedParser) Parse(message *SyslogMessage) error {
	message.DeviceType = "firewall"
	content := message.Content
	
	// Try traffic log parsing
	if matches := p.patterns["traffic"].FindStringSubmatch(content); len(matches) > 20 {
		message.EventType = "traffic"
		message.ParsedFields["log_type"] = "traffic"
		message.ParsedFields["receive_time"] = matches[1]
		message.ParsedFields["serial"] = matches[2]
		message.ParsedFields["type"] = matches[3]
		message.ParsedFields["subtype"] = matches[4]
		message.ParsedFields["time_generated"] = matches[5]
		message.ParsedFields["source_ip"] = matches[6]
		message.ParsedFields["dest_ip"] = matches[7]
		message.ParsedFields["nat_source_ip"] = matches[8]
		message.ParsedFields["nat_dest_ip"] = matches[9]
		message.ParsedFields["rule"] = matches[10]
		message.ParsedFields["source_user"] = matches[11]
		message.ParsedFields["dest_user"] = matches[12]
		message.ParsedFields["application"] = matches[13]
		message.ParsedFields["virtual_system"] = matches[14]
		message.ParsedFields["source_zone"] = matches[15]
		message.ParsedFields["dest_zone"] = matches[16]
		message.ParsedFields["inbound_interface"] = matches[17]
		message.ParsedFields["outbound_interface"] = matches[18]
		message.ParsedFields["action"] = matches[19]
		if len(matches) > 20 {
			message.ParsedFields["bytes"] = matches[20]
		}
		return nil
	}

	// Try threat log parsing
	if matches := p.patterns["threat"].FindStringSubmatch(content); len(matches) > 15 {
		message.EventType = "threat"
		message.ParsedFields["log_type"] = "threat"
		message.ParsedFields["receive_time"] = matches[1]
		message.ParsedFields["serial"] = matches[2]
		message.ParsedFields["type"] = matches[3]
		message.ParsedFields["subtype"] = matches[4]
		message.ParsedFields["time_generated"] = matches[5]
		message.ParsedFields["source_ip"] = matches[6]
		message.ParsedFields["dest_ip"] = matches[7]
		message.ParsedFields["nat_source_ip"] = matches[8]
		message.ParsedFields["nat_dest_ip"] = matches[9]
		message.ParsedFields["rule"] = matches[10]
		message.ParsedFields["source_user"] = matches[11]
		message.ParsedFields["dest_user"] = matches[12]
		message.ParsedFields["application"] = matches[13]
		message.ParsedFields["virtual_system"] = matches[14]
		message.ParsedFields["source_zone"] = matches[15]
		if len(matches) > 16 {
			message.ParsedFields["dest_zone"] = matches[16]
		}
		return nil
	}

	return nil
}

// FortinetAdvancedParser provides advanced Fortinet parsing
type FortinetAdvancedParser struct {
	patterns map[string]*regexp.Regexp
}

func NewFortinetAdvancedParser() *FortinetAdvancedParser {
	parser := &FortinetAdvancedParser{
		patterns: make(map[string]*regexp.Regexp),
	}
	
	parser.patterns["traffic"] = regexp.MustCompile(`logid="(\d+)" type="(\w+)" subtype="(\w+)" level="(\w+)" vd="([^"]*)" time="([^"]*)" srcip=([^\s]+) srcport=(\d+) srcintf="([^"]*)" dstip=([^\s]+) dstport=(\d+) dstintf="([^"]*)" policyid=(\d+) sessionid=(\d+) proto=(\d+) action="(\w+)" policytype="(\w+)" service="([^"]*)" dstcountry="([^"]*)" srccountry="([^"]*)" trandisp="(\w+)" duration=(\d+) sentbyte=(\d+) rcvdbyte=(\d+)`)
	parser.patterns["utm"] = regexp.MustCompile(`logid="(\d+)" type="(\w+)" subtype="(\w+)" level="(\w+)" vd="([^"]*)" eventtime=(\d+) srcip=([^\s]+) srcport=(\d+) srcintf="([^"]*)" dstip=([^\s]+) dstport=(\d+) dstintf="([^"]*)" sessionid=(\d+) proto=(\d+) action="(\w+)" policyid=(\d+) service="([^"]*)" hostname="([^"]*)" profile="([^"]*)" reqtype="([^"]*)" url="([^"]*)" sentbyte=(\d+) rcvdbyte=(\d+)`)
	
	return parser
}

func (p *FortinetAdvancedParser) GetVendor() string { return "Fortinet" }
func (p *FortinetAdvancedParser) GetDeviceTypes() []string { return []string{"firewall", "fortigate"} }

func (p *FortinetAdvancedParser) CanParse(message *SyslogMessage) bool {
	content := strings.ToLower(message.Content)
	
	fortiIndicators := []string{
		"fortigate", "fortios", "fortimanager", "fortianalyzer",
		"logid=", "type=", "subtype=", "vd=",
	}

	for _, indicator := range fortiIndicators {
		if strings.Contains(content, indicator) {
			return true
		}
	}

	return false
}

func (p *FortinetAdvancedParser) Parse(message *SyslogMessage) error {
	message.DeviceType = "firewall"
	content := message.Content
	
	// Try traffic log parsing
	if matches := p.patterns["traffic"].FindStringSubmatch(content); matches != nil {
		message.EventType = "traffic"
		message.ParsedFields["logid"] = matches[1]
		message.ParsedFields["type"] = matches[2]
		message.ParsedFields["subtype"] = matches[3]
		message.ParsedFields["level"] = matches[4]
		message.ParsedFields["vd"] = matches[5]
		message.ParsedFields["time"] = matches[6]
		message.ParsedFields["source_ip"] = matches[7]
		message.ParsedFields["source_port"] = matches[8]
		message.ParsedFields["source_interface"] = matches[9]
		message.ParsedFields["dest_ip"] = matches[10]
		message.ParsedFields["dest_port"] = matches[11]
		message.ParsedFields["dest_interface"] = matches[12]
		message.ParsedFields["policy_id"] = matches[13]
		message.ParsedFields["session_id"] = matches[14]
		message.ParsedFields["protocol"] = matches[15]
		message.ParsedFields["action"] = matches[16]
		message.ParsedFields["policy_type"] = matches[17]
		message.ParsedFields["service"] = matches[18]
		message.ParsedFields["dest_country"] = matches[19]
		message.ParsedFields["source_country"] = matches[20]
		message.ParsedFields["duration"] = matches[22]
		message.ParsedFields["sent_bytes"] = matches[23]
		message.ParsedFields["received_bytes"] = matches[24]
		return nil
	}

	// Try UTM log parsing
	if matches := p.patterns["utm"].FindStringSubmatch(content); matches != nil {
		message.EventType = "utm"
		message.ParsedFields["logid"] = matches[1]
		message.ParsedFields["type"] = matches[2]
		message.ParsedFields["subtype"] = matches[3]
		message.ParsedFields["level"] = matches[4]
		message.ParsedFields["vd"] = matches[5]
		message.ParsedFields["eventtime"] = matches[6]
		message.ParsedFields["source_ip"] = matches[7]
		message.ParsedFields["source_port"] = matches[8]
		message.ParsedFields["source_interface"] = matches[9]
		message.ParsedFields["dest_ip"] = matches[10]
		message.ParsedFields["dest_port"] = matches[11]
		message.ParsedFields["dest_interface"] = matches[12]
		message.ParsedFields["session_id"] = matches[13]
		message.ParsedFields["protocol"] = matches[14]
		message.ParsedFields["action"] = matches[15]
		message.ParsedFields["policy_id"] = matches[16]
		message.ParsedFields["service"] = matches[17]
		message.ParsedFields["hostname"] = matches[18]
		message.ParsedFields["profile"] = matches[19]
		message.ParsedFields["request_type"] = matches[20]
		message.ParsedFields["url"] = matches[21]
		message.ParsedFields["sent_bytes"] = matches[22]
		message.ParsedFields["received_bytes"] = matches[23]
		return nil
	}

	// Fallback to key-value parsing
	re := regexp.MustCompile(`(\w+)=(?:"([^"]*)"|([^\s]+))`)
	matches := re.FindAllStringSubmatch(content, -1)
	
	for _, match := range matches {
		if len(match) >= 3 {
			key := match[1]
			value := match[2]
			if value == "" && len(match) > 3 {
				value = match[3]
			}
			message.ParsedFields[key] = value
		}
	}
	
	// Set event type based on parsed fields
	if logType, exists := message.ParsedFields["type"]; exists {
		message.EventType = logType
	}

	return nil
}

// CheckPointParser for Check Point firewalls
type CheckPointParser struct {
	patterns map[string]*regexp.Regexp
}

func NewCheckPointParser() *CheckPointParser {
	parser := &CheckPointParser{
		patterns: make(map[string]*regexp.Regexp),
	}
	
	parser.patterns["accept"] = regexp.MustCompile(`action="accept" orig="([^"]*)" i/f_dir="([^"]*)" i/f_name="([^"]*)" has_accounting="([^"]*)" uuid="([^"]*)" product="([^"]*)" __policy_id_tag="([^"]*)" rule_name="([^"]*)" rule_uid="([^"]*)" src="([^"]*)" dst="([^"]*)" proto="([^"]*)" s_port="([^"]*)" service="([^"]*)"`)
	parser.patterns["drop"] = regexp.MustCompile(`action="drop" orig="([^"]*)" i/f_dir="([^"]*)" i/f_name="([^"]*)" product="([^"]*)" src="([^"]*)" dst="([^"]*)" proto="([^"]*)" s_port="([^"]*)" service="([^"]*)" rule_name="([^"]*)" rule_uid="([^"]*)"`)
	
	return parser
}

func (p *CheckPointParser) GetVendor() string { return "Check Point" }
func (p *CheckPointParser) GetDeviceTypes() []string { return []string{"firewall", "gateway"} }

func (p *CheckPointParser) CanParse(message *SyslogMessage) bool {
	content := strings.ToLower(message.Content)
	
	checkpointIndicators := []string{
		"checkpoint", "action=\"accept\"", "action=\"drop\"",
		"__policy_id_tag=", "rule_uid=", "smartdefense",
	}

	for _, indicator := range checkpointIndicators {
		if strings.Contains(content, indicator) {
			return true
		}
	}

	return false
}

func (p *CheckPointParser) Parse(message *SyslogMessage) error {
	message.DeviceType = "firewall"
	content := message.Content
	
	// Try accept pattern
	if matches := p.patterns["accept"].FindStringSubmatch(content); matches != nil {
		message.EventType = "accept"
		message.ParsedFields["action"] = "accept"
		message.ParsedFields["orig"] = matches[1]
		message.ParsedFields["interface_direction"] = matches[2]
		message.ParsedFields["interface_name"] = matches[3]
		message.ParsedFields["has_accounting"] = matches[4]
		message.ParsedFields["uuid"] = matches[5]
		message.ParsedFields["product"] = matches[6]
		message.ParsedFields["policy_id"] = matches[7]
		message.ParsedFields["rule_name"] = matches[8]
		message.ParsedFields["rule_uid"] = matches[9]
		message.ParsedFields["source_ip"] = matches[10]
		message.ParsedFields["dest_ip"] = matches[11]
		message.ParsedFields["protocol"] = matches[12]
		message.ParsedFields["source_port"] = matches[13]
		message.ParsedFields["service"] = matches[14]
		return nil
	}

	// Try drop pattern
	if matches := p.patterns["drop"].FindStringSubmatch(content); matches != nil {
		message.EventType = "drop"
		message.ParsedFields["action"] = "drop"
		message.ParsedFields["orig"] = matches[1]
		message.ParsedFields["interface_direction"] = matches[2]
		message.ParsedFields["interface_name"] = matches[3]
		message.ParsedFields["product"] = matches[4]
		message.ParsedFields["source_ip"] = matches[5]
		message.ParsedFields["dest_ip"] = matches[6]
		message.ParsedFields["protocol"] = matches[7]
		message.ParsedFields["source_port"] = matches[8]
		message.ParsedFields["service"] = matches[9]
		message.ParsedFields["rule_name"] = matches[10]
		message.ParsedFields["rule_uid"] = matches[11]
		return nil
	}

	return nil
}

// SonicWallParser for SonicWall firewalls
type SonicWallParser struct {
	patterns map[string]*regexp.Regexp
}

func NewSonicWallParser() *SonicWallParser {
	parser := &SonicWallParser{
		patterns: make(map[string]*regexp.Regexp),
	}
	
	parser.patterns["connection"] = regexp.MustCompile(`id=(\w+) sn=(\d+) time="([^"]*)" fw=([^\s]+) pri=(\d+) c=(\d+) m=(\d+) msg="([^"]*)" n=(\d+) src=([^:]+):(\d+):([^\s]+) dst=([^:]+):(\d+):([^\s]+) proto=([^\s]+)`)
	
	return parser
}

func (p *SonicWallParser) GetVendor() string { return "SonicWall" }
func (p *SonicWallParser) GetDeviceTypes() []string { return []string{"firewall", "nsa", "tz"} }

func (p *SonicWallParser) CanParse(message *SyslogMessage) bool {
	content := strings.ToLower(message.Content)
	
	sonicwallIndicators := []string{
		"sonicwall", "id=firewall", "sn=", "fw=",
		"msg=\"connection", "msg=\"dropped",
	}

	for _, indicator := range sonicwallIndicators {
		if strings.Contains(content, indicator) {
			return true
		}
	}

	return false
}

func (p *SonicWallParser) Parse(message *SyslogMessage) error {
	message.DeviceType = "firewall"
	content := message.Content
	
	if matches := p.patterns["connection"].FindStringSubmatch(content); matches != nil {
		message.EventType = "connection"
		message.ParsedFields["id"] = matches[1]
		message.ParsedFields["serial_number"] = matches[2]
		message.ParsedFields["time"] = matches[3]
		message.ParsedFields["firmware"] = matches[4]
		message.ParsedFields["priority"] = matches[5]
		message.ParsedFields["category"] = matches[6]
		message.ParsedFields["message_id"] = matches[7]
		message.ParsedFields["message"] = matches[8]
		message.ParsedFields["note"] = matches[9]
		message.ParsedFields["source_ip"] = matches[10]
		message.ParsedFields["source_port"] = matches[11]
		message.ParsedFields["source_interface"] = matches[12]
		message.ParsedFields["dest_ip"] = matches[13]
		message.ParsedFields["dest_port"] = matches[14]
		message.ParsedFields["dest_interface"] = matches[15]
		message.ParsedFields["protocol"] = matches[16]
		return nil
	}

	return nil
}

// ParserManager manages all device parsers
type ParserManager struct {
	parsers []DeviceParser
	mutex   sync.RWMutex
}

func NewParserManager() *ParserManager {
	pm := &ParserManager{
		parsers: make([]DeviceParser, 0),
	}
	
	// Register all advanced parsers
	pm.RegisterParser(NewCiscoAdvancedParser())
	pm.RegisterParser(NewJuniperAdvancedParser())
	pm.RegisterParser(NewPaloAltoAdvancedParser())
	pm.RegisterParser(NewFortinetAdvancedParser())
	pm.RegisterParser(NewCheckPointParser())
	pm.RegisterParser(NewSonicWallParser())
	
	return pm
}

func (pm *ParserManager) RegisterParser(parser DeviceParser) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()
	pm.parsers = append(pm.parsers, parser)
}

func (pm *ParserManager) ParseMessage(message *SyslogMessage) error {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()
	
	for _, parser := range pm.parsers {
		if parser.CanParse(message) {
			err := parser.Parse(message)
			if err != nil {
				log.Printf("Parser error for %s: %v", parser.GetVendor(), err)
				continue
			}
			message.Vendor = parser.GetVendor()
			return nil
		}
	}
	
	return fmt.Errorf("no suitable parser found")
}

func (pm *ParserManager) GetSupportedVendors() []string {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()
	
	vendors := make([]string, 0, len(pm.parsers))
	for _, parser := range pm.parsers {
		vendors = append(vendors, parser.GetVendor())
	}
	
	return vendors
}
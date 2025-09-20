# Network Infrastructure Monitoring

This document describes the network infrastructure monitoring capabilities added to the MUSAFIR SecOps Agent for monitoring routers, firewalls, and other network devices.

## Overview

The network infrastructure monitoring system consists of four main components:

1. **SNMP Client Module** - For querying device statistics and configurations
2. **Network Scanner** - For discovering network infrastructure devices  
3. **Syslog Receiver** - For collecting logs from network devices
4. **Configuration Monitor** - For tracking changes to device configurations

## Components

### 1. SNMP Client Module (`snmp_client.go`)

The SNMP client provides comprehensive device monitoring capabilities:

#### Features
- Support for SNMP v1, v2c, and v3
- Device discovery and inventory management
- Real-time metrics collection
- Interface monitoring
- System information gathering
- Custom OID queries

#### Usage
```go
// Initialize SNMP client
snmpClient := NewSNMPClient()

// Add a device
device := &NetworkDevice{
    IP:          "192.168.1.1",
    Community:   "public",
    Version:     "2c",
    Port:        161,
    DeviceType:  "router",
    Vendor:      "Cisco",
    Hostname:    "core-router",
}

err := snmpClient.AddDevice(device)
if err != nil {
    log.Printf("Failed to add device: %v", err)
}

// Query device information
info, err := snmpClient.QueryDeviceInfo(device.IP)
if err != nil {
    log.Printf("Failed to query device: %v", err)
}
```

#### Supported OIDs
- System Information (sysDescr, sysUpTime, sysName, etc.)
- Interface Statistics (ifTable, ifXTable)
- IP Routing Table
- ARP Table
- TCP/UDP Connection Tables
- Custom vendor-specific OIDs

### 2. Network Scanner (`network_scanner.go`)

The network scanner discovers and identifies network infrastructure devices:

#### Features
- CIDR range scanning
- Port scanning and service detection
- SNMP-based device identification
- MAC address resolution
- OS fingerprinting
- Continuous monitoring

#### Usage
```go
// Initialize network scanner
scanner := NewNetworkScanner()

// Start scanning
err := scanner.Start()
if err != nil {
    log.Printf("Failed to start scanner: %v", err)
}

// Add network range to scan
err = scanner.AddScanRange("192.168.1.0/24")
if err != nil {
    log.Printf("Failed to add scan range: %v", err)
}
```

#### Discovery Methods
- **Ping Sweep** - ICMP echo requests to identify live hosts
- **Port Scanning** - TCP/UDP port probes for service identification
- **SNMP Discovery** - SNMP queries for device identification
- **ARP Table Analysis** - MAC address and vendor identification

### 3. Syslog Receiver (`syslog_receiver.go`)

The syslog receiver collects and parses logs from network devices:

#### Features
- UDP and TCP syslog reception
- Multi-vendor log parsing
- Real-time log processing
- Structured event generation
- Alert correlation

#### Usage
```go
// Initialize syslog receiver
receiver := NewSyslogReceiver()

// Configure listening ports
receiver.SetUDPPort(514)
receiver.SetTCPPort(514)

// Start receiving
err := receiver.Start()
if err != nil {
    log.Printf("Failed to start syslog receiver: %v", err)
}
```

#### Supported Vendors
- **Cisco** - IOS, NX-OS, ASA logs
- **Juniper** - JUNOS logs
- **Palo Alto Networks** - PAN-OS logs
- **Fortinet** - FortiOS logs
- **Generic** - Standard syslog format

### 4. Configuration Monitor (`config_monitor.go`)

The configuration monitor tracks changes to device configurations:

#### Features
- Multi-method configuration retrieval (SNMP, SSH, HTTP)
- Change detection and analysis
- Configuration versioning
- Vendor-specific parsing
- Security impact assessment

#### Usage
```go
// Initialize configuration monitor
snmpClient := NewSNMPClient()
configMonitor := NewConfigurationMonitor(snmpClient)

// Add device to monitor
device := &MonitoredDevice{
    IP:               "192.168.1.1",
    Hostname:         "core-router",
    DeviceType:       "router",
    Vendor:           "Cisco",
    SNMPCommunity:    "public",
    MonitoringMethod: "snmp",
    Enabled:          true,
}

err := configMonitor.AddDevice(device)
if err != nil {
    log.Printf("Failed to add device: %v", err)
}

// Start monitoring
err = configMonitor.Start()
if err != nil {
    log.Printf("Failed to start config monitor: %v", err)
}
```

#### Change Detection
- **Line-by-line comparison** for generic devices
- **Section-based analysis** for structured configurations
- **Semantic parsing** for vendor-specific formats
- **Impact assessment** based on change type and location

## Device-Specific Parsers (`device_parsers.go`)

Enhanced parsing capabilities for different network device vendors:

### Supported Vendors

#### Cisco
- IOS/IOS-XE command logs
- NX-OS system events
- ASA firewall logs
- Interface state changes
- Routing protocol events

#### Juniper
- JUNOS system logs
- Routing engine events
- Interface statistics
- Security policy logs
- Chassis alarms

#### Palo Alto Networks
- Traffic logs
- Threat logs
- System logs
- Configuration logs
- User activity logs

#### Fortinet
- Traffic logs
- Security events
- System logs
- VPN logs
- Web filter logs

#### Check Point
- Security logs
- System events
- VPN logs
- Policy logs
- Audit logs

#### SonicWall
- Security services logs
- Network access logs
- System events
- VPN logs
- Content filter logs

## Integration with Main Agent

The network infrastructure monitoring components are fully integrated with the main MUSAFIR agent:

### Initialization
```go
// Global variables in agent_windows.go
var (
    snmpClient           *SNMPClient
    networkScanner       *NetworkScanner
    syslogReceiver       *SyslogReceiver
    configurationMonitor *ConfigurationMonitor
)

// Initialization in initializeMonitoring()
snmpClient = NewSNMPClient()
networkScanner = NewNetworkScanner()
syslogReceiver = NewSyslogReceiver()
configurationMonitor = NewConfigurationMonitor(snmpClient)
```

### Event Generation
All components generate OCSF-compliant events that are forwarded to the gateway:

```go
envelope := Envelope{
    Ts:       time.Now().UTC().Format(time.RFC3339),
    TenantID: "t-aci",
    Asset: map[string]string{
        "id":   deviceIP,
        "type": "network_device",
        "name": hostname,
    },
    Event: map[string]interface{}{
        "class":    "network_activity",
        "name":     "device_discovered",
        "severity": 1,
        "attrs":    eventAttributes,
    },
    Ingest: map[string]string{
        "agent_version": "0.0.2",
        "schema":        "ocsf:1.2",
        "platform":      "network_monitor",
    },
}
```

## Configuration

### Environment Variables
- `GATEWAY_URL` - Gateway endpoint for event forwarding
- `SNMP_COMMUNITY` - Default SNMP community string
- `SYSLOG_UDP_PORT` - UDP port for syslog reception (default: 514)
- `SYSLOG_TCP_PORT` - TCP port for syslog reception (default: 514)
- `SCAN_INTERVAL` - Network scan interval in minutes (default: 60)
- `CONFIG_CHECK_INTERVAL` - Configuration check interval in minutes (default: 15)

### Device Configuration
Devices can be configured through:
1. **Automatic Discovery** - Network scanner finds devices automatically
2. **Manual Addition** - Devices added programmatically
3. **Configuration File** - JSON configuration file (future enhancement)

## Security Considerations

### SNMP Security
- Use SNMP v3 with authentication and encryption when possible
- Limit SNMP community strings to read-only access
- Implement IP-based access controls on devices
- Regularly rotate SNMP credentials

### Syslog Security
- Use TLS encryption for syslog transmission when supported
- Implement source IP validation
- Consider using certificate-based authentication
- Monitor for syslog injection attacks

### Network Scanning
- Limit scan frequency to avoid network congestion
- Use appropriate scan timing to minimize impact
- Implement rate limiting and backoff mechanisms
- Respect network policies and scan windows

## Performance Considerations

### Resource Usage
- **Memory**: ~50MB additional for all components
- **CPU**: <5% additional load during normal operation
- **Network**: Minimal bandwidth usage for monitoring traffic
- **Storage**: Configuration history and logs (configurable retention)

### Scalability
- Supports monitoring up to 1000 devices per agent
- Concurrent processing with configurable worker pools
- Efficient event batching and compression
- Automatic cleanup of old data

## Troubleshooting

### Common Issues

#### SNMP Connection Failures
```
Error: Failed to query device 192.168.1.1: timeout
```
**Solutions:**
- Verify SNMP is enabled on the device
- Check community string and version
- Verify network connectivity and firewall rules
- Increase timeout values for slow devices

#### Syslog Reception Issues
```
Error: Failed to bind to UDP port 514: permission denied
```
**Solutions:**
- Run agent with appropriate privileges
- Use alternative ports (>1024) if needed
- Check firewall rules and port availability
- Verify syslog forwarding configuration on devices

#### Configuration Retrieval Failures
```
Error: No available method to retrieve configuration
```
**Solutions:**
- Configure SNMP, SSH, or HTTP credentials
- Verify device supports configuration retrieval
- Check network connectivity and authentication
- Enable appropriate management protocols on device

### Logging and Debugging
Enable debug logging by setting log level:
```go
log.SetLevel(log.DebugLevel)
```

Monitor component status through agent logs:
```
2024-01-15 10:30:00 INFO Network scanner started successfully
2024-01-15 10:30:01 INFO Syslog receiver started successfully  
2024-01-15 10:30:02 INFO Configuration monitor started successfully
2024-01-15 10:30:03 INFO SNMP client initialized and ready for device queries
```

## Testing

### Integration Tests
Run the comprehensive integration test suite:
```go
// In network_integration_test.go
RunNetworkInfrastructureIntegrationTests()
```

### Performance Testing
Run benchmark tests:
```go
go test -bench=BenchmarkNetworkMonitoring
```

### Manual Testing
1. **SNMP Testing**: Use `snmpwalk` to verify device connectivity
2. **Syslog Testing**: Send test messages using `logger` command
3. **Network Scanning**: Use `nmap` to verify scan results
4. **Configuration Testing**: Compare retrieved configs manually

## Future Enhancements

### Planned Features
- **REST API** for device management
- **Web Dashboard** for monitoring status
- **Machine Learning** for anomaly detection
- **Integration** with external SIEM systems
- **Mobile App** for alerts and monitoring

### Vendor Support Expansion
- **Arista** EOS support
- **HPE/Aruba** networking devices
- **Extreme Networks** devices
- **Mikrotik** RouterOS support
- **pfSense/OPNsense** firewall support

## Support

For issues, questions, or feature requests related to network infrastructure monitoring:

1. Check the troubleshooting section above
2. Review agent logs for error messages
3. Verify device configuration and connectivity
4. Test individual components using integration tests
5. Contact the development team with detailed error information

## License

This network infrastructure monitoring system is part of the MUSAFIR SecOps platform and is subject to the same licensing terms as the main project.
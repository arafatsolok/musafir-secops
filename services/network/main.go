package main

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"os"
	"strings"
	"time"

	ch "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/segmentio/kafka-go"
)

type NetworkEvent struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	SourceIP    string                 `json:"source_ip"`
	DestIP      string                 `json:"dest_ip"`
	SourcePort  int                    `json:"source_port"`
	DestPort    int                    `json:"dest_port"`
	Protocol    string                 `json:"protocol"`
	PacketSize  int                    `json:"packet_size"`
	Flags       string                 `json:"flags"`
	Payload     []byte                 `json:"payload,omitempty"`
	Direction   string                 `json:"direction"` // ingress/egress
	Interface   string                 `json:"interface"`
	VLAN        int                    `json:"vlan"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type NetFlowEvent struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	SrcIP       string    `json:"src_ip"`
	DstIP       string    `json:"dst_ip"`
	SrcPort     int       `json:"src_port"`
	DstPort     int       `json:"dst_port"`
	Protocol    int       `json:"protocol"`
	Bytes       int64     `json:"bytes"`
	Packets     int64     `json:"packets"`
	Duration    int64     `json:"duration"`
	Flags       int       `json:"flags"`
	Interface   int       `json:"interface"`
	VLAN        int       `json:"vlan"`
	NextHop     string    `json:"next_hop"`
	EngineType  int       `json:"engine_type"`
	EngineID    int       `json:"engine_id"`
}

type SuricataEvent struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	EventType   string                 `json:"event_type"`
	SourceIP    string                 `json:"src_ip"`
	DestIP      string                 `json:"dest_ip"`
	SourcePort  int                    `json:"src_port"`
	DestPort    int                    `json:"dest_port"`
	Protocol    string                 `json:"proto"`
	Signature   string                 `json:"signature"`
	Category    string                 `json:"category"`
	Severity    int                    `json:"severity"`
	Action      string                 `json:"action"`
	FlowID      int64                  `json:"flow_id"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type NetworkMonitor struct {
	interfaces []string
	handles    []*pcap.Handle
	eventChan  chan NetworkEvent
	running    bool
}

func main() {
	kbrokers := os.Getenv("KAFKA_BROKERS")
	if kbrokers == "" { kbrokers = "localhost:9092" }
	group := os.Getenv("KAFKA_GROUP")
	if group == "" { group = "network" }

	chDsn := os.Getenv("CLICKHOUSE_DSN")
	if chDsn == "" { chDsn = "tcp://localhost:9000?database=default" }

	ctx := context.Background()
	conn, err := ch.Open(&ch.Options{Addr: []string{"localhost:9000"}})
	if err != nil { log.Fatalf("clickhouse connect: %v", err) }
	defer conn.Close()

	// Ensure network tables exist
	createNetworkTables(conn, ctx)

	writer := kafka.NewWriter(kafka.WriterConfig{
		Brokers: strings.Split(kbrokers, ","),
		Topic:   "musafir.network_events",
	})

	// Initialize network monitor
	monitor := NewNetworkMonitor()
	if err := monitor.Start(); err != nil {
		log.Fatalf("failed to start network monitor: %v", err)
	}
	defer monitor.Stop()

	log.Printf("network monitor starting brokers=%s", kbrokers)

	// Process network events
	go processNetworkEvents(monitor.GetEventChannel(), writer, ctx)

	// Simulate NetFlow events
	go simulateNetFlowEvents(writer, ctx)

	// Simulate Suricata events
	go simulateSuricataEvents(writer, ctx)

	// Keep running
	select {}
}

func createNetworkTables(conn ch.Conn, ctx context.Context) {
	// Network events table
	ddl := `CREATE TABLE IF NOT EXISTS musafir_network_events (
  id String,
  timestamp DateTime,
  source_ip String,
  dest_ip String,
  source_port Int32,
  dest_port Int32,
  protocol String,
  packet_size Int32,
  flags String,
  direction String,
  interface String,
  vlan Int32,
  metadata String
) ENGINE = MergeTree ORDER BY timestamp`
	
	if err := conn.Exec(ctx, ddl); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}

	// NetFlow events table
	ddl2 := `CREATE TABLE IF NOT EXISTS musafir_netflow_events (
  id String,
  timestamp DateTime,
  src_ip String,
  dst_ip String,
  src_port Int32,
  dst_port Int32,
  protocol Int32,
  bytes Int64,
  packets Int64,
  duration Int64,
  flags Int32,
  interface Int32,
  vlan Int32,
  next_hop String,
  engine_type Int32,
  engine_id Int32
) ENGINE = MergeTree ORDER BY timestamp`
	
	if err := conn.Exec(ctx, ddl2); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}

	// Suricata events table
	ddl3 := `CREATE TABLE IF NOT EXISTS musafir_suricata_events (
  id String,
  timestamp DateTime,
  event_type String,
  src_ip String,
  dest_ip String,
  src_port Int32,
  dest_port Int32,
  protocol String,
  signature String,
  category String,
  severity Int32,
  action String,
  flow_id Int64,
  metadata String
) ENGINE = MergeTree ORDER BY timestamp`
	
	if err := conn.Exec(ctx, ddl3); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}
}

func NewNetworkMonitor() *NetworkMonitor {
	return &NetworkMonitor{
		interfaces: []string{"eth0", "eth1", "wlan0"},
		eventChan:  make(chan NetworkEvent, 1000),
		running:    false,
	}
}

func (nm *NetworkMonitor) Start() error {
	nm.running = true

	// Try to open network interfaces
	for _, iface := range nm.interfaces {
		handle, err := pcap.OpenLive(iface, 1024, true, pcap.BlockForever)
		if err != nil {
			log.Printf("warning: failed to open interface %s: %v", iface, err)
			continue
		}
		nm.handles = append(nm.handles, handle)
	}

	if len(nm.handles) == 0 {
		log.Println("no network interfaces available, using simulation mode")
		go nm.simulateNetworkEvents()
		return nil
	}

	// Start packet capture on each interface
	for i, handle := range nm.handles {
		go nm.capturePackets(handle, nm.interfaces[i])
	}

	return nil
}

func (nm *NetworkMonitor) Stop() {
	nm.running = false
	for _, handle := range nm.handles {
		handle.Close()
	}
	close(nm.eventChan)
}

func (nm *NetworkMonitor) GetEventChannel() <-chan NetworkEvent {
	return nm.eventChan
}

func (nm *NetworkMonitor) capturePackets(handle *pcap.Handle, iface string) {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	
	for packet := range packetSource.Packets() {
		if !nm.running {
			break
		}

		event := nm.parsePacket(packet, iface)
		if event != nil {
			select {
			case nm.eventChan <- *event:
			default:
				log.Printf("network event channel full, dropping packet")
			}
		}
	}
}

func (nm *NetworkMonitor) parsePacket(packet gopacket.Packet, iface string) *NetworkEvent {
	// Parse network layers
	networkLayer := packet.NetworkLayer()
	if networkLayer == nil {
		return nil
	}

	transportLayer := packet.TransportLayer()
	if transportLayer == nil {
		return nil
	}

	// Extract IP information
	srcIP, dstIP := networkLayer.NetworkFlow().Endpoints()
	
	// Extract port information
	srcPort, dstPort := transportLayer.TransportFlow().Endpoints()

	// Determine protocol
	protocol := "unknown"
	switch transportLayer.LayerType() {
	case layers.LayerTypeTCP:
		protocol = "tcp"
	case layers.LayerTypeUDP:
		protocol = "udp"
	case layers.LayerTypeICMPv4:
		protocol = "icmp"
	}

	// Determine direction (simplified)
	direction := "egress"
	if strings.HasPrefix(srcIP.String(), "192.168.") || strings.HasPrefix(srcIP.String(), "10.") {
		direction = "ingress"
	}

	event := &NetworkEvent{
		ID:         generateNetworkEventID(),
		Timestamp:  packet.Metadata().Timestamp,
		SourceIP:   srcIP.String(),
		DestIP:     dstIP.String(),
		SourcePort: int(srcPort.Endpoint().(layers.TCPPort)),
		DestPort:   int(dstPort.Endpoint().(layers.TCPPort)),
		Protocol:   protocol,
		PacketSize: len(packet.Data()),
		Direction:  direction,
		Interface:  iface,
		Metadata: map[string]interface{}{
			"capture_length": packet.Metadata().CaptureLength,
			"length":         packet.Metadata().Length,
		},
	}

	// Extract flags for TCP
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		if tcp, ok := tcpLayer.(*layers.TCP); ok {
			event.Flags = tcpFlagsToString(tcp.Flags)
		}
	}

	return event
}

func (nm *NetworkMonitor) simulateNetworkEvents() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if !nm.running {
				return
			}

			// Generate simulated network events
			event := &NetworkEvent{
				ID:         generateNetworkEventID(),
				Timestamp:  time.Now(),
				SourceIP:   "192.168.1.100",
				DestIP:     "8.8.8.8",
				SourcePort: 12345,
				DestPort:   53,
				Protocol:   "udp",
				PacketSize: 64,
				Direction:  "egress",
				Interface:  "eth0",
				Metadata: map[string]interface{}{
					"simulated": true,
				},
			}

			select {
			case nm.eventChan <- *event:
			default:
			}
		}
	}
}

func processNetworkEvents(eventChan <-chan NetworkEvent, writer *kafka.Writer, ctx context.Context) {
	for event := range eventChan {
		eventData, _ := json.Marshal(event)
		if err := writer.WriteMessages(ctx, kafka.Message{Value: eventData}); err != nil {
			log.Printf("write network event: %v", err)
		} else {
			log.Printf("NETWORK EVENT: %s -> %s:%d (%s)", event.SourceIP, event.DestIP, event.DestPort, event.Protocol)
		}
	}
}

func simulateNetFlowEvents(writer *kafka.Writer, ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			event := NetFlowEvent{
				ID:         generateNetworkEventID(),
				Timestamp:  time.Now(),
				SrcIP:      "192.168.1.100",
				DstIP:      "10.0.0.1",
				SrcPort:    80,
				DstPort:    8080,
				Protocol:   6, // TCP
				Bytes:      1024,
				Packets:    10,
				Duration:   5000,
				Flags:      2,
				Interface:  1,
				VLAN:       0,
				NextHop:    "192.168.1.1",
				EngineType: 0,
				EngineID:   1,
			}

			eventData, _ := json.Marshal(event)
			if err := writer.WriteMessages(ctx, kafka.Message{Value: eventData}); err != nil {
				log.Printf("write netflow event: %v", err)
			} else {
				log.Printf("NETFLOW EVENT: %s -> %s (%d bytes)", event.SrcIP, event.DstIP, event.Bytes)
			}
		}
	}
}

func simulateSuricataEvents(writer *kafka.Writer, ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	signatures := []string{
		"ET MALWARE Suspicious DNS Query",
		"ET TROJAN Possible C2 Communication",
		"ET POLICY Suspicious User Agent",
		"ET SCAN Potential Port Scan",
		"ET INFO Suspicious File Download",
	}

	for {
		select {
		case <-ticker.C:
			event := SuricataEvent{
				ID:         generateNetworkEventID(),
				Timestamp:  time.Now(),
				EventType:  "alert",
				SourceIP:   "192.168.1.50",
				DestIP:     "203.0.113.1",
				SourcePort: 12345,
				DestPort:   80,
				Protocol:   "tcp",
				Signature:  signatures[time.Now().Second()%len(signatures)],
				Category:   "malware",
				Severity:   2,
				Action:     "alert",
				FlowID:     int64(time.Now().Unix()),
				Metadata: map[string]interface{}{
					"simulated": true,
				},
			}

			eventData, _ := json.Marshal(event)
			if err := writer.WriteMessages(ctx, kafka.Message{Value: eventData}); err != nil {
				log.Printf("write suricata event: %v", err)
			} else {
				log.Printf("SURICATA EVENT: %s - %s", event.Signature, event.SourceIP)
			}
		}
	}
}

func generateNetworkEventID() string {
	return "net-" + time.Now().Format("20060102150405")
}

func tcpFlagsToString(flags layers.TCPFlags) string {
	var flagStrs []string
	if flags.FIN() { flagStrs = append(flagStrs, "FIN") }
	if flags.SYN() { flagStrs = append(flagStrs, "SYN") }
	if flags.RST() { flagStrs = append(flagStrs, "RST") }
	if flags.PSH() { flagStrs = append(flagStrs, "PSH") }
	if flags.ACK() { flagStrs = append(flagStrs, "ACK") }
	if flags.URG() { flagStrs = append(flagStrs, "URG") }
	if flags.ECE() { flagStrs = append(flagStrs, "ECE") }
	if flags.CWR() { flagStrs = append(flagStrs, "CWR") }
	if flags.NS() { flagStrs = append(flagStrs, "NS") }
	
	if len(flagStrs) == 0 {
		return "none"
	}
	return strings.Join(flagStrs, ",")
}

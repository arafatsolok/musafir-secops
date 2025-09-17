package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"strings"
	"time"

	ch "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/segmentio/kafka-go"
)

type NetworkEvent struct {
	ID         string                 `json:"id"`
	Timestamp  time.Time              `json:"timestamp"`
	SourceIP   string                 `json:"source_ip"`
	DestIP     string                 `json:"dest_ip"`
	SourcePort int                    `json:"source_port"`
	DestPort   int                    `json:"dest_port"`
	Protocol   string                 `json:"protocol"`
	Bytes      int64                  `json:"bytes"`
	Packets    int64                  `json:"packets"`
	Duration   float64                `json:"duration"`
	Flags      string                 `json:"flags"`
	Payload    string                 `json:"payload"`
	Metadata   map[string]interface{} `json:"metadata"`
}

type NetworkAlert struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	AlertType   string                 `json:"alert_type"`
	Severity    string                 `json:"severity"`
	SourceIP    string                 `json:"source_ip"`
	DestIP      string                 `json:"dest_ip"`
	Port        int                    `json:"port"`
	Protocol    string                 `json:"protocol"`
	Description string                 `json:"description"`
	IOCs        []string               `json:"iocs"`
	TTPs        []string               `json:"ttps"`
	Confidence  float64                `json:"confidence"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type NetworkSensor struct {
	ID        string                 `json:"id"`
	Name      string                 `json:"name"`
	Type      string                 `json:"type"` // span, tap, mirror
	Location  string                 `json:"location"`
	Interface string                 `json:"interface"`
	Status    string                 `json:"status"`
	LastSeen  time.Time              `json:"last_seen"`
	Config    map[string]interface{} `json:"config"`
}

type NetworkFlow struct {
	ID         string                 `json:"id"`
	Timestamp  time.Time              `json:"timestamp"`
	SourceIP   string                 `json:"source_ip"`
	DestIP     string                 `json:"dest_ip"`
	SourcePort int                    `json:"source_port"`
	DestPort   int                    `json:"dest_port"`
	Protocol   string                 `json:"protocol"`
	Bytes      int64                  `json:"bytes"`
	Packets    int64                  `json:"packets"`
	Duration   float64                `json:"duration"`
	Flags      string                 `json:"flags"`
	State      string                 `json:"state"`
	Metadata   map[string]interface{} `json:"metadata"`
}

func main() {
	kbrokers := os.Getenv("KAFKA_BROKERS")
	if kbrokers == "" {
		kbrokers = "localhost:9092"
	}
	group := os.Getenv("KAFKA_GROUP")
	if group == "" {
		group = "network"
	}

	chDsn := os.Getenv("CLICKHOUSE_DSN")
	if chDsn == "" {
		chDsn = "tcp://localhost:9000?database=default"
	}

	ctx := context.Background()
	conn, err := ch.Open(&ch.Options{Addr: []string{"localhost:9000"}})
	if err != nil {
		log.Fatalf("clickhouse connect: %v", err)
	}
	defer conn.Close()

	// Ensure network tables exist
	createNetworkTables(conn, ctx)

	// Event reader
	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:  strings.Split(kbrokers, ","),
		Topic:    "musafir.events",
		GroupID:  group,
		MinBytes: 1, MaxBytes: 10e6,
	})
	defer reader.Close()

	// Alert writer
	writer := kafka.NewWriter(kafka.WriterConfig{
		Brokers: strings.Split(kbrokers, ","),
		Topic:   "musafir.network_alerts",
	})

	// Initialize network sensors
	sensors := initializeNetworkSensors()

	log.Printf("Network service consuming events brokers=%s", kbrokers)
	for {
		m, err := reader.ReadMessage(ctx)
		if err != nil {
			log.Fatalf("kafka read: %v", err)
		}

		var event map[string]interface{}
		if err := json.Unmarshal(m.Value, &event); err != nil {
			log.Printf("unmarshal event: %v", err)
			continue
		}

		// Process network event
		processNetworkEvent(event, writer, ctx)

		// Monitor network sensors
		go monitorNetworkSensors(sensors, writer, ctx)
	}
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
  bytes Int64,
  packets Int64,
  duration Float64,
  flags String,
  payload String,
  metadata String
) ENGINE = MergeTree ORDER BY timestamp`

	if err := conn.Exec(ctx, ddl); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}

	// Network alerts table
	ddl2 := `CREATE TABLE IF NOT EXISTS musafir_network_alerts (
  id String,
  timestamp DateTime,
  alert_type String,
  severity String,
  source_ip String,
  dest_ip String,
  port Int32,
  protocol String,
  description String,
  iocs Array(String),
  ttps Array(String),
  confidence Float64,
  metadata String
) ENGINE = MergeTree ORDER BY timestamp`

	if err := conn.Exec(ctx, ddl2); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}

	// Network flows table
	ddl3 := `CREATE TABLE IF NOT EXISTS musafir_network_flows (
  id String,
  timestamp DateTime,
  source_ip String,
  dest_ip String,
  source_port Int32,
  dest_port Int32,
  protocol String,
  bytes Int64,
  packets Int64,
  duration Float64,
  flags String,
  state String,
  metadata String
) ENGINE = MergeTree ORDER BY timestamp`

	if err := conn.Exec(ctx, ddl3); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}

	// Network sensors table
	ddl4 := `CREATE TABLE IF NOT EXISTS musafir_network_sensors (
  id String,
  name String,
  type String,
  location String,
  interface String,
  status String,
  last_seen DateTime,
  config String
) ENGINE = MergeTree ORDER BY last_seen`

	if err := conn.Exec(ctx, ddl4); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}
}

func processNetworkEvent(event map[string]interface{}, writer *kafka.Writer, ctx context.Context) {
	// Extract network data from event
	networkEvent := extractNetworkData(event)

	// Store network event
	storeNetworkEvent(networkEvent)

	// Analyze for network threats
	alerts := analyzeNetworkThreats(networkEvent)

	// Send alerts
	for _, alert := range alerts {
		alertData, _ := json.Marshal(alert)
		if err := writer.WriteMessages(ctx, kafka.Message{Value: alertData}); err != nil {
			log.Printf("write network alert: %v", err)
		} else {
			log.Printf("NETWORK ALERT: %s - %s (%s)", alert.AlertType, alert.SourceIP, alert.Severity)
		}
	}
}

func extractNetworkData(event map[string]interface{}) NetworkEvent {
	networkEvent := NetworkEvent{
		ID:        generateNetworkEventID(),
		Timestamp: time.Now(),
		Metadata:  make(map[string]interface{}),
	}

	// Extract network data from event
	if eventData, ok := event["event"].(map[string]interface{}); ok {
		if attrs, ok := eventData["attrs"].(map[string]interface{}); ok {
			networkEvent.SourceIP = getString(attrs, "src_ip")
			networkEvent.DestIP = getString(attrs, "dest_ip")
			networkEvent.SourcePort = getInt(attrs, "src_port")
			networkEvent.DestPort = getInt(attrs, "dest_port")
			networkEvent.Protocol = getString(attrs, "protocol")
			networkEvent.Bytes = getInt64(attrs, "bytes")
			networkEvent.Packets = getInt64(attrs, "packets")
			networkEvent.Duration = getFloat64(attrs, "duration")
			networkEvent.Flags = getString(attrs, "flags")
			networkEvent.Payload = getString(attrs, "payload")
		}
	}

	return networkEvent
}

func analyzeNetworkThreats(event NetworkEvent) []NetworkAlert {
	var alerts []NetworkAlert

	// Check for suspicious ports
	if isSuspiciousPort(event.DestPort) {
		alert := NetworkAlert{
			ID:          generateNetworkAlertID(),
			Timestamp:   time.Now(),
			AlertType:   "suspicious_port",
			Severity:    "medium",
			SourceIP:    event.SourceIP,
			DestIP:      event.DestIP,
			Port:        event.DestPort,
			Protocol:    event.Protocol,
			Description: "Connection to suspicious port detected",
			IOCs:        []string{event.DestIP, event.Protocol},
			TTPs:        []string{"T1043", "T1044"},
			Confidence:  0.7,
			Metadata: map[string]interface{}{
				"port":     event.DestPort,
				"protocol": event.Protocol,
			},
		}
		alerts = append(alerts, alert)
	}

	// Check for data exfiltration
	if isDataExfiltration(event) {
		alert := NetworkAlert{
			ID:          generateNetworkAlertID(),
			Timestamp:   time.Now(),
			AlertType:   "data_exfiltration",
			Severity:    "high",
			SourceIP:    event.SourceIP,
			DestIP:      event.DestIP,
			Port:        event.DestPort,
			Protocol:    event.Protocol,
			Description: "Potential data exfiltration detected",
			IOCs:        []string{event.DestIP, event.Protocol},
			TTPs:        []string{"T1041", "T1048"},
			Confidence:  0.8,
			Metadata: map[string]interface{}{
				"bytes":    event.Bytes,
				"duration": event.Duration,
			},
		}
		alerts = append(alerts, alert)
	}

	// Check for lateral movement
	if isLateralMovement(event) {
		alert := NetworkAlert{
			ID:          generateNetworkAlertID(),
			Timestamp:   time.Now(),
			AlertType:   "lateral_movement",
			Severity:    "high",
			SourceIP:    event.SourceIP,
			DestIP:      event.DestIP,
			Port:        event.DestPort,
			Protocol:    event.Protocol,
			Description: "Potential lateral movement detected",
			IOCs:        []string{event.DestIP, event.Protocol},
			TTPs:        []string{"T1021", "T1071"},
			Confidence:  0.75,
			Metadata: map[string]interface{}{
				"port":     event.DestPort,
				"protocol": event.Protocol,
			},
		}
		alerts = append(alerts, alert)
	}

	return alerts
}

func isSuspiciousPort(port int) bool {
	suspiciousPorts := []int{22, 23, 135, 139, 445, 1433, 3389, 5985, 5986}
	for _, p := range suspiciousPorts {
		if port == p {
			return true
		}
	}
	return false
}

func isDataExfiltration(event NetworkEvent) bool {
	// Check for large data transfers to external IPs
	return event.Bytes > 100*1024*1024 && isExternalIP(event.DestIP)
}

func isLateralMovement(event NetworkEvent) bool {
	// Check for connections to internal IPs on admin ports
	adminPorts := []int{22, 3389, 5985, 5986}
	for _, port := range adminPorts {
		if event.DestPort == port && isInternalIP(event.DestIP) {
			return true
		}
	}
	return false
}

func isExternalIP(ip string) bool {
	// Simple check for external IPs (not RFC 1918)
	return !strings.HasPrefix(ip, "10.") &&
		!strings.HasPrefix(ip, "192.168.") &&
		!strings.HasPrefix(ip, "172.")
}

func isInternalIP(ip string) bool {
	// Check for internal IPs (RFC 1918)
	return strings.HasPrefix(ip, "10.") ||
		strings.HasPrefix(ip, "192.168.") ||
		strings.HasPrefix(ip, "172.")
}

func initializeNetworkSensors() []NetworkSensor {
	return []NetworkSensor{
		{
			ID:        "sensor-001",
			Name:      "Core Switch SPAN",
			Type:      "span",
			Location:  "datacenter-1",
			Interface: "eth0",
			Status:    "active",
			LastSeen:  time.Now(),
			Config: map[string]interface{}{
				"mirror_ports": []string{"1/0/1", "1/0/2"},
				"vlan_filter":  []string{"10", "20", "30"},
			},
		},
		{
			ID:        "sensor-002",
			Name:      "DMZ TAP",
			Type:      "tap",
			Location:  "dmz-1",
			Interface: "eth1",
			Status:    "active",
			LastSeen:  time.Now(),
			Config: map[string]interface{}{
				"tap_type": "network",
				"speed":    "1G",
			},
		},
		{
			ID:        "sensor-003",
			Name:      "Internet Gateway Mirror",
			Type:      "mirror",
			Location:  "internet-gateway",
			Interface: "eth2",
			Status:    "active",
			LastSeen:  time.Now(),
			Config: map[string]interface{}{
				"mirror_direction": "both",
				"filter_rules":     []string{"tcp", "udp"},
			},
		},
	}
}

func monitorNetworkSensors(sensors []NetworkSensor, writer *kafka.Writer, ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			for _, sensor := range sensors {
				// Check sensor health
				if time.Since(sensor.LastSeen) > 5*time.Minute {
					// Sensor is down
					alert := NetworkAlert{
						ID:          generateNetworkAlertID(),
						Timestamp:   time.Now(),
						AlertType:   "sensor_down",
						Severity:    "high",
						SourceIP:    "",
						DestIP:      "",
						Port:        0,
						Protocol:    "",
						Description: "Network sensor is down",
						IOCs:        []string{sensor.ID},
						TTPs:        []string{},
						Confidence:  1.0,
						Metadata: map[string]interface{}{
							"sensor_id":   sensor.ID,
							"sensor_name": sensor.Name,
							"last_seen":   sensor.LastSeen,
						},
					}

					alertData, _ := json.Marshal(alert)
					if err := writer.WriteMessages(ctx, kafka.Message{Value: alertData}); err != nil {
						log.Printf("write sensor alert: %v", err)
					}
				}
			}
		}
	}
}

func storeNetworkEvent(event NetworkEvent) {
	// Store network event in ClickHouse
	// Implementation would store the event in the database
}

// Helper functions
func generateNetworkEventID() string {
	return "net-" + time.Now().Format("20060102150405")
}

func generateNetworkAlertID() string {
	return "net-alert-" + time.Now().Format("20060102150405")
}

func getString(data map[string]interface{}, key string) string {
	if val, ok := data[key].(string); ok {
		return val
	}
	return ""
}

func getInt(data map[string]interface{}, key string) int {
	if val, ok := data[key].(float64); ok {
		return int(val)
	}
	return 0
}

func getInt64(data map[string]interface{}, key string) int64 {
	if val, ok := data[key].(float64); ok {
		return int64(val)
	}
	return 0
}

func getFloat64(data map[string]interface{}, key string) float64 {
	if val, ok := data[key].(float64); ok {
		return val
	}
	return 0.0
}

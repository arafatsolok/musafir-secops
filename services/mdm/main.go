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

type MDMCommand struct {
	ID          string            `json:"id"`
	Type        string            `json:"type"`
	DeviceID    string            `json:"device_id"`
	UserID      string            `json:"user_id"`
	Command     string            `json:"command"`
	Parameters  map[string]string `json:"parameters"`
	Priority    int               `json:"priority"`
	CreatedAt   time.Time         `json:"created_at"`
	ExpiresAt   time.Time         `json:"expires_at"`
	Status      string            `json:"status"`
}

type MDMResponse struct {
	ID          string            `json:"id"`
	CommandID   string            `json:"command_id"`
	DeviceID    string            `json:"device_id"`
	UserID      string            `json:"user_id"`
	Status      string            `json:"status"` // success, failed, timeout
	Result      string            `json:"result"`
	Error       string            `json:"error,omitempty"`
	Timestamp   time.Time         `json:"timestamp"`
	Metadata    map[string]string `json:"metadata"`
}

type DeviceInfo struct {
	DeviceID    string            `json:"device_id"`
	UserID      string            `json:"user_id"`
	DeviceType  string            `json:"device_type"` // windows, macos, ios, android
	OSVersion   string            `json:"os_version"`
	Model       string            `json:"model"`
	Serial      string            `json:"serial"`
	LastSeen    time.Time         `json:"last_seen"`
	Status      string            `json:"status"` // online, offline, compromised
	Compliance  string            `json:"compliance"` // compliant, non_compliant, unknown
	Properties  map[string]string `json:"properties"`
}

func main() {
	kbrokers := os.Getenv("KAFKA_BROKERS")
	if kbrokers == "" { kbrokers = "localhost:9092" }
	group := os.Getenv("KAFKA_GROUP")
	if group == "" { group = "mdm" }

	chDsn := os.Getenv("CLICKHOUSE_DSN")
	if chDsn == "" { chDsn = "tcp://localhost:9000?database=default" }

	ctx := context.Background()
	conn, err := ch.Open(&ch.Options{Addr: []string{"localhost:9000"}})
	if err != nil { log.Fatalf("clickhouse connect: %v", err) }
	defer conn.Close()

	// Ensure MDM tables exist
	createMDMTables(conn, ctx)

	// Command reader
	cmdReader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:  strings.Split(kbrokers, ","),
		Topic:    "musafir.mdm_commands",
		GroupID:  group + "_commands",
		MinBytes: 1, MaxBytes: 10e6,
	})
	defer cmdReader.Close()

	// Response writer
	responseWriter := kafka.NewWriter(kafka.WriterConfig{
		Brokers: strings.Split(kbrokers, ","),
		Topic:   "musafir.mdm_responses",
	})

	// Device status writer
	deviceWriter := kafka.NewWriter(kafka.WriterConfig{
		Brokers: strings.Split(kbrokers, ","),
		Topic:   "musafir.device_status",
	})

	log.Printf("MDM service consuming commands brokers=%s", kbrokers)
	for {
		m, err := cmdReader.ReadMessage(ctx)
		if err != nil { log.Fatalf("kafka read: %v", err) }

		var command MDMCommand
		if err := json.Unmarshal(m.Value, &command); err != nil {
			log.Printf("unmarshal MDM command: %v", err)
			continue
		}

		// Process MDM command
		response := processMDMCommand(command)

		// Send response
		responseData, _ := json.Marshal(response)
		if err := responseWriter.WriteMessages(ctx, kafka.Message{Value: responseData}); err != nil {
			log.Printf("write MDM response: %v", err)
		} else {
			log.Printf("MDM RESPONSE: %s - %s", command.ID, response.Status)
		}

		// Update device status
		deviceInfo := updateDeviceStatus(command, response)
		deviceData, _ := json.Marshal(deviceInfo)
		if err := deviceWriter.WriteMessages(ctx, kafka.Message{Value: deviceData}); err != nil {
			log.Printf("write device status: %v", err)
		}
	}
}

func createMDMTables(conn ch.Conn, ctx context.Context) {
	// MDM commands table
	ddl := `CREATE TABLE IF NOT EXISTS musafir_mdm_commands (
  id String,
  type String,
  device_id String,
  user_id String,
  command String,
  parameters String,
  priority Int32,
  created_at DateTime,
  expires_at DateTime,
  status String
) ENGINE = MergeTree ORDER BY created_at`
	
	if err := conn.Exec(ctx, ddl); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}

	// MDM responses table
	ddl2 := `CREATE TABLE IF NOT EXISTS musafir_mdm_responses (
  id String,
  command_id String,
  device_id String,
  user_id String,
  status String,
  result String,
  error String,
  timestamp DateTime,
  metadata String
) ENGINE = MergeTree ORDER BY timestamp`
	
	if err := conn.Exec(ctx, ddl2); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}

	// Device info table
	ddl3 := `CREATE TABLE IF NOT EXISTS musafir_device_info (
  device_id String,
  user_id String,
  device_type String,
  os_version String,
  model String,
  serial String,
  last_seen DateTime,
  status String,
  compliance String,
  properties String
) ENGINE = MergeTree ORDER BY device_id`
	
	if err := conn.Exec(ctx, ddl3); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}
}

func processMDMCommand(command MDMCommand) MDMResponse {
	// Simulate MDM command processing
	response := MDMResponse{
		ID:        generateResponseID(),
		CommandID: command.ID,
		DeviceID:  command.DeviceID,
		UserID:    command.UserID,
		Timestamp: time.Now(),
		Metadata:  make(map[string]string),
	}

	switch command.Command {
	case "isolate_device":
		response.Status = "success"
		response.Result = "Device isolated successfully"
		response.Metadata["action"] = "network_isolation"
		response.Metadata["duration"] = command.Parameters["duration"]

	case "wipe_device":
		response.Status = "success"
		response.Result = "Device wipe initiated"
		response.Metadata["action"] = "device_wipe"
		response.Metadata["preserve_corporate_data"] = command.Parameters["preserve_corporate_data"]

	case "install_app":
		response.Status = "success"
		response.Result = "App installation initiated"
		response.Metadata["action"] = "app_install"
		response.Metadata["app_id"] = command.Parameters["app_id"]

	case "update_policy":
		response.Status = "success"
		response.Result = "Policy updated successfully"
		response.Metadata["action"] = "policy_update"
		response.Metadata["policy_version"] = command.Parameters["policy_version"]

	case "check_compliance":
		response.Status = "success"
		response.Result = "Compliance check completed"
		response.Metadata["action"] = "compliance_check"
		response.Metadata["compliance_status"] = "compliant"

	case "enable_camera":
		response.Status = "success"
		response.Result = "Camera access enabled"
		response.Metadata["action"] = "camera_enable"

	case "disable_camera":
		response.Status = "success"
		response.Result = "Camera access disabled"
		response.Metadata["action"] = "camera_disable"

	case "lock_device":
		response.Status = "success"
		response.Result = "Device locked successfully"
		response.Metadata["action"] = "device_lock"

	case "unlock_device":
		response.Status = "success"
		response.Result = "Device unlocked successfully"
		response.Metadata["action"] = "device_unlock"

	default:
		response.Status = "failed"
		response.Error = "Unknown command: " + command.Command
	}

	return response
}

func updateDeviceStatus(command MDMCommand, response MDMResponse) DeviceInfo {
	// Simulate device status update
	deviceInfo := DeviceInfo{
		DeviceID:   command.DeviceID,
		UserID:     command.UserID,
		DeviceType: "windows", // Would be determined from device registration
		OSVersion:  "Windows 11",
		Model:      "Surface Pro",
		Serial:     "SURFACE123456",
		LastSeen:   time.Now(),
		Status:     "online",
		Compliance: "compliant",
		Properties: make(map[string]string),
	}

	// Update status based on command result
	if response.Status == "success" {
		switch command.Command {
		case "isolate_device":
			deviceInfo.Status = "isolated"
			deviceInfo.Properties["isolation_status"] = "isolated"
		case "wipe_device":
			deviceInfo.Status = "wiping"
			deviceInfo.Properties["wipe_status"] = "in_progress"
		case "lock_device":
			deviceInfo.Properties["lock_status"] = "locked"
		case "unlock_device":
			deviceInfo.Properties["lock_status"] = "unlocked"
		}
	} else {
		deviceInfo.Status = "error"
		deviceInfo.Properties["last_error"] = response.Error
	}

	return deviceInfo
}

func generateResponseID() string {
	return "mdm-resp-" + time.Now().Format("20060102150405")
}

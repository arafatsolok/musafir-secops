package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	ch "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/segmentio/kafka-go"
)

type DeceptionService struct {
	honeypots    map[string]*Honeypot
	canaryTokens map[string]*CanaryToken
	ctx          context.Context
	conn         ch.Conn
	writer       *kafka.Writer
}

type Honeypot struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Type         string                 `json:"type"` // http, ssh, ftp, smb, rdp, database
	Port         int                    `json:"port"`
	IP           string                 `json:"ip"`
	Status       string                 `json:"status"` // active, inactive, triggered
	Config       map[string]interface{} `json:"config"`
	CreatedAt    time.Time              `json:"created_at"`
	LastTrigger  time.Time              `json:"last_trigger"`
	TriggerCount int64                  `json:"trigger_count"`
	Logs         []HoneypotLog          `json:"logs"`
}

type CanaryToken struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Type         string                 `json:"type"` // file, url, email, database, api
	Token        string                 `json:"token"`
	Location     string                 `json:"location"`
	Status       string                 `json:"status"` // active, inactive, triggered
	Config       map[string]interface{} `json:"config"`
	CreatedAt    time.Time              `json:"created_at"`
	LastTrigger  time.Time              `json:"last_trigger"`
	TriggerCount int64                  `json:"trigger_count"`
	Logs         []CanaryLog            `json:"logs"`
}

type HoneypotLog struct {
	ID         string                 `json:"id"`
	HoneypotID string                 `json:"honeypot_id"`
	Timestamp  time.Time              `json:"timestamp"`
	SourceIP   string                 `json:"source_ip"`
	UserAgent  string                 `json:"user_agent"`
	Action     string                 `json:"action"`
	Details    map[string]interface{} `json:"details"`
	RiskScore  float64                `json:"risk_score"`
}

type CanaryLog struct {
	ID        string                 `json:"id"`
	CanaryID  string                 `json:"canary_id"`
	Timestamp time.Time              `json:"timestamp"`
	SourceIP  string                 `json:"source_ip"`
	UserAgent string                 `json:"user_agent"`
	Action    string                 `json:"action"`
	Details   map[string]interface{} `json:"details"`
	RiskScore float64                `json:"risk_score"`
	Location  string                 `json:"location"`
}

type DeceptionAlert struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"` // honeypot_trigger, canary_trigger, suspicious_activity
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Severity    string                 `json:"severity"`
	Source      string                 `json:"source"`
	Target      string                 `json:"target"`
	Timestamp   time.Time              `json:"timestamp"`
	RiskScore   float64                `json:"risk_score"`
	Metadata    map[string]interface{} `json:"metadata"`
	Status      string                 `json:"status"`
}

type DeceptionConfig struct {
	Honeypots    []HoneypotConfig    `json:"honeypots"`
	CanaryTokens []CanaryTokenConfig `json:"canary_tokens"`
	Alerting     AlertingConfig      `json:"alerting"`
}

type HoneypotConfig struct {
	Type     string                 `json:"type"`
	Port     int                    `json:"port"`
	IP       string                 `json:"ip"`
	Services []string               `json:"services"`
	Config   map[string]interface{} `json:"config"`
}

type CanaryTokenConfig struct {
	Type     string                 `json:"type"`
	Location string                 `json:"location"`
	Config   map[string]interface{} `json:"config"`
}

type AlertingConfig struct {
	Enabled    bool               `json:"enabled"`
	Channels   []string           `json:"channels"`
	Thresholds map[string]float64 `json:"thresholds"`
	Recipients []string           `json:"recipients"`
}

func NewDeceptionService() *DeceptionService {
	chDsn := os.Getenv("CLICKHOUSE_DSN")
	if chDsn == "" {
		chDsn = "tcp://localhost:9000?database=default"
	}

	conn, err := ch.Open(&ch.Options{Addr: []string{"localhost:9000"}})
	if err != nil {
		log.Fatalf("clickhouse connect: %v", err)
	}

	kbrokers := os.Getenv("KAFKA_BROKERS")
	if kbrokers == "" {
		kbrokers = "localhost:9092"
	}

	writer := kafka.NewWriter(kafka.WriterConfig{
		Brokers: strings.Split(kbrokers, ","),
		Topic:   "musafir.deception_alerts",
	})

	return &DeceptionService{
		honeypots:    make(map[string]*Honeypot),
		canaryTokens: make(map[string]*CanaryToken),
		ctx:          context.Background(),
		conn:         conn,
		writer:       writer,
	}
}

func (d *DeceptionService) Initialize() {
	// Create deception tables
	d.createDeceptionTables()

	// Load existing honeypots and canary tokens
	d.loadExistingDeceptions()

	// Start honeypot servers
	d.startHoneypotServers()

	// Start canary token monitoring
	d.startCanaryTokenMonitoring()

	log.Println("Deception service initialized successfully")
}

func (d *DeceptionService) createDeceptionTables() {
	// Create honeypot logs table
	honeypotTable := `
		CREATE TABLE IF NOT EXISTS musafir_honeypot_logs (
			id String,
			honeypot_id String,
			timestamp DateTime,
			source_ip String,
			user_agent String,
			action String,
			details String,
			risk_score Float64,
			created_at DateTime DEFAULT now()
		) ENGINE = MergeTree()
		ORDER BY (timestamp, honeypot_id)
	`

	if err := d.conn.Exec(d.ctx, honeypotTable); err != nil {
		log.Printf("Error creating honeypot logs table: %v", err)
	}

	// Create canary token logs table
	canaryTable := `
		CREATE TABLE IF NOT EXISTS musafir_canary_logs (
			id String,
			canary_id String,
			timestamp DateTime,
			source_ip String,
			user_agent String,
			action String,
			details String,
			risk_score Float64,
			location String,
			created_at DateTime DEFAULT now()
		) ENGINE = MergeTree()
		ORDER BY (timestamp, canary_id)
	`

	if err := d.conn.Exec(d.ctx, canaryTable); err != nil {
		log.Printf("Error creating canary logs table: %v", err)
	}

	// Create deception alerts table
	alertsTable := `
		CREATE TABLE IF NOT EXISTS musafir_deception_alerts (
			id String,
			type String,
			title String,
			description String,
			severity String,
			source String,
			target String,
			timestamp DateTime,
			risk_score Float64,
			metadata String,
			status String,
			created_at DateTime DEFAULT now()
		) ENGINE = MergeTree()
		ORDER BY (timestamp, type)
	`

	if err := d.conn.Exec(d.ctx, alertsTable); err != nil {
		log.Printf("Error creating deception alerts table: %v", err)
	}
}

func (d *DeceptionService) loadExistingDeceptions() {
	// Load honeypots from configuration
	honeypotConfigs := []HoneypotConfig{
		{
			Type:     "http",
			Port:     8080,
			IP:       "0.0.0.0",
			Services: []string{"web", "api"},
			Config: map[string]interface{}{
				"fake_content": true,
				"fake_forms":   true,
				"fake_login":   true,
			},
		},
		{
			Type:     "ssh",
			Port:     2222,
			IP:       "0.0.0.0",
			Services: []string{"ssh"},
			Config: map[string]interface{}{
				"fake_banner": "OpenSSH_8.2p1 Ubuntu-4ubuntu0.2",
				"fake_users":  []string{"admin", "root", "user"},
			},
		},
		{
			Type:     "ftp",
			Port:     2121,
			IP:       "0.0.0.0",
			Services: []string{"ftp"},
			Config: map[string]interface{}{
				"fake_files": []string{"confidential.txt", "passwords.txt", "backup.zip"},
			},
		},
		{
			Type:     "smb",
			Port:     445,
			IP:       "0.0.0.0",
			Services: []string{"smb"},
			Config: map[string]interface{}{
				"fake_shares": []string{"Documents", "Backup", "Confidential"},
			},
		},
		{
			Type:     "database",
			Port:     3306,
			IP:       "0.0.0.0",
			Services: []string{"mysql"},
			Config: map[string]interface{}{
				"fake_databases": []string{"users", "passwords", "financial"},
			},
		},
	}

	for _, config := range honeypotConfigs {
		honeypot := &Honeypot{
			ID:           generateHoneypotID(),
			Name:         config.Type + "_honeypot",
			Type:         config.Type,
			Port:         config.Port,
			IP:           config.IP,
			Status:       "active",
			Config:       config.Config,
			CreatedAt:    time.Now(),
			TriggerCount: 0,
			Logs:         []HoneypotLog{},
		}
		d.honeypots[honeypot.ID] = honeypot
	}

	// Load canary tokens from configuration
	canaryConfigs := []CanaryTokenConfig{
		{
			Type:     "file",
			Location: "/var/www/html/canary.txt",
			Config: map[string]interface{}{
				"content": "This file contains sensitive information",
				"size":    1024,
			},
		},
		{
			Type:     "url",
			Location: "https://internal.company.com/admin",
			Config: map[string]interface{}{
				"fake_content": true,
				"fake_forms":   true,
			},
		},
		{
			Type:     "email",
			Location: "admin@company.com",
			Config: map[string]interface{}{
				"fake_content":     "Password reset request",
				"fake_attachments": []string{"passwords.xlsx", "confidential.pdf"},
			},
		},
		{
			Type:     "database",
			Location: "mysql://admin:password@localhost:3306/users",
			Config: map[string]interface{}{
				"fake_tables": []string{"users", "passwords", "financial"},
			},
		},
		{
			Type:     "api",
			Location: "/api/v1/admin/users",
			Config: map[string]interface{}{
				"fake_endpoints": []string{"/users", "/admin", "/config"},
			},
		},
	}

	for _, config := range canaryConfigs {
		canary := &CanaryToken{
			ID:           generateCanaryID(),
			Name:         config.Type + "_canary",
			Type:         config.Type,
			Token:        generateCanaryToken(),
			Location:     config.Location,
			Status:       "active",
			Config:       config.Config,
			CreatedAt:    time.Now(),
			TriggerCount: 0,
			Logs:         []CanaryLog{},
		}
		d.canaryTokens[canary.ID] = canary
	}
}

func (d *DeceptionService) startHoneypotServers() {
	for _, honeypot := range d.honeypots {
		go d.startHoneypotServer(honeypot)
	}
}

func (d *DeceptionService) startHoneypotServer(honeypot *Honeypot) {
	switch honeypot.Type {
	case "http":
		d.startHTTPHoneypot(honeypot)
	case "ssh":
		d.startSSHHoneypot(honeypot)
	case "ftp":
		d.startFTPHoneypot(honeypot)
	case "smb":
		d.startSMBHoneypot(honeypot)
	case "database":
		d.startDatabaseHoneypot(honeypot)
	}
}

func (d *DeceptionService) startHTTPHoneypot(honeypot *Honeypot) {
	mux := http.NewServeMux()

	// Fake login page
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		d.logHoneypotAccess(honeypot, r, "login_attempt")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`
			<!DOCTYPE html>
			<html>
			<head><title>Admin Login</title></head>
			<body>
				<h1>Administrator Login</h1>
				<form method="post">
					<input type="text" name="username" placeholder="Username">
					<input type="password" name="password" placeholder="Password">
					<button type="submit">Login</button>
				</form>
			</body>
			</html>
		`))
	})

	// Fake admin panel
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		d.logHoneypotAccess(honeypot, r, "admin_access")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`
			<!DOCTYPE html>
			<html>
			<head><title>Admin Panel</title></head>
			<body>
				<h1>Administrator Panel</h1>
				<p>Welcome to the admin panel</p>
				<ul>
					<li><a href="/users">User Management</a></li>
					<li><a href="/config">System Configuration</a></li>
					<li><a href="/logs">System Logs</a></li>
				</ul>
			</body>
			</html>
		`))
	})

	// Fake API endpoints
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		d.logHoneypotAccess(honeypot, r, "api_access")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status": "success", "data": "fake_data"}`))
	})

	// Default handler
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		d.logHoneypotAccess(honeypot, r, "general_access")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`
			<!DOCTYPE html>
			<html>
			<head><title>Company Intranet</title></head>
			<body>
				<h1>Welcome to Company Intranet</h1>
				<p>This is a fake intranet page</p>
			</body>
			</html>
		`))
	})

	server := &http.Server{
		Addr:    honeypot.IP + ":" + string(rune(honeypot.Port)),
		Handler: mux,
	}

	log.Printf("Starting HTTP honeypot on port %d", honeypot.Port)
	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.Printf("HTTP honeypot error: %v", err)
		}
	}()
}

func (d *DeceptionService) startSSHHoneypot(honeypot *Honeypot) {
	// Simulate SSH honeypot (simplified)
	go func() {
		listener, err := net.Listen("tcp", honeypot.IP+":"+string(rune(honeypot.Port)))
		if err != nil {
			log.Printf("SSH honeypot error: %v", err)
			return
		}
		defer listener.Close()

		for {
			conn, err := listener.Accept()
			if err != nil {
				continue
			}

			go func(conn net.Conn) {
				defer conn.Close()

				// Send fake SSH banner
				conn.Write([]byte("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2\r\n"))

				// Simulate SSH handshake
				buffer := make([]byte, 1024)
				n, err := conn.Read(buffer)
				if err != nil {
					return
				}

				// Log the connection attempt
				d.logHoneypotAccess(honeypot, &http.Request{
					RemoteAddr: conn.RemoteAddr().String(),
					Header:     make(http.Header),
				}, "ssh_connection")
			}(conn)
		}
	}()
}

func (d *DeceptionService) startFTPHoneypot(honeypot *Honeypot) {
	// Simulate FTP honeypot (simplified)
	go func() {
		listener, err := net.Listen("tcp", honeypot.IP+":"+string(rune(honeypot.Port)))
		if err != nil {
			log.Printf("FTP honeypot error: %v", err)
			return
		}
		defer listener.Close()

		for {
			conn, err := listener.Accept()
			if err != nil {
				continue
			}

			go func(conn net.Conn) {
				defer conn.Close()

				// Send fake FTP banner
				conn.Write([]byte("220 Welcome to FTP server\r\n"))

				// Simulate FTP commands
				buffer := make([]byte, 1024)
				n, err := conn.Read(buffer)
				if err != nil {
					return
				}

				// Log the connection attempt
				d.logHoneypotAccess(honeypot, &http.Request{
					RemoteAddr: conn.RemoteAddr().String(),
					Header:     make(http.Header),
				}, "ftp_connection")
			}(conn)
		}
	}()
}

func (d *DeceptionService) startSMBHoneypot(honeypot *Honeypot) {
	// Simulate SMB honeypot (simplified)
	go func() {
		listener, err := net.Listen("tcp", honeypot.IP+":"+string(rune(honeypot.Port)))
		if err != nil {
			log.Printf("SMB honeypot error: %v", err)
			return
		}
		defer listener.Close()

		for {
			conn, err := listener.Accept()
			if err != nil {
				continue
			}

			go func(conn net.Conn) {
				defer conn.Close()

				// Simulate SMB handshake
				buffer := make([]byte, 1024)
				n, err := conn.Read(buffer)
				if err != nil {
					return
				}

				// Log the connection attempt
				d.logHoneypotAccess(honeypot, &http.Request{
					RemoteAddr: conn.RemoteAddr().String(),
					Header:     make(http.Header),
				}, "smb_connection")
			}(conn)
		}
	}()
}

func (d *DeceptionService) startDatabaseHoneypot(honeypot *Honeypot) {
	// Simulate database honeypot (simplified)
	go func() {
		listener, err := net.Listen("tcp", honeypot.IP+":"+string(rune(honeypot.Port)))
		if err != nil {
			log.Printf("Database honeypot error: %v", err)
			return
		}
		defer listener.Close()

		for {
			conn, err := listener.Accept()
			if err != nil {
				continue
			}

			go func(conn net.Conn) {
				defer conn.Close()

				// Simulate database handshake
				buffer := make([]byte, 1024)
				n, err := conn.Read(buffer)
				if err != nil {
					return
				}

				// Log the connection attempt
				d.logHoneypotAccess(honeypot, &http.Request{
					RemoteAddr: conn.RemoteAddr().String(),
					Header:     make(http.Header),
				}, "database_connection")
			}(conn)
		}
	}()
}

func (d *DeceptionService) startCanaryTokenMonitoring() {
	// Start monitoring canary tokens
	for _, canary := range d.canaryTokens {
		go d.monitorCanaryToken(canary)
	}
}

func (d *DeceptionService) monitorCanaryToken(canary *CanaryToken) {
	// Simulate canary token monitoring
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Simulate random canary token triggers
			if rand.Float64() < 0.01 { // 1% chance per check
				d.triggerCanaryToken(canary)
			}
		}
	}
}

func (d *DeceptionService) logHoneypotAccess(honeypot *Honeypot, r *http.Request, action string) {
	// Extract source IP
	sourceIP := r.RemoteAddr
	if r.Header.Get("X-Forwarded-For") != "" {
		sourceIP = r.Header.Get("X-Forwarded-For")
	}

	// Create log entry
	logEntry := HoneypotLog{
		ID:         generateLogID(),
		HoneypotID: honeypot.ID,
		Timestamp:  time.Now(),
		SourceIP:   sourceIP,
		UserAgent:  r.UserAgent(),
		Action:     action,
		Details: map[string]interface{}{
			"method":  r.Method,
			"path":    r.URL.Path,
			"query":   r.URL.RawQuery,
			"headers": r.Header,
		},
		RiskScore: d.calculateRiskScore(action, r),
	}

	// Update honeypot
	honeypot.Logs = append(honeypot.Logs, logEntry)
	honeypot.TriggerCount++
	honeypot.LastTrigger = time.Now()

	// Store in ClickHouse
	d.storeHoneypotLog(logEntry)

	// Generate alert if high risk
	if logEntry.RiskScore > 0.7 {
		d.generateDeceptionAlert("honeypot_trigger", honeypot, logEntry)
	}
}

func (d *DeceptionService) triggerCanaryToken(canary *CanaryToken) {
	// Create log entry
	logEntry := CanaryLog{
		ID:        generateLogID(),
		CanaryID:  canary.ID,
		Timestamp: time.Now(),
		SourceIP:  "unknown",
		UserAgent: "unknown",
		Action:    "access",
		Details: map[string]interface{}{
			"location": canary.Location,
			"type":     canary.Type,
		},
		RiskScore: 0.9, // Canary tokens are always high risk
		Location:  canary.Location,
	}

	// Update canary token
	canary.Logs = append(canary.Logs, logEntry)
	canary.TriggerCount++
	canary.LastTrigger = time.Now()

	// Store in ClickHouse
	d.storeCanaryLog(logEntry)

	// Generate alert
	d.generateDeceptionAlert("canary_trigger", canary, logEntry)
}

func (d *DeceptionService) calculateRiskScore(action string, r *http.Request) float64 {
	score := 0.0

	// Base score based on action
	switch action {
	case "login_attempt":
		score = 0.6
	case "admin_access":
		score = 0.8
	case "api_access":
		score = 0.7
	case "ssh_connection":
		score = 0.9
	case "ftp_connection":
		score = 0.8
	case "smb_connection":
		score = 0.8
	case "database_connection":
		score = 0.9
	default:
		score = 0.3
	}

	// Increase score for suspicious user agents
	userAgent := r.UserAgent()
	if strings.Contains(strings.ToLower(userAgent), "bot") ||
		strings.Contains(strings.ToLower(userAgent), "crawler") ||
		strings.Contains(strings.ToLower(userAgent), "scanner") {
		score += 0.2
	}

	// Increase score for suspicious paths
	path := r.URL.Path
	if strings.Contains(strings.ToLower(path), "admin") ||
		strings.Contains(strings.ToLower(path), "login") ||
		strings.Contains(strings.ToLower(path), "api") {
		score += 0.1
	}

	return math.Min(score, 1.0)
}

func (d *DeceptionService) storeHoneypotLog(log HoneypotLog) {
	detailsJSON, _ := json.Marshal(log.Details)

	query := `
		INSERT INTO musafir_honeypot_logs 
		(id, honeypot_id, timestamp, source_ip, user_agent, action, details, risk_score, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	err := d.conn.Exec(d.ctx, query,
		log.ID,
		log.HoneypotID,
		log.Timestamp,
		log.SourceIP,
		log.UserAgent,
		log.Action,
		string(detailsJSON),
		log.RiskScore,
		time.Now(),
	)

	if err != nil {
		log.Printf("Error storing honeypot log: %v", err)
	}
}

func (d *DeceptionService) storeCanaryLog(log CanaryLog) {
	detailsJSON, _ := json.Marshal(log.Details)

	query := `
		INSERT INTO musafir_canary_logs 
		(id, canary_id, timestamp, source_ip, user_agent, action, details, risk_score, location, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	err := d.conn.Exec(d.ctx, query,
		log.ID,
		log.CanaryID,
		log.Timestamp,
		log.SourceIP,
		log.UserAgent,
		log.Action,
		string(detailsJSON),
		log.RiskScore,
		log.Location,
		time.Now(),
	)

	if err != nil {
		log.Printf("Error storing canary log: %v", err)
	}
}

func (d *DeceptionService) generateDeceptionAlert(alertType string, source interface{}, log interface{}) {
	alert := DeceptionAlert{
		ID:        generateAlertID(),
		Type:      alertType,
		Timestamp: time.Now(),
		RiskScore: 0.9,
		Status:    "active",
		Metadata:  make(map[string]interface{}),
	}

	switch alertType {
	case "honeypot_trigger":
		if honeypot, ok := source.(*Honeypot); ok {
			alert.Title = "Honeypot Triggered"
			alert.Description = "Suspicious activity detected on honeypot: " + honeypot.Name
			alert.Severity = "high"
			alert.Source = honeypot.IP + ":" + string(rune(honeypot.Port))
			alert.Target = honeypot.Type
		}
	case "canary_trigger":
		if canary, ok := source.(*CanaryToken); ok {
			alert.Title = "Canary Token Triggered"
			alert.Description = "Canary token accessed: " + canary.Name
			alert.Severity = "critical"
			alert.Source = canary.Location
			alert.Target = canary.Type
		}
	}

	// Store alert in ClickHouse
	d.storeDeceptionAlert(alert)

	// Send to Kafka
	alertJSON, _ := json.Marshal(alert)
	d.writer.WriteMessages(d.ctx, kafka.Message{
		Key:   []byte(alert.ID),
		Value: alertJSON,
	})

	log.Printf("Deception alert generated: %s", alert.Title)
}

func (d *DeceptionService) storeDeceptionAlert(alert DeceptionAlert) {
	metadataJSON, _ := json.Marshal(alert.Metadata)

	query := `
		INSERT INTO musafir_deception_alerts 
		(id, type, title, description, severity, source, target, timestamp, risk_score, metadata, status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	err := d.conn.Exec(d.ctx, query,
		alert.ID,
		alert.Type,
		alert.Title,
		alert.Description,
		alert.Severity,
		alert.Source,
		alert.Target,
		alert.Timestamp,
		alert.RiskScore,
		string(metadataJSON),
		alert.Status,
		time.Now(),
	)

	if err != nil {
		log.Printf("Error storing deception alert: %v", err)
	}
}

func (d *DeceptionService) GetHoneypots() map[string]*Honeypot {
	return d.honeypots
}

func (d *DeceptionService) GetCanaryTokens() map[string]*CanaryToken {
	return d.canaryTokens
}

func (d *DeceptionService) Close() {
	d.writer.Close()
	d.conn.Close()
}

// Utility functions
func generateHoneypotID() string {
	return "honeypot_" + generateRandomID()
}

func generateCanaryID() string {
	return "canary_" + generateRandomID()
}

func generateCanaryToken() string {
	return "canary_" + generateRandomID()
}

func generateLogID() string {
	return "log_" + generateRandomID()
}

func generateAlertID() string {
	return "alert_" + generateRandomID()
}

func generateRandomID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func main() {
	deceptionService := NewDeceptionService()
	deceptionService.Initialize()

	// Keep service running
	select {}
}

package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	ch "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"
	"golang.org/x/time/rate"
)

// Controller represents the unified MUSAFIR SecOps controller
type Controller struct {
	router    *mux.Router
	chConn    ch.Conn
	wsClients map[*websocket.Conn]bool
	wsMu      sync.RWMutex
	
	// Authentication
	jwtSecret  string
	hmacSecret string
	
	// Rate limiting
	rateLimiter *rate.Limiter
	
	// Agent management
	agents      map[string]*Agent
	agentsMu    sync.RWMutex
	enrollTokens map[string]time.Time
	
	// Metrics
	metrics *Metrics
}

// Agent represents a registered agent
type Agent struct {
	ID        string    `json:"id"`
	Token     string    `json:"token"`
	HMAC      string    `json:"hmac"`
	Hostname  string    `json:"hostname"`
	Platform  string    `json:"platform"`
	Version   string    `json:"version"`
	IPAddress string    `json:"ip_address"`
	CreatedAt time.Time `json:"created_at"`
	LastSeen  time.Time `json:"last_seen"`
	Status    string    `json:"status"`
}

// Metrics holds system metrics
type Metrics struct {
	EventsReceived    int64 `json:"events_received"`
	EventsProcessed   int64 `json:"events_processed"`
	AlertsGenerated   int64 `json:"alerts_generated"`
	ActiveAgents      int64 `json:"active_agents"`
	DatabaseWrites    int64 `json:"database_writes"`
	WebSocketClients  int64 `json:"websocket_clients"`
	mu                sync.RWMutex
}

// Event represents a security event from an agent
type Event struct {
	ID        string                 `json:"id"`
	AgentID   string                 `json:"agent_id"`
	Timestamp time.Time              `json:"timestamp"`
	Type      string                 `json:"type"`
	Severity  string                 `json:"severity"`
	Data      map[string]interface{} `json:"data"`
	Tags      []string               `json:"tags"`
}

// WebSocket message structure
type WSMessage struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins for demo
	},
}

// NewController creates a new controller instance
func NewController() *Controller {
	return &Controller{
		router:       mux.NewRouter(),
		wsClients:    make(map[*websocket.Conn]bool),
		agents:       make(map[string]*Agent),
		enrollTokens: make(map[string]time.Time),
		rateLimiter:  rate.NewLimiter(rate.Limit(1000), 5000), // 1000 req/s, burst 5000
		metrics:      &Metrics{},
	}
}

// Initialize sets up the controller
func (c *Controller) Initialize() error {
	// Load environment variables
	godotenv.Load()
	
	// Set up secrets
	c.jwtSecret = os.Getenv("JWT_SECRET")
	if c.jwtSecret == "" {
		c.jwtSecret = c.generateRandomHex(32)
		log.Printf("Generated JWT secret: %s", c.jwtSecret)
	}
	
	c.hmacSecret = os.Getenv("HMAC_SECRET")
	if c.hmacSecret == "" {
		c.hmacSecret = "default-hmac-secret-for-demo"
		log.Printf("Using default HMAC secret for demo")
	}
	
	// Connect to ClickHouse
	if err := c.connectDatabase(); err != nil {
		log.Printf("Database connection failed: %v", err)
		return err
	}
	
	// Setup routes
	c.setupRoutes()
	
	// Setup middleware
	c.setupMiddleware()
	
	log.Println("MUSAFIR Controller initialized successfully")
	return nil
}

// connectDatabase establishes ClickHouse connection
func (c *Controller) connectDatabase() error {
	dsn := os.Getenv("CLICKHOUSE_DSN")
	if dsn == "" {
		dsn = "tcp://localhost:9000?database=default"
	}
	
	conn, err := ch.Open(&ch.Options{
		Addr: []string{"localhost:9000"},
		Auth: ch.Auth{
			Database: "default",
		},
	})
	if err != nil {
		return fmt.Errorf("failed to connect to ClickHouse: %v", err)
	}
	
	c.chConn = conn
	
	// Ensure tables exist
	if err := c.ensureTables(); err != nil {
		return fmt.Errorf("failed to create tables: %v", err)
	}
	
	log.Println("Connected to ClickHouse database")
	return nil
}

// ensureTables creates necessary database tables
func (c *Controller) ensureTables() error {
	ctx := context.Background()
	
	// Events table
	eventsTable := `
	CREATE TABLE IF NOT EXISTS musafir_events (
		id String,
		agent_id String,
		timestamp DateTime,
		event_type String,
		severity String,
		source_ip String,
		destination_ip String,
		process_name String,
		process_id UInt32,
		user_name String,
		file_path String,
		command_line String,
		hash_sha256 String,
		raw_data String,
		tags Array(String)
	) ENGINE = MergeTree()
	ORDER BY (agent_id, timestamp)
	PARTITION BY toYYYYMM(timestamp)
	TTL timestamp + INTERVAL 1 YEAR`
	
	if err := c.chConn.Exec(ctx, eventsTable); err != nil {
		return err
	}
	
	// Agents table
	agentsTable := `
	CREATE TABLE IF NOT EXISTS musafir_agents (
		id String,
		token String,
		hmac String,
		hostname String,
		platform String,
		version String,
		ip_address String,
		created_at DateTime,
		last_seen DateTime,
		status String
	) ENGINE = MergeTree()
	ORDER BY (id, created_at)
	PARTITION BY toYYYYMM(created_at)`
	
	if err := c.chConn.Exec(ctx, agentsTable); err != nil {
		return err
	}
	
	// Alerts table
	alertsTable := `
	CREATE TABLE IF NOT EXISTS musafir_alerts (
		id String,
		agent_id String,
		timestamp DateTime,
		alert_type String,
		severity String,
		title String,
		description String,
		mitre_tactics Array(String),
		mitre_techniques Array(String),
		raw_data String
	) ENGINE = MergeTree()
	ORDER BY (timestamp, severity)
	PARTITION BY toYYYYMM(timestamp)
	TTL timestamp + INTERVAL 2 YEAR`
	
	return c.chConn.Exec(ctx, alertsTable)
}

// setupMiddleware configures HTTP middleware
func (c *Controller) setupMiddleware() {
	c.router.Use(c.corsMiddleware)
	c.router.Use(c.loggingMiddleware)
	c.router.Use(c.rateLimitMiddleware)
}

// setupRoutes configures HTTP routes
func (c *Controller) setupRoutes() {
	// Health check
	c.router.HandleFunc("/health", c.healthHandler).Methods("GET", "OPTIONS")
	
	// Metrics
	c.router.HandleFunc("/metrics", c.metricsHandler).Methods("GET", "OPTIONS")
	
	// WebSocket for real-time updates
	c.router.HandleFunc("/ws", c.websocketHandler)
	
	// Agent endpoints
	c.router.HandleFunc("/v1/enroll", c.agentEnrollHandler).Methods("POST", "OPTIONS")
	c.router.HandleFunc("/v1/events", c.eventsHandler).Methods("POST", "OPTIONS")
	
	// API endpoints
	api := c.router.PathPrefix("/api").Subrouter()
	api.Use(c.authMiddleware)
	
	// Authentication
	c.router.HandleFunc("/api/auth/login", c.loginHandler).Methods("POST", "OPTIONS")
	
	// Events and search
	api.HandleFunc("/events", c.getEventsHandler).Methods("GET", "OPTIONS")
	api.HandleFunc("/search", c.searchHandler).Methods("GET", "POST", "OPTIONS")
	
	// Agents management
	api.HandleFunc("/agents", c.getAgentsHandler).Methods("GET", "OPTIONS")
	api.HandleFunc("/agents/{id}", c.getAgentHandler).Methods("GET", "OPTIONS")
	
	// Alerts
	api.HandleFunc("/alerts", c.getAlertsHandler).Methods("GET", "OPTIONS")
	
	// Admin endpoints
	admin := api.PathPrefix("/admin").Subrouter()
	admin.HandleFunc("/tokens", c.createEnrollmentTokenHandler).Methods("POST", "OPTIONS")
}

// Middleware functions
func (c *Controller) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Agent-ID, X-HMAC-Signature")
		
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

func (c *Controller) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %v", r.Method, r.URL.Path, time.Since(start))
	})
}

func (c *Controller) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !c.rateLimiter.Allow() {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (c *Controller) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for login endpoint
		if strings.HasSuffix(r.URL.Path, "/login") {
			next.ServeHTTP(w, r)
			return
		}
		
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}
		
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(c.jwtSecret), nil
		})
		
		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

// Handler functions
func (c *Controller) healthHandler(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC(),
		"database":  c.chConn != nil,
		"agents":    len(c.agents),
		"clients":   len(c.wsClients),
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (c *Controller) metricsHandler(w http.ResponseWriter, r *http.Request) {
	c.metrics.mu.RLock()
	defer c.metrics.mu.RUnlock()
	
	c.metrics.ActiveAgents = int64(len(c.agents))
	c.metrics.WebSocketClients = int64(len(c.wsClients))
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(c.metrics)
}

func (c *Controller) websocketHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()
	
	c.wsMu.Lock()
	c.wsClients[conn] = true
	c.wsMu.Unlock()
	
	defer func() {
		c.wsMu.Lock()
		delete(c.wsClients, conn)
		c.wsMu.Unlock()
	}()
	
	// Send welcome message
	welcome := WSMessage{
		Type: "welcome",
		Data: map[string]interface{}{
			"message": "Connected to MUSAFIR Controller",
			"time":    time.Now().UTC(),
		},
	}
	conn.WriteJSON(welcome)
	
	// Keep connection alive
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

func (c *Controller) loginHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	
	// For demo: accept any non-empty credentials
	if req.Username == "" || req.Password == "" {
		http.Error(w, "Username and password required", http.StatusBadRequest)
		return
	}
	
	// Generate JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": req.Username,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(24 * time.Hour).Unix(),
	})
	
	tokenString, err := token.SignedString([]byte(c.jwtSecret))
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"token": tokenString,
	})
}

func (c *Controller) agentEnrollHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token    string `json:"token"`
		Hostname string `json:"hostname"`
		Platform string `json:"platform"`
		Version  string `json:"version"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	
	// Verify enrollment token
	if expiry, exists := c.enrollTokens[req.Token]; !exists || time.Now().After(expiry) {
		http.Error(w, "Invalid or expired enrollment token", http.StatusUnauthorized)
		return
	}
	
	// Create new agent
	agentID := c.generateRandomHex(16)
	agentToken := c.generateRandomHex(32)
	agentHMAC := c.generateRandomHex(32)
	
	agent := &Agent{
		ID:        agentID,
		Token:     agentToken,
		HMAC:      agentHMAC,
		Hostname:  req.Hostname,
		Platform:  req.Platform,
		Version:   req.Version,
		IPAddress: c.getClientIP(r),
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
		Status:    "active",
	}
	
	c.agentsMu.Lock()
	c.agents[agentID] = agent
	delete(c.enrollTokens, req.Token) // Remove used token
	c.agentsMu.Unlock()
	
	// Store in database
	if c.chConn != nil {
		ctx := context.Background()
		c.chConn.Exec(ctx, `
			INSERT INTO musafir_agents (id, token, hmac, hostname, platform, version, ip_address, created_at, last_seen, status)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			agent.ID, agent.Token, agent.HMAC, agent.Hostname, agent.Platform,
			agent.Version, agent.IPAddress, agent.CreatedAt, agent.LastSeen, agent.Status)
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"agent_id":   agentID,
		"token":      agentToken,
		"hmac":       agentHMAC,
		"message":    "Agent enrolled successfully",
	})
}

func (c *Controller) eventsHandler(w http.ResponseWriter, r *http.Request) {
	// Verify HMAC signature
	agentID := r.Header.Get("X-Agent-ID")
	signature := r.Header.Get("X-HMAC-Signature")
	
	if agentID == "" || signature == "" {
		http.Error(w, "Missing agent ID or HMAC signature", http.StatusBadRequest)
		return
	}
	
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	
	// Verify HMAC
	c.agentsMu.RLock()
	agent, exists := c.agents[agentID]
	c.agentsMu.RUnlock()
	
	if !exists {
		http.Error(w, "Unknown agent", http.StatusUnauthorized)
		return
	}
	
	expectedMAC := hmac.New(sha256.New, []byte(agent.HMAC))
	expectedMAC.Write(body)
	expectedSignature := hex.EncodeToString(expectedMAC.Sum(nil))
	
	if !hmac.Equal([]byte(signature), []byte(expectedSignature)) {
		http.Error(w, "Invalid HMAC signature", http.StatusUnauthorized)
		return
	}
	
	// Update agent last seen
	c.agentsMu.Lock()
	agent.LastSeen = time.Now()
	c.agentsMu.Unlock()
	
	// Process events
	var events []Event
	if err := json.Unmarshal(body, &events); err != nil {
		// Try single event
		var event Event
		if err := json.Unmarshal(body, &event); err != nil {
			http.Error(w, "Invalid event format", http.StatusBadRequest)
			return
		}
		events = []Event{event}
	}
	
	// Store events and process them
	for _, event := range events {
		event.AgentID = agentID
		if event.Timestamp.IsZero() {
			event.Timestamp = time.Now()
		}
		
		c.storeEvent(event)
		c.processEvent(event)
	}
	
	// Update metrics
	c.metrics.mu.Lock()
	c.metrics.EventsReceived += int64(len(events))
	c.metrics.EventsProcessed += int64(len(events))
	c.metrics.mu.Unlock()
	
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("Processed %d events", len(events)),
	})
}

func (c *Controller) storeEvent(event Event) {
	if c.chConn == nil {
		return
	}
	
	ctx := context.Background()
	rawData, _ := json.Marshal(event.Data)
	
	c.chConn.Exec(ctx, `
		INSERT INTO musafir_events (id, agent_id, timestamp, event_type, severity, raw_data, tags)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		event.ID, event.AgentID, event.Timestamp, event.Type, event.Severity, string(rawData), event.Tags)
	
	c.metrics.mu.Lock()
	c.metrics.DatabaseWrites++
	c.metrics.mu.Unlock()
}

func (c *Controller) processEvent(event Event) {
	// Basic threat detection logic
	if c.shouldGenerateAlert(event) {
		alert := c.createAlert(event)
		c.storeAlert(alert)
		c.broadcastAlert(alert)
	}
	
	// Broadcast event to WebSocket clients
	c.broadcastEvent(event)
}

func (c *Controller) shouldGenerateAlert(event Event) bool {
	// Simple alerting rules
	switch event.Type {
	case "threat_detected", "malware_detected":
		return true
	case "process_start":
		if cmd, ok := event.Data["command_line"].(string); ok {
			suspiciousCommands := []string{"powershell", "cmd.exe", "wscript", "cscript"}
			for _, suspicious := range suspiciousCommands {
				if strings.Contains(strings.ToLower(cmd), suspicious) {
					return true
				}
			}
		}
	case "network_connection":
		if port, ok := event.Data["port"].(float64); ok {
			suspiciousPorts := []int{4444, 5555, 6666, 7777, 8888, 9999}
			for _, suspicious := range suspiciousPorts {
				if int(port) == suspicious {
					return true
				}
			}
		}
	}
	return false
}

func (c *Controller) createAlert(event Event) map[string]interface{} {
	return map[string]interface{}{
		"id":          c.generateRandomHex(16),
		"agent_id":    event.AgentID,
		"timestamp":   time.Now(),
		"alert_type":  "security_event",
		"severity":    event.Severity,
		"title":       fmt.Sprintf("Security Alert: %s", event.Type),
		"description": fmt.Sprintf("Suspicious activity detected: %s", event.Type),
		"event_id":    event.ID,
		"raw_data":    event.Data,
	}
}

func (c *Controller) storeAlert(alert map[string]interface{}) {
	if c.chConn == nil {
		return
	}
	
	ctx := context.Background()
	rawData, _ := json.Marshal(alert["raw_data"])
	
	c.chConn.Exec(ctx, `
		INSERT INTO musafir_alerts (id, agent_id, timestamp, alert_type, severity, title, description, raw_data)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		alert["id"], alert["agent_id"], alert["timestamp"], alert["alert_type"],
		alert["severity"], alert["title"], alert["description"], string(rawData))
	
	c.metrics.mu.Lock()
	c.metrics.AlertsGenerated++
	c.metrics.mu.Unlock()
}

func (c *Controller) broadcastEvent(event Event) {
	message := WSMessage{
		Type: "event",
		Data: event,
	}
	c.broadcast(message)
}

func (c *Controller) broadcastAlert(alert map[string]interface{}) {
	message := WSMessage{
		Type: "alert",
		Data: alert,
	}
	c.broadcast(message)
}

func (c *Controller) broadcast(message WSMessage) {
	c.wsMu.RLock()
	defer c.wsMu.RUnlock()
	
	for client := range c.wsClients {
		if err := client.WriteJSON(message); err != nil {
			client.Close()
			delete(c.wsClients, client)
		}
	}
}

// Additional handler functions
func (c *Controller) getEventsHandler(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	
	if c.chConn == nil {
		http.Error(w, "Database not available", http.StatusServiceUnavailable)
		return
	}
	
	ctx := context.Background()
	rows, err := c.chConn.Query(ctx, `
		SELECT id, agent_id, timestamp, event_type, severity, raw_data
		FROM musafir_events
		ORDER BY timestamp DESC
		LIMIT ?`, limit)
	
	if err != nil {
		http.Error(w, "Database query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	
	var events []map[string]interface{}
	for rows.Next() {
		var id, agentID, eventType, severity, rawData string
		var timestamp time.Time
		
		if err := rows.Scan(&id, &agentID, &timestamp, &eventType, &severity, &rawData); err != nil {
			continue
		}
		
		var data map[string]interface{}
		json.Unmarshal([]byte(rawData), &data)
		
		events = append(events, map[string]interface{}{
			"id":        id,
			"agent_id":  agentID,
			"timestamp": timestamp,
			"type":      eventType,
			"severity":  severity,
			"data":      data,
		})
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(events)
}

func (c *Controller) searchHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		http.Error(w, "Query parameter 'q' is required", http.StatusBadRequest)
		return
	}
	
	// Simple search implementation
	results := map[string]interface{}{
		"query":   query,
		"results": []interface{}{},
		"total":   0,
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func (c *Controller) getAgentsHandler(w http.ResponseWriter, r *http.Request) {
	c.agentsMu.RLock()
	agents := make([]*Agent, 0, len(c.agents))
	for _, agent := range c.agents {
		agents = append(agents, agent)
	}
	c.agentsMu.RUnlock()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(agents)
}

func (c *Controller) getAgentHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	agentID := vars["id"]
	
	c.agentsMu.RLock()
	agent, exists := c.agents[agentID]
	c.agentsMu.RUnlock()
	
	if !exists {
		http.Error(w, "Agent not found", http.StatusNotFound)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(agent)
}

func (c *Controller) getAlertsHandler(w http.ResponseWriter, r *http.Request) {
	if c.chConn == nil {
		http.Error(w, "Database not available", http.StatusServiceUnavailable)
		return
	}
	
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	
	ctx := context.Background()
	rows, err := c.chConn.Query(ctx, `
		SELECT id, agent_id, timestamp, alert_type, severity, title, description
		FROM musafir_alerts
		ORDER BY timestamp DESC
		LIMIT ?`, limit)
	
	if err != nil {
		http.Error(w, "Database query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	
	var alerts []map[string]interface{}
	for rows.Next() {
		var id, agentID, alertType, severity, title, description string
		var timestamp time.Time
		
		if err := rows.Scan(&id, &agentID, &timestamp, &alertType, &severity, &title, &description); err != nil {
			continue
		}
		
		alerts = append(alerts, map[string]interface{}{
			"id":          id,
			"agent_id":    agentID,
			"timestamp":   timestamp,
			"alert_type":  alertType,
			"severity":    severity,
			"title":       title,
			"description": description,
		})
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(alerts)
}

func (c *Controller) createEnrollmentTokenHandler(w http.ResponseWriter, r *http.Request) {
	token := c.generateRandomHex(16)
	expiry := time.Now().Add(15 * time.Minute)
	
	c.enrollTokens[token] = expiry
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"token":      token,
		"expires_at": expiry,
		"message":    "Enrollment token created successfully",
	})
}

// Utility functions
func (c *Controller) generateRandomHex(length int) string {
	bytes := make([]byte, length/2)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func (c *Controller) getClientIP(r *http.Request) string {
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		return strings.Split(forwarded, ",")[0]
	}
	return strings.Split(r.RemoteAddr, ":")[0]
}

// Start starts the controller server
func (c *Controller) Start(port string) {
	server := &http.Server{
		Addr:         ":" + port,
		Handler:      c.router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	
	// Graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		
		log.Println("Shutting down controller...")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		
		if c.chConn != nil {
			c.chConn.Close()
		}
		
		server.Shutdown(ctx)
	}()
	
	log.Printf("MUSAFIR Controller starting on port %s", port)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed to start: %v", err)
	}
}

func main() {
	controller := NewController()
	
	if err := controller.Initialize(); err != nil {
		log.Fatalf("Failed to initialize controller: %v", err)
	}
	
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	
	controller.Start(port)
}
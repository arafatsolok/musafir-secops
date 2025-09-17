package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	mrand "math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	ch "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"
	"golang.org/x/time/rate"
)

type AdvancedGateway struct {
	router          *mux.Router
	rateLimiters    map[string]*rate.Limiter
	circuitBreakers map[string]*CircuitBreaker
	authService     *AuthService
	metrics         *GatewayMetrics
	wsUpgrader      websocket.Upgrader
	services        map[string]*ServiceConfig
	wsMu            sync.Mutex
	wsClients       map[*websocket.Conn]struct{}
	agentsMu        sync.Mutex
	enrollTokens    map[string]time.Time
	agentRecords    map[string]*AgentRecord
	chConn          ch.Conn
}
type ServiceConfig struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Port    string `json:"port"`
	Health  string `json:"health"`
	Enabled bool   `json:"enabled"`
}

type CircuitBreaker struct {
	State        string        `json:"state"` // closed, open, half-open
	FailureCount int           `json:"failure_count"`
	LastFailTime time.Time     `json:"last_fail_time"`
	SuccessCount int           `json:"success_count"`
	Threshold    int           `json:"threshold"`
	Timeout      time.Duration `json:"timeout"`
}

type AuthService struct {
	JWTSecret     string
	TokenExpiry   time.Duration
	RefreshExpiry time.Duration
	HMACSecret    string
}

type GatewayMetrics struct {
	RequestCount      int64     `json:"request_count"`
	ErrorCount        int64     `json:"error_count"`
	ResponseTime      float64   `json:"avg_response_time"`
	ActiveConnections int64     `json:"active_connections"`
	LastUpdated       time.Time `json:"last_updated"`
}

type RateLimitConfig struct {
	RequestsPerSecond float64 `json:"requests_per_second"`
	BurstSize         int     `json:"burst_size"`
}

type ServiceHealth struct {
	Service      string    `json:"service"`
	Status       string    `json:"status"`
	LastCheck    time.Time `json:"last_check"`
	ResponseTime int64     `json:"response_time_ms"`
	ErrorRate    float64   `json:"error_rate"`
}

type WebSocketMessage struct {
	Type      string      `json:"type"`
	Data      interface{} `json:"data"`
	Timestamp time.Time   `json:"timestamp"`
}

type AgentRecord struct {
	ID        string    `json:"id"`
	Token     string    `json:"token"`
	HMAC      string    `json:"hmac"`
	CreatedAt time.Time `json:"created_at"`
	LastSeen  time.Time `json:"last_seen"`
}

type AgentConfig struct {
	GatewayURL   string `json:"gateway_url"`
	PollInterval int    `json:"poll_interval_seconds"`
	UseMTLS      bool   `json:"use_mtls"`
}

const correlationHeader = "X-Correlation-Id"
const traceParentHeader = "traceparent"
const traceStateHeader = "tracestate"

type ctxKey string

var correlationKey ctxKey = "correlation-id"

func NewAdvancedGateway() *AdvancedGateway {
	router := mux.NewRouter()

	// Initialize rate limiters for different endpoints
	rateLimiters := make(map[string]*rate.Limiter)
	rateLimiters["/api/"] = rate.NewLimiter(rate.Limit(100), 1000) // 100 req/s, burst 1000
	rateLimiters["/v1/events"] = rate.NewLimiter(rate.Limit(200), 2000)

	// Initialize circuit breakers for services
	circuitBreakers := make(map[string]*CircuitBreaker)
	services := []string{"ingest", "detect", "correlate", "respond", "cases", "ueba", "threatintel"}
	for _, service := range services {
		circuitBreakers[service] = &CircuitBreaker{
			State:     "closed",
			Threshold: 5,
			Timeout:   30 * time.Second,
		}
	}

	jwtSecret := os.Getenv("GATEWAY_JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "your-secret-key"
	}
	hmacSecret := os.Getenv("GATEWAY_HMAC_SECRET")
	if hmacSecret == "" {
		hmacSecret = "change-me"
	}

	authService := &AuthService{
		JWTSecret:     jwtSecret,
		TokenExpiry:   15 * time.Minute,
		RefreshExpiry: 7 * 24 * time.Hour,
		HMACSecret:    hmacSecret,
	}

	metrics := &GatewayMetrics{
		LastUpdated: time.Now(),
	}

	wsUpgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true // Allow all origins in development
		},
	}

	return &AdvancedGateway{
		router:          router,
		rateLimiters:    rateLimiters,
		circuitBreakers: circuitBreakers,
		authService:     authService,
		metrics:         metrics,
		wsUpgrader:      wsUpgrader,
		services:        make(map[string]*ServiceConfig),
		wsClients:       make(map[*websocket.Conn]struct{}),
		enrollTokens:    make(map[string]time.Time),
		agentRecords:    make(map[string]*AgentRecord),
	}
}

func (g *AdvancedGateway) Initialize() {
	// Load service configurations
	g.loadServiceConfigs()

	// Setup middleware
	g.setupMiddleware()

	// Setup routes
	g.setupRoutes()

	// Start health monitoring
	go g.monitorServices()

	// Start metrics collection
	go g.collectMetrics()

	// Connect ClickHouse (best-effort)
	dsn := os.Getenv("CLICKHOUSE_DSN")
	if dsn == "" {
		dsn = "tcp://localhost:9000?database=default"
	}
	conn, err := ch.Open(&ch.Options{Addr: []string{"localhost:9000"}})
	if err == nil {
		g.chConn = conn
		g.ensureAgentTables()
	} else {
		log.Printf("{\"level\":\"warn\",\"msg\":\"clickhouse connect failed\",\"err\":%q}", err.Error())
	}

	log.Println("Advanced Gateway initialized successfully")
}

func (g *AdvancedGateway) ensureAgentTables() {
	ctx := context.Background()
	ddl1 := `CREATE TABLE IF NOT EXISTS musafir_agents (
  id String, token String, hmac String, created_at DateTime, last_seen DateTime
) ENGINE = MergeTree ORDER BY id`
	_ = g.chConn.Exec(ctx, ddl1)
	ddl2 := `CREATE TABLE IF NOT EXISTS musafir_enroll_tokens (
  token String, expires_at DateTime, created_at DateTime, created_by String
) ENGINE = MergeTree ORDER BY created_at`
	_ = g.chConn.Exec(ctx, ddl2)
}

func (g *AdvancedGateway) loadServiceConfigs() {
	// Load service configurations from environment or config file
	serviceConfigs := map[string]*ServiceConfig{
		"ingest": {
			Name:    "Ingest",
			URL:     "http://localhost:8081",
			Port:    "8081",
			Health:  "/health",
			Enabled: true,
		},
		"detect": {
			Name:    "Detect",
			URL:     "http://localhost:8082",
			Port:    "8082",
			Health:  "/health",
			Enabled: true,
		},
		"correlate": {
			Name:    "Correlate",
			URL:     "http://localhost:8083",
			Port:    "8083",
			Health:  "/health",
			Enabled: true,
		},
		"respond": {
			Name:    "Respond",
			URL:     "http://localhost:8084",
			Port:    "8084",
			Health:  "/health",
			Enabled: true,
		},
		"cases": {
			Name:    "Cases",
			URL:     "http://localhost:8085",
			Port:    "8085",
			Health:  "/health",
			Enabled: true,
		},
		"ueba": {
			Name:    "UEBA",
			URL:     "http://localhost:8086",
			Port:    "8086",
			Health:  "/health",
			Enabled: true,
		},
		"threatintel": {
			Name:    "ThreatIntel",
			URL:     "http://localhost:8087",
			Port:    "8087",
			Health:  "/health",
			Enabled: true,
		},
		"ml": {
			Name:    "ML",
			URL:     "http://localhost:8088",
			Port:    "8088",
			Health:  "/health",
			Enabled: true,
		},
		"ai": {
			Name:    "AI",
			URL:     "http://localhost:8089",
			Port:    "8089",
			Health:  "/health",
			Enabled: true,
		},
		"monitor": {
			Name:    "Monitor",
			URL:     "http://localhost:9090",
			Port:    "9090",
			Health:  "/health",
			Enabled: true,
		},
		"deception": {
			Name:    "Deception",
			URL:     "http://localhost:8090",
			Port:    "8090",
			Health:  "/health",
			Enabled: true,
		},
		"graph": {
			Name:    "Graph",
			URL:     "http://localhost:8091",
			Port:    "8091",
			Health:  "/health",
			Enabled: true,
		},
		"cache": {
			Name:    "Cache",
			URL:     "http://localhost:8092",
			Port:    "8092",
			Health:  "/health",
			Enabled: true,
		},
		"observability": {
			Name:    "Observability",
			URL:     "http://localhost:8093",
			Port:    "8093",
			Health:  "/health",
			Enabled: true,
		},
		"search": {
			Name:    "Search",
			URL:     "http://localhost:8094",
			Port:    "8094",
			Health:  "/health",
			Enabled: true,
		},
		"forensics": {
			Name:    "Forensics",
			URL:     "http://localhost:8095",
			Port:    "8095",
			Health:  "/health",
			Enabled: true,
		},
		"network": {
			Name:    "Network",
			URL:     "http://localhost:8096",
			Port:    "8096",
			Health:  "/health",
			Enabled: true,
		},
		"email": {
			Name:    "Email",
			URL:     "http://localhost:8097",
			Port:    "8097",
			Health:  "/health",
			Enabled: true,
		},
		"identity": {
			Name:    "Identity",
			URL:     "http://localhost:8098",
			Port:    "8098",
			Health:  "/health",
			Enabled: true,
		},
		"vuln": {
			Name:    "Vulnerability",
			URL:     "http://localhost:8099",
			Port:    "8099",
			Health:  "/health",
			Enabled: true,
		},
		"compliance": {
			Name:    "Compliance",
			URL:     "http://localhost:8100",
			Port:    "8100",
			Health:  "/health",
			Enabled: true,
		},
		"slsa": {
			Name:    "SLSA",
			URL:     "http://localhost:8101",
			Port:    "8101",
			Health:  "/health",
			Enabled: true,
		},
		"tenant": {
			Name:    "Tenant",
			URL:     "http://localhost:8102",
			Port:    "8102",
			Health:  "/health",
			Enabled: true,
		},
		"mdm": {
			Name:    "MDM",
			URL:     "http://localhost:8103",
			Port:    "8103",
			Health:  "/health",
			Enabled: true,
		},
		"yara": {
			Name:    "YARA",
			URL:     "http://localhost:8104",
			Port:    "8104",
			Health:  "/health",
			Enabled: true,
		},
		"cloud": {
			Name:    "Cloud",
			URL:     "http://localhost:8105",
			Port:    "8105",
			Health:  "/health",
			Enabled: true,
		},
		"spire": {
			Name:    "SPIRE",
			URL:     "http://localhost:8106",
			Port:    "8106",
			Health:  "/health",
			Enabled: true,
		},
		"sandbox": {
			Name:    "Sandbox",
			URL:     "http://localhost:8107",
			Port:    "8107",
			Health:  "/health",
			Enabled: true,
		},
	}

	g.services = serviceConfigs
}

func (g *AdvancedGateway) setupMiddleware() {
	// CORS middleware
	g.router.Use(g.corsMiddleware)

	// Correlation ID middleware
	g.router.Use(g.correlationIDMiddleware)

	// Logging middleware
	g.router.Use(g.loggingMiddleware)

	// Rate limiting middleware
	g.router.Use(g.rateLimitMiddleware)

	// Authentication middleware
	g.router.Use(g.authMiddleware)

	// Metrics middleware
	g.router.Use(g.metricsMiddleware)

	// Circuit breaker middleware
	g.router.Use(g.circuitBreakerMiddleware)
}

func (g *AdvancedGateway) correlationIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cid := r.Header.Get(correlationHeader)
		if cid == "" {
			cid = generateCorrelationID()
		}
		w.Header().Set(correlationHeader, cid)
		// Attach to context
		r = r.WithContext(withCorrelationID(r.Context(), cid))
		next.ServeHTTP(w, r)
	})
}

func (g *AdvancedGateway) setupRoutes() {
	// Health check endpoint
	g.router.HandleFunc("/health", g.healthHandler).Methods("GET")

	// Metrics endpoint
	g.router.HandleFunc("/metrics", g.metricsHandler).Methods("GET")

	// WebSocket endpoint for real-time updates
	g.router.HandleFunc("/ws", g.websocketHandler)

	// Agent enrollment (public, token-based)
	g.router.HandleFunc("/v1/enroll", g.agentEnrollHandler).Methods("POST")
	// Agent/event HMAC ingest
	g.router.HandleFunc("/v1/events", g.eventsIngestV1Handler).Methods("POST")

	// API routes
	api := g.router.PathPrefix("/api").Subrouter()

	// Events endpoint
	api.HandleFunc("/events", g.eventsHandler).Methods("POST")

	// Agent config polling (authenticated by per-agent HMAC headers)
	api.HandleFunc("/agent/config", g.agentConfigHandler).Methods("GET")

	// Search endpoint
	api.HandleFunc("/search", g.searchHandler).Methods("GET", "POST")

	// Admin endpoints
	admin := api.PathPrefix("/admin").Subrouter()
	admin.HandleFunc("/services", g.servicesHandler).Methods("GET")
	admin.HandleFunc("/services/{service}/health", g.serviceHealthHandler).Methods("GET")
	admin.HandleFunc("/services/{service}/restart", g.restartServiceHandler).Methods("POST")
	admin.HandleFunc("/config", g.configHandler).Methods("GET", "PUT")
	admin.HandleFunc("/agents", g.createEnrollmentTokenHandler).Methods("POST")

	// Service-specific routes
	for serviceName, config := range g.services {
		servicePath := "/" + serviceName + "/"
		api.PathPrefix(servicePath).HandlerFunc(g.createServiceHandler(serviceName, config))
	}
}

func (g *AdvancedGateway) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (g *AdvancedGateway) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create response writer wrapper to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(wrapped, r)

		duration := time.Since(start)
		cid := getCorrelationID(r.Context())
		entry := map[string]interface{}{
			"ts":             time.Now().Format(time.RFC3339),
			"method":         r.Method,
			"path":           r.URL.Path,
			"status":         wrapped.statusCode,
			"duration_ms":    duration.Milliseconds(),
			"correlation_id": cid,
		}
		b, _ := json.Marshal(entry)
		log.Print(string(b))
	})
}

func (g *AdvancedGateway) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Find appropriate rate limiter
		limiter := g.rateLimiters["/api/"] // Default
		for path, l := range g.rateLimiters {
			if strings.HasPrefix(r.URL.Path, path) {
				limiter = l
				break
			}
		}

		if limiter != nil && !limiter.Allow() {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (g *AdvancedGateway) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for health, metrics, websocket, and v1 enroll/events HMAC
		if r.URL.Path == "/health" || r.URL.Path == "/metrics" || r.URL.Path == "/ws" || r.URL.Path == "/v1/enroll" || r.URL.Path == "/v1/events" {
			next.ServeHTTP(w, r)
			return
		}
		// Agent config uses HMAC headers, no JWT
		if strings.HasPrefix(r.URL.Path, "/api/agent/config") {
			next.ServeHTTP(w, r)
			return
		}
		// Require JWT for all other /api/* requests
		if strings.HasPrefix(r.URL.Path, "/api/") {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
				http.Error(w, "missing bearer token", http.StatusUnauthorized)
				return
			}
			tokenStr := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer"))
			if !g.validateJWT(tokenStr) {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (g *AdvancedGateway) validateJWT(tokenStr string) bool {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(g.authService.JWTSecret), nil
	})
	if err != nil || !token.Valid {
		return false
	}
	return true
}

// HMAC validation for agent events on /v1/events
func (g *AdvancedGateway) eventsIngestV1Handler(w http.ResponseWriter, r *http.Request) {
	// Read original body for HMAC verification and forwarding
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "unable to read body", http.StatusBadRequest)
		return
	}
	r.Body.Close()

	ts := r.Header.Get("X-Timestamp")
	sig := r.Header.Get("X-Signature")
	if ts == "" || sig == "" {
		http.Error(w, "missing signature headers", http.StatusUnauthorized)
		return
	}

	if !g.validateHMAC(ts, bodyBytes, sig) {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	// Forward to ingest service
	serviceConfig := g.services["ingest"]
	if serviceConfig == nil {
		http.Error(w, "Ingest service not available", http.StatusServiceUnavailable)
		return
	}

	// Create a new request with the original body bytes
	req, err := http.NewRequest("POST", serviceConfig.URL+"/events", io.NopCloser(strings.NewReader(string(bodyBytes))))
	if err != nil {
		http.Error(w, "Error creating request", http.StatusInternalServerError)
		return
	}
	for k, vals := range r.Header {
		for _, v := range vals {
			req.Header.Add(k, v)
		}
	}

	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Error forwarding request", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)

	// Broadcast notification to WebSocket clients
	g.broadcast(WebSocketMessage{Type: "event", Data: map[string]interface{}{"status": resp.StatusCode, "ts": time.Now()}, Timestamp: time.Now()})
}

func (g *AdvancedGateway) validateHMAC(ts string, body []byte, providedSig string) bool {
	mac := hmac.New(sha256.New, []byte(g.authService.HMACSecret))
	mac.Write([]byte(ts))
	mac.Write(body)
	computed := hex.EncodeToString(mac.Sum(nil))
	provided := strings.ToLower(strings.TrimSpace(providedSig))
	provided = strings.TrimPrefix(provided, "sha256=")
	return hmac.Equal([]byte(computed), []byte(provided))
}

func (g *AdvancedGateway) metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(wrapped, r)

		// Update metrics
		g.metrics.RequestCount++
		if wrapped.statusCode >= 400 {
			g.metrics.ErrorCount++
		}

		duration := time.Since(start).Seconds()
		g.metrics.ResponseTime = (g.metrics.ResponseTime + duration) / 2
		g.metrics.LastUpdated = time.Now()
	})
}

func (g *AdvancedGateway) circuitBreakerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract service name from path
		serviceName := g.extractServiceName(r.URL.Path)
		if serviceName == "" {
			next.ServeHTTP(w, r)
			return
		}

		breaker, exists := g.circuitBreakers[serviceName]
		if !exists {
			next.ServeHTTP(w, r)
			return
		}

		// Check circuit breaker state
		if breaker.State == "open" {
			if time.Since(breaker.LastFailTime) > breaker.Timeout {
				breaker.State = "half-open"
			} else {
				http.Error(w, "Service temporarily unavailable", http.StatusServiceUnavailable)
				return
			}
		}

		// Execute request
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(wrapped, r)

		// Update circuit breaker based on response
		if wrapped.statusCode >= 500 {
			breaker.FailureCount++
			breaker.LastFailTime = time.Now()
			if breaker.FailureCount >= breaker.Threshold {
				breaker.State = "open"
			}
		} else {
			breaker.SuccessCount++
			if breaker.State == "half-open" && breaker.SuccessCount >= 3 {
				breaker.State = "closed"
				breaker.FailureCount = 0
				breaker.SuccessCount = 0
			}
		}
	})
}

func (g *AdvancedGateway) healthHandler(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now(),
		"version":   "1.0.0",
		"services":  len(g.services),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

func (g *AdvancedGateway) metricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(g.metrics)
}

func (g *AdvancedGateway) websocketHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := g.wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}

	g.wsMu.Lock()
	g.wsClients[conn] = struct{}{}
	g.wsMu.Unlock()
	defer func() {
		g.wsMu.Lock()
		delete(g.wsClients, conn)
		g.wsMu.Unlock()
		conn.Close()
	}()

	g.metrics.ActiveConnections++

	// Send periodic updates
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		message := WebSocketMessage{
			Type:      "metrics",
			Data:      g.metrics,
			Timestamp: time.Now(),
		}
		if err := conn.WriteJSON(message); err != nil {
			log.Printf("WebSocket write error: %v", err)
			return
		}
	}
}

func (g *AdvancedGateway) broadcast(message WebSocketMessage) {
	g.wsMu.Lock()
	defer g.wsMu.Unlock()
	for c := range g.wsClients {
		_ = c.WriteJSON(message)
	}
}

func (g *AdvancedGateway) eventsHandler(w http.ResponseWriter, r *http.Request) {
	// Forward to ingest service
	serviceConfig := g.services["ingest"]
	if serviceConfig == nil {
		http.Error(w, "Ingest service not available", http.StatusServiceUnavailable)
		return
	}

	g.proxyRequest(w, r, serviceConfig.URL+"/events")
}

func (g *AdvancedGateway) searchHandler(w http.ResponseWriter, r *http.Request) {
	// Forward to search service
	serviceConfig := g.services["search"]
	if serviceConfig == nil {
		http.Error(w, "Search service not available", http.StatusServiceUnavailable)
		return
	}

	g.proxyRequest(w, r, serviceConfig.URL+"/search")
}

func (g *AdvancedGateway) servicesHandler(w http.ResponseWriter, r *http.Request) {
	services := make([]map[string]interface{}, 0)
	for _, config := range g.services {
		service := map[string]interface{}{
			"name":    config.Name,
			"url":     config.URL,
			"port":    config.Port,
			"enabled": config.Enabled,
		}
		services = append(services, service)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(services)
}

func (g *AdvancedGateway) serviceHealthHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	serviceName := vars["service"]

	config, exists := g.services[serviceName]
	if !exists {
		http.Error(w, "Service not found", http.StatusNotFound)
		return
	}

	// Check service health
	health := g.checkServiceHealth(config)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

func (g *AdvancedGateway) restartServiceHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	serviceName := vars["service"]

	// TODO: Implement actual service restart logic
	response := map[string]interface{}{
		"message": fmt.Sprintf("Service %s restart initiated", serviceName),
		"status":  "success",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (g *AdvancedGateway) configHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		// Return current configuration
		config := map[string]interface{}{
			"services":         g.services,
			"rate_limits":      g.rateLimiters,
			"circuit_breakers": g.circuitBreakers,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(config)
	case "PUT":
		// Update configuration
		var newConfig map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
			http.Error(w, "Invalid configuration", http.StatusBadRequest)
			return
		}

		// TODO: Implement configuration update logic
		response := map[string]interface{}{
			"message": "Configuration updated successfully",
			"status":  "success",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (g *AdvancedGateway) createServiceHandler(_ string, config *ServiceConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		g.proxyRequest(w, r, config.URL)
	}
}

func (g *AdvancedGateway) proxyRequest(w http.ResponseWriter, r *http.Request, targetURL string) {
	// Create new request
	req, err := http.NewRequest(r.Method, targetURL+r.URL.Path, r.Body)
	if err != nil {
		http.Error(w, "Error creating request", http.StatusInternalServerError)
		return
	}

	// Copy headers
	for key, values := range r.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	// Ensure correlation header is forwarded
	cid := getCorrelationID(r.Context())
	if cid != "" {
		req.Header.Set(correlationHeader, cid)
	}
	// Ensure trace headers
	if req.Header.Get(traceParentHeader) == "" {
		req.Header.Set(traceParentHeader, generateTraceParent())
	}
	if req.Header.Get(traceStateHeader) == "" {
		// optional; leave empty or set tenant
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Error forwarding request", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	// Include correlation and trace on response
	if cid != "" {
		w.Header().Set(correlationHeader, cid)
	}
	if tp := req.Header.Get(traceParentHeader); tp != "" {
		w.Header().Set(traceParentHeader, tp)
	}

	// Set status code
	w.WriteHeader(resp.StatusCode)

	// Copy response body
	io.Copy(w, resp.Body)
}

func (g *AdvancedGateway) checkServiceHealth(config *ServiceConfig) *ServiceHealth {
	start := time.Now()

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(config.URL + config.Health)

	responseTime := time.Since(start).Milliseconds()

	health := &ServiceHealth{
		Service:      config.Name,
		LastCheck:    time.Now(),
		ResponseTime: responseTime,
	}

	if err != nil || resp.StatusCode != 200 {
		health.Status = "unhealthy"
		health.ErrorRate = 1.0
	} else {
		health.Status = "healthy"
		health.ErrorRate = 0.0
	}

	if resp != nil {
		resp.Body.Close()
	}

	return health
}

func (g *AdvancedGateway) monitorServices() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		for _, config := range g.services {
			go func(cfg *ServiceConfig) {
				health := g.checkServiceHealth(cfg)
				log.Printf("Service %s: %s (%.2fms)", cfg.Name, health.Status, float64(health.ResponseTime))
			}(config)
		}
	}
}

func (g *AdvancedGateway) collectMetrics() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// Update metrics
		g.metrics.LastUpdated = time.Now()
	}
}

func (g *AdvancedGateway) extractServiceName(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) >= 3 && parts[1] == "api" {
		return parts[2]
	}
	return ""
}

func (g *AdvancedGateway) Start(port string) {
	log.Printf("Advanced Gateway starting on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, g.router))
}

// Response writer wrapper to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Correlation ID helpers

func withCorrelationID(ctx context.Context, cid string) context.Context {
	return context.WithValue(ctx, correlationKey, cid)
}

func getCorrelationID(ctx context.Context) string {
	if v := ctx.Value(correlationKey); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// fallback simple generator
func generateCorrelationID() string {
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), mrand.Int63())
}

func generateTraceParent() string {
	// version 00, 16-byte trace id, 8-byte span id, flags 01
	traceID := make([]byte, 16)
	spanID := make([]byte, 8)
	if _, err := rand.Read(traceID); err != nil {
		mrand.Read(traceID)
	}
	if _, err := rand.Read(spanID); err != nil {
		mrand.Read(spanID)
	}
	return fmt.Sprintf("00-%s-%s-01", hex.EncodeToString(traceID), hex.EncodeToString(spanID))
}

func main() {
	_ = godotenv.Load()
	gateway := NewAdvancedGateway()
	gateway.Initialize()
	gateway.Start("8080")
}

// Admin: create enrollment token
func (g *AdvancedGateway) createEnrollmentTokenHandler(w http.ResponseWriter, r *http.Request) {
	token := generateRandomHex(16)
	g.agentsMu.Lock()
	g.enrollTokens[token] = time.Now().Add(15 * time.Minute)
	g.agentsMu.Unlock()
	if g.chConn != nil {
		ctx := context.Background()
		_ = g.chConn.Exec(ctx, "INSERT INTO musafir_enroll_tokens (token, expires_at, created_at, created_by) VALUES (?, ?, ?, ?)", token, time.Now().Add(15*time.Minute), time.Now(), "admin")
	}
	resp := map[string]string{"enrollment_token": token}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// POST /v1/enroll { token: "..." }
func (g *AdvancedGateway) agentEnrollHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token == "" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	g.agentsMu.Lock()
	exp, ok := g.enrollTokens[req.Token]
	if !ok || time.Now().After(exp) {
		g.agentsMu.Unlock()
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	delete(g.enrollTokens, req.Token)
	agentID := generateRandomHex(12)
	hmacSecret := generateRandomHex(24)
	rec := &AgentRecord{ID: agentID, Token: req.Token, HMAC: hmacSecret, CreatedAt: time.Now(), LastSeen: time.Now()}
	g.agentRecords[agentID] = rec
	g.agentsMu.Unlock()
	if g.chConn != nil {
		ctx := context.Background()
		_ = g.chConn.Exec(ctx, "INSERT INTO musafir_agents (id, token, hmac, created_at, last_seen) VALUES (?, ?, ?, ?, ?)", agentID, req.Token, hmacSecret, time.Now(), time.Now())
	}
	cfg := AgentConfig{GatewayURL: g.discoverGatewayURL(), PollInterval: 30, UseMTLS: false}
	resp := map[string]interface{}{"agent_id": agentID, "hmac": hmacSecret, "config": cfg}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// GET /api/agent/config with headers: X-Agent-Id, X-Timestamp, X-Signature
func (g *AdvancedGateway) agentConfigHandler(w http.ResponseWriter, r *http.Request) {
	agentID := r.Header.Get("X-Agent-Id")
	ts := r.Header.Get("X-Timestamp")
	sig := r.Header.Get("X-Signature")
	if agentID == "" || ts == "" || sig == "" {
		http.Error(w, "missing headers", http.StatusUnauthorized)
		return
	}
	if !g.validateAgentSignature(agentID, ts, nil, sig) {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}
	g.agentsMu.Lock()
	rec := g.agentRecords[agentID]
	if rec != nil {
		rec.LastSeen = time.Now()
	}
	g.agentsMu.Unlock()
	if g.chConn != nil {
		ctx := context.Background()
		_ = g.chConn.Exec(ctx, "ALTER TABLE musafir_agents UPDATE last_seen = ? WHERE id = ?", time.Now(), agentID)
	}
	cfg := AgentConfig{GatewayURL: g.discoverGatewayURL(), PollInterval: 30, UseMTLS: false}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cfg)
}

func (g *AdvancedGateway) validateAgentSignature(agentID, ts string, body []byte, provided string) bool {
	g.agentsMu.Lock()
	rec := g.agentRecords[agentID]
	g.agentsMu.Unlock()
	if rec == nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(rec.HMAC))
	mac.Write([]byte(ts))
	if body != nil {
		mac.Write(body)
	}
	computed := hex.EncodeToString(mac.Sum(nil))
	p := strings.ToLower(strings.TrimSpace(provided))
	p = strings.TrimPrefix(p, "sha256=")
	return hmac.Equal([]byte(computed), []byte(p))
}

func (g *AdvancedGateway) discoverGatewayURL() string {
	// Basic discovery for return URL; can be enhanced
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	return "http://" + "localhost:" + port
}

func generateRandomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		mrand.Read(b)
	}
	return hex.EncodeToString(b)
}

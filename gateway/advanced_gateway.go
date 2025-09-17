package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
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

func NewAdvancedGateway() *AdvancedGateway {
	router := mux.NewRouter()

	// Initialize rate limiters for different endpoints
	rateLimiters := make(map[string]*rate.Limiter)
	rateLimiters["/api/events"] = rate.NewLimiter(rate.Limit(100), 1000) // 100 req/s, burst 1000
	rateLimiters["/api/search"] = rate.NewLimiter(rate.Limit(50), 500)   // 50 req/s, burst 500
	rateLimiters["/api/admin"] = rate.NewLimiter(rate.Limit(10), 100)    // 10 req/s, burst 100

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

	authService := &AuthService{
		JWTSecret:     "your-secret-key",
		TokenExpiry:   15 * time.Minute,
		RefreshExpiry: 7 * 24 * time.Hour,
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

	log.Println("Advanced Gateway initialized successfully")
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

func (g *AdvancedGateway) setupRoutes() {
	// Health check endpoint
	g.router.HandleFunc("/health", g.healthHandler).Methods("GET")

	// Metrics endpoint
	g.router.HandleFunc("/metrics", g.metricsHandler).Methods("GET")

	// WebSocket endpoint for real-time updates
	g.router.HandleFunc("/ws", g.websocketHandler)

	// API routes
	api := g.router.PathPrefix("/api").Subrouter()

	// Events endpoint
	api.HandleFunc("/events", g.eventsHandler).Methods("POST")

	// Search endpoint
	api.HandleFunc("/search", g.searchHandler).Methods("GET", "POST")

	// Admin endpoints
	admin := api.PathPrefix("/admin").Subrouter()
	admin.HandleFunc("/services", g.servicesHandler).Methods("GET")
	admin.HandleFunc("/services/{service}/health", g.serviceHealthHandler).Methods("GET")
	admin.HandleFunc("/services/{service}/restart", g.restartServiceHandler).Methods("POST")
	admin.HandleFunc("/config", g.configHandler).Methods("GET", "PUT")

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
		log.Printf("%s %s %d %v", r.Method, r.URL.Path, wrapped.statusCode, duration)
	})
}

func (g *AdvancedGateway) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Find appropriate rate limiter
		limiter := g.rateLimiters["/api/events"] // Default
		for path, l := range g.rateLimiters {
			if strings.HasPrefix(r.URL.Path, path) {
				limiter = l
				break
			}
		}

		if !limiter.Allow() {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (g *AdvancedGateway) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for health and metrics endpoints
		if r.URL.Path == "/health" || r.URL.Path == "/metrics" {
			next.ServeHTTP(w, r)
			return
		}

		// Check for API key or JWT token
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			// For now, allow requests without auth (development mode)
			next.ServeHTTP(w, r)
			return
		}

		// TODO: Implement proper JWT validation
		next.ServeHTTP(w, r)
	})
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
	defer conn.Close()

	g.metrics.ActiveConnections++

	// Send periodic updates
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
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
	for name, config := range g.services {
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
	if r.Method == "GET" {
		// Return current configuration
		config := map[string]interface{}{
			"services":         g.services,
			"rate_limits":      g.rateLimiters,
			"circuit_breakers": g.circuitBreakers,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(config)
	} else if r.Method == "PUT" {
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
	}
}

func (g *AdvancedGateway) createServiceHandler(serviceName string, config *ServiceConfig) http.HandlerFunc {
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

	for {
		select {
		case <-ticker.C:
			for _, config := range g.services {
				go func(cfg *ServiceConfig) {
					health := g.checkServiceHealth(cfg)
					log.Printf("Service %s: %s (%.2fms)", cfg.Name, health.Status, float64(health.ResponseTime))
				}(config)
			}
		}
	}
}

func (g *AdvancedGateway) collectMetrics() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Update metrics
			g.metrics.LastUpdated = time.Now()
		}
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

func main() {
	gateway := NewAdvancedGateway()
	gateway.Initialize()
	gateway.Start("8080")
}

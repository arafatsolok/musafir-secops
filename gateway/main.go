package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/segmentio/kafka-go"
)

type ServiceConfig struct {
	Name    string
	URL     string
	Port    string
	Health  string
	Enabled bool
}

type QueryRequest struct {
	Query string `json:"query"`
}

type QueryResponse struct {
	Columns       []string                 `json:"columns"`
	Rows          []map[string]interface{} `json:"rows"`
	ExecutionTime int64                    `json:"executionTime"`
	RowCount      int                      `json:"rowCount"`
}

type ServiceHealth struct {
	Service string `json:"service"`
	Status  string `json:"status"`
	URL     string `json:"url"`
	Uptime  string `json:"uptime,omitempty"`
	Error   string `json:"error,omitempty"`
}

var services = map[string]ServiceConfig{
	"ingest":      {Name: "Ingest", URL: "http://localhost:8081", Port: "8081", Health: "/health", Enabled: true},
	"detect":      {Name: "Detect", URL: "http://localhost:8082", Port: "8082", Health: "/health", Enabled: true},
	"respond":     {Name: "Respond", URL: "http://localhost:8083", Port: "8083", Health: "/health", Enabled: true},
	"ueba":        {Name: "UEBA", URL: "http://localhost:8084", Port: "8084", Health: "/health", Enabled: true},
	"threatintel": {Name: "Threat Intel", URL: "http://localhost:8085", Port: "8085", Health: "/health", Enabled: true},
	"correlate":   {Name: "Correlate", URL: "http://localhost:8086", Port: "8086", Health: "/health", Enabled: true},
	"sandbox":     {Name: "Sandbox", URL: "http://localhost:8087", Port: "8087", Health: "/health", Enabled: true},
	"ml":          {Name: "ML", URL: "http://localhost:8088", Port: "8088", Health: "/health", Enabled: true},
	"mdm":         {Name: "MDM", URL: "http://localhost:8089", Port: "8089", Health: "/health", Enabled: true},
	"yara":        {Name: "YARA", URL: "http://localhost:8090", Port: "8090", Health: "/health", Enabled: true},
	"cases":       {Name: "Cases", URL: "http://localhost:8091", Port: "8091", Health: "/health", Enabled: true},
	"cloud":       {Name: "Cloud", URL: "http://localhost:8092", Port: "8092", Health: "/health", Enabled: true},
	"network":     {Name: "Network", URL: "http://localhost:8093", Port: "8093", Health: "/health", Enabled: true},
	"email":       {Name: "Email", URL: "http://localhost:8094", Port: "8094", Health: "/health", Enabled: true},
	"identity":    {Name: "Identity", URL: "http://localhost:8095", Port: "8095", Health: "/health", Enabled: true},
	"vuln":        {Name: "Vulnerability", URL: "http://localhost:8096", Port: "8096", Health: "/health", Enabled: true},
	"compliance":  {Name: "Compliance", URL: "http://localhost:8097", Port: "8097", Health: "/health", Enabled: true},
	"slsa":        {Name: "SLSA", URL: "http://localhost:8098", Port: "8098", Health: "/health", Enabled: true},
	"tenant":      {Name: "Tenant", URL: "http://localhost:8099", Port: "8099", Health: "/health", Enabled: true},
	"monitor":     {Name: "Monitor", URL: "http://localhost:9090", Port: "9090", Health: "/health", Enabled: true},
	"ai":          {Name: "AI", URL: "http://localhost:9001", Port: "9001", Health: "/health", Enabled: true},
}

func newKafkaWriter(brokersCSV, topic string) *kafka.Writer {
	brokers := strings.Split(brokersCSV, ",")
	return &kafka.Writer{
		Addr:         kafka.TCP(brokers...),
		Topic:        topic,
		Balancer:     &kafka.LeastBytes{},
		RequiredAcks: kafka.RequireOne,
	}
}

func checkServiceHealth(serviceName string, config ServiceConfig) ServiceHealth {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(config.URL + config.Health)

	health := ServiceHealth{
		Service: serviceName,
		URL:     config.URL,
		Status:  "unhealthy",
	}

	if err != nil {
		health.Error = err.Error()
		return health
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		health.Status = "healthy"
	} else {
		health.Status = "degraded"
		health.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}

	return health
}

func getAllServicesHealth() []ServiceHealth {
	var healthChecks []ServiceHealth
	for name, config := range services {
		if config.Enabled {
			healthChecks = append(healthChecks, checkServiceHealth(name, config))
		}
	}
	return healthChecks
}

func proxyToService(serviceName string, w http.ResponseWriter, r *http.Request) {
	config, exists := services[serviceName]
	if !exists || !config.Enabled {
		http.Error(w, "Service not found or disabled", http.StatusNotFound)
		return
	}

	// Create new request
	targetURL := config.URL + r.URL.Path
	req, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}

	// Copy headers
	for key, values := range r.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	// Make request
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Service unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func main() {
	brokers := os.Getenv("KAFKA_BROKERS")
	if brokers == "" {
		brokers = "localhost:9092"
	}
	topic := os.Getenv("KAFKA_TOPIC")
	if topic == "" {
		topic = "musafir.events"
	}

	writer := newKafkaWriter(brokers, topic)
	defer writer.Close()

	mux := http.NewServeMux()

	// Health check
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// Service health dashboard
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		healthChecks := getAllServicesHealth()
		json.NewEncoder(w).Encode(healthChecks)
	})

	// Events ingestion
	mux.HandleFunc("/v1/events", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2<<20))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = r.Body.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		msg := kafka.Message{Value: body}
		if err := writer.WriteMessages(ctx, msg); err != nil {
			log.Printf("kafka write error: %v", err)
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})

	// Events API for dashboard - proxy to ingest service
	mux.HandleFunc("/api/events", func(w http.ResponseWriter, r *http.Request) {
		proxyToService("ingest", w, r)
	})

	// Query workbench endpoints
	mux.HandleFunc("/api/query/execute", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var queryReq QueryRequest
		if err := json.NewDecoder(r.Body).Decode(&queryReq); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		// For now, return mock data - in production this would query ClickHouse
		response := QueryResponse{
			Columns: []string{"timestamp", "service", "status", "message"},
			Rows: []map[string]interface{}{
				{"timestamp": time.Now().Format(time.RFC3339), "service": "gateway", "status": "healthy", "message": "Service running"},
				{"timestamp": time.Now().Add(-1 * time.Minute).Format(time.RFC3339), "service": "ingest", "status": "healthy", "message": "Processing events"},
			},
			ExecutionTime: 15,
			RowCount:      2,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	// Query management endpoints
	mux.HandleFunc("/api/queries/saved", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]map[string]interface{}{})
	})

	mux.HandleFunc("/api/queries/history", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{})
	})

	mux.HandleFunc("/api/queries/save", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "saved"})
	})

	// Metrics endpoint - proxy to monitor service
	mux.HandleFunc("/api/metrics", func(w http.ResponseWriter, r *http.Request) {
		proxyToService("monitor", w, r)
	})

	// Service management endpoints
	mux.HandleFunc("/api/services", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(services)
	})

	mux.HandleFunc("/api/services/start", func(w http.ResponseWriter, r *http.Request) {
		// In production, this would start the service
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "started"})
	})

	mux.HandleFunc("/api/services/stop", func(w http.ResponseWriter, r *http.Request) {
		// In production, this would stop the service
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
	})

	mux.HandleFunc("/api/services/restart", func(w http.ResponseWriter, r *http.Request) {
		// In production, this would restart the service
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "restarted"})
	})

	// Configuration management
	mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		config := map[string]interface{}{
			"kafka_brokers": brokers,
			"kafka_topic":   topic,
			"services":      services,
			"environment":   "development",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(config)
	})

	// Logs endpoint
	mux.HandleFunc("/api/logs", func(w http.ResponseWriter, r *http.Request) {
		// Mock logs - in production this would fetch from log aggregation
		logs := []map[string]interface{}{
			{
				"timestamp": time.Now().Format(time.RFC3339),
				"service":   "gateway",
				"level":     "INFO",
				"message":   "Gateway started successfully",
			},
			{
				"timestamp": time.Now().Add(-1 * time.Minute).Format(time.RFC3339),
				"service":   "ingest",
				"level":     "INFO",
				"message":   "Processing 150 events",
			},
			{
				"timestamp": time.Now().Add(-2 * time.Minute).Format(time.RFC3339),
				"service":   "detect",
				"level":     "WARN",
				"message":   "High CPU usage detected",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(logs)
	})

	// Service-specific routing
	for serviceName := range services {
		pattern := "/api/" + serviceName + "/"
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			// Extract service name from path
			pathParts := strings.Split(r.URL.Path, "/")
			if len(pathParts) >= 3 {
				serviceName := pathParts[2]
				proxyToService(serviceName, w, r)
			} else {
				http.Error(w, "Invalid service path", http.StatusBadRequest)
			}
		})
	}

	// Setup mTLS server
	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	// Load certificates for mTLS
	certFile := os.Getenv("TLS_CERT_FILE")
	keyFile := os.Getenv("TLS_KEY_FILE")
	caFile := os.Getenv("TLS_CA_FILE")

	if certFile != "" && keyFile != "" {
		// Load server certificate
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			log.Fatalf("failed to load server certificate: %v", err)
		}

		// Load CA certificate for client verification
		caCert, err := os.ReadFile(caFile)
		if err != nil {
			log.Fatalf("failed to load CA certificate: %v", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		// Configure TLS
		server.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    caCertPool,
		}

		log.Printf("gateway listening with mTLS on %s -> kafka[%s] topic[%s]", server.Addr, brokers, topic)
		if err := server.ListenAndServeTLS("", ""); err != nil {
			log.Fatalf("gateway failed: %v", err)
		}
	} else {
		log.Printf("gateway listening on %s -> kafka[%s] topic[%s] (no TLS)", server.Addr, brokers, topic)
		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("gateway failed: %v", err)
		}
	}
}

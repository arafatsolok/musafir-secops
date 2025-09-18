package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Envelope defines the common event schema sent by the agent
type Envelope struct {
	Ts       string                 `json:"ts"`
	TenantID string                 `json:"tenant_id"`
	Asset    map[string]string      `json:"asset"`
	User     map[string]string      `json:"user"`
	Event    map[string]interface{} `json:"event"`
	Ingest   map[string]string      `json:"ingest"`
}

const (
	diskQueueFile = "musafir_agent_queue.log"
	maxRetry      = 5
)

// Common functionality shared across all platforms
func sendEventToGateway(gatewayURL string, data []byte) {
	client := buildHTTPClient()
	if err := postWithRetry(client, gatewayURL+"/v1/events", data); err != nil {
		persistToDiskQueue(data)
		log.Printf("post failed; queued to disk: %v", err)
	}

	// Attempt draining any queued payloads opportunistically
	drainDiskQueue(client, gatewayURL+"/v1/events")
}

func buildHTTPClient() *http.Client {
	// Setup mTLS client
	client := &http.Client{Timeout: 10 * time.Second}

	// Load client certificate for mTLS (optional, if provided)
	certFile := os.Getenv("TLS_CERT_FILE")
	keyFile := os.Getenv("TLS_KEY_FILE")
	caFile := os.Getenv("TLS_CA_FILE")

	if certFile != "" && keyFile != "" && caFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			log.Printf("failed to load client certificate: %v", err)
		} else {
			caCert, err := os.ReadFile(caFile)
			if err != nil {
				log.Printf("failed to load CA certificate: %v", err)
			} else {
				caCertPool := x509.NewCertPool()
				caCertPool.AppendCertsFromPEM(caCert)
				client.Transport = &http.Transport{
					TLSClientConfig: &tls.Config{
						Certificates: []tls.Certificate{cert},
						RootCAs:      caCertPool,
					},
				}
			}
		}
	}

	return client
}

func postWithRetry(client *http.Client, url string, data []byte) error {
	var lastErr error
	backoff := 500 * time.Millisecond
	for attempt := 0; attempt < maxRetry; attempt++ {
		if attempt > 0 {
			time.Sleep(backoff)
			if backoff < 10*time.Second {
				backoff *= 2
			}
		}

		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		
		// Add timestamp for HMAC validation
		ts := time.Now().UTC().Format(time.RFC3339)
		req.Header.Set("X-Timestamp", ts)
		
		// HMAC signing with timestamp
		secret := strings.TrimSpace(os.Getenv("AGENT_HMAC_SECRET"))
		if secret == "" {
			secret = "default-hmac-secret-for-demo" // Default for demo purposes
		}
		
		// Create HMAC with timestamp + body
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(ts))
		mac.Write(data)
		sign := hex.EncodeToString(mac.Sum(nil))
		req.Header.Set("X-Signature", "sha256="+sign)

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		lastErr = fmtError(resp.StatusCode)
	}
	return lastErr
}

func fmtError(code int) error {
	return &httpError{code: code}
}

type httpError struct{ code int }

func (e *httpError) Error() string { return "http error: " + http.StatusText(e.code) }

func persistToDiskQueue(data []byte) {
	path := filepath.Join(os.TempDir(), diskQueueFile)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("disk queue open failed: %v", err)
		return
	}
	defer f.Close()
	f.Write(data)
	f.Write([]byte("\n"))
}

func drainDiskQueue(client *http.Client, url string) {
	path := filepath.Join(os.TempDir(), diskQueueFile)
	b, err := os.ReadFile(path)
	if err != nil || len(b) == 0 {
		return
	}
	lines := bytes.Split(b, []byte("\n"))
	var keep [][]byte
	for _, line := range lines {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		if err := postWithRetry(client, url, line); err != nil {
			keep = append(keep, line)
		}
	}
	if len(keep) == 0 {
		os.Remove(path)
		return
	}
	// rewrite leftovers
	_ = os.WriteFile(path, bytes.Join(keep, []byte("\n")), 0644)
}

// getHostname returns the system hostname
func getHostname() string {
	hostname, _ := os.Hostname()
	return hostname
}

// getEventSeverity returns the severity level for different event types
func getEventSeverity(eventType string) int {
	switch eventType {
	case "process_create":
		return 2 // Informational
	case "process_terminate":
		return 2 // Informational
	case "process_inject":
		return 4 // High
	case "process_hollow":
		return 5 // Critical
	default:
		return 3 // Medium
	}
}

// startHeartbeat sends heartbeat envelopes periodically via the normal event path

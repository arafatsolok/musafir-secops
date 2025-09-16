package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"os"
	"time"
)

// Common functionality shared across all platforms
func sendEventToGateway(gatewayURL string, data []byte) {
	req, err := http.NewRequest(http.MethodPost, gatewayURL+"/v1/events", bytes.NewReader(data))
	if err != nil {
		log.Fatalf("build request failed: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Setup mTLS client
	client := &http.Client{Timeout: 5 * time.Second}

	// Load client certificate for mTLS
	certFile := os.Getenv("TLS_CERT_FILE")
	keyFile := os.Getenv("TLS_KEY_FILE")
	caFile := os.Getenv("TLS_CA_FILE")

	if certFile != "" && keyFile != "" {
		// Load client certificate
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			log.Fatalf("failed to load client certificate: %v", err)
		}

		// Load CA certificate
		caCert, err := os.ReadFile(caFile)
		if err != nil {
			log.Fatalf("failed to load CA certificate: %v", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		// Configure TLS
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				RootCAs:      caCertPool,
			},
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("post failed: %v", err)
	}
	defer resp.Body.Close()
	log.Printf("gateway response: %s", resp.Status)
}

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/segmentio/kafka-go"
)

func newKafkaWriter(brokersCSV, topic string) *kafka.Writer {
	brokers := strings.Split(brokersCSV, ",")
	return &kafka.Writer{
		Addr:         kafka.TCP(brokers...),
		Topic:        topic,
		Balancer:     &kafka.LeastBytes{},
		RequiredAcks: kafka.RequireOne,
	}
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
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

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

	// Events API for dashboard
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		// For now, return empty array - in production this would query ClickHouse
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("[]"))
	})

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
		caCert, err := ioutil.ReadFile(caFile)
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

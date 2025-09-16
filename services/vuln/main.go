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

type VulnerabilityEvent struct {
	ID            string                 `json:"id"`
	Timestamp     time.Time              `json:"timestamp"`
	AssetID       string                 `json:"asset_id"`
	AssetType     string                 `json:"asset_type"`
	Hostname      string                 `json:"hostname"`
	IPAddress     string                 `json:"ip_address"`
	OS            string                 `json:"os"`
	OSVersion     string                 `json:"os_version"`
	CVE           string                 `json:"cve"`
	CVSS          float64                `json:"cvss"`
	Severity      string                 `json:"severity"`
	Title         string                 `json:"title"`
	Description   string                 `json:"description"`
	Package       string                 `json:"package"`
	Version       string                 `json:"version"`
	FixedVersion  string                 `json:"fixed_version"`
	Status        string                 `json:"status"` // open, patched, ignored
	FirstSeen     time.Time              `json:"first_seen"`
	LastSeen      time.Time              `json:"last_seen"`
	ExploitAvailable bool                `json:"exploit_available"`
	PatchAvailable  bool                 `json:"patch_available"`
	References    []string               `json:"references"`
	Metadata      map[string]interface{} `json:"metadata"`
}

type SBOMEvent struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	AssetID     string                 `json:"asset_id"`
	Format      string                 `json:"format"` // spdx, cyclonedx
	Version     string                 `json:"version"`
	Packages    []SBOMPackage          `json:"packages"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type SBOMPackage struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Type         string   `json:"type"`
	License      string   `json:"license"`
	Supplier     string   `json:"supplier"`
	Description  string   `json:"description"`
	Homepage     string   `json:"homepage"`
	DownloadURL  string   `json:"download_url"`
	Checksums    []string `json:"checksums"`
	Dependencies []string `json:"dependencies"`
}

type PatchEvent struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	AssetID     string                 `json:"asset_id"`
	PatchID     string                 `json:"patch_id"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Severity    string                 `json:"severity"`
	Status      string                 `json:"status"` // available, installed, failed
	Size        int64                  `json:"size"`
	RebootRequired bool                `json:"reboot_required"`
	Metadata    map[string]interface{} `json:"metadata"`
}

func main() {
	kbrokers := os.Getenv("KAFKA_BROKERS")
	if kbrokers == "" { kbrokers = "localhost:9092" }
	group := os.Getenv("KAFKA_GROUP")
	if group == "" { group = "vuln" }

	chDsn := os.Getenv("CLICKHOUSE_DSN")
	if chDsn == "" { chDsn = "tcp://localhost:9000?database=default" }

	ctx := context.Background()
	conn, err := ch.Open(&ch.Options{Addr: []string{"localhost:9000"}})
	if err != nil { log.Fatalf("clickhouse connect: %v", err) }
	defer conn.Close()

	// Ensure vulnerability tables exist
	createVulnerabilityTables(conn, ctx)

	writer := kafka.NewWriter(kafka.WriterConfig{
		Brokers: strings.Split(kbrokers, ","),
		Topic:   "musafir.vuln_events",
	})

	log.Printf("vulnerability management starting brokers=%s", kbrokers)

	// Simulate vulnerability scanning
	go simulateVulnerabilityScanning(writer, ctx)

	// Simulate SBOM analysis
	go simulateSBOMAnalysis(writer, ctx)

	// Simulate patch management
	go simulatePatchManagement(writer, ctx)

	// Keep running
	select {}
}

func createVulnerabilityTables(conn ch.Conn, ctx context.Context) {
	// Vulnerability events table
	ddl := `CREATE TABLE IF NOT EXISTS musafir_vuln_events (
  id String,
  timestamp DateTime,
  asset_id String,
  asset_type String,
  hostname String,
  ip_address String,
  os String,
  os_version String,
  cve String,
  cvss Float64,
  severity String,
  title String,
  description String,
  package String,
  version String,
  fixed_version String,
  status String,
  first_seen DateTime,
  last_seen DateTime,
  exploit_available UInt8,
  patch_available UInt8,
  references Array(String),
  metadata String
) ENGINE = MergeTree ORDER BY timestamp`
	
	if err := conn.Exec(ctx, ddl); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}

	// SBOM events table
	ddl2 := `CREATE TABLE IF NOT EXISTS musafir_sbom_events (
  id String,
  timestamp DateTime,
  asset_id String,
  format String,
  version String,
  packages String,
  metadata String
) ENGINE = MergeTree ORDER BY timestamp`
	
	if err := conn.Exec(ctx, ddl2); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}

	// Patch events table
	ddl3 := `CREATE TABLE IF NOT EXISTS musafir_patch_events (
  id String,
  timestamp DateTime,
  asset_id String,
  patch_id String,
  title String,
  description String,
  severity String,
  status String,
  size Int64,
  reboot_required UInt8,
  metadata String
) ENGINE = MergeTree ORDER BY timestamp`
	
	if err := conn.Exec(ctx, ddl3); err != nil {
		log.Fatalf("clickhouse ddl: %v", err)
	}
}

func simulateVulnerabilityScanning(writer *kafka.Writer, ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	cves := []string{
		"CVE-2023-1234", "CVE-2023-5678", "CVE-2023-9012",
		"CVE-2023-3456", "CVE-2023-7890", "CVE-2023-2345",
	}

	packages := []string{
		"openssl", "nginx", "apache2", "mysql", "postgresql",
		"nodejs", "python", "java", "docker", "kubernetes",
	}

	severities := []string{"critical", "high", "medium", "low"}

	for {
		select {
		case <-ticker.C:
			// Generate sample vulnerability events
			for i := 0; i < 3; i++ {
				cve := cves[time.Now().Second()%len(cves)]
				packageName := packages[time.Now().Second()%len(packages)]
				severity := severities[time.Now().Second()%len(severities)]

				event := VulnerabilityEvent{
					ID:            generateVulnEventID(),
					Timestamp:     time.Now(),
					AssetID:       "asset-" + time.Now().Format("20060102150405"),
					AssetType:     "server",
					Hostname:      "server-" + time.Now().Format("20060102150405"),
					IPAddress:     "192.168.1." + string(rune(100+i)),
					OS:            "ubuntu",
					OSVersion:     "22.04",
					CVE:           cve,
					CVSS:          getCVSSScore(severity),
					Severity:      severity,
					Title:         "Vulnerability in " + packageName,
					Description:   "A security vulnerability has been discovered in " + packageName,
					Package:       packageName,
					Version:       "1.0." + string(rune(48+i)),
					FixedVersion:  "1.0." + string(rune(49+i)),
					Status:        "open",
					FirstSeen:     time.Now().Add(-24 * time.Hour),
					LastSeen:      time.Now(),
					ExploitAvailable: severity == "critical" || severity == "high",
					PatchAvailable:  true,
					References:    []string{"https://cve.mitre.org/cgi-bin/cvename.cgi?name=" + cve},
					Metadata: map[string]interface{}{
						"scanner": "grype",
						"scan_id": "scan-" + time.Now().Format("20060102150405"),
					},
				}

				sendVulnEvent(event, writer, ctx)
			}
		}
	}
}

func simulateSBOMAnalysis(writer *kafka.Writer, ctx context.Context) {
	ticker := time.NewTicker(120 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Generate sample SBOM events
			event := SBOMEvent{
				ID:        generateVulnEventID(),
				Timestamp: time.Now(),
				AssetID:   "asset-" + time.Now().Format("20060102150405"),
				Format:    "cyclonedx",
				Version:   "1.4",
				Packages: []SBOMPackage{
					{
						Name:         "nginx",
						Version:      "1.18.0",
						Type:         "library",
						License:      "BSD-2-Clause",
						Supplier:     "nginx.org",
						Description:  "Web server",
						Homepage:     "https://nginx.org",
						DownloadURL:  "https://nginx.org/download/nginx-1.18.0.tar.gz",
						Checksums:    []string{"sha256:abc123...", "sha1:def456..."},
						Dependencies: []string{"openssl", "pcre"},
					},
					{
						Name:         "openssl",
						Version:      "1.1.1f",
						Type:         "library",
						License:      "OpenSSL",
						Supplier:     "openssl.org",
						Description:  "Cryptographic library",
						Homepage:     "https://openssl.org",
						DownloadURL:  "https://openssl.org/source/openssl-1.1.1f.tar.gz",
						Checksums:    []string{"sha256:ghi789...", "sha1:jkl012..."},
						Dependencies: []string{},
					},
				},
				Metadata: map[string]interface{}{
					"scanner": "syft",
					"scan_id": "sbom-" + time.Now().Format("20060102150405"),
				},
			}

			sendSBOMEvent(event, writer, ctx)
		}
	}
}

func simulatePatchManagement(writer *kafka.Writer, ctx context.Context) {
	ticker := time.NewTicker(180 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Generate sample patch events
			event := PatchEvent{
				ID:            generateVulnEventID(),
				Timestamp:     time.Now(),
				AssetID:       "asset-" + time.Now().Format("20060102150405"),
				PatchID:       "patch-" + time.Now().Format("20060102150405"),
				Title:         "Security Update for OpenSSL",
				Description:   "Critical security update for OpenSSL library",
				Severity:      "critical",
				Status:        "available",
				Size:          1024000,
				RebootRequired: true,
				Metadata: map[string]interface{}{
					"source": "ubuntu-security",
					"package": "openssl",
					"version": "1.1.1f-1ubuntu2.1",
				},
			}

			sendPatchEvent(event, writer, ctx)
		}
	}
}

func sendVulnEvent(event VulnerabilityEvent, writer *kafka.Writer, ctx context.Context) {
	eventData, _ := json.Marshal(event)
	if err := writer.WriteMessages(ctx, kafka.Message{Value: eventData}); err != nil {
		log.Printf("write vuln event: %v", err)
	} else {
		log.Printf("VULN EVENT: %s - %s (%s)", event.CVE, event.Severity, event.AssetID)
	}
}

func sendSBOMEvent(event SBOMEvent, writer *kafka.Writer, ctx context.Context) {
	eventData, _ := json.Marshal(event)
	if err := writer.WriteMessages(ctx, kafka.Message{Value: eventData}); err != nil {
		log.Printf("write sbom event: %v", err)
	} else {
		log.Printf("SBOM EVENT: %s - %d packages", event.AssetID, len(event.Packages))
	}
}

func sendPatchEvent(event PatchEvent, writer *kafka.Writer, ctx context.Context) {
	eventData, _ := json.Marshal(event)
	if err := writer.WriteMessages(ctx, kafka.Message{Value: eventData}); err != nil {
		log.Printf("write patch event: %v", err)
	} else {
		log.Printf("PATCH EVENT: %s - %s (%s)", event.PatchID, event.Title, event.Status)
	}
}

func generateVulnEventID() string {
	return "vuln-" + time.Now().Format("20060102150405")
}

func getCVSSScore(severity string) float64 {
	switch severity {
	case "critical":
		return 9.0 + float64(time.Now().Second()%10)/10.0
	case "high":
		return 7.0 + float64(time.Now().Second()%20)/10.0
	case "medium":
		return 4.0 + float64(time.Now().Second()%30)/10.0
	case "low":
		return 0.1 + float64(time.Now().Second()%40)/10.0
	default:
		return 5.0
	}
}

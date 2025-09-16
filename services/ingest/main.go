package main

import (
	"context"
	"database/sql"
	"log"
	"os"
	"strings"
	"time"

	ch "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/segmentio/kafka-go"
)

func main() {
	kbrokers := os.Getenv("KAFKA_BROKERS")
	if kbrokers == "" { kbrokers = "localhost:9092" }
	topic := os.Getenv("KAFKA_TOPIC")
	if topic == "" { topic = "musafir.events" }
	group := os.Getenv("KAFKA_GROUP")
	if group == "" { group = "ingest" }

	chDsn := os.Getenv("CLICKHOUSE_DSN")
	if chDsn == "" { chDsn = "tcp://localhost:9000?database=default" }

	ctx := context.Background()
	conn, err := ch.Open(&ch.Options{Addr: []string{"localhost:9000"}})
	if err != nil { log.Fatalf("clickhouse connect: %v", err) }
	defer conn.Close()

	// Ensure table exists
	ddl := `CREATE TABLE IF NOT EXISTS musafir_events_raw (\n  ts DateTime DEFAULT now(),\n  raw String\n) ENGINE = MergeTree ORDER BY ts`
	if err := conn.Exec(ctx, ddl); err != nil { log.Fatalf("clickhouse ddl: %v", err) }

	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:  strings.Split(kbrokers, ","),
		Topic:    topic,
		GroupID:  group,
		MinBytes: 1, MaxBytes: 10e6,
	})
	defer reader.Close()

	log.Printf("ingest consuming topic=%s brokers=%s", topic, kbrokers)
	for {
		m, err := reader.ReadMessage(ctx)
		if err != nil { log.Fatalf("kafka read: %v", err) }

		batch, err := conn.PrepareBatch(ctx, "INSERT INTO musafir_events_raw (raw)")
		if err != nil { log.Fatalf("clickhouse batch: %v", err) }
		if err := batch.Append(string(m.Value)); err != nil { log.Fatalf("append: %v", err) }
		if err := batch.Send(); err != nil { log.Fatalf("send: %v", err) }
	}
}

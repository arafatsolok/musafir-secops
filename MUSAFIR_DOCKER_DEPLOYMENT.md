# MUSAFIR Docker Deployment Guide

## Overview
This document provides comprehensive Docker containerization and deployment strategies for the MUSAFIR central web UI platform, covering development, staging, and production environments.

## 1. Container Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    MUSAFIR Platform                         │
├─────────────────────────────────────────────────────────────┤
│  Frontend (React)  │  API Gateway  │  Auth Service          │
├─────────────────────────────────────────────────────────────┤
│  Event Processor   │  Analytics    │  Alert Manager         │
├─────────────────────────────────────────────────────────────┤
│  Kafka            │  InfluxDB     │  MongoDB    │  Redis    │
├─────────────────────────────────────────────────────────────┤
│  Nginx            │  Prometheus   │  Grafana    │  Vault    │
└─────────────────────────────────────────────────────────────┘
```

## 2. Docker Compose Configuration

### 2.1 Main Docker Compose File

```yaml
# docker-compose.yml
version: '3.8'

services:
  # Frontend Service
  musafir-frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
      target: production
    container_name: musafir-frontend
    ports:
      - "3000:80"
    environment:
      - REACT_APP_API_URL=https://api.musafir.local
      - REACT_APP_WS_URL=wss://api.musafir.local/ws
    volumes:
      - ./frontend/nginx.conf:/etc/nginx/nginx.conf:ro
    networks:
      - musafir-network
    depends_on:
      - musafir-api-gateway
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:80/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  # API Gateway
  musafir-api-gateway:
    build:
      context: ./backend/api-gateway
      dockerfile: Dockerfile
    container_name: musafir-api-gateway
    ports:
      - "8080:8080"
      - "8443:8443"
    environment:
      - GIN_MODE=release
      - JWT_PRIVATE_KEY_PATH=/etc/musafir/keys/jwt-private.pem
      - JWT_PUBLIC_KEY_PATH=/etc/musafir/keys/jwt-public.pem
      - TLS_CERT_PATH=/etc/musafir/certs/server.crt
      - TLS_KEY_PATH=/etc/musafir/certs/server.key
      - REDIS_URL=redis://redis:6379
      - KAFKA_BROKERS=kafka:9092
    volumes:
      - ./certs:/etc/musafir/certs:ro
      - ./keys:/etc/musafir/keys:ro
      - ./config:/etc/musafir/config:ro
    networks:
      - musafir-network
    depends_on:
      - redis
      - kafka
      - musafir-auth-service
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Authentication Service
  musafir-auth-service:
    build:
      context: ./backend/auth-service
      dockerfile: Dockerfile
    container_name: musafir-auth-service
    ports:
      - "8081:8081"
    environment:
      - DATABASE_URL=mongodb://admin:password@mongodb:27017/musafir?authSource=admin
      - REDIS_URL=redis://redis:6379
      - JWT_PRIVATE_KEY_PATH=/etc/musafir/keys/jwt-private.pem
      - JWT_PUBLIC_KEY_PATH=/etc/musafir/keys/jwt-public.pem
      - ENCRYPTION_KEY_PATH=/etc/musafir/keys/encryption.key
    volumes:
      - ./keys:/etc/musafir/keys:ro
      - ./config:/etc/musafir/config:ro
    networks:
      - musafir-network
    depends_on:
      - mongodb
      - redis
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8081/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Event Processing Service
  musafir-event-processor:
    build:
      context: ./backend/event-processor
      dockerfile: Dockerfile
    container_name: musafir-event-processor
    environment:
      - KAFKA_BROKERS=kafka:9092
      - INFLUXDB_URL=http://influxdb:8086
      - INFLUXDB_TOKEN=admin-token
      - MONGODB_URL=mongodb://admin:password@mongodb:27017/musafir?authSource=admin
      - REDIS_URL=redis://redis:6379
    volumes:
      - ./config:/etc/musafir/config:ro
    networks:
      - musafir-network
    depends_on:
      - kafka
      - influxdb
      - mongodb
      - redis
    restart: unless-stopped
    deploy:
      replicas: 3

  # Analytics Service
  musafir-analytics:
    build:
      context: ./backend/analytics
      dockerfile: Dockerfile
    container_name: musafir-analytics
    ports:
      - "8082:8082"
    environment:
      - INFLUXDB_URL=http://influxdb:8086
      - INFLUXDB_TOKEN=admin-token
      - MONGODB_URL=mongodb://admin:password@mongodb:27017/musafir?authSource=admin
      - REDIS_URL=redis://redis:6379
    volumes:
      - ./config:/etc/musafir/config:ro
    networks:
      - musafir-network
    depends_on:
      - influxdb
      - mongodb
      - redis
    restart: unless-stopped

  # Alert Manager Service
  musafir-alert-manager:
    build:
      context: ./backend/alert-manager
      dockerfile: Dockerfile
    container_name: musafir-alert-manager
    ports:
      - "8083:8083"
    environment:
      - MONGODB_URL=mongodb://admin:password@mongodb:27017/musafir?authSource=admin
      - KAFKA_BROKERS=kafka:9092
      - SMTP_HOST=smtp.gmail.com
      - SMTP_PORT=587
      - SMTP_USERNAME=${SMTP_USERNAME}
      - SMTP_PASSWORD=${SMTP_PASSWORD}
    volumes:
      - ./config:/etc/musafir/config:ro
    networks:
      - musafir-network
    depends_on:
      - mongodb
      - kafka
    restart: unless-stopped

  # Data Ingestion Service
  musafir-ingestion:
    build:
      context: ./backend/ingestion
      dockerfile: Dockerfile
    container_name: musafir-ingestion
    ports:
      - "8084:8084"
    environment:
      - KAFKA_BROKERS=kafka:9092
      - TLS_CERT_PATH=/etc/musafir/certs/server.crt
      - TLS_KEY_PATH=/etc/musafir/certs/server.key
      - CA_CERT_PATH=/etc/musafir/certs/ca.crt
    volumes:
      - ./certs:/etc/musafir/certs:ro
      - ./config:/etc/musafir/config:ro
    networks:
      - musafir-network
    depends_on:
      - kafka
    restart: unless-stopped

  # Message Queue (Kafka)
  zookeeper:
    image: confluentinc/cp-zookeeper:7.4.0
    container_name: musafir-zookeeper
    environment:
      ZOOKEEPER_CLIENT_PORT: 2181
      ZOOKEEPER_TICK_TIME: 2000
    volumes:
      - zookeeper_data:/var/lib/zookeeper/data
      - zookeeper_logs:/var/lib/zookeeper/log
    networks:
      - musafir-network
    restart: unless-stopped

  kafka:
    image: confluentinc/cp-kafka:7.4.0
    container_name: musafir-kafka
    depends_on:
      - zookeeper
    ports:
      - "9092:9092"
      - "9094:9094"
    environment:
      KAFKA_BROKER_ID: 1
      KAFKA_ZOOKEEPER_CONNECT: zookeeper:2181
      KAFKA_LISTENER_SECURITY_PROTOCOL_MAP: PLAINTEXT:PLAINTEXT,PLAINTEXT_HOST:PLAINTEXT
      KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://kafka:9092,PLAINTEXT_HOST://localhost:9094
      KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR: 1
      KAFKA_TRANSACTION_STATE_LOG_MIN_ISR: 1
      KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR: 1
      KAFKA_AUTO_CREATE_TOPICS_ENABLE: true
      KAFKA_NUM_PARTITIONS: 3
      KAFKA_DEFAULT_REPLICATION_FACTOR: 1
    volumes:
      - kafka_data:/var/lib/kafka/data
    networks:
      - musafir-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "kafka-broker-api-versions", "--bootstrap-server", "localhost:9092"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Time Series Database (InfluxDB)
  influxdb:
    image: influxdb:2.7
    container_name: musafir-influxdb
    ports:
      - "8086:8086"
    environment:
      DOCKER_INFLUXDB_INIT_MODE: setup
      DOCKER_INFLUXDB_INIT_USERNAME: admin
      DOCKER_INFLUXDB_INIT_PASSWORD: password123
      DOCKER_INFLUXDB_INIT_ORG: musafir
      DOCKER_INFLUXDB_INIT_BUCKET: events
      DOCKER_INFLUXDB_INIT_ADMIN_TOKEN: admin-token
    volumes:
      - influxdb_data:/var/lib/influxdb2
      - influxdb_config:/etc/influxdb2
    networks:
      - musafir-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "influx", "ping"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Document Database (MongoDB)
  mongodb:
    image: mongo:6.0
    container_name: musafir-mongodb
    ports:
      - "27017:27017"
    environment:
      MONGO_INITDB_ROOT_USERNAME: admin
      MONGO_INITDB_ROOT_PASSWORD: password
      MONGO_INITDB_DATABASE: musafir
    volumes:
      - mongodb_data:/data/db
      - mongodb_config:/data/configdb
      - ./scripts/mongo-init.js:/docker-entrypoint-initdb.d/mongo-init.js:ro
    networks:
      - musafir-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "mongosh", "--eval", "db.adminCommand('ping')"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Cache (Redis)
  redis:
    image: redis:7.0-alpine
    container_name: musafir-redis
    ports:
      - "6379:6379"
    command: redis-server --appendonly yes --requirepass password123
    volumes:
      - redis_data:/data
    networks:
      - musafir-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "redis-cli", "-a", "password123", "ping"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Secrets Management (Vault)
  vault:
    image: vault:1.15.0
    container_name: musafir-vault
    ports:
      - "8200:8200"
    environment:
      VAULT_DEV_ROOT_TOKEN_ID: root-token
      VAULT_DEV_LISTEN_ADDRESS: 0.0.0.0:8200
    cap_add:
      - IPC_LOCK
    volumes:
      - vault_data:/vault/data
      - vault_logs:/vault/logs
      - ./config/vault.hcl:/vault/config/vault.hcl:ro
    networks:
      - musafir-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "vault", "status"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Reverse Proxy (Nginx)
  nginx:
    image: nginx:1.25-alpine
    container_name: musafir-nginx
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/conf.d:/etc/nginx/conf.d:ro
      - ./certs:/etc/nginx/certs:ro
      - nginx_logs:/var/log/nginx
    networks:
      - musafir-network
    depends_on:
      - musafir-frontend
      - musafir-api-gateway
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "nginx", "-t"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Monitoring (Prometheus)
  prometheus:
    image: prom/prometheus:v2.45.0
    container_name: musafir-prometheus
    ports:
      - "9090:9090"
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--storage.tsdb.retention.time=200h'
      - '--web.enable-lifecycle'
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus_data:/prometheus
    networks:
      - musafir-network
    restart: unless-stopped

  # Visualization (Grafana)
  grafana:
    image: grafana/grafana:10.0.0
    container_name: musafir-grafana
    ports:
      - "3001:3000"
    environment:
      GF_SECURITY_ADMIN_USER: admin
      GF_SECURITY_ADMIN_PASSWORD: admin123
      GF_INSTALL_PLUGINS: grafana-clock-panel,grafana-simple-json-datasource
    volumes:
      - grafana_data:/var/lib/grafana
      - ./monitoring/grafana/provisioning:/etc/grafana/provisioning:ro
      - ./monitoring/grafana/dashboards:/var/lib/grafana/dashboards:ro
    networks:
      - musafir-network
    depends_on:
      - prometheus
    restart: unless-stopped

volumes:
  kafka_data:
  zookeeper_data:
  zookeeper_logs:
  influxdb_data:
  influxdb_config:
  mongodb_data:
  mongodb_config:
  redis_data:
  vault_data:
  vault_logs:
  prometheus_data:
  grafana_data:
  nginx_logs:

networks:
  musafir-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16
```

## 3. Individual Service Dockerfiles

### 3.1 Frontend Dockerfile

```dockerfile
# frontend/Dockerfile
# Multi-stage build for React frontend
FROM node:18-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./
RUN npm ci --only=production

# Copy source code
COPY . .

# Build the application
RUN npm run build

# Production stage
FROM nginx:1.25-alpine AS production

# Copy built assets
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf

# Add health check
RUN apk add --no-cache curl

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nextjs -u 1001

# Set permissions
RUN chown -R nextjs:nodejs /usr/share/nginx/html && \
    chown -R nextjs:nodejs /var/cache/nginx && \
    chown -R nextjs:nodejs /var/log/nginx && \
    chown -R nextjs:nodejs /etc/nginx/conf.d

# Switch to non-root user
USER nextjs

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
```

### 3.2 Backend Service Dockerfile Template

```dockerfile
# backend/*/Dockerfile
FROM golang:1.21-alpine AS builder

# Install dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Create non-root user
RUN adduser -D -g '' appuser

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o app ./cmd/main.go

# Production stage
FROM scratch

# Copy certificates and timezone data
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy user
COPY --from=builder /etc/passwd /etc/passwd

# Copy binary
COPY --from=builder /build/app /app

# Switch to non-root user
USER appuser

EXPOSE 8080

ENTRYPOINT ["/app"]
```

## 4. Configuration Files

### 4.1 Nginx Configuration

```nginx
# nginx/nginx.conf
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
    use epoll;
    multi_accept on;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Logging
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';
    access_log /var/log/nginx/access.log main;

    # Performance
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;

    # Security headers
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css text/xml text/javascript application/javascript application/xml+rss application/json;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;

    # Upstream servers
    upstream api_backend {
        server musafir-api-gateway:8080;
        keepalive 32;
    }

    upstream frontend_backend {
        server musafir-frontend:80;
        keepalive 32;
    }

    # HTTP to HTTPS redirect
    server {
        listen 80;
        server_name _;
        return 301 https://$host$request_uri;
    }

    # Main HTTPS server
    server {
        listen 443 ssl http2;
        server_name musafir.local;

        # SSL configuration
        ssl_certificate /etc/nginx/certs/server.crt;
        ssl_certificate_key /etc/nginx/certs/server.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
        ssl_prefer_server_ciphers off;
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout 10m;

        # Frontend
        location / {
            proxy_pass http://frontend_backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # API endpoints
        location /api/ {
            limit_req zone=api burst=20 nodelay;
            proxy_pass http://api_backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_connect_timeout 30s;
            proxy_send_timeout 30s;
            proxy_read_timeout 30s;
        }

        # WebSocket endpoints
        location /ws/ {
            proxy_pass http://api_backend;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Login endpoint with stricter rate limiting
        location /api/auth/login {
            limit_req zone=login burst=5 nodelay;
            proxy_pass http://api_backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Health check endpoint
        location /health {
            access_log off;
            return 200 "healthy\n";
            add_header Content-Type text/plain;
        }
    }
}
```

### 4.2 Prometheus Configuration

```yaml
# monitoring/prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "rules/*.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'musafir-api-gateway'
    static_configs:
      - targets: ['musafir-api-gateway:8080']
    metrics_path: '/metrics'
    scrape_interval: 30s

  - job_name: 'musafir-auth-service'
    static_configs:
      - targets: ['musafir-auth-service:8081']
    metrics_path: '/metrics'
    scrape_interval: 30s

  - job_name: 'musafir-event-processor'
    static_configs:
      - targets: ['musafir-event-processor:8080']
    metrics_path: '/metrics'
    scrape_interval: 30s

  - job_name: 'musafir-analytics'
    static_configs:
      - targets: ['musafir-analytics:8082']
    metrics_path: '/metrics'
    scrape_interval: 30s

  - job_name: 'kafka'
    static_configs:
      - targets: ['kafka:9092']

  - job_name: 'influxdb'
    static_configs:
      - targets: ['influxdb:8086']

  - job_name: 'mongodb'
    static_configs:
      - targets: ['mongodb:27017']

  - job_name: 'redis'
    static_configs:
      - targets: ['redis:6379']
```

## 5. Environment Configuration

### 5.1 Environment Variables

```bash
# .env
# Database Configuration
MONGODB_URL=mongodb://admin:password@mongodb:27017/musafir?authSource=admin
INFLUXDB_URL=http://influxdb:8086
INFLUXDB_TOKEN=admin-token
REDIS_URL=redis://redis:6379

# Kafka Configuration
KAFKA_BROKERS=kafka:9092

# Security Configuration
JWT_PRIVATE_KEY_PATH=/etc/musafir/keys/jwt-private.pem
JWT_PUBLIC_KEY_PATH=/etc/musafir/keys/jwt-public.pem
ENCRYPTION_KEY_PATH=/etc/musafir/keys/encryption.key

# TLS Configuration
TLS_CERT_PATH=/etc/musafir/certs/server.crt
TLS_KEY_PATH=/etc/musafir/certs/server.key
CA_CERT_PATH=/etc/musafir/certs/ca.crt

# Email Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password

# Vault Configuration
VAULT_ADDR=http://vault:8200
VAULT_TOKEN=root-token

# Application Configuration
GIN_MODE=release
LOG_LEVEL=info
```

## 6. Production Deployment with Docker Swarm

### 6.1 Docker Swarm Stack

```yaml
# docker-stack.yml
version: '3.8'

services:
  musafir-frontend:
    image: musafir/frontend:latest
    ports:
      - "3000:80"
    networks:
      - musafir-overlay
    deploy:
      replicas: 2
      update_config:
        parallelism: 1
        delay: 10s
      restart_policy:
        condition: on-failure
      resources:
        limits:
          cpus: '0.5'
          memory: 512M
        reservations:
          cpus: '0.25'
          memory: 256M

  musafir-api-gateway:
    image: musafir/api-gateway:latest
    ports:
      - "8080:8080"
    networks:
      - musafir-overlay
    secrets:
      - jwt_private_key
      - jwt_public_key
      - tls_cert
      - tls_key
    deploy:
      replicas: 3
      update_config:
        parallelism: 1
        delay: 10s
      restart_policy:
        condition: on-failure
      resources:
        limits:
          cpus: '1.0'
          memory: 1G
        reservations:
          cpus: '0.5'
          memory: 512M

  musafir-event-processor:
    image: musafir/event-processor:latest
    networks:
      - musafir-overlay
    deploy:
      replicas: 5
      update_config:
        parallelism: 2
        delay: 10s
      restart_policy:
        condition: on-failure
      resources:
        limits:
          cpus: '2.0'
          memory: 2G
        reservations:
          cpus: '1.0'
          memory: 1G

  kafka:
    image: confluentinc/cp-kafka:7.4.0
    ports:
      - "9092:9092"
    networks:
      - musafir-overlay
    volumes:
      - kafka_data:/var/lib/kafka/data
    deploy:
      replicas: 3
      placement:
        constraints:
          - node.role == manager
      resources:
        limits:
          cpus: '2.0'
          memory: 4G
        reservations:
          cpus: '1.0'
          memory: 2G

networks:
  musafir-overlay:
    driver: overlay
    attachable: true

volumes:
  kafka_data:
    driver: local

secrets:
  jwt_private_key:
    external: true
  jwt_public_key:
    external: true
  tls_cert:
    external: true
  tls_key:
    external: true
```

## 7. Kubernetes Deployment

### 7.1 Kubernetes Manifests

```yaml
# k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: musafir
---
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: musafir-config
  namespace: musafir
data:
  kafka.brokers: "kafka:9092"
  mongodb.url: "mongodb://admin:password@mongodb:27017/musafir?authSource=admin"
  influxdb.url: "http://influxdb:8086"
  redis.url: "redis://redis:6379"
---
# k8s/secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: musafir-secrets
  namespace: musafir
type: Opaque
data:
  jwt-private-key: <base64-encoded-private-key>
  jwt-public-key: <base64-encoded-public-key>
  encryption-key: <base64-encoded-encryption-key>
  tls-cert: <base64-encoded-certificate>
  tls-key: <base64-encoded-private-key>
---
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: musafir-api-gateway
  namespace: musafir
spec:
  replicas: 3
  selector:
    matchLabels:
      app: musafir-api-gateway
  template:
    metadata:
      labels:
        app: musafir-api-gateway
    spec:
      containers:
      - name: api-gateway
        image: musafir/api-gateway:latest
        ports:
        - containerPort: 8080
        env:
        - name: KAFKA_BROKERS
          valueFrom:
            configMapKeyRef:
              name: musafir-config
              key: kafka.brokers
        - name: MONGODB_URL
          valueFrom:
            configMapKeyRef:
              name: musafir-config
              key: mongodb.url
        volumeMounts:
        - name: secrets
          mountPath: /etc/musafir/secrets
          readOnly: true
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: secrets
        secret:
          secretName: musafir-secrets
---
# k8s/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: musafir-api-gateway
  namespace: musafir
spec:
  selector:
    app: musafir-api-gateway
  ports:
  - protocol: TCP
    port: 8080
    targetPort: 8080
  type: ClusterIP
---
# k8s/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: musafir-ingress
  namespace: musafir
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  tls:
  - hosts:
    - musafir.yourdomain.com
    secretName: musafir-tls
  rules:
  - host: musafir.yourdomain.com
    http:
      paths:
      - path: /api
        pathType: Prefix
        backend:
          service:
            name: musafir-api-gateway
            port:
              number: 8080
      - path: /
        pathType: Prefix
        backend:
          service:
            name: musafir-frontend
            port:
              number: 80
```

## 8. CI/CD Pipeline

### 8.1 GitHub Actions Workflow

```yaml
# .github/workflows/deploy.yml
name: Build and Deploy MUSAFIR Platform

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: musafir

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Go
      uses: actions/setup-go@v3
      with:
        go-version: 1.21
    
    - name: Run tests
      run: |
        go test -v ./...
        go test -race -coverprofile=coverage.out ./...
    
    - name: Upload coverage
      uses: codecov/codecov-action@v3

  build:
    needs: test
    runs-on: ubuntu-latest
    strategy:
      matrix:
        service: [frontend, api-gateway, auth-service, event-processor, analytics, alert-manager, ingestion]
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Log in to Container Registry
      uses: docker/login-action@v2
      with:
        registry: ${{ env.REGISTRY }}
        username: ${{ github.actor }}
        password: ${{ secrets.GITHUB_TOKEN }}
    
    - name: Extract metadata
      id: meta
      uses: docker/metadata-action@v4
      with:
        images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}/${{ matrix.service }}
        tags: |
          type=ref,event=branch
          type=ref,event=pr
          type=sha
    
    - name: Build and push Docker image
      uses: docker/build-push-action@v4
      with:
        context: ./${{ matrix.service }}
        push: true
        tags: ${{ steps.meta.outputs.tags }}
        labels: ${{ steps.meta.outputs.labels }}

  deploy:
    needs: build
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Deploy to production
      run: |
        # Deploy using Docker Swarm or Kubernetes
        echo "Deploying to production..."
```

## 9. Monitoring and Logging

### 9.1 Docker Compose Override for Monitoring

```yaml
# docker-compose.monitoring.yml
version: '3.8'

services:
  # Log aggregation
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.8.0
    container_name: musafir-elasticsearch
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
    volumes:
      - elasticsearch_data:/usr/share/elasticsearch/data
    networks:
      - musafir-network

  logstash:
    image: docker.elastic.co/logstash/logstash:8.8.0
    container_name: musafir-logstash
    volumes:
      - ./monitoring/logstash.conf:/usr/share/logstash/pipeline/logstash.conf:ro
    networks:
      - musafir-network
    depends_on:
      - elasticsearch

  kibana:
    image: docker.elastic.co/kibana/kibana:8.8.0
    container_name: musafir-kibana
    ports:
      - "5601:5601"
    environment:
      ELASTICSEARCH_HOSTS: http://elasticsearch:9200
    networks:
      - musafir-network
    depends_on:
      - elasticsearch

  # Metrics collection
  node-exporter:
    image: prom/node-exporter:v1.6.0
    container_name: musafir-node-exporter
    ports:
      - "9100:9100"
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/rootfs:ro
    command:
      - '--path.procfs=/host/proc'
      - '--path.rootfs=/rootfs'
      - '--path.sysfs=/host/sys'
      - '--collector.filesystem.mount-points-exclude=^/(sys|proc|dev|host|etc)($$|/)'
    networks:
      - musafir-network

volumes:
  elasticsearch_data:
```

This comprehensive Docker deployment guide provides everything needed to containerize and deploy the MUSAFIR platform in various environments, from development to production, with proper monitoring, security, and scalability considerations.
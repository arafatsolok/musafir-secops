# MUSAFIR Implementation Guide

## Overview
This comprehensive guide provides step-by-step instructions for implementing the MUSAFIR central web UI platform, from initial setup to production deployment.

## 1. Prerequisites and Environment Setup

### 1.1 Development Environment Requirements

```bash
# Required Software
- Go 1.21+
- Node.js 18+
- Docker 24.0+
- Docker Compose 2.0+
- Git 2.40+
- Make (optional but recommended)

# Development Tools
- VS Code with Go extension
- Postman or similar API testing tool
- MongoDB Compass (optional)
- InfluxDB UI (optional)
```

### 1.2 Project Structure Setup

```bash
# Create project directory
mkdir musafir-platform
cd musafir-platform

# Initialize project structure
mkdir -p {backend/{api-gateway,auth-service,event-processor,analytics,alert-manager,ingestion},frontend,scripts,config,certs,keys,monitoring,nginx,k8s}

# Project structure
musafir-platform/
├── backend/
│   ├── api-gateway/
│   ├── auth-service/
│   ├── event-processor/
│   ├── analytics/
│   ├── alert-manager/
│   └── ingestion/
├── frontend/
├── scripts/
├── config/
├── certs/
├── keys/
├── monitoring/
├── nginx/
├── k8s/
├── docker-compose.yml
├── docker-compose.override.yml
├── .env
├── .gitignore
├── Makefile
└── README.md
```

## 2. Backend Development Workflow

### 2.1 Initialize Go Modules

```bash
# Initialize each backend service
cd backend/api-gateway
go mod init github.com/your-org/musafir-platform/backend/api-gateway

cd ../auth-service
go mod init github.com/your-org/musafir-platform/backend/auth-service

cd ../event-processor
go mod init github.com/your-org/musafir-platform/backend/event-processor

cd ../analytics
go mod init github.com/your-org/musafir-platform/backend/analytics

cd ../alert-manager
go mod init github.com/your-org/musafir-platform/backend/alert-manager

cd ../ingestion
go mod init github.com/your-org/musafir-platform/backend/ingestion
```

### 2.2 Common Dependencies

```bash
# Add common dependencies to each service
go get github.com/gin-gonic/gin
go get github.com/golang-jwt/jwt/v5
go get github.com/redis/go-redis/v9
go get go.mongodb.org/mongo-driver/mongo
go get github.com/influxdata/influxdb-client-go/v2
go get github.com/segmentio/kafka-go
go get github.com/prometheus/client_golang/prometheus
go get github.com/sirupsen/logrus
go get github.com/spf13/viper
go get github.com/gorilla/websocket
go get golang.org/x/crypto/bcrypt
go get google.golang.org/grpc
go get google.golang.org/protobuf
```

### 2.3 API Gateway Implementation

```go
// backend/api-gateway/cmd/main.go
package main

import (
    "context"
    "log"
    "net/http"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/gin-gonic/gin"
    "github.com/your-org/musafir-platform/backend/api-gateway/internal/config"
    "github.com/your-org/musafir-platform/backend/api-gateway/internal/handlers"
    "github.com/your-org/musafir-platform/backend/api-gateway/internal/middleware"
    "github.com/your-org/musafir-platform/backend/api-gateway/internal/services"
)

func main() {
    // Load configuration
    cfg := config.Load()

    // Initialize services
    authService := services.NewAuthService(cfg)
    eventService := services.NewEventService(cfg)
    analyticsService := services.NewAnalyticsService(cfg)

    // Initialize handlers
    authHandler := handlers.NewAuthHandler(authService)
    eventHandler := handlers.NewEventHandler(eventService)
    analyticsHandler := handlers.NewAnalyticsHandler(analyticsService)

    // Setup router
    router := gin.New()
    router.Use(gin.Logger())
    router.Use(gin.Recovery())
    router.Use(middleware.CORS())
    router.Use(middleware.SecurityHeaders())

    // Health check
    router.GET("/health", func(c *gin.Context) {
        c.JSON(http.StatusOK, gin.H{"status": "healthy"})
    })

    // API routes
    v1 := router.Group("/api/v1")
    {
        // Authentication routes
        auth := v1.Group("/auth")
        {
            auth.POST("/login", authHandler.Login)
            auth.POST("/logout", middleware.AuthRequired(), authHandler.Logout)
            auth.POST("/refresh", authHandler.RefreshToken)
            auth.GET("/profile", middleware.AuthRequired(), authHandler.GetProfile)
        }

        // Agent management routes
        agents := v1.Group("/agents", middleware.AuthRequired())
        {
            agents.GET("", eventHandler.ListAgents)
            agents.GET("/:id", eventHandler.GetAgent)
            agents.POST("", eventHandler.RegisterAgent)
            agents.PUT("/:id", eventHandler.UpdateAgent)
            agents.DELETE("/:id", eventHandler.DeleteAgent)
        }

        // Event routes
        events := v1.Group("/events", middleware.AuthRequired())
        {
            events.GET("", eventHandler.GetEvents)
            events.GET("/:id", eventHandler.GetEvent)
            events.POST("/search", eventHandler.SearchEvents)
        }

        // Analytics routes
        analytics := v1.Group("/analytics", middleware.AuthRequired())
        {
            analytics.GET("/dashboard", analyticsHandler.GetDashboardData)
            analytics.GET("/threats", analyticsHandler.GetThreatAnalytics)
            analytics.GET("/network", analyticsHandler.GetNetworkAnalytics)
            analytics.POST("/query", analyticsHandler.ExecuteQuery)
        }
    }

    // WebSocket endpoint
    router.GET("/ws", middleware.AuthRequired(), eventHandler.HandleWebSocket)

    // Start server
    srv := &http.Server{
        Addr:    ":" + cfg.Port,
        Handler: router,
    }

    go func() {
        if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            log.Fatalf("Failed to start server: %v", err)
        }
    }()

    // Graceful shutdown
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit

    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    if err := srv.Shutdown(ctx); err != nil {
        log.Fatal("Server forced to shutdown:", err)
    }
}
```

### 2.4 Configuration Management

```go
// backend/api-gateway/internal/config/config.go
package config

import (
    "log"
    "os"

    "github.com/spf13/viper"
)

type Config struct {
    Port        string `mapstructure:"PORT"`
    Environment string `mapstructure:"ENVIRONMENT"`
    
    // Database
    MongoURL    string `mapstructure:"MONGODB_URL"`
    RedisURL    string `mapstructure:"REDIS_URL"`
    InfluxDBURL string `mapstructure:"INFLUXDB_URL"`
    
    // Kafka
    KafkaBrokers []string `mapstructure:"KAFKA_BROKERS"`
    
    // JWT
    JWTPrivateKeyPath string `mapstructure:"JWT_PRIVATE_KEY_PATH"`
    JWTPublicKeyPath  string `mapstructure:"JWT_PUBLIC_KEY_PATH"`
    
    // TLS
    TLSCertPath string `mapstructure:"TLS_CERT_PATH"`
    TLSKeyPath  string `mapstructure:"TLS_KEY_PATH"`
}

func Load() *Config {
    viper.SetConfigName("config")
    viper.SetConfigType("yaml")
    viper.AddConfigPath("./config")
    viper.AddConfigPath(".")

    // Environment variables
    viper.AutomaticEnv()

    // Default values
    viper.SetDefault("PORT", "8080")
    viper.SetDefault("ENVIRONMENT", "development")

    if err := viper.ReadInConfig(); err != nil {
        log.Printf("Config file not found, using environment variables: %v", err)
    }

    var config Config
    if err := viper.Unmarshal(&config); err != nil {
        log.Fatalf("Failed to unmarshal config: %v", err)
    }

    return &config
}
```

## 3. Frontend Development Workflow

### 3.1 Initialize React Project

```bash
cd frontend

# Create React app with Vite
npm create vite@latest . -- --template react-ts

# Install dependencies
npm install

# Install additional packages
npm install @reduxjs/toolkit react-redux
npm install @tanstack/react-query
npm install react-router-dom
npm install @headlessui/react @heroicons/react
npm install tailwindcss @tailwindcss/forms @tailwindcss/typography
npm install recharts
npm install socket.io-client
npm install axios
npm install date-fns
npm install react-hook-form @hookform/resolvers yup
npm install react-hot-toast
npm install framer-motion

# Development dependencies
npm install -D @types/node
npm install -D autoprefixer postcss
npm install -D eslint-plugin-react-hooks
npm install -D prettier eslint-config-prettier
```

### 3.2 Project Structure

```bash
frontend/
├── src/
│   ├── components/
│   │   ├── common/
│   │   ├── dashboard/
│   │   ├── edr/
│   │   ├── xdr/
│   │   └── siem/
│   ├── hooks/
│   ├── services/
│   ├── store/
│   ├── types/
│   ├── utils/
│   ├── pages/
│   └── styles/
├── public/
├── package.json
├── tailwind.config.js
├── vite.config.ts
└── tsconfig.json
```

### 3.3 API Service Setup

```typescript
// frontend/src/services/api.ts
import axios, { AxiosInstance, AxiosRequestConfig } from 'axios';

class ApiService {
  private client: AxiosInstance;

  constructor() {
    this.client = axios.create({
      baseURL: import.meta.env.VITE_API_URL || 'http://localhost:8080/api/v1',
      timeout: 10000,
    });

    this.setupInterceptors();
  }

  private setupInterceptors() {
    // Request interceptor
    this.client.interceptors.request.use(
      (config) => {
        const token = localStorage.getItem('accessToken');
        if (token) {
          config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
      },
      (error) => Promise.reject(error)
    );

    // Response interceptor
    this.client.interceptors.response.use(
      (response) => response,
      async (error) => {
        if (error.response?.status === 401) {
          // Handle token refresh
          try {
            const refreshToken = localStorage.getItem('refreshToken');
            if (refreshToken) {
              const response = await this.client.post('/auth/refresh', {
                refreshToken,
              });
              
              const { accessToken } = response.data;
              localStorage.setItem('accessToken', accessToken);
              
              // Retry original request
              error.config.headers.Authorization = `Bearer ${accessToken}`;
              return this.client.request(error.config);
            }
          } catch (refreshError) {
            // Redirect to login
            localStorage.removeItem('accessToken');
            localStorage.removeItem('refreshToken');
            window.location.href = '/login';
          }
        }
        return Promise.reject(error);
      }
    );
  }

  // Authentication
  async login(credentials: LoginCredentials) {
    const response = await this.client.post('/auth/login', credentials);
    return response.data;
  }

  async logout() {
    const response = await this.client.post('/auth/logout');
    return response.data;
  }

  // Agents
  async getAgents(params?: AgentQueryParams) {
    const response = await this.client.get('/agents', { params });
    return response.data;
  }

  async getAgent(id: string) {
    const response = await this.client.get(`/agents/${id}`);
    return response.data;
  }

  // Events
  async getEvents(params?: EventQueryParams) {
    const response = await this.client.get('/events', { params });
    return response.data;
  }

  async searchEvents(query: EventSearchQuery) {
    const response = await this.client.post('/events/search', query);
    return response.data;
  }

  // Analytics
  async getDashboardData() {
    const response = await this.client.get('/analytics/dashboard');
    return response.data;
  }

  async getThreatAnalytics(params?: AnalyticsParams) {
    const response = await this.client.get('/analytics/threats', { params });
    return response.data;
  }
}

export const apiService = new ApiService();
```

## 4. Database Setup and Migration

### 4.1 MongoDB Setup Script

```javascript
// scripts/mongo-init.js
db = db.getSiblingDB('musafir');

// Create collections
db.createCollection('users');
db.createCollection('agents');
db.createCollection('events');
db.createCollection('alerts');
db.createCollection('rules');
db.createCollection('dashboards');

// Create indexes
db.users.createIndex({ "email": 1 }, { unique: true });
db.users.createIndex({ "username": 1 }, { unique: true });

db.agents.createIndex({ "agent_id": 1 }, { unique: true });
db.agents.createIndex({ "hostname": 1 });
db.agents.createIndex({ "ip_address": 1 });
db.agents.createIndex({ "last_seen": 1 });

db.events.createIndex({ "timestamp": 1 });
db.events.createIndex({ "agent_id": 1 });
db.events.createIndex({ "event_type": 1 });
db.events.createIndex({ "severity": 1 });
db.events.createIndex({ "source": 1 });

db.alerts.createIndex({ "created_at": 1 });
db.alerts.createIndex({ "severity": 1 });
db.alerts.createIndex({ "status": 1 });
db.alerts.createIndex({ "rule_id": 1 });

// Insert default admin user
db.users.insertOne({
  username: "admin",
  email: "admin@musafir.local",
  password_hash: "$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj8xBdHRUjHu", // password123
  role: "admin",
  permissions: ["read", "write", "admin"],
  created_at: new Date(),
  updated_at: new Date(),
  is_active: true
});

// Insert sample rules
db.rules.insertMany([
  {
    name: "High CPU Usage",
    description: "Alert when CPU usage exceeds 90%",
    condition: "cpu_usage > 90",
    severity: "high",
    enabled: true,
    created_at: new Date()
  },
  {
    name: "Suspicious Network Activity",
    description: "Alert on unusual network connections",
    condition: "network_connections > 1000",
    severity: "medium",
    enabled: true,
    created_at: new Date()
  }
]);

print("Database initialization completed");
```

### 4.2 InfluxDB Setup Script

```bash
#!/bin/bash
# scripts/influxdb-init.sh

# Wait for InfluxDB to be ready
until curl -f http://localhost:8086/ping; do
  echo "Waiting for InfluxDB..."
  sleep 2
done

# Create organization and bucket
influx setup \
  --username admin \
  --password password123 \
  --org musafir \
  --bucket events \
  --token admin-token \
  --force

# Create additional buckets
influx bucket create \
  --name metrics \
  --org musafir \
  --token admin-token

influx bucket create \
  --name logs \
  --org musafir \
  --token admin-token

echo "InfluxDB initialization completed"
```

## 5. Development Workflow

### 5.1 Makefile for Development

```makefile
# Makefile
.PHONY: help build test clean dev prod

# Default target
help:
	@echo "Available targets:"
	@echo "  dev      - Start development environment"
	@echo "  prod     - Start production environment"
	@echo "  build    - Build all services"
	@echo "  test     - Run tests"
	@echo "  clean    - Clean up containers and volumes"
	@echo "  logs     - Show logs"

# Development environment
dev:
	docker-compose -f docker-compose.yml -f docker-compose.dev.yml up --build

# Production environment
prod:
	docker-compose -f docker-compose.yml up -d

# Build all services
build:
	docker-compose build

# Run tests
test:
	@echo "Running backend tests..."
	@for service in api-gateway auth-service event-processor analytics alert-manager ingestion; do \
		echo "Testing $$service..."; \
		cd backend/$$service && go test -v ./... && cd ../..; \
	done
	@echo "Running frontend tests..."
	cd frontend && npm test

# Clean up
clean:
	docker-compose down -v
	docker system prune -f

# Show logs
logs:
	docker-compose logs -f

# Generate certificates
certs:
	./scripts/generate-certs.sh

# Initialize databases
init-db:
	./scripts/mongo-init.sh
	./scripts/influxdb-init.sh

# Lint code
lint:
	@echo "Linting backend..."
	@for service in api-gateway auth-service event-processor analytics alert-manager ingestion; do \
		echo "Linting $$service..."; \
		cd backend/$$service && golangci-lint run && cd ../..; \
	done
	@echo "Linting frontend..."
	cd frontend && npm run lint

# Format code
fmt:
	@echo "Formatting backend..."
	@for service in api-gateway auth-service event-processor analytics alert-manager ingestion; do \
		echo "Formatting $$service..."; \
		cd backend/$$service && go fmt ./... && cd ../..; \
	done
	@echo "Formatting frontend..."
	cd frontend && npm run format
```

### 5.2 Development Docker Compose Override

```yaml
# docker-compose.dev.yml
version: '3.8'

services:
  musafir-frontend:
    build:
      target: development
    volumes:
      - ./frontend:/app
      - /app/node_modules
    environment:
      - CHOKIDAR_USEPOLLING=true
    ports:
      - "3000:3000"

  musafir-api-gateway:
    volumes:
      - ./backend/api-gateway:/app
    environment:
      - GIN_MODE=debug
      - LOG_LEVEL=debug
    ports:
      - "8080:8080"

  musafir-auth-service:
    volumes:
      - ./backend/auth-service:/app
    environment:
      - LOG_LEVEL=debug

  musafir-event-processor:
    volumes:
      - ./backend/event-processor:/app
    environment:
      - LOG_LEVEL=debug

  # Hot reload for Go services
  air:
    image: cosmtrek/air:v1.44.0
    working_dir: /app
    volumes:
      - ./backend:/app
    environment:
      - AIR_CONF=/app/.air.toml
```

## 6. Testing Strategy

### 6.1 Backend Testing

```go
// backend/api-gateway/internal/handlers/auth_test.go
package handlers

import (
    "bytes"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/gin-gonic/gin"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"
)

type MockAuthService struct {
    mock.Mock
}

func (m *MockAuthService) Login(credentials LoginCredentials) (*AuthResponse, error) {
    args := m.Called(credentials)
    return args.Get(0).(*AuthResponse), args.Error(1)
}

func TestAuthHandler_Login(t *testing.T) {
    gin.SetMode(gin.TestMode)

    tests := []struct {
        name           string
        requestBody    LoginCredentials
        mockResponse   *AuthResponse
        mockError      error
        expectedStatus int
    }{
        {
            name: "successful login",
            requestBody: LoginCredentials{
                Username: "admin",
                Password: "password123",
            },
            mockResponse: &AuthResponse{
                AccessToken:  "access-token",
                RefreshToken: "refresh-token",
                User: User{
                    ID:       "user-id",
                    Username: "admin",
                    Email:    "admin@example.com",
                },
            },
            mockError:      nil,
            expectedStatus: http.StatusOK,
        },
        {
            name: "invalid credentials",
            requestBody: LoginCredentials{
                Username: "admin",
                Password: "wrong-password",
            },
            mockResponse:   nil,
            mockError:      errors.New("invalid credentials"),
            expectedStatus: http.StatusUnauthorized,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            mockService := new(MockAuthService)
            mockService.On("Login", tt.requestBody).Return(tt.mockResponse, tt.mockError)

            handler := NewAuthHandler(mockService)

            body, _ := json.Marshal(tt.requestBody)
            req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewBuffer(body))
            req.Header.Set("Content-Type", "application/json")

            w := httptest.NewRecorder()
            c, _ := gin.CreateTestContext(w)
            c.Request = req

            handler.Login(c)

            assert.Equal(t, tt.expectedStatus, w.Code)
            mockService.AssertExpectations(t)
        })
    }
}
```

### 6.2 Frontend Testing

```typescript
// frontend/src/components/__tests__/Dashboard.test.tsx
import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Provider } from 'react-redux';
import { BrowserRouter } from 'react-router-dom';
import { Dashboard } from '../Dashboard';
import { store } from '../../store';

const createWrapper = () => {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });

  return ({ children }: { children: React.ReactNode }) => (
    <BrowserRouter>
      <Provider store={store}>
        <QueryClientProvider client={queryClient}>
          {children}
        </QueryClientProvider>
      </Provider>
    </BrowserRouter>
  );
};

describe('Dashboard', () => {
  it('renders dashboard components', async () => {
    render(<Dashboard />, { wrapper: createWrapper() });

    await waitFor(() => {
      expect(screen.getByText('Security Overview')).toBeInTheDocument();
      expect(screen.getByText('Active Threats')).toBeInTheDocument();
      expect(screen.getByText('System Health')).toBeInTheDocument();
    });
  });

  it('displays loading state', () => {
    render(<Dashboard />, { wrapper: createWrapper() });
    
    expect(screen.getByTestId('dashboard-loading')).toBeInTheDocument();
  });
});
```

## 7. Deployment Checklist

### 7.1 Pre-deployment Checklist

```bash
# Security checklist
□ Generate and configure TLS certificates
□ Set up proper JWT keys
□ Configure encryption keys
□ Set up HashiCorp Vault
□ Review and set environment variables
□ Configure firewall rules
□ Set up monitoring and alerting

# Performance checklist
□ Configure database indexes
□ Set up Redis caching
□ Configure Kafka partitions
□ Set up load balancing
□ Configure resource limits
□ Set up auto-scaling

# Monitoring checklist
□ Configure Prometheus metrics
□ Set up Grafana dashboards
□ Configure log aggregation
□ Set up health checks
□ Configure alerting rules
□ Set up backup procedures
```

### 7.2 Deployment Script

```bash
#!/bin/bash
# scripts/deploy.sh

set -e

echo "Starting MUSAFIR platform deployment..."

# Check prerequisites
command -v docker >/dev/null 2>&1 || { echo "Docker is required but not installed. Aborting." >&2; exit 1; }
command -v docker-compose >/dev/null 2>&1 || { echo "Docker Compose is required but not installed. Aborting." >&2; exit 1; }

# Generate certificates if they don't exist
if [ ! -f "certs/server.crt" ]; then
    echo "Generating TLS certificates..."
    ./scripts/generate-certs.sh
fi

# Generate JWT keys if they don't exist
if [ ! -f "keys/jwt-private.pem" ]; then
    echo "Generating JWT keys..."
    ./scripts/generate-jwt-keys.sh
fi

# Pull latest images
echo "Pulling latest images..."
docker-compose pull

# Build and start services
echo "Building and starting services..."
docker-compose up -d --build

# Wait for services to be ready
echo "Waiting for services to be ready..."
./scripts/wait-for-services.sh

# Initialize databases
echo "Initializing databases..."
./scripts/init-databases.sh

# Run health checks
echo "Running health checks..."
./scripts/health-check.sh

echo "Deployment completed successfully!"
echo "Access the platform at: https://localhost"
echo "Default admin credentials: admin / password123"
```

This comprehensive implementation guide provides everything needed to build, test, and deploy the MUSAFIR platform from scratch, with proper development workflows, testing strategies, and deployment procedures.
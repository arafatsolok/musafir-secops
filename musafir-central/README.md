# MUSAFIR Central Platform

A comprehensive EDR/XDR/SIEM central management platform that aggregates and analyzes security events from MUSAFIR agents across multiple endpoints and platforms.

## Overview

The MUSAFIR Central Platform provides:
- **Centralized Event Collection**: Aggregates events from Windows, Linux, macOS, Android, and iOS agents
- **Real-time Analytics**: Stream processing and threat detection
- **Interactive Dashboards**: Web-based UI for monitoring and investigation
- **Multi-tenant Support**: Isolated environments for different organizations
- **Scalable Architecture**: Microservices-based design with container orchestration

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   MUSAFIR       │    │   API Gateway   │    │   Web UI        │
│   Agents        │───▶│   (Go)          │───▶│   (React)       │
│                 │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │
                                ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Event         │    │   Analytics     │    │   Notification  │
│   Processor     │◀───│   Engine        │───▶│   Service       │
│   (Go)          │    │   (Go)          │    │   (Go)          │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │
         ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Data Storage  │    │   Time Series   │    │   Message Queue │
│   (MongoDB)     │    │   (InfluxDB)    │    │   (Kafka)       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Technology Stack

### Backend Services
- **Language**: Go 1.21+
- **API Framework**: Gin/Echo
- **Authentication**: JWT + OAuth2
- **Message Queue**: Apache Kafka
- **Databases**: 
  - MongoDB (document storage)
  - InfluxDB (time-series data)
  - Redis (caching)

### Frontend
- **Framework**: React 18 + TypeScript
- **State Management**: Redux Toolkit
- **UI Components**: Material-UI / Ant Design
- **Charts**: Chart.js / D3.js
- **Real-time**: WebSocket

### Infrastructure
- **Containerization**: Docker + Docker Compose
- **Orchestration**: Kubernetes
- **Monitoring**: Prometheus + Grafana
- **Logging**: ELK Stack
- **Security**: HashiCorp Vault

## Quick Start

### Prerequisites
- Go 1.21+
- Node.js 18+
- Docker & Docker Compose
- MongoDB
- InfluxDB
- Redis
- Apache Kafka

### Development Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd musafir-central
   ```

2. **Start infrastructure services**
   ```bash
   docker-compose up -d mongodb influxdb redis kafka
   ```

3. **Set up backend services**
   ```bash
   cd backend
   go mod tidy
   go run cmd/api-gateway/main.go
   ```

4. **Set up frontend**
   ```bash
   cd frontend
   npm install
   npm start
   ```

5. **Access the platform**
   - Web UI: http://localhost:3000
   - API Gateway: http://localhost:8080
   - API Documentation: http://localhost:8080/swagger

## Project Structure

```
musafir-central/
├── backend/
│   ├── cmd/                    # Application entry points
│   │   ├── api-gateway/
│   │   ├── event-processor/
│   │   ├── analytics-engine/
│   │   └── notification-service/
│   ├── internal/               # Internal packages
│   │   ├── auth/
│   │   ├── events/
│   │   ├── analytics/
│   │   ├── storage/
│   │   └── websocket/
│   ├── pkg/                    # Shared packages
│   │   ├── config/
│   │   ├── logger/
│   │   └── utils/
│   └── api/                    # API definitions
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── services/
│   │   ├── store/
│   │   └── utils/
│   └── public/
├── deployments/
│   ├── docker/
│   ├── kubernetes/
│   └── terraform/
├── docs/
├── scripts/
└── docker-compose.yml
```

## Event Schema

The platform processes events from MUSAFIR agents using this schema:

```json
{
  "ts": "2024-01-15T10:30:00Z",
  "tenant_id": "t-aci",
  "asset": {
    "id": "hostname",
    "type": "endpoint",
    "os": "windows",
    "ip": "10.10.1.15"
  },
  "user": {
    "id": "aad:user@domain.com",
    "sid": "S-1-5-21-...",
    "domain": "CORP"
  },
  "event": {
    "class": "process",
    "name": "process_start",
    "severity": 3,
    "attrs": {
      "image": "C:\\Windows\\System32\\cmd.exe",
      "cmd": "cmd.exe /c whoami",
      "pid": 1234,
      "ppid": 5678
    }
  },
  "ingest": {
    "agent_version": "1.0.0",
    "schema": "ocsf:1.2"
  }
}
```

## Development

### Running Tests
```bash
# Backend tests
cd backend && go test ./...

# Frontend tests
cd frontend && npm test
```

### Building for Production
```bash
# Build all services
make build

# Build Docker images
make docker-build

# Deploy to Kubernetes
make k8s-deploy
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
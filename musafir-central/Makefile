# MUSAFIR Central Platform Makefile

# Variables
DOCKER_COMPOSE = docker-compose
BACKEND_DIR = backend
FRONTEND_DIR = frontend
SCRIPTS_DIR = scripts

# Colors for output
RED = \033[0;31m
GREEN = \033[0;32m
YELLOW = \033[1;33m
BLUE = \033[0;34m
NC = \033[0m # No Color

.PHONY: help setup dev-up dev-down build test clean docker-build docker-push k8s-deploy

# Default target
help: ## Show this help message
	@echo "$(BLUE)MUSAFIR Central Platform$(NC)"
	@echo "Available commands:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Development Environment
setup: ## Set up development environment
	@echo "$(YELLOW)Setting up development environment...$(NC)"
	@$(SCRIPTS_DIR)/setup-dev.sh

dev-up: ## Start development environment
	@echo "$(YELLOW)Starting development environment...$(NC)"
	@$(DOCKER_COMPOSE) up -d mongodb influxdb redis kafka zookeeper prometheus grafana vault elasticsearch kibana
	@echo "$(GREEN)Development environment started!$(NC)"
	@echo "Services available at:"
	@echo "  - MongoDB: localhost:27017"
	@echo "  - InfluxDB: localhost:8086"
	@echo "  - Redis: localhost:6379"
	@echo "  - Kafka: localhost:9092"
	@echo "  - Prometheus: localhost:9090"
	@echo "  - Grafana: localhost:3001"
	@echo "  - Vault: localhost:8200"
	@echo "  - Elasticsearch: localhost:9200"
	@echo "  - Kibana: localhost:5601"

dev-down: ## Stop development environment
	@echo "$(YELLOW)Stopping development environment...$(NC)"
	@$(DOCKER_COMPOSE) down
	@echo "$(GREEN)Development environment stopped!$(NC)"

dev-logs: ## Show logs from development services
	@$(DOCKER_COMPOSE) logs -f

dev-clean: ## Clean development environment (remove volumes)
	@echo "$(RED)Cleaning development environment (this will remove all data)...$(NC)"
	@read -p "Are you sure? [y/N] " -n 1 -r; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		$(DOCKER_COMPOSE) down -v; \
		docker system prune -f; \
		echo "$(GREEN)Development environment cleaned!$(NC)"; \
	else \
		echo "$(YELLOW)Cancelled.$(NC)"; \
	fi

# Backend Development
backend-deps: ## Install backend dependencies
	@echo "$(YELLOW)Installing backend dependencies...$(NC)"
	@cd $(BACKEND_DIR) && go mod tidy && go mod download

backend-test: ## Run backend tests
	@echo "$(YELLOW)Running backend tests...$(NC)"
	@cd $(BACKEND_DIR) && go test -v ./...

backend-lint: ## Lint backend code
	@echo "$(YELLOW)Linting backend code...$(NC)"
	@cd $(BACKEND_DIR) && golangci-lint run

backend-build: ## Build backend services
	@echo "$(YELLOW)Building backend services...$(NC)"
	@cd $(BACKEND_DIR) && go build -o bin/api-gateway cmd/api-gateway/main.go
	@cd $(BACKEND_DIR) && go build -o bin/event-processor cmd/event-processor/main.go
	@cd $(BACKEND_DIR) && go build -o bin/analytics-engine cmd/analytics-engine/main.go
	@cd $(BACKEND_DIR) && go build -o bin/notification-service cmd/notification-service/main.go
	@echo "$(GREEN)Backend services built successfully!$(NC)"

backend-run-gateway: ## Run API Gateway locally
	@echo "$(YELLOW)Starting API Gateway...$(NC)"
	@cd $(BACKEND_DIR) && go run cmd/api-gateway/main.go

backend-run-processor: ## Run Event Processor locally
	@echo "$(YELLOW)Starting Event Processor...$(NC)"
	@cd $(BACKEND_DIR) && go run cmd/event-processor/main.go

backend-run-analytics: ## Run Analytics Engine locally
	@echo "$(YELLOW)Starting Analytics Engine...$(NC)"
	@cd $(BACKEND_DIR) && go run cmd/analytics-engine/main.go

backend-run-notifications: ## Run Notification Service locally
	@echo "$(YELLOW)Starting Notification Service...$(NC)"
	@cd $(BACKEND_DIR) && go run cmd/notification-service/main.go

# Frontend Development
frontend-deps: ## Install frontend dependencies
	@echo "$(YELLOW)Installing frontend dependencies...$(NC)"
	@cd $(FRONTEND_DIR) && npm install

frontend-test: ## Run frontend tests
	@echo "$(YELLOW)Running frontend tests...$(NC)"
	@cd $(FRONTEND_DIR) && npm test

frontend-lint: ## Lint frontend code
	@echo "$(YELLOW)Linting frontend code...$(NC)"
	@cd $(FRONTEND_DIR) && npm run lint

frontend-build: ## Build frontend for production
	@echo "$(YELLOW)Building frontend...$(NC)"
	@cd $(FRONTEND_DIR) && npm run build
	@echo "$(GREEN)Frontend built successfully!$(NC)"

frontend-dev: ## Start frontend development server
	@echo "$(YELLOW)Starting frontend development server...$(NC)"
	@cd $(FRONTEND_DIR) && npm start

# Full Application
build: backend-build frontend-build ## Build all services

test: backend-test frontend-test ## Run all tests

lint: backend-lint frontend-lint ## Lint all code

clean: ## Clean build artifacts
	@echo "$(YELLOW)Cleaning build artifacts...$(NC)"
	@rm -rf $(BACKEND_DIR)/bin
	@rm -rf $(FRONTEND_DIR)/build
	@rm -rf $(FRONTEND_DIR)/dist
	@echo "$(GREEN)Build artifacts cleaned!$(NC)"

# Docker Operations
docker-build: ## Build Docker images
	@echo "$(YELLOW)Building Docker images...$(NC)"
	@$(DOCKER_COMPOSE) build
	@echo "$(GREEN)Docker images built successfully!$(NC)"

docker-up: ## Start all services with Docker
	@echo "$(YELLOW)Starting all services...$(NC)"
	@$(DOCKER_COMPOSE) up -d
	@echo "$(GREEN)All services started!$(NC)"
	@echo "Access the application at: http://localhost"

docker-down: ## Stop all Docker services
	@echo "$(YELLOW)Stopping all services...$(NC)"
	@$(DOCKER_COMPOSE) down
	@echo "$(GREEN)All services stopped!$(NC)"

docker-logs: ## Show Docker logs
	@$(DOCKER_COMPOSE) logs -f

docker-clean: ## Clean Docker resources
	@echo "$(RED)Cleaning Docker resources...$(NC)"
	@$(DOCKER_COMPOSE) down -v --rmi all
	@docker system prune -f
	@echo "$(GREEN)Docker resources cleaned!$(NC)"

# Database Operations
db-migrate: ## Run database migrations
	@echo "$(YELLOW)Running database migrations...$(NC)"
	@$(SCRIPTS_DIR)/migrate.sh
	@echo "$(GREEN)Database migrations completed!$(NC)"

db-seed: ## Seed database with sample data
	@echo "$(YELLOW)Seeding database...$(NC)"
	@$(SCRIPTS_DIR)/seed-data.sh
	@echo "$(GREEN)Database seeded successfully!$(NC)"

db-backup: ## Backup databases
	@echo "$(YELLOW)Backing up databases...$(NC)"
	@$(SCRIPTS_DIR)/backup.sh
	@echo "$(GREEN)Database backup completed!$(NC)"

# Kubernetes Operations
k8s-deploy: ## Deploy to Kubernetes
	@echo "$(YELLOW)Deploying to Kubernetes...$(NC)"
	@kubectl apply -f deployments/kubernetes/
	@echo "$(GREEN)Deployed to Kubernetes successfully!$(NC)"

k8s-delete: ## Delete from Kubernetes
	@echo "$(YELLOW)Deleting from Kubernetes...$(NC)"
	@kubectl delete -f deployments/kubernetes/
	@echo "$(GREEN)Deleted from Kubernetes successfully!$(NC)"

k8s-status: ## Check Kubernetes deployment status
	@kubectl get pods,services,deployments -l app=musafir

# Monitoring
monitor-up: ## Start monitoring stack
	@echo "$(YELLOW)Starting monitoring stack...$(NC)"
	@$(DOCKER_COMPOSE) up -d prometheus grafana
	@echo "$(GREEN)Monitoring stack started!$(NC)"
	@echo "  - Prometheus: http://localhost:9090"
	@echo "  - Grafana: http://localhost:3001 (admin/musafir123)"

logs-up: ## Start logging stack
	@echo "$(YELLOW)Starting logging stack...$(NC)"
	@$(DOCKER_COMPOSE) up -d elasticsearch kibana
	@echo "$(GREEN)Logging stack started!$(NC)"
	@echo "  - Elasticsearch: http://localhost:9200"
	@echo "  - Kibana: http://localhost:5601"

# Security
security-scan: ## Run security scans
	@echo "$(YELLOW)Running security scans...$(NC)"
	@$(SCRIPTS_DIR)/security-scan.sh
	@echo "$(GREEN)Security scan completed!$(NC)"

# Documentation
docs-build: ## Build documentation
	@echo "$(YELLOW)Building documentation...$(NC)"
	@$(SCRIPTS_DIR)/build-docs.sh
	@echo "$(GREEN)Documentation built successfully!$(NC)"

docs-serve: ## Serve documentation locally
	@echo "$(YELLOW)Serving documentation...$(NC)"
	@$(SCRIPTS_DIR)/serve-docs.sh

# Development Workflow
dev: dev-up backend-deps frontend-deps ## Start full development environment
	@echo "$(GREEN)Development environment ready!$(NC)"
	@echo "Next steps:"
	@echo "  1. Run 'make backend-run-gateway' in one terminal"
	@echo "  2. Run 'make frontend-dev' in another terminal"
	@echo "  3. Access the application at http://localhost:3000"

prod: docker-build docker-up ## Build and start production environment
	@echo "$(GREEN)Production environment started!$(NC)"
	@echo "Access the application at: http://localhost"

# Quick commands
install: backend-deps frontend-deps ## Install all dependencies

start: docker-up ## Start all services

stop: docker-down ## Stop all services

restart: docker-down docker-up ## Restart all services

status: ## Show service status
	@$(DOCKER_COMPOSE) ps
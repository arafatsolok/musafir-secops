# Docker Deployment Guide

This guide explains how to deploy the Musafir SecOps platform using Docker.

## Prerequisites

- Docker Engine 20.10+
- Docker Compose 2.0+
- At least 4GB RAM available
- At least 10GB disk space

## Quick Start

1. **Clone the repository and navigate to the project directory:**
   ```bash
   cd D:\MW
   ```

2. **Copy the environment configuration:**
   ```bash
   copy .env.example .env
   ```
   
   Edit the `.env` file and update the values as needed, especially:
   - `JWT_SECRET` - Use a strong, unique secret key
   - `ADMIN_PASSWORD` - Set a secure admin password
   - `CLICKHOUSE_PASSWORD` - Set a password for ClickHouse (optional but recommended)

3. **Build and start all services:**
   ```bash
   docker-compose up --build
   ```

4. **Access the application:**
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:3001
   - ClickHouse: http://localhost:8123

## Services Overview

### ClickHouse Database
- **Port:** 8123 (HTTP), 9000 (Native)
- **Data:** Persisted in `clickhouse_data` volume
- **Initialization:** Automatic database and table creation

### Backend Controller
- **Port:** 3001
- **Environment:** Production mode
- **Dependencies:** ClickHouse database
- **Health Check:** `/api/health` endpoint

### Frontend
- **Port:** 3000
- **Built with:** React + Nginx
- **Features:** Optimized production build with gzip compression

### Agent (Optional)
- **Port:** 9001
- **Purpose:** Security monitoring agent
- **Status:** Currently placeholder for future implementation

## Environment Variables

Key environment variables for Docker deployment:

```env
# Application
NODE_ENV=production
PORT=3001

# Database
CLICKHOUSE_HOST=clickhouse
CLICKHOUSE_PORT=8123
CLICKHOUSE_DATABASE=musafir_secops

# Security
JWT_SECRET=your-super-secure-jwt-secret-key
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your-secure-password
```

## Docker Commands

### Start services in background:
```bash
docker-compose up -d
```

### View logs:
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f backend
docker-compose logs -f frontend
docker-compose logs -f clickhouse
```

### Stop services:
```bash
docker-compose down
```

### Rebuild and restart:
```bash
docker-compose down
docker-compose up --build
```

### Clean up (removes volumes):
```bash
docker-compose down -v
```

## Data Persistence

- **ClickHouse Data:** Stored in `clickhouse_data` Docker volume
- **Application Logs:** Stored in `app_logs` Docker volume
- **Configuration:** Environment variables and config files

## Troubleshooting

### ClickHouse Connection Issues
If the backend can't connect to ClickHouse:
1. Check if ClickHouse container is running: `docker-compose ps`
2. View ClickHouse logs: `docker-compose logs clickhouse`
3. Verify network connectivity: `docker-compose exec backend ping clickhouse`

### Frontend Not Loading
1. Check if frontend container is running: `docker-compose ps`
2. View frontend logs: `docker-compose logs frontend`
3. Verify Nginx configuration: `docker-compose exec frontend nginx -t`

### Backend API Errors
1. Check backend logs: `docker-compose logs backend`
2. Verify environment variables: `docker-compose exec backend env`
3. Test database connection: `docker-compose exec backend npm run test:db`

## Security Considerations

1. **Change default passwords** in production
2. **Use strong JWT secrets**
3. **Enable ClickHouse authentication** for production
4. **Configure firewall rules** to restrict access
5. **Use HTTPS** in production (configure reverse proxy)

## Production Deployment

For production deployment:

1. Use a reverse proxy (Nginx/Apache) with SSL certificates
2. Configure proper firewall rules
3. Set up monitoring and logging
4. Use Docker Swarm or Kubernetes for orchestration
5. Implement backup strategies for ClickHouse data
6. Configure resource limits in docker-compose.yml

## Monitoring

Health check endpoints:
- Backend: `http://localhost:3001/api/health`
- Frontend: `http://localhost:3000/health`
- ClickHouse: `http://localhost:8123/ping`

## Backup and Recovery

### Backup ClickHouse Data:
```bash
docker-compose exec clickhouse clickhouse-client --query "BACKUP DATABASE musafir_secops TO Disk('backups', 'backup-$(date +%Y%m%d).zip')"
```

### Restore from Backup:
```bash
docker-compose exec clickhouse clickhouse-client --query "RESTORE DATABASE musafir_secops FROM Disk('backups', 'backup-YYYYMMDD.zip')"
```
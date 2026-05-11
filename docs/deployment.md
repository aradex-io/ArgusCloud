# CloudGraph Deployment Guide

This guide covers deploying CloudGraph in various environments.

## Table of Contents

- [Quick Start](#quick-start)
- [Docker Deployment](#docker-deployment)
- [Production Configuration](#production-configuration)
- [Environment Variables](#environment-variables)
- [Reverse Proxy Setup](#reverse-proxy-setup)
- [SSL/TLS Configuration](#ssltls-configuration)
- [High Availability](#high-availability)
- [Monitoring](#monitoring)
- [Troubleshooting](#troubleshooting)

## Quick Start

### Minimal Setup

```bash
# Start Neo4j
docker run -d --name neo4j \
  -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/password \
  neo4j:5

# Install CloudGraph
pip install cloudgraph

# Start the API server
cloudgraph serve --port 9847
```

### With Docker Compose

```bash
# Clone repository
git clone https://github.com/owner/cloudgraph.git
cd cloudgraph

# Start services
docker-compose up -d

# Access UI at http://localhost:8080
# API at http://localhost:9847
```

## Docker Deployment

### Development

```yaml
# docker-compose.yml
version: '3.8'

services:
  neo4j:
    image: neo4j:5
    ports:
      - "7474:7474"
      - "7687:7687"
    environment:
      NEO4J_AUTH: neo4j/password
    volumes:
      - neo4j_data:/data

  api:
    build: .
    ports:
      - "9847:9847"
    environment:
      CLOUDGRAPH_NEO4J_URI: bolt://neo4j:7687
      CLOUDGRAPH_NEO4J_USER: neo4j
      CLOUDGRAPH_NEO4J_PASSWORD: password
    depends_on:
      - neo4j

  ui:
    image: nginx:alpine
    ports:
      - "8080:80"
    volumes:
      - ./ui:/usr/share/nginx/html:ro

volumes:
  neo4j_data:
```

### Production

Use `docker-compose.prod.yml` for production deployments:

```bash
docker-compose -f docker-compose.prod.yml up -d
```

Key differences:
- Non-root user
- Resource limits
- Health checks
- Log management
- Persistent volumes

## Production Configuration

### Security Checklist

- [ ] Enable authentication (`CLOUDGRAPH_AUTH_ENABLED=true`)
- [ ] Set strong JWT secret (`CLOUDGRAPH_JWT_SECRET`)
- [ ] Configure specific CORS origins
- [ ] Use HTTPS (via reverse proxy)
- [ ] Secure Neo4j with authentication
- [ ] Set up firewall rules
- [ ] Enable audit logging

### Recommended Architecture

```
                    ┌─────────────┐
                    │   Nginx     │
                    │ (TLS/Proxy) │
                    └──────┬──────┘
                           │
           ┌───────────────┼───────────────┐
           │               │               │
           ▼               ▼               ▼
    ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
    │ CloudGraph  │ │ CloudGraph  │ │     UI      │
    │   API #1    │ │   API #2    │ │   (static)  │
    └──────┬──────┘ └──────┬──────┘ └─────────────┘
           │               │
           └───────┬───────┘
                   │
           ┌───────▼───────┐
           │    Neo4j      │
           │   (Cluster)   │
           └───────────────┘
```

## Environment Variables

### Required

| Variable | Description | Example |
|----------|-------------|---------|
| `CLOUDGRAPH_NEO4J_URI` | Neo4j connection URI | `bolt://neo4j:7687` |
| `CLOUDGRAPH_NEO4J_USER` | Neo4j username | `neo4j` |
| `CLOUDGRAPH_NEO4J_PASSWORD` | Neo4j password | `secretpassword` |

### Optional

| Variable | Description | Default |
|----------|-------------|---------|
| `CLOUDGRAPH_API_HOST` | API bind address | `0.0.0.0` |
| `CLOUDGRAPH_API_PORT` | API port | `9847` |
| `CLOUDGRAPH_AUTH_ENABLED` | Enable authentication | `true` |
| `CLOUDGRAPH_JWT_SECRET` | JWT signing secret | (auto-generated) |
| `CLOUDGRAPH_JWT_EXPIRY` | JWT expiry in seconds | `3600` |
| `CLOUDGRAPH_CORS_ORIGINS` | Allowed CORS origins | `http://localhost:8080` |
| `CLOUDGRAPH_LOG_LEVEL` | Logging level | `INFO` |
| `CLOUDGRAPH_MAX_QUERY_LIMIT` | Max query results | `10000` |

### API Keys

Generate API keys for programmatic access:

```bash
cloudgraph auth generate-key --name "ci-pipeline"
```

Configure via environment:
```bash
CLOUDGRAPH_API_KEYS="ci-pipeline:hash1,admin:hash2"
```

## Reverse Proxy Setup

### Nginx

```nginx
upstream cloudgraph_api {
    server 127.0.0.1:9847;
    keepalive 32;
}

server {
    listen 443 ssl http2;
    server_name cloudgraph.example.com;

    ssl_certificate /etc/ssl/certs/cloudgraph.crt;
    ssl_certificate_key /etc/ssl/private/cloudgraph.key;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000" always;

    # API
    location /api/ {
        rewrite ^/api/(.*)$ /$1 break;
        proxy_pass http://cloudgraph_api;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support (for future streaming)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    # UI static files
    location / {
        root /var/www/cloudgraph/ui;
        try_files $uri $uri/ /index.html;
    }
}
```

### Traefik

```yaml
# traefik.yml
http:
  routers:
    cloudgraph-api:
      rule: "Host(`cloudgraph.example.com`) && PathPrefix(`/api`)"
      service: cloudgraph-api
      tls:
        certResolver: letsencrypt
      middlewares:
        - strip-api-prefix

    cloudgraph-ui:
      rule: "Host(`cloudgraph.example.com`)"
      service: cloudgraph-ui
      tls:
        certResolver: letsencrypt

  services:
    cloudgraph-api:
      loadBalancer:
        servers:
          - url: "http://api:9847"

    cloudgraph-ui:
      loadBalancer:
        servers:
          - url: "http://ui:80"

  middlewares:
    strip-api-prefix:
      stripPrefix:
        prefixes:
          - "/api"
```

## SSL/TLS Configuration

### Let's Encrypt with Certbot

```bash
# Install certbot
sudo apt install certbot python3-certbot-nginx

# Obtain certificate
sudo certbot --nginx -d cloudgraph.example.com

# Auto-renewal
sudo certbot renew --dry-run
```

### Self-Signed (Development)

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/ssl/private/cloudgraph.key \
  -out /etc/ssl/certs/cloudgraph.crt \
  -subj "/CN=cloudgraph.local"
```

## High Availability

### Neo4j Cluster

For production, use Neo4j Cluster for high availability:

```yaml
# neo4j-cluster.yml
version: '3.8'

services:
  core1:
    image: neo4j:5-enterprise
    environment:
      NEO4J_ACCEPT_LICENSE_AGREEMENT: "yes"
      NEO4J_dbms_mode: CORE
      NEO4J_causal__clustering_initial__discovery__members: core1:5000,core2:5000,core3:5000

  core2:
    image: neo4j:5-enterprise
    environment:
      NEO4J_ACCEPT_LICENSE_AGREEMENT: "yes"
      NEO4J_dbms_mode: CORE
      NEO4J_causal__clustering_initial__discovery__members: core1:5000,core2:5000,core3:5000

  core3:
    image: neo4j:5-enterprise
    environment:
      NEO4J_ACCEPT_LICENSE_AGREEMENT: "yes"
      NEO4J_dbms_mode: CORE
      NEO4J_causal__clustering_initial__discovery__members: core1:5000,core2:5000,core3:5000
```

### API Load Balancing

Run multiple API instances behind a load balancer:

```yaml
services:
  api:
    image: cloudgraph:latest
    deploy:
      replicas: 3
      resources:
        limits:
          cpus: '1'
          memory: 1G
```

## Monitoring

### Health Endpoint

```bash
curl http://localhost:9847/health
```

Response:
```json
{
  "status": "ok",
  "version": "0.2.0",
  "checks": {
    "neo4j": "ok",
    "plugins": "ok (3 loaded)"
  }
}
```

### Prometheus Metrics (Future)

When implemented, metrics will be available at `/metrics`:

```bash
curl http://localhost:9847/metrics
```

### Logging

Configure log level:
```bash
CLOUDGRAPH_LOG_LEVEL=DEBUG cloudgraph serve
```

Log format (JSON):
```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "level": "INFO",
  "message": "Request completed",
  "method": "GET",
  "path": "/graph",
  "status": 200,
  "duration_ms": 45
}
```

## Troubleshooting

### Common Issues

#### Neo4j Connection Failed

```
Error: Unable to connect to Neo4j at bolt://localhost:7687
```

Solutions:
1. Verify Neo4j is running: `docker ps | grep neo4j`
2. Check connection string: `CLOUDGRAPH_NEO4J_URI`
3. Verify credentials
4. Check network connectivity

#### Authentication Errors

```
Error: Invalid API key or token
```

Solutions:
1. Verify API key is correct
2. Check if token is expired
3. Regenerate API key if needed

#### CORS Errors

```
Error: CORS policy blocked request
```

Solutions:
1. Add origin to `CLOUDGRAPH_CORS_ORIGINS`
2. Verify origin matches exactly (including protocol)

### Debug Mode

Enable debug logging:
```bash
CLOUDGRAPH_LOG_LEVEL=DEBUG cloudgraph serve
```

### Health Check Troubleshooting

```bash
# Check API health
curl -v http://localhost:9847/health

# Check Neo4j directly
cypher-shell -u neo4j -p password "RETURN 1"

# Check container logs
docker logs cloudgraph-api
```

---

For additional help, see:
- [API Reference](api-reference.md)
- [Security Guide](security.md)
- [CONTRIBUTING.md](../CONTRIBUTING.md)

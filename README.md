# MCP Security Guardian 🛡️

An advanced, production-ready security platform for detecting and mitigating malicious instructions in MCP (Model Context Protocol) communications, featuring comprehensive security enhancements and enterprise-grade protection.

## 🚀 Overview

MCP Security Guardian provides comprehensive security monitoring and protection for MCP servers and clients. The platform uses a defense-in-depth approach with multiple security layers to ensure maximum protection against threats.

### 🔥 Key Features

#### Core Security Capabilities
- **Multi-Layer Threat Detection**
  - Pattern-based detection with regex and YARA rules
  - Behavioral analysis for anomaly detection
  - LLM-powered classification for sophisticated threats
  - Real-time traffic analysis

- **Advanced Security Features**
  - **Input Validation**: Comprehensive protection against SQL injection, XSS, path traversal, and command injection
  - **Enhanced JWT Security**: Strong algorithm enforcement (RS256/ES256) with CSRF protection
  - **Password Security**: Argon2 hashing, breach detection, and account lockout mechanisms
  - **Sandbox Isolation**: Docker/gVisor-based secure execution environment
  - **Rate Limiting**: Intelligent throttling to prevent abuse
  - **Security Logging**: Sensitive data redaction and audit trails

- **Vulnerability Management**
  - Automated vulnerability scanning
  - Real-time threat intelligence
  - Token revocation system
  - Security alert distribution

- **Enterprise Features**
  - Horizontal scaling support
  - High availability configuration
  - Comprehensive monitoring with Prometheus/Grafana
  - Structured JSON logging with ELK stack support

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────┐
│              Load Balancer (nginx)               │
│         • SSL Termination • Rate Limiting        │
└────────────────┬────────────────────────────────┘
                 │
┌────────────────┴────────────────────────────────┐
│              API Gateway Layer                   │
│    • Authentication • CORS • Rate Limiting       │
└────────────────┬────────────────────────────────┘
                 │
┌────────────────┴────────────────────────────────┐
│         Security Validation Layer                │
│  • Input Validation • XSS/SQL Protection         │
└────────────────┬────────────────────────────────┘
                 │
┌────────────────┴────────────────────────────────┐
│          Detection Engine                        │
│  • Pattern Matching • Behavioral Analysis        │
│  • LLM Classification • Traffic Analysis         │
└────────────────┬────────────────────────────────┘
                 │
┌────────────────┴────────────────────────────────┐
│         Sandbox Execution Layer                  │
│    • Docker Isolation • Resource Limits          │
└────────────────┬────────────────────────────────┘
                 │
┌────────────────┴────────────────────────────────┐
│           Data Persistence                       │
│  PostgreSQL • MongoDB • Redis • Neo4j            │
└─────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Prerequisites

- Docker and Docker Compose (v2.x)
- Python 3.9+ (for development)
- 8GB+ RAM (16GB recommended for production)
- 4+ CPU cores
- 50GB+ disk space

### Basic Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-org/mcp-security-guardian.git
   cd mcp-security-guardian
   ```

2. **Generate secure secrets**
   ```bash
   ./scripts/generate_secrets.sh
   ```

3. **Configure environment**
   ```bash
   cp .env.example .env.production
   # Edit .env.production with your values
   ```

4. **Start services**
   ```bash
   docker-compose up -d
   ```

5. **Verify deployment**
   ```bash
   curl http://localhost:8000/health
   ```

## 🔒 Security Features

### 1. Input Validation & Sanitization
- **SQL Injection Protection**: Advanced pattern matching and parameterized queries
- **XSS Prevention**: HTML entity encoding and content security policies
- **Path Traversal Protection**: Path normalization and whitelist validation
- **Command Injection Prevention**: Shell command sanitization
- **File Upload Security**: Type validation, size limits, and sandboxed storage

### 2. Authentication & Authorization
- **JWT Security**:
  - Strong algorithms only (RS256, ES256)
  - Automatic weak algorithm rejection
  - Token expiration and refresh mechanisms
  - JTI tracking for revocation
- **CSRF Protection**: Double-submit cookie pattern
- **Multi-Factor Authentication**: TOTP support

### 3. Password Security
- **Strong Password Policy**:
  - Minimum 12 characters
  - Mixed case, numbers, and special characters required
  - Common password rejection
- **Breach Detection**: Integration with HaveIBeenPwned API
- **Account Lockout**: Progressive delays after failed attempts
- **Secure Storage**: Argon2id hashing with salt

### 4. Sandbox Isolation
- **Docker-based Isolation**:
  - Read-only root filesystem
  - No network access
  - Dropped Linux capabilities
  - User namespace isolation
- **Resource Limits**:
  - CPU: 50% of one core max
  - Memory: 512MB limit
  - Process count: 100 max
  - Execution timeout: 30 seconds
- **gVisor Support**: For enhanced kernel isolation

### 5. API Security
- **Rate Limiting**:
  - Per-IP and per-user limits
  - Sliding window algorithm
  - Configurable thresholds
- **Request Validation**:
  - Size limits (100KB default)
  - Content-type validation
  - Schema validation with Pydantic
- **Security Headers**:
  - X-Content-Type-Options: nosniff
  - X-Frame-Options: DENY
  - X-XSS-Protection: 1; mode=block
  - Strict-Transport-Security

### 6. Monitoring & Logging
- **Security Event Logging**:
  - Failed authentication attempts
  - Rate limit violations
  - Detected threats
  - System errors
- **Sensitive Data Redaction**:
  - Automatic PII removal
  - Token/password masking
  - Credit card number redaction
- **Audit Trail**:
  - User actions
  - Configuration changes
  - Access logs

## 📋 Production Deployment Guide

### 1. Environment Configuration

Create a production environment file:

```bash
# Security Settings
JWT_ALGORITHM=RS256
JWT_PRIVATE_KEY_PATH=/secrets/jwt-private.pem
JWT_PUBLIC_KEY_PATH=/secrets/jwt-public.pem
ENABLE_CSRF_PROTECTION=true
PASSWORD_MIN_LENGTH=12
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION=300

# Database Configuration
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
POSTGRES_DB=mcp_security
POSTGRES_USER=mcp_user
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}

MONGODB_HOST=mongodb
MONGODB_PORT=27017
MONGODB_DATABASE=mcp_security
MONGODB_USERNAME=mcp_user
MONGODB_PASSWORD=${MONGODB_PASSWORD}

REDIS_HOST=redis
REDIS_PORT=6379
REDIS_PASSWORD=${REDIS_PASSWORD}

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
API_WORKERS=4
API_CORS_ORIGINS=https://your-domain.com
API_TIMEOUT=30

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_PER_MINUTE=100
RATE_LIMIT_PER_HOUR=1000

# Logging
LOG_LEVEL=INFO
LOG_FORMAT=json
LOG_FILE=/logs/mcp_guardian.log
ENABLE_AUDIT_LOGGING=true

# Monitoring
PROMETHEUS_ENABLED=true
GRAFANA_ENABLED=true
ALERTS_ENABLED=true
```

### 2. SSL/TLS Configuration

Configure nginx for SSL termination:

```nginx
server {
    listen 443 ssl http2;
    server_name api.your-domain.com;
    
    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Content-Security-Policy "default-src 'self'" always;
    
    location / {
        proxy_pass http://api:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Rate limiting
        limit_req zone=api_limit burst=20 nodelay;
    }
}
```

### 3. Database Setup

Initialize databases with secure configurations:

```bash
# PostgreSQL
docker-compose exec postgres psql -U postgres -c "
CREATE USER mcp_user WITH ENCRYPTED PASSWORD '$POSTGRES_PASSWORD';
CREATE DATABASE mcp_security OWNER mcp_user;
GRANT ALL PRIVILEGES ON DATABASE mcp_security TO mcp_user;
"

# MongoDB
docker-compose exec mongodb mongosh admin -u root -p $MONGO_ROOT_PASSWORD --eval "
db.createUser({
  user: 'mcp_user',
  pwd: '$MONGODB_PASSWORD',
  roles: [{role: 'readWrite', db: 'mcp_security'}]
})
"

# Run migrations
docker-compose exec api alembic upgrade head
```

### 4. Monitoring Setup

Configure Prometheus and Grafana:

```yaml
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'mcp-guardian-api'
    static_configs:
      - targets: ['api:8000']
    metrics_path: '/metrics'
    
  - job_name: 'mcp-guardian-detection'
    static_configs:
      - targets: ['detection-engine:9090']
      
  - job_name: 'mcp-guardian-sandbox'
    static_configs:
      - targets: ['sandbox:9091']
```

### 5. Backup Configuration

Set up automated backups:

```bash
# backup.sh
#!/bin/bash
BACKUP_DIR="/backups/$(date +%Y%m%d_%H%M%S)"
mkdir -p $BACKUP_DIR

# Backup PostgreSQL
docker-compose exec postgres pg_dump -U mcp_user mcp_security | gzip > $BACKUP_DIR/postgres.sql.gz

# Backup MongoDB
docker-compose exec mongodb mongodump --db mcp_security --gzip --archive=$BACKUP_DIR/mongodb.gz

# Backup Redis
docker-compose exec redis redis-cli --rdb $BACKUP_DIR/redis.rdb

# Encrypt backups
tar -czf - $BACKUP_DIR | openssl enc -aes-256-cbc -salt -out $BACKUP_DIR.tar.gz.enc -k $BACKUP_PASSWORD

# Upload to S3 (optional)
aws s3 cp $BACKUP_DIR.tar.gz.enc s3://your-backup-bucket/mcp-guardian/
```

## 📊 API Documentation

### Authentication

All API endpoints require JWT authentication:

```bash
# Get access token
curl -X POST https://api.your-domain.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "your-password"}'

# Use token in requests
curl -X POST https://api.your-domain.com/api/v1/security/analyze \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"instruction": "Check server status", "session_id": "uuid"}'
```

### Core Endpoints

- `POST /api/v1/security/analyze` - Analyze instruction for threats
- `POST /api/v1/security/scan/vulnerabilities` - Scan for vulnerabilities
- `POST /api/v1/security/revoke/token` - Revoke compromised token
- `GET /api/v1/monitoring/alerts` - Get security alerts
- `GET /api/v1/health` - Health check
- `GET /api/v1/metrics` - Prometheus metrics

Full API documentation available at `https://api.your-domain.com/docs`

## 🔧 Development Setup

### Local Development

1. **Create virtual environment**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```

3. **Run tests**
   ```bash
   pytest tests/
   python test_comprehensive_security.py
   ```

4. **Start development server**
   ```bash
   uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000
   ```

### Code Quality

- **Linting**: `ruff check src/`
- **Type checking**: `mypy src/`
- **Security scanning**: `bandit -r src/`
- **Dependency scanning**: `safety check`

## 🚨 Security Considerations

1. **Never commit secrets** - Use environment variables
2. **Keep dependencies updated** - Run `pip-audit` regularly
3. **Review security alerts** - Monitor GitHub security advisories
4. **Audit logs regularly** - Check for suspicious patterns
5. **Rotate secrets** - JWT keys, database passwords, API keys
6. **Test security features** - Run security test suite before deployment

## 📈 Performance Tuning

### Optimization Tips

1. **Database**:
   - Add appropriate indexes
   - Use connection pooling
   - Enable query caching

2. **API**:
   - Use async endpoints
   - Implement response caching
   - Enable gzip compression

3. **Detection Engine**:
   - Optimize regex patterns
   - Use compiled YARA rules
   - Cache LLM responses

4. **Monitoring**:
   - Adjust scrape intervals
   - Use recording rules
   - Implement data retention policies

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Workflow

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new features
5. Run the test suite
6. Submit a pull request

## 👤 Author

**Author:** Jae Sup Hwang <jaesuphwang@gmail.com>  
**Maintainer:** Jae Sup Hwang <jaesuphwang@gmail.com>

## 📜 License

This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- OWASP for security best practices
- The MCP community for protocol specifications
- All contributors who helped make this project secure and robust

## 📞 Support

- **Documentation**: [https://docs.mcp-guardian.com](https://docs.mcp-guardian.com)
- **Issues**: [GitHub Issues](https://github.com/your-org/mcp-security-guardian/issues)
- **Security**: security@mcp-guardian.com (PGP key available)
- **Community**: [Discord Server](https://discord.gg/mcp-guardian)

## 🤝 Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

---

**⚠️ Security Notice**: This is security software. Please review all configurations carefully before deployment. Report security vulnerabilities responsibly via our security email.

Copyright 2025 Jae Sup Hwang. Licensed under the Apache License, Version 2.0.
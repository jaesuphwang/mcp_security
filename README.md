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
│              MCP Client                          │
│         (Claude Desktop/Other)                   │
└────────────────┬────────────────────────────────┘
                 │
┌────────────────┴────────────────────────────────┐
│          MCP Security Guardian                   │
│    • Threat Detection • Vulnerability Scan       │
│    • Token Revocation • Alert Distribution       │
└────────────────┬────────────────────────────────┘
                 │
┌────────────────┴────────────────────────────────┐
│         Security Analysis Engine                 │
│  • Pattern Matching • Behavioral Analysis        │
│  • LLM Classification • Traffic Analysis         │
└────────────────┬────────────────────────────────┘
                 │
┌────────────────┴────────────────────────────────┐
│           Security Services                      │
│  • Detection Engine • Vulnerability Scanner      │
│  • Token Revocation • Alert Distribution         │
└─────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Prerequisites

- Python 3.10+ (tested with Python 3.10+)
- Virtual environment (recommended)
- Git (for cloning)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/jaesuphwang/mcp_security.git
   cd mcp_security
   ```

2. **Create and activate virtual environment**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Test the basic server**
   ```bash
   python test_mcp_basic.py
   ```

5. **Run the full security server**
   ```bash
   python mcp_server.py
   ```

### Integration with Claude Desktop

Add to your Claude Desktop MCP configuration (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "mcp-security-guardian": {
      "command": "python",
      "args": ["/path/to/your/mcp_security_git/mcp_server.py"],
      "env": {
        "PYTHONPATH": "/path/to/your/mcp_security_git"
      }
    }
  }
}
```

Replace `/path/to/your/mcp_security_git` with the actual absolute path to your project directory.

### Using with Smithery

If you prefer to use the Smithery MCP server manager:

```bash
# Install via Smithery
smithery install mcp-security-guardian

# Or add to smithery.json
{
  "servers": {
    "mcp-security-guardian": {
      "command": "python",
      "args": ["/path/to/mcp_server.py"]
    }
  }
}
```

## 🔧 Available Tools

The MCP Security Guardian provides the following tools:

### 1. **analyze_instruction**
Analyze MCP instructions for security threats using multi-layer detection.

```json
{
  "instruction": "SELECT * FROM users WHERE id = 1",
  "context": {
    "source": "client",
    "session_id": "12345"
  }
}
```

**Detects:**
- SQL injection attempts
- Command injection
- Path traversal attacks
- Credential theft attempts
- Data exfiltration patterns

### 2. **scan_connection**
Scan MCP connections for security vulnerabilities.

```json
{
  "server_url": "https://api.example.com",
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "connection_params": {}
}
```

**Checks:**
- SSL/TLS configuration
- Certificate validity
- Token security
- Protocol compliance

### 3. **revoke_token**
Revoke compromised or suspicious tokens.

```json
{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "reason": "compromised",
  "description": "Token found in public repository"
}
```

**Reasons:**
- `compromised`: Token has been exposed
- `expired`: Token past validity period
- `misused`: Suspicious usage patterns
- `suspicious`: Potential security risk

### 4. **audit_capabilities**
Audit MCP server capabilities for security issues.

```json
{
  "server_url": "https://api.example.com",
  "capabilities": ["read_files", "execute_commands"]
}
```

### 5. **distribute_alert**
Distribute security alerts through the threat intelligence network.

```json
{
  "alert_type": "malicious_instruction",
  "severity": "high",
  "message": "Detected SQL injection attempt",
  "tlp_level": "amber"
}
```

## 📊 Resources

Access security resources:

- `security://threat-patterns` - Known threat signatures database
- `security://revoked-tokens` - List of revoked authentication tokens  
- `security://alerts` - Active security alerts and notifications

## 🔒 Security Features

### 1. Multi-Layer Detection Engine
- **Pattern Matching**: Regex and YARA rule-based detection
- **Behavioral Analysis**: Anomaly detection and suspicious behavior identification
- **LLM Classification**: AI-powered threat categorization
- **Traffic Analysis**: Real-time communication monitoring

### 2. Vulnerability Scanning
- **SSL/TLS Security**: Certificate validation and cipher analysis
- **Token Security**: JWT structure and algorithm verification
- **Connection Security**: Protocol and configuration auditing
- **Capability Assessment**: Server permission and capability review

### 3. Token Revocation System
- **Real-time Revocation**: Instant token blacklisting
- **Bulk Operations**: Multiple token revocation support
- **Distribution Network**: Automatic alert propagation
- **Audit Trail**: Complete revocation history tracking

### 4. Alert Distribution
- **TLP-based Sharing**: Traffic Light Protocol classification
- **Real-time Notifications**: Instant security updates
- **Categorized Alerts**: Structured threat information
- **Network Effect**: Collaborative security improvement

## 🧪 Testing

Run the comprehensive test suite:

```bash
# Run basic functionality test
python test_mcp_basic.py

# Test individual components (if available)
python -m pytest tests/ -v

# Security-specific tests
python test_comprehensive_security.py  # If available
```

## 🔧 Development

### Local Development Setup

1. **Set up development environment**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Code Quality Tools**
   ```bash
   # Linting
   ruff check src/
   
   # Type checking  
   mypy src/
   
   # Security scanning
   bandit -r src/
   ```

3. **Running Tests**
   ```bash
   # Basic server test
   python test_mcp_basic.py
   
   # Full server test
   python mcp_server.py
   ```

### Project Structure

```
mcp_security_git/
├── src/                           # Source code
│   ├── detection_engine/          # Threat detection
│   ├── vulnerability_scanning/    # Security scanning
│   ├── revocation/               # Token management
│   ├── alerting/                 # Alert distribution
│   └── core/                     # Core utilities
├── tests/                        # Test suite
├── mcp_server.py                 # Main MCP server
├── test_mcp_basic.py            # Basic test server
├── requirements.txt             # Dependencies
└── README.md                    # This file
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### How to Contribute

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## 📋 Troubleshooting

### Common Issues

**1. Import Errors**
```bash
# Make sure virtual environment is activated
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt
```

**2. MCP Connection Issues**
```bash
# Verify Claude Desktop configuration
cat ~/Library/Application\ Support/Claude/claude_desktop_config.json

# Check server is running
python mcp_server.py
```

**3. Missing Dependencies**
```bash
# Install specific missing packages
pip install mcp sqlalchemy redis motor

# Or reinstall all requirements
pip install -r requirements.txt --force-reinstall
```

## 📈 Performance & Monitoring

- **Logging**: Structured JSON logging with configurable levels
- **Metrics**: Built-in performance monitoring
- **Health Checks**: Endpoint status monitoring
- **Error Tracking**: Comprehensive error reporting

## 🚨 Security Considerations

1. **Keep dependencies updated** - Run `pip install -U -r requirements.txt` regularly
2. **Monitor security alerts** - Check logs for suspicious patterns
3. **Audit configurations** - Review MCP server settings periodically
4. **Test security features** - Run security tests before deployment
5. **Use strong secrets in production** - Copy `.env.production.template` to `.env` and replace values such as `JWT_SECRET` and `POSTGRES_PASSWORD` with secure random strings (`openssl rand -hex 64`)

## 📄 License

Apache License 2.0 - See [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- Built with the Model Context Protocol (MCP) framework by Anthropic
- Security patterns inspired by OWASP guidelines
- Community contributions and feedback

---

For more information, visit the [GitHub repository](https://github.com/jaesuphwang/mcp_security) or check out the [documentation](https://github.com/jaesuphwang/mcp_security/wiki).

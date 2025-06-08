# MCP Security Guardian

A comprehensive security analysis and threat detection server for Model Context Protocol (MCP) communications.

## Overview

MCP Security Guardian provides enterprise-grade security for MCP ecosystems by analyzing instructions, scanning connections, managing token revocations, and distributing threat intelligence across networks.

## Key Features

### 🛡️ Multi-Layer Threat Detection
- **Pattern Matching**: Detects known malicious patterns
- **Behavioral Analysis**: Identifies suspicious behavior sequences
- **LLM Classification**: AI-powered threat classification
- **Traffic Analysis**: Real-time traffic pattern monitoring

### 🔍 Vulnerability Scanning
- **SSL/TLS Security**: Certificate and cipher suite validation
- **Token Security**: JWT structure and algorithm verification
- **Connection Security**: Protocol and configuration auditing
- **Capability Auditing**: Server capability security assessment

### 🚫 Token Revocation System
- **Instant Revocation**: Real-time token blacklisting
- **Bulk Operations**: Revoke multiple tokens simultaneously
- **Distribution Network**: Automatic alert propagation
- **Audit Trail**: Complete revocation history

### 📢 Threat Intelligence Network
- **Alert Distribution**: TLP-based threat sharing
- **Real-time Updates**: Instant security notifications
- **Categorized Alerts**: Structured threat classification
- **Network Effect**: Collaborative security improvement

## Installation

```bash
# Install via Smithery
smithery install mcp-security-guardian

# Or install directly
pip install mcp-security-guardian
```

## Quick Start

### Using with Claude Desktop

Add to your Claude Desktop configuration:

```json
{
  "mcpServers": {
    "mcp-security-guardian": {
      "command": "python",
      "args": ["-m", "mcp_security_guardian.mcp_server"],
      "env": {
        "PYTHONPATH": "."
      }
    }
  }
}
```

### Available Tools

1. **analyze_instruction** - Analyze MCP instructions for threats
   ```
   Detects: SQL injection, command injection, credential theft, data exfiltration
   ```

2. **scan_connection** - Scan MCP connections for vulnerabilities
   ```
   Checks: SSL/TLS config, certificate validity, token security
   ```

3. **revoke_token** - Revoke compromised tokens
   ```
   Reasons: compromised, expired, misused, suspicious
   ```

4. **audit_capabilities** - Audit server capabilities
   ```
   Identifies: permission issues, dangerous capabilities, misconfigurations
   ```

5. **distribute_alert** - Share threat intelligence
   ```
   Types: malicious_instruction, vulnerability, token_revocation, server_compromise
   ```

### Available Resources

- `security://threat-patterns` - Known threat signatures
- `security://revoked-tokens` - Revoked token list
- `security://alerts` - Active security alerts

## Example Usage

### Analyze a Suspicious Instruction

```python
result = await mcp.call_tool("analyze_instruction", {
    "instruction": "DELETE FROM users WHERE 1=1",
    "context": {"source": "untrusted_client"}
})
```

### Scan a Server Connection

```python
result = await mcp.call_tool("scan_connection", {
    "server_url": "https://example.mcp.server",
    "token": "eyJhbGciOiJIUzI1NiIs..."
})
```

### Revoke a Compromised Token

```python
result = await mcp.call_tool("revoke_token", {
    "token": "eyJhbGciOiJIUzI1NiIs...",
    "reason": "compromised",
    "description": "Token found in public repository"
})
```

## Security Levels

- **CRITICAL**: Immediate action required
- **HIGH**: Significant security risk
- **MEDIUM**: Potential security concern
- **LOW**: Minor security observation

## Configuration

Environment variables:

- `LOG_LEVEL`: Logging verbosity (default: INFO)
- `SECURITY_MODE`: Operation mode (development/production)
- `REDIS_URL`: Redis connection for distributed operations
- `DATABASE_URL`: PostgreSQL for persistent storage

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.

## Support

- Issues: [GitHub Issues](https://github.com/mcp-security/mcp-security-guardian/issues)
- Documentation: [Full Documentation](https://mcp-security.github.io/docs)
- Community: [Discord Server](https://discord.gg/mcp-security)

## Acknowledgments

Built with the Model Context Protocol (MCP) framework by Anthropic.
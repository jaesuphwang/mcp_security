# Security Policy

## Reporting Security Vulnerabilities

We take security seriously. If you discover a security vulnerability, please report it responsibly.

**DO NOT** create a public GitHub issue for security vulnerabilities.

### How to Report

Email: security@mcp-guardian.com

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide updates on our progress.

## Security Features

### 1. Authentication & Authorization
- **JWT Authentication**: RS256/ES256 algorithms only
- **CSRF Protection**: Double-submit cookie pattern
- **Session Management**: Secure token storage
- **MFA Support**: TOTP-based two-factor authentication

### 2. Input Security
- **Validation**: All inputs validated with Pydantic
- **Sanitization**: HTML entity encoding, null byte removal
- **Size Limits**: Request size limits (100KB default)
- **File Upload**: Type validation and sandboxed storage

### 3. Injection Prevention
- **SQL Injection**: Parameterized queries, pattern detection
- **XSS**: Content Security Policy, output encoding
- **Command Injection**: Shell command sanitization
- **Path Traversal**: Path normalization and validation
- **LDAP Injection**: Special character escaping

### 4. Password Security
- **Hashing**: Argon2id with salt
- **Policy**: 12+ chars, mixed case, numbers, special chars
- **Breach Check**: HaveIBeenPwned API integration
- **History**: Prevents password reuse
- **Lockout**: Progressive delays after failures

### 5. API Security
- **Rate Limiting**: Per-IP and per-user limits
- **HTTPS Only**: TLS 1.2+ enforced
- **Security Headers**: HSTS, X-Frame-Options, CSP
- **CORS**: Strict origin validation

### 6. Data Protection
- **Encryption at Rest**: AES-256 for databases
- **Encryption in Transit**: TLS for all connections
- **PII Handling**: Automatic redaction in logs
- **Backup Encryption**: Encrypted offsite backups

### 7. Infrastructure Security
- **Container Security**: Non-root users, dropped capabilities
- **Network Isolation**: Segmented networks
- **Secret Management**: Environment-based, no hardcoding
- **Dependency Scanning**: Regular vulnerability checks

## Security Checklist for Deployment

### Pre-Deployment
- [ ] Generate strong JWT keys (RS256/ES256)
- [ ] Set secure database passwords
- [ ] Configure CORS origins
- [ ] Set up SSL certificates
- [ ] Review firewall rules
- [ ] Configure rate limits
- [ ] Enable audit logging
- [ ] Set up monitoring alerts

### Post-Deployment
- [ ] Verify HTTPS is enforced
- [ ] Test rate limiting
- [ ] Confirm logs don't contain sensitive data
- [ ] Verify backup encryption
- [ ] Test incident response plan
- [ ] Schedule security audits
- [ ] Configure SIEM integration
- [ ] Set up vulnerability scanning

## Security Headers

The following security headers are enforced:

```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

## Compliance

The MCP Security Guardian is designed to help meet various compliance requirements:

- **OWASP Top 10**: Full coverage
- **CIS Controls**: Implemented
- **GDPR**: Privacy by design
- **SOC 2**: Audit logging and controls
- **HIPAA**: Encryption and access controls (if applicable)

## Security Updates

- Security patches are released as soon as vulnerabilities are discovered
- Subscribe to security announcements at: https://mcp-guardian.com/security
- Check for updates regularly: `docker pull mcp-guardian:latest`

## Security Tools Integration

### SIEM Integration
- Supports CEF and LEEF formats
- Syslog forwarding available
- Splunk HEC compatible

### Vulnerability Scanning
- SAST: Integrated with CI/CD
- DAST: Regular penetration testing
- Dependency scanning: Daily automated scans

## Incident Response

### Severity Levels
- **Critical**: Immediate response, potential data breach
- **High**: Response within 4 hours, significant impact
- **Medium**: Response within 24 hours, limited impact
- **Low**: Response within 72 hours, minimal impact

### Response Process
1. **Detection**: Automated alerts or user report
2. **Triage**: Assess severity and impact
3. **Containment**: Isolate affected systems
4. **Investigation**: Root cause analysis
5. **Remediation**: Fix vulnerability
6. **Recovery**: Restore normal operations
7. **Lessons Learned**: Update procedures

## Security Training

All contributors should:
- Complete OWASP secure coding training
- Understand the security features
- Follow secure development practices
- Participate in security reviews

## Contact

- Security Issues: security@mcp-guardian.com
- PGP Key: Available at https://mcp-guardian.com/pgp
- Bug Bounty: https://mcp-guardian.com/bounty

---

Remember: Security is everyone's responsibility. When in doubt, ask the security team.
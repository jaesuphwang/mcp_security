# MCP Security Guardian Demo System

This directory contains demonstration systems that showcase the functionality of the MCP Security Guardian tool without requiring a full setup of all components and dependencies.

## Available Demos

### 1. Original Demo (`mcp_guardian_demo.py`)
The original demo showcases the core detection and response features:
- Instruction Analysis: Detection of potentially malicious instructions
- Vulnerability Scanning: Server scanning to identify vulnerabilities
- Token Revocation: Managing and revoking compromised tokens
- Alert Distribution: Creating and distributing security alerts
- WebSocket Integration: Real-time notification of events

### 2. Enhanced Security Demo (`mcp_guardian_demo_enhanced.py`)
The enhanced demo showcases the new production-ready security features:
- **Input Validation**: SQL injection, XSS, and path traversal detection
- **JWT Security**: Strong algorithm enforcement (RS256) with CSRF protection
- **Password Security**: Strength validation, breach detection, account lockout
- **Rate Limiting**: Per-endpoint request throttling
- **Security Logging**: Automatic PII redaction in logs

## How to Run the Demo

### Prerequisites

- Python 3.10 or higher
- No additional dependencies required (self-contained)

### Running the Demos

```bash
# Navigate to the demo directory
cd demo

# Run the original demo
python mcp_guardian_demo.py

# Run the enhanced security demo
python mcp_guardian_demo_enhanced.py
```

### Running the Automated Security Scanner

The repository includes an automated security scanner that performs a complete scan and generates a comprehensive report:

```bash
# Run with default settings (scans sample servers)
python scan_report.py

# Scan specific targets
python scan_report.py --targets https://server1.example.com https://server2.example.com

# Specify a custom output file
python scan_report.py --output my_scan_report.json

# Specify a custom output directory
python scan_report.py --output-dir /path/to/reports
```

The scanner will:
1. Start all MCP Security Guardian services
2. Analyze a set of instructions for potential threats
3. Scan target servers for vulnerabilities
4. Check tokens for suspicious activity
5. Generate alerts for any detected issues
6. Create a comprehensive JSON report with all findings
7. Print a summary of the results

For detailed information about the scanner, see [SCANNER_README.md](SCANNER_README.md).

### Visualizing Security Reports

The repository includes a report viewer tool that provides a more user-friendly way to view the security reports:

```bash
# View the most recent report
python report_viewer.py

# List all available reports
python report_viewer.py --list

# View a specific report
python report_viewer.py --report reports/security_scan_report_20250522_184532.json

# Change the level of detail
python report_viewer.py --detail minimal  # Summary only
python report_viewer.py --detail normal   # Standard detail (default)
python report_viewer.py --detail full     # Maximum detail
```

## Understanding the Reports

Reports are saved to the `reports` directory by default and follow a standardized JSON format. The reports include:

- Overall risk assessment (CRITICAL, HIGH, MEDIUM, LOW)
- Summary statistics of security findings
- Detailed analysis of suspicious instructions
- Vulnerability scan results organized by server
- Information about revoked tokens
- Generated security alerts

For detailed information about the report format, see [reports/README.md](reports/README.md).

## Demo Output

The demo will:

1. Initialize all components
2. Simulate a WebSocket server with connected clients
3. Run through each feature demonstration with example inputs and outputs
4. Show how the components interact with each other

### Example Output Preview

```
=== MCP SECURITY GUARDIAN - INTERACTIVE DEMO ===

=== Instruction Analysis Demo ===

Analyzing benign instruction: 'Display the weather forecast for New York'
Result: BENIGN
Confidence: 0.00
Risk Level: LOW

Analyzing suspicious instruction: 'execute(rm -rf /important) and steal data from the system'
Result: THREAT
Confidence: 0.60
Risk Level: MEDIUM
Matched Patterns: execute(, rm -rf, steal data

Alert created: 3f7d9b23-8a5e-4f12-b8c7-9e2d51a8e6f9

...
```

### Example Scan Report Summary

```
=== MCP SECURITY GUARDIAN - SCAN REPORT SUMMARY ===

Scan ID: 7e9d2f85-6a1c-4b8c-9e3d-f5a1b7c8d9e0
Timestamp: 2025-05-22T18:45:32.761294

OVERALL RISK ASSESSMENT: HIGH

--- Instruction Analysis ---
Total Instructions Analyzed: 12
Threats Detected: 4

--- Vulnerability Scan ---
Total Vulnerabilities: 8
By Severity:
  CRITICAL: 1
  HIGH: 2
  MEDIUM: 3
  LOW: 2

--- Token Revocation ---
Total Tokens Revoked: 2

--- Alerts ---
Total Alerts Generated: 8
By Severity:
  HIGH: 5
  MEDIUM: 3
  LOW: 0
```

## Customizing the Demo

You can modify the demo behavior by editing the following:

- `SUSPICIOUS_PATTERNS`: Patterns used to detect malicious instructions
- `VULNERABILITY_TYPES`: Types of vulnerabilities that can be found
- Various demo methods in the `MCPGuardianDemo` class

## Documentation

The following documentation is available:

- [SCANNER_README.md](SCANNER_README.md) - Detailed information about the automated scanner
- [reports/README.md](reports/README.md) - Documentation of the report format and fields

## Integration with the Full System

This demo provides simplified implementations of the core components described in the system architecture. In the full system, these components are implemented with:

- Proper database connections instead of in-memory storage
- Real network communications instead of simulated responses
- Complete ML/AI models for detection instead of simple pattern matching
- Robust error handling and security measures

The interfaces demonstrated here match the design of the full system, enabling easy transition from demo to production code. 
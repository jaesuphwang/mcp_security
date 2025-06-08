# MCP Security Guardian - Automated Scanner

The `scan_report.py` script provides a comprehensive security scanning and reporting solution for MCP servers and instructions. This tool runs a full security scan across all security components of the MCP Security Guardian system and generates a detailed report of findings.

## Features

- **Multi-component Security Scanning**: Runs all security analysis components in parallel
- **Comprehensive Reporting**: Generates detailed JSON reports with categorized findings
- **Risk Assessment**: Provides an overall risk score based on detected issues
- **Automated Alerting**: Generates security alerts for detected issues
- **Token Security**: Validates and revokes suspicious tokens
- **Customizable**: Configurable scanning targets and output options

## Usage

### Basic Usage

```bash
# Run with default settings (scans sample servers)
python scan_report.py

# View help and options
python scan_report.py --help
```

### Command Line Options

```
usage: scan_report.py [-h] [--targets TARGETS [TARGETS ...]] [--output OUTPUT] [--output-dir OUTPUT_DIR]

MCP Security Guardian Scanner

options:
  -h, --help            show this help message and exit
  --targets TARGETS [TARGETS ...]
                        List of server URLs to scan
  --output OUTPUT       Output filename for the report
  --output-dir OUTPUT_DIR
                        Directory to store reports
```

### Examples

```bash
# Scan specific servers
python scan_report.py --targets https://server1.example.com https://server2.example.com

# Save the report with a custom filename
python scan_report.py --output myreport.json

# Use a different directory for reports
python scan_report.py --output-dir /path/to/reports
```

## Report Format

The generated reports are in JSON format with the following structure:

```json
{
  "scan_id": "unique-id-for-the-scan",
  "timestamp": "ISO-8601-timestamp",
  "summary": {
    "total_instructions_analyzed": 12,
    "threats_detected": 4,
    "total_vulnerabilities": 8,
    "vulnerabilities_by_severity": {
      "CRITICAL": 1,
      "HIGH": 2,
      "MEDIUM": 3,
      "LOW": 2
    },
    "total_tokens_revoked": 2,
    "total_alerts": 8,
    "alerts_by_severity": {
      "HIGH": 5,
      "MEDIUM": 3,
      "LOW": 0
    },
    "risk_assessment": "HIGH"
  },
  "instruction_analysis": [
    {
      "instruction": "text-of-analyzed-instruction",
      "analysis": {
        // Analysis results with confidence scores, risk level, etc.
      }
    }
  ],
  "vulnerabilities": [
    {
      "target": "https://server-url.example.com",
      "findings": [
        // List of vulnerabilities found
      ]
    }
  ],
  "revoked_tokens": [
    {
      "token": {
        // Token information
      },
      "revocation": {
        // Revocation details
      }
    }
  ],
  "alerts": [
    // List of generated alerts
  ]
}
```

## Risk Assessment Logic

The overall risk assessment is calculated based on:

- **CRITICAL**: Any critical vulnerabilities or more than 2 high-severity alerts
- **HIGH**: Multiple high vulnerabilities or any high-severity alerts
- **MEDIUM**: Multiple medium vulnerabilities or alerts
- **LOW**: Few or no significant findings

## Customizing the Scanner

You can modify the scanner behavior by editing the following:

1. **Detection Patterns**: Edit `SUSPICIOUS_PATTERNS` in `mcp_guardian_demo.py` to customize what patterns trigger alerts
2. **Vulnerability Types**: Modify `VULNERABILITY_TYPES` in `mcp_guardian_demo.py` to adjust vulnerability categories
3. **Risk Assessment Logic**: Adjust the `_assess_overall_risk` method in the `ReportGenerator` class
4. **Sample Data**: Change the `generate_sample_instructions()` and `generate_sample_servers()` functions for different test data

## Integration with Monitoring Systems

The generated JSON reports can be integrated with:

- Security Information and Event Management (SIEM) systems
- Monitoring dashboards 
- Alerting platforms
- Ticketing systems for vulnerability management

## Troubleshooting

If the scanner encounters errors:

1. Check that the demo components are working correctly
2. Ensure your target servers are reachable (if using custom targets)
3. Verify you have write permissions in the output directory
4. Check the logs for specific error messages 
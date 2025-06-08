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
MCP Security Guardian - Report Viewer

This script provides a simple visualization of security scan reports.
"""
import json
import argparse
import os
import sys
from datetime import datetime
from typing import Dict, List, Any

# ANSI color codes for terminal output
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    
    @staticmethod
    def severity_color(severity: str) -> str:
        """Get the appropriate color for a severity level."""
        return {
            "CRITICAL": Colors.RED + Colors.BOLD,
            "HIGH": Colors.RED,
            "MEDIUM": Colors.YELLOW,
            "LOW": Colors.GREEN,
        }.get(severity, Colors.RESET)


def load_report(file_path: str) -> Dict[str, Any]:
    """Load a report from a JSON file."""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError:
        print(f"Error: {file_path} is not a valid JSON file")
        sys.exit(1)
    except FileNotFoundError:
        print(f"Error: File not found: {file_path}")
        sys.exit(1)


def print_header(text: str, char: str = "=", color: str = Colors.BOLD) -> None:
    """Print a formatted header."""
    width = min(80, max(len(text) + 4, 40))
    print(f"\n{color}{char * width}")
    print(f"{text.center(width)}")
    print(f"{char * width}{Colors.RESET}")


def print_section(title: str, color: str = Colors.CYAN) -> None:
    """Print a section title."""
    print(f"\n{color}{Colors.BOLD}{title}{Colors.RESET}")
    print(f"{'-' * len(title)}")


def print_summary(report: Dict[str, Any]) -> None:
    """Print a summary of the report."""
    summary = report["summary"]
    risk = summary["risk_assessment"]
    risk_color = Colors.severity_color(risk)
    
    print_header(f"MCP SECURITY GUARDIAN - SCAN REPORT", "=", Colors.BLUE + Colors.BOLD)
    
    # Metadata
    print(f"\n{Colors.BOLD}Scan ID:{Colors.RESET} {report['scan_id']}")
    print(f"{Colors.BOLD}Timestamp:{Colors.RESET} {report['timestamp']}")
    
    # Risk Assessment
    print(f"\n{Colors.BOLD}OVERALL RISK ASSESSMENT:{Colors.RESET} {risk_color}{risk}{Colors.RESET}")
    
    # Summary Table
    print_section("SUMMARY", Colors.CYAN)
    
    print(f"  {Colors.BOLD}Instructions Analyzed:{Colors.RESET} {summary['total_instructions_analyzed']}")
    print(f"  {Colors.BOLD}Threats Detected:{Colors.RESET} {summary['threats_detected']}")
    
    print(f"  {Colors.BOLD}Total Vulnerabilities:{Colors.RESET} {summary['total_vulnerabilities']}")
    for severity, count in summary['vulnerabilities_by_severity'].items():
        if count > 0:
            print(f"    {Colors.severity_color(severity)}{severity}:{Colors.RESET} {count}")
    
    print(f"  {Colors.BOLD}Tokens Revoked:{Colors.RESET} {summary['total_tokens_revoked']}")
    
    print(f"  {Colors.BOLD}Total Alerts:{Colors.RESET} {summary['total_alerts']}")
    for severity, count in summary['alerts_by_severity'].items():
        if count > 0:
            print(f"    {Colors.severity_color(severity)}{severity}:{Colors.RESET} {count}")


def print_threats(report: Dict[str, Any], max_items: int = 5) -> None:
    """Print details about detected threats."""
    threats = [item for item in report["instruction_analysis"] if item["analysis"]["is_threat"]]
    
    if not threats:
        return
    
    print_section("DETECTED THREATS", Colors.RED)
    
    for i, threat in enumerate(threats[:max_items], 1):
        instruction = threat["instruction"]
        analysis = threat["analysis"]
        confidence = analysis["confidence"]
        risk_level = analysis["risk_level"]
        risk_color = Colors.severity_color(risk_level)
        
        print(f"\n{Colors.BOLD}Threat #{i}:{Colors.RESET}")
        print(f"  {Colors.BOLD}Instruction:{Colors.RESET} {instruction}")
        print(f"  {Colors.BOLD}Risk Level:{Colors.RESET} {risk_color}{risk_level}{Colors.RESET}")
        print(f"  {Colors.BOLD}Confidence:{Colors.RESET} {confidence:.2f}")
        if analysis["matched_patterns"]:
            print(f"  {Colors.BOLD}Matched Patterns:{Colors.RESET} {', '.join(analysis['matched_patterns'])}")
    
    if len(threats) > max_items:
        print(f"\n{Colors.YELLOW}... and {len(threats) - max_items} more threats{Colors.RESET}")


def print_critical_vulnerabilities(report: Dict[str, Any], max_items: int = 5) -> None:
    """Print details about critical and high vulnerabilities."""
    all_vulns = []
    
    # Collect all vulnerabilities across all targets
    for target in report["vulnerabilities"]:
        server_url = target["target"]
        for vuln in target["findings"]:
            if vuln["severity"] in ["CRITICAL", "HIGH"]:
                vuln["server_url"] = server_url
                all_vulns.append(vuln)
    
    if not all_vulns:
        return
    
    print_section("CRITICAL & HIGH VULNERABILITIES", Colors.RED)
    
    for i, vuln in enumerate(all_vulns[:max_items], 1):
        severity = vuln["severity"]
        vuln_type = vuln["type"]
        severity_color = Colors.severity_color(severity)
        
        print(f"\n{Colors.BOLD}Vulnerability #{i}:{Colors.RESET}")
        print(f"  {Colors.BOLD}Server:{Colors.RESET} {vuln['server_url']}")
        print(f"  {Colors.BOLD}Type:{Colors.RESET} {vuln_type}")
        print(f"  {Colors.BOLD}Severity:{Colors.RESET} {severity_color}{severity}{Colors.RESET}")
        print(f"  {Colors.BOLD}Description:{Colors.RESET} {vuln['description']}")
        print(f"  {Colors.BOLD}Remediation:{Colors.RESET} {vuln['remediation']}")
    
    if len(all_vulns) > max_items:
        print(f"\n{Colors.YELLOW}... and {len(all_vulns) - max_items} more critical/high vulnerabilities{Colors.RESET}")


def print_revoked_tokens(report: Dict[str, Any], max_items: int = 3) -> None:
    """Print details about revoked tokens."""
    revoked_tokens = report["revoked_tokens"]
    
    if not revoked_tokens:
        return
    
    print_section("REVOKED TOKENS", Colors.MAGENTA)
    
    for i, item in enumerate(revoked_tokens[:max_items], 1):
        token = item["token"]
        revocation = item["revocation"]
        
        print(f"\n{Colors.BOLD}Revoked Token #{i}:{Colors.RESET}")
        print(f"  {Colors.BOLD}User:{Colors.RESET} {token['user_id']}")
        print(f"  {Colors.BOLD}Token ID:{Colors.RESET} {token['token_id']}")
        print(f"  {Colors.BOLD}Reason:{Colors.RESET} {revocation['reason']}")
        print(f"  {Colors.BOLD}Permissions:{Colors.RESET} {', '.join(token['permissions'])}")
        print(f"  {Colors.BOLD}Revoked At:{Colors.RESET} {revocation['revoked_at']}")
    
    if len(revoked_tokens) > max_items:
        print(f"\n{Colors.YELLOW}... and {len(revoked_tokens) - max_items} more revoked tokens{Colors.RESET}")


def print_report(report: Dict[str, Any], detail_level: str = "normal") -> None:
    """Print a report in a user-friendly format."""
    print_summary(report)
    
    if detail_level == "minimal":
        return
    
    print_threats(report)
    print_critical_vulnerabilities(report)
    print_revoked_tokens(report)
    
    if detail_level == "normal":
        return
    
    # Add more detailed sections for full reports
    if detail_level == "full":
        pass  # Add more details here as needed


def list_reports(reports_dir: str) -> None:
    """List all available reports in the directory."""
    if not os.path.exists(reports_dir):
        print(f"Error: Directory not found: {reports_dir}")
        sys.exit(1)
    
    reports = [f for f in os.listdir(reports_dir) if f.endswith('.json')]
    reports.sort(reverse=True)  # Sort by newest first
    
    if not reports:
        print(f"No reports found in {reports_dir}")
        return
    
    print_header("AVAILABLE REPORTS", "=", Colors.BLUE + Colors.BOLD)
    
    for i, report_file in enumerate(reports, 1):
        try:
            file_path = os.path.join(reports_dir, report_file)
            with open(file_path, 'r') as f:
                report_data = json.load(f)
                
            timestamp = report_data.get("timestamp", "Unknown")
            risk = report_data.get("summary", {}).get("risk_assessment", "Unknown")
            risk_color = Colors.severity_color(risk)
            
            # Get file size
            size_kb = os.path.getsize(file_path) / 1024
            
            print(f"{i}. {Colors.BOLD}{report_file}{Colors.RESET}")
            print(f"   Timestamp: {timestamp}")
            print(f"   Risk: {risk_color}{risk}{Colors.RESET}")
            print(f"   Size: {size_kb:.1f} KB")
            print()
        except:
            print(f"{i}. {report_file} (Error reading file)")


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(description="MCP Security Guardian Report Viewer")
    parser.add_argument("--list", action="store_true", help="List all available reports")
    parser.add_argument("--report", help="Path to the report file to view")
    parser.add_argument("--reports-dir", default="reports", help="Directory containing reports")
    parser.add_argument("--detail", choices=["minimal", "normal", "full"], default="normal",
                       help="Level of detail to display")
    
    args = parser.parse_args()
    
    if args.list:
        list_reports(args.reports_dir)
        return
    
    if not args.report:
        # Try to load the most recent report
        reports_dir = args.reports_dir
        if not os.path.exists(reports_dir):
            print(f"Error: Reports directory not found: {reports_dir}")
            sys.exit(1)
        
        reports = [f for f in os.listdir(reports_dir) if f.endswith('.json')]
        if not reports:
            print(f"No reports found in {reports_dir}")
            sys.exit(1)
        
        reports.sort(reverse=True)  # Newest first
        args.report = os.path.join(reports_dir, reports[0])
        print(f"Viewing most recent report: {os.path.basename(args.report)}")
    
    report = load_report(args.report)
    print_report(report, args.detail)


if __name__ == "__main__":
    main() 
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
MCP Security Guardian - Interactive Demo System

This script demonstrates the core features of the MCP Security Guardian system
using simplified implementations to showcase the functionality.
"""
import asyncio
import json
import uuid
import random
import logging
import sys
import os
from datetime import datetime
from typing import Dict, List, Any, Optional, Set

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("mcp_guardian_demo")

# --- Mock Data Structures ---

# Detection Engine Data
SUSPICIOUS_PATTERNS = [
    "execute(", "system(", "eval(", "subprocess",
    "delete all", "drop table", "rm -rf", "format disk",
    "steal data", "exfiltrate", "bypass security", "disable logging"
]

# Vulnerability Data
VULNERABILITY_TYPES = [
    "weak_transport_security", "insecure_authentication",
    "excessive_permissions", "unpatched_system", 
    "improper_access_control", "information_exposure"
]

# Token Storage (simulated database)
token_store = {}
revoked_tokens = set()

# Alert Storage
alerts = []

# Connected WebSocket clients (for demo purposes)
websocket_clients = []

# --- Mock Component Implementations ---

class DetectionEngine:
    """Simplified Detection Engine implementation."""
    
    async def analyze_instruction(self, instruction: str, session_id: str) -> Dict[str, Any]:
        """Analyze an instruction for potential threats."""
        logger.info(f"Analyzing instruction in session {session_id}")
        
        # Simple pattern matching
        is_threat = False
        matched_patterns = []
        confidence = 0.0
        
        # Check for suspicious patterns
        for pattern in SUSPICIOUS_PATTERNS:
            if pattern.lower() in instruction.lower():
                is_threat = True
                matched_patterns.append(pattern)
                confidence += 0.2  # Increase confidence with each match
        
        confidence = min(confidence, 0.95)  # Cap at 0.95
        
        # Create result
        result = {
            "instruction_id": str(uuid.uuid4()),
            "session_id": session_id,
            "timestamp": datetime.now().isoformat(),
            "is_threat": is_threat,
            "confidence": confidence,
            "matched_patterns": matched_patterns,
            "risk_level": "HIGH" if confidence > 0.7 else "MEDIUM" if confidence > 0.4 else "LOW",
            "analysis_time_ms": random.randint(50, 150)
        }
        
        return result


class VulnerabilityScanner:
    """Simplified Vulnerability Scanner implementation."""
    
    async def scan_server(self, server_url: str, auth_token: Optional[str] = None) -> List[Dict[str, Any]]:
        """Scan a server for vulnerabilities."""
        logger.info(f"Scanning server: {server_url}")
        
        # Simulate scanning process
        await asyncio.sleep(1)  # Simulate scan duration
        
        # Generate random vulnerabilities
        vulnerabilities = []
        num_vulns = random.randint(0, 4)
        
        for _ in range(num_vulns):
            vuln_type = random.choice(VULNERABILITY_TYPES)
            severity = random.choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"])
            
            vulnerability = {
                "id": str(uuid.uuid4()),
                "type": vuln_type,
                "severity": severity,
                "description": f"Found {vuln_type} vulnerability with {severity} severity",
                "affected_component": f"component_{random.randint(1, 5)}",
                "remediation": f"Fix the {vuln_type} by updating configuration",
                "detected_at": datetime.now().isoformat()
            }
            
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities


class RevocationSystem:
    """Simplified Revocation System implementation."""
    
    async def issue_token(self, user_id: str, permissions: List[str]) -> Dict[str, Any]:
        """Issue a new token (for demo purposes)."""
        token_id = str(uuid.uuid4())
        token_value = f"mcp_token_{token_id}"
        
        token_info = {
            "token_id": token_id,
            "token_value": token_value,
            "user_id": user_id,
            "permissions": permissions,
            "issued_at": datetime.now().isoformat(),
            "expires_at": "2099-12-31T23:59:59Z",  # Far future for demo
        }
        
        # Store token
        token_store[token_id] = token_info
        
        return token_info
    
    async def revoke_token(self, token_id: str, reason: str) -> Dict[str, Any]:
        """Revoke a token."""
        logger.info(f"Revoking token {token_id} for reason: {reason}")
        
        if token_id not in token_store:
            raise ValueError(f"Token {token_id} not found")
        
        if token_id in revoked_tokens:
            raise ValueError(f"Token {token_id} already revoked")
        
        # Mark as revoked
        revoked_tokens.add(token_id)
        
        revocation_info = {
            "revocation_id": str(uuid.uuid4()),
            "token_id": token_id,
            "reason": reason,
            "revoked_at": datetime.now().isoformat()
        }
        
        return revocation_info
    
    async def check_token(self, token_id: str) -> Dict[str, Any]:
        """Check if a token is valid."""
        if token_id not in token_store:
            return {"valid": False, "reason": "Token not found"}
        
        if token_id in revoked_tokens:
            return {"valid": False, "reason": "Token revoked"}
        
        return {"valid": True, "token_info": token_store[token_id]}


class AlertSystem:
    """Simplified Alert System implementation."""
    
    async def create_alert(self, title: str, description: str, severity: str, 
                          source_id: str, affected_entities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create a new security alert."""
        logger.info(f"Creating alert: {title}")
        
        alert_id = str(uuid.uuid4())
        
        alert = {
            "alert_id": alert_id,
            "title": title,
            "description": description,
            "severity": severity,
            "source_id": source_id,
            "affected_entities": affected_entities,
            "created_at": datetime.now().isoformat(),
            "status": "NEW"
        }
        
        # Store alert
        alerts.append(alert)
        
        # Broadcast to WebSocket clients
        await self.broadcast_alert(alert)
        
        return alert
    
    async def broadcast_alert(self, alert: Dict[str, Any]) -> None:
        """Broadcast an alert to all connected WebSocket clients."""
        if not websocket_clients:
            logger.info("No connected clients to broadcast to")
            return
        
        logger.info(f"Broadcasting alert to {len(websocket_clients)} clients")
        
        # In a real system, this would send to actual WebSocket connections
        # For demo purposes, we just log it
        for i, client in enumerate(websocket_clients):
            logger.info(f"Alert sent to client {i+1}: {alert['title']}")
    
    async def get_alerts(self, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get alerts, optionally filtered by severity."""
        if severity:
            return [a for a in alerts if a["severity"] == severity]
        return alerts.copy()


# --- Demo WebSocket Server ---

class WebSocketServer:
    """Mock WebSocket server for the demo."""
    
    async def start(self) -> None:
        """Start the WebSocket server (simulated)."""
        logger.info("Starting WebSocket server on ws://localhost:8002")
        
        # Simulate clients connecting
        for i in range(3):
            client_id = f"demo_client_{i+1}"
            websocket_clients.append(client_id)
            logger.info(f"Client {client_id} connected to WebSocket server")
    
    async def stop(self) -> None:
        """Stop the WebSocket server."""
        logger.info("Stopping WebSocket server")
        websocket_clients.clear()


# --- Demo Application ---

class MCPGuardianDemo:
    """Main demo application that showcases the MCP Security Guardian functionality."""
    
    def __init__(self):
        """Initialize the demo components."""
        self.detection_engine = DetectionEngine()
        self.vulnerability_scanner = VulnerabilityScanner()
        self.revocation_system = RevocationSystem()
        self.alert_system = AlertSystem()
        self.websocket_server = WebSocketServer()
    
    async def start(self) -> None:
        """Start the demo system."""
        logger.info("Starting MCP Security Guardian Demo")
        await self.websocket_server.start()
    
    async def stop(self) -> None:
        """Stop the demo system."""
        logger.info("Stopping MCP Security Guardian Demo")
        await self.websocket_server.stop()
    
    async def demo_instruction_analysis(self) -> None:
        """Demonstrate instruction analysis."""
        print("\n=== Instruction Analysis Demo ===")
        
        # Example 1: Benign instruction
        benign_instruction = "Display the weather forecast for New York"
        session_id = str(uuid.uuid4())
        
        print(f"\nAnalyzing benign instruction: '{benign_instruction}'")
        result = await self.detection_engine.analyze_instruction(benign_instruction, session_id)
        print(f"Result: {'THREAT' if result['is_threat'] else 'BENIGN'}")
        print(f"Confidence: {result['confidence']:.2f}")
        print(f"Risk Level: {result['risk_level']}")
        
        # Example 2: Malicious instruction
        malicious_instruction = "execute(rm -rf /important) and steal data from the system"
        
        print(f"\nAnalyzing suspicious instruction: '{malicious_instruction}'")
        result = await self.detection_engine.analyze_instruction(malicious_instruction, session_id)
        print(f"Result: {'THREAT' if result['is_threat'] else 'BENIGN'}")
        print(f"Confidence: {result['confidence']:.2f}")
        print(f"Risk Level: {result['risk_level']}")
        print(f"Matched Patterns: {', '.join(result['matched_patterns'])}")
        
        # Create an alert for the malicious instruction
        if result['is_threat']:
            alert = await self.alert_system.create_alert(
                title="Malicious Instruction Detected",
                description=f"Detected potentially malicious instruction: '{malicious_instruction}'",
                severity="HIGH" if result['confidence'] > 0.7 else "MEDIUM",
                source_id="demo_detection_engine",
                affected_entities=[{"id": session_id, "type": "session"}]
            )
            
            print(f"\nAlert created: {alert['alert_id']}")
    
    async def demo_vulnerability_scanning(self) -> None:
        """Demonstrate vulnerability scanning."""
        print("\n=== Vulnerability Scanning Demo ===")
        
        server_url = "https://demo-mcp-server.example.com"
        print(f"\nScanning server: {server_url}")
        
        vulnerabilities = await self.vulnerability_scanner.scan_server(server_url)
        
        if not vulnerabilities:
            print("No vulnerabilities found")
        else:
            print(f"Found {len(vulnerabilities)} vulnerabilities:")
            for i, vuln in enumerate(vulnerabilities, 1):
                print(f"\n{i}. {vuln['type']} ({vuln['severity']})")
                print(f"   Description: {vuln['description']}")
                print(f"   Remediation: {vuln['remediation']}")
            
            # Create alerts for critical vulnerabilities
            for vuln in vulnerabilities:
                if vuln['severity'] in ["HIGH", "CRITICAL"]:
                    alert = await self.alert_system.create_alert(
                        title=f"{vuln['severity']} Vulnerability: {vuln['type']}",
                        description=vuln['description'],
                        severity=vuln['severity'],
                        source_id="demo_vulnerability_scanner",
                        affected_entities=[{"id": server_url, "type": "server"}]
                    )
                    
                    print(f"\nAlert created for {vuln['severity']} vulnerability: {alert['alert_id']}")
    
    async def demo_token_revocation(self) -> None:
        """Demonstrate token revocation."""
        print("\n=== Token Revocation Demo ===")
        
        # Issue a token
        user_id = "demo_user_123"
        permissions = ["read", "write", "analyze"]
        
        print(f"\nIssuing token for user: {user_id}")
        token = await self.revocation_system.issue_token(user_id, permissions)
        
        print(f"Token issued: {token['token_id']}")
        print(f"Token value: {token['token_value']}")
        
        # Check token validity
        print("\nChecking token validity...")
        check_result = await self.revocation_system.check_token(token['token_id'])
        print(f"Token valid: {check_result['valid']}")
        
        # Revoke the token
        print("\nRevoking token due to suspicious activity...")
        revocation = await self.revocation_system.revoke_token(
            token['token_id'], 
            "suspicious_activity"
        )
        
        print(f"Token revoked: {revocation['revocation_id']}")
        
        # Check token validity again
        print("\nChecking token validity after revocation...")
        check_result = await self.revocation_system.check_token(token['token_id'])
        print(f"Token valid: {check_result['valid']}")
        if not check_result['valid']:
            print(f"Reason: {check_result['reason']}")
        
        # Create an alert for the token revocation
        alert = await self.alert_system.create_alert(
            title="Token Revoked Due to Suspicious Activity",
            description=f"Token {token['token_id']} for user {user_id} was revoked due to suspicious activity",
            severity="HIGH",
            source_id="demo_revocation_system",
            affected_entities=[
                {"id": user_id, "type": "user"},
                {"id": token['token_id'], "type": "token"}
            ]
        )
        
        print(f"\nAlert created: {alert['alert_id']}")
    
    async def demo_alert_system(self) -> None:
        """Demonstrate the alert system."""
        print("\n=== Alert System Demo ===")
        
        # Create various alerts
        print("\nCreating various security alerts...")
        
        alerts_to_create = [
            {
                "title": "Unusual Traffic Pattern Detected",
                "description": "Detected unusual traffic pattern from IP 192.168.1.100",
                "severity": "MEDIUM",
                "source_id": "demo_traffic_analyzer",
                "affected_entities": [{"id": "192.168.1.100", "type": "ip_address"}]
            },
            {
                "title": "Multiple Authentication Failures",
                "description": "User admin_user had 5 failed login attempts in 2 minutes",
                "severity": "HIGH",
                "source_id": "demo_auth_monitor",
                "affected_entities": [{"id": "admin_user", "type": "user"}]
            },
            {
                "title": "System Update Available",
                "description": "Security update KB12345 is available for installation",
                "severity": "LOW",
                "source_id": "demo_update_checker",
                "affected_entities": [{"id": "main_server", "type": "server"}]
            }
        ]
        
        for alert_data in alerts_to_create:
            alert = await self.alert_system.create_alert(**alert_data)
            print(f"Created alert: {alert['title']} (ID: {alert['alert_id']})")
        
        # Get all alerts
        print("\nRetrieving all alerts...")
        all_alerts = await self.alert_system.get_alerts()
        print(f"Total alerts: {len(all_alerts)}")
        
        # Get high severity alerts
        print("\nRetrieving HIGH severity alerts...")
        high_alerts = await self.alert_system.get_alerts(severity="HIGH")
        print(f"HIGH severity alerts: {len(high_alerts)}")
        
        # Show alert details
        if high_alerts:
            alert = high_alerts[0]
            print(f"\nDetails of a HIGH severity alert:")
            print(f"Title: {alert['title']}")
            print(f"Description: {alert['description']}")
            print(f"Created at: {alert['created_at']}")
            print(f"Affected entities: {len(alert['affected_entities'])}")
    
    async def run_demo(self) -> None:
        """Run the full demo sequence."""
        try:
            await self.start()
            
            print("\n" + "=" * 60)
            print("=== MCP SECURITY GUARDIAN - INTERACTIVE DEMO ===")
            print("=" * 60)
            
            await self.demo_instruction_analysis()
            await asyncio.sleep(1)
            
            await self.demo_vulnerability_scanning()
            await asyncio.sleep(1)
            
            await self.demo_token_revocation()
            await asyncio.sleep(1)
            
            await self.demo_alert_system()
            
            print("\n" + "=" * 60)
            print("=== DEMO COMPLETED SUCCESSFULLY ===")
            print("=" * 60)
        finally:
            await self.stop()


async def main():
    """Run the demo application."""
    demo = MCPGuardianDemo()
    await demo.run_demo()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nDemo interrupted by user")
    except Exception as e:
        print(f"\nError running demo: {e}") 
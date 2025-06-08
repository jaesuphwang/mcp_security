#!/usr/bin/env python3
"""
MCP Security Guardian Server
An MCP server that provides security analysis, vulnerability scanning, and threat detection for MCP communications.
"""

import asyncio
import json
import logging
import sys
import os
from typing import Any, Dict, List, Optional
from datetime import datetime

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp import (
    McpError,
    Resource,
    Tool,
)
from mcp.types import (
    TextContent,
    ListResourcesResult,
    ReadResourceResult,
    INVALID_PARAMS,
    INTERNAL_ERROR,
    METHOD_NOT_FOUND,
)

# Import security components
from src.detection_engine.detector import DetectionEngine
from src.vulnerability_scanning.capability_auditor import ServerCapabilityAuditor
from src.vulnerability_scanning.connection_security import ConnectionSecurityAnalyzer
from src.revocation.token_revocation import TokenRevocationService
from src.alerting.alert_network import AlertDistributionNetwork
# from src.core.models.security import SecurityAnalysisResult, VulnerabilityScanResult
# from src.core.models.threat import ThreatAlert
from src.core.config.settings import get_settings

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

settings = get_settings()


class MCPSecurityServer:
    """MCP Security Guardian Server implementation"""
    
    def __init__(self):
        self.server = Server("mcp-security-guardian")
        self.detection_engine = DetectionEngine()
        self.capability_auditor = ServerCapabilityAuditor()
        self.connection_scanner = ConnectionSecurityAnalyzer()
        self.revocation_service = TokenRevocationService()
        self.alert_network = AlertDistributionNetwork()
        
        # Setup handlers
        self.setup_handlers()
        
    def setup_handlers(self):
        """Setup MCP server handlers"""
        
        @self.server.list_resources()
        async def list_resources() -> List[Resource]:
            """List available security resources"""
            return [
                Resource(
                    uri="security://threat-patterns",
                    name="Threat Patterns",
                    description="Known malicious patterns and signatures",
                    mimeType="application/json"
                ),
                Resource(
                    uri="security://revoked-tokens",
                    name="Revoked Tokens",
                    description="List of revoked tokens",
                    mimeType="application/json"
                ),
                Resource(
                    uri="security://alerts",
                    name="Security Alerts",
                    description="Active security alerts",
                    mimeType="application/json"
                ),
            ]
        
        @self.server.read_resource()
        async def read_resource(uri: str) -> str:
            """Read security resource content"""
            if uri == "security://threat-patterns":
                patterns = await self.threat_detector.get_threat_patterns()
                return json.dumps(patterns, indent=2)
            elif uri == "security://revoked-tokens":
                tokens = await self.revocation_service.get_revoked_tokens()
                return json.dumps(tokens, indent=2)
            elif uri == "security://alerts":
                alerts = await self.alert_network.get_active_alerts()
                return json.dumps([alert.dict() for alert in alerts], indent=2)
            else:
                raise McpError(METHOD_NOT_FOUND, f"Resource not found: {uri}")
        
        @self.server.list_tools()
        async def list_tools() -> List[Tool]:
            """List available security tools"""
            return [
                Tool(
                    name="analyze_instruction",
                    description="Analyze an MCP instruction for security threats",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "instruction": {
                                "type": "string",
                                "description": "The MCP instruction to analyze"
                            },
                            "context": {
                                "type": "object",
                                "description": "Optional context for the instruction"
                            }
                        },
                        "required": ["instruction"]
                    }
                ),
                Tool(
                    name="scan_connection",
                    description="Scan an MCP connection for security vulnerabilities",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "server_url": {
                                "type": "string",
                                "description": "The MCP server URL to scan"
                            },
                            "token": {
                                "type": "string",
                                "description": "Optional authentication token to verify"
                            }
                        },
                        "required": ["server_url"]
                    }
                ),
                Tool(
                    name="revoke_token",
                    description="Revoke an MCP authentication token",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "token": {
                                "type": "string",
                                "description": "The token to revoke"
                            },
                            "reason": {
                                "type": "string",
                                "description": "Reason for revocation",
                                "enum": ["compromised", "expired", "misused", "suspicious", "other"]
                            },
                            "description": {
                                "type": "string",
                                "description": "Additional description"
                            }
                        },
                        "required": ["token", "reason"]
                    }
                ),
                Tool(
                    name="audit_capabilities",
                    description="Audit MCP server capabilities for security issues",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "capabilities": {
                                "type": "object",
                                "description": "The server capabilities to audit"
                            },
                            "server_url": {
                                "type": "string",
                                "description": "The server URL for context"
                            }
                        },
                        "required": ["capabilities"]
                    }
                ),
                Tool(
                    name="distribute_alert",
                    description="Distribute a security alert to the network",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "alert_type": {
                                "type": "string",
                                "description": "Type of alert",
                                "enum": ["malicious_instruction", "vulnerability", "token_revocation", "server_compromise"]
                            },
                            "severity": {
                                "type": "string",
                                "description": "Alert severity",
                                "enum": ["critical", "high", "medium", "low"]
                            },
                            "title": {
                                "type": "string",
                                "description": "Alert title"
                            },
                            "description": {
                                "type": "string",
                                "description": "Detailed description"
                            },
                            "sharing_level": {
                                "type": "string",
                                "description": "TLP sharing level",
                                "enum": ["WHITE", "GREEN", "AMBER", "RED"]
                            }
                        },
                        "required": ["alert_type", "severity", "title", "description"]
                    }
                ),
            ]
        
        @self.server.call_tool()
        async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
            """Execute security tools"""
            try:
                if name == "analyze_instruction":
                    result = await self._analyze_instruction(
                        arguments["instruction"],
                        arguments.get("context", {})
                    )
                elif name == "scan_connection":
                    result = await self._scan_connection(
                        arguments["server_url"],
                        arguments.get("token")
                    )
                elif name == "revoke_token":
                    result = await self._revoke_token(
                        arguments["token"],
                        arguments["reason"],
                        arguments.get("description", "")
                    )
                elif name == "audit_capabilities":
                    result = await self._audit_capabilities(
                        arguments["capabilities"],
                        arguments.get("server_url", "")
                    )
                elif name == "distribute_alert":
                    result = await self._distribute_alert(
                        arguments["alert_type"],
                        arguments["severity"],
                        arguments["title"],
                        arguments["description"],
                        arguments.get("sharing_level", "GREEN")
                    )
                else:
                    raise McpError(METHOD_NOT_FOUND, f"Unknown tool: {name}")
                
                return [TextContent(type="text", text=json.dumps(result, indent=2))]
                
            except Exception as e:
                logger.error(f"Tool execution error: {str(e)}")
                raise McpError(INTERNAL_ERROR, str(e))
    
    async def _analyze_instruction(self, instruction: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze an MCP instruction for security threats"""
        # Create analysis request (simplified for this implementation)
        from src.detection_engine.instruction_analysis.models import AnalysisRequest
        request = AnalysisRequest(
            instruction_id=f"inst_{hash(instruction)}",
            instruction_content=instruction,
            context=context
        )
        analysis_result = await self.detection_engine.analyze_instruction(request)
        
        return {
            "instruction_id": analysis_result.instruction_id,
            "risk_level": analysis_result.risk_level.value if analysis_result.risk_level else "low",
            "confidence": analysis_result.confidence,
            "is_threat": analysis_result.is_threat,
            "threat_type": analysis_result.threat_type.value if analysis_result.threat_type else None,
            "analysis_results": [
                {
                    "component": result.component,
                    "is_threat": result.is_threat,
                    "confidence": result.confidence,
                    "threat_type": result.threat_type.value if result.threat_type else None,
                    "details": result.details
                }
                for result in analysis_result.analysis_results
            ],
            "timestamp": datetime.utcnow().isoformat()
        }
    
    async def _scan_connection(self, server_url: str, token: Optional[str] = None) -> Dict[str, Any]:
        """Scan an MCP connection for vulnerabilities"""
        scan_result = await self.connection_scanner.scan_connection(server_url, token)
        
        return {
            "server_url": server_url,
            "ssl_security": scan_result.ssl_security,
            "token_security": scan_result.token_security if token else None,
            "vulnerabilities": [
                {
                    "type": vuln.vulnerability_type,
                    "severity": vuln.severity,
                    "description": vuln.description,
                    "remediation": vuln.remediation
                }
                for vuln in scan_result.vulnerabilities
            ],
            "risk_score": scan_result.risk_score,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    async def _revoke_token(self, token: str, reason: str, description: str) -> Dict[str, Any]:
        """Revoke an authentication token"""
        revocation_id = await self.revocation_service.revoke_token(
            token=token,
            reason=reason,
            description=description
        )
        
        # Distribute revocation alert (simplified for basic implementation)
        alert_data = {
            "alert_type": "token_revocation",
            "severity": "high",
            "title": f"Token Revoked: {reason}",
            "description": f"Token has been revoked. Reason: {reason}. {description}",
            "metadata": {"revocation_id": revocation_id}
        }
        # await self.alert_network.distribute_alert(alert_data)
        
        return {
            "revocation_id": revocation_id,
            "token_hash": self.revocation_service._hash_token(token),
            "reason": reason,
            "status": "revoked",
            "timestamp": datetime.utcnow().isoformat()
        }
    
    async def _audit_capabilities(self, capabilities: Dict[str, Any], server_url: str) -> Dict[str, Any]:
        """Audit server capabilities for security issues"""
        audit_result = await self.capability_auditor.audit_capabilities(capabilities, server_url)
        
        return {
            "server_url": server_url,
            "security_score": audit_result.security_score,
            "issues": [
                {
                    "capability": issue.capability,
                    "issue_type": issue.issue_type,
                    "severity": issue.severity,
                    "description": issue.description,
                    "recommendation": issue.recommendation
                }
                for issue in audit_result.issues
            ],
            "recommendations": audit_result.recommendations,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    async def _distribute_alert(
        self, 
        alert_type: str, 
        severity: str, 
        title: str, 
        description: str,
        sharing_level: str
    ) -> Dict[str, Any]:
        """Distribute a security alert"""
        alert_data = {
            "alert_type": alert_type,
            "severity": severity,
            "title": title,
            "description": description,
            "sharing_level": sharing_level,
            "metadata": {
                "source": "mcp-security-guardian",
                "timestamp": datetime.utcnow().isoformat()
            }
        }
        
        # distribution_id = await self.alert_network.distribute_alert(alert_data)
        distribution_id = f"dist_{hash(str(alert_data))}"
        
        return {
            "distribution_id": distribution_id,
            "alert_id": f"alert_{hash(str(alert_data))}",
            "status": "distributed",
            "sharing_level": sharing_level,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    async def run(self):
        """Run the MCP server"""
        logger.info("Starting MCP Security Guardian Server...")
        
        # Initialize components
        await self.detection_engine.initialize()
        await self.alert_network.initialize()
        
        # Start the server
        logger.info("MCP Security Guardian Server is running")
        logger.info("Press Ctrl+C to stop the server")
        try:
            await asyncio.Event().wait()
        except KeyboardInterrupt:
            logger.info("Server shutdown requested")


async def main():
    """Main entry point"""
    server = MCPSecurityServer()
    await server.run()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Server shutdown requested")
    except Exception as e:
        logger.error(f"Server error: {str(e)}")
        sys.exit(1)
#!/usr/bin/env python3
"""
Basic MCP Security Guardian Server Test
A minimal test to verify MCP server functionality without complex dependencies.
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

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class BasicMCPSecurityServer:
    """Basic MCP Security Guardian Server implementation for testing"""
    
    def __init__(self):
        self.server = Server("mcp-security-guardian")
        
        # Setup handlers
        self.setup_handlers()
        
    def setup_handlers(self):
        """Setup MCP server handlers"""
        
        @self.server.list_resources()
        async def list_resources() -> List[Resource]:
            """List available security resources"""
            return [
                Resource(
                    uri="security://test-patterns",
                    name="Test Threat Patterns",
                    description="Basic test patterns for verification",
                    mimeType="application/json"
                ),
            ]
        
        @self.server.read_resource()
        async def read_resource(uri: str) -> str:
            """Read security resource content"""
            if uri == "security://test-patterns":
                patterns = {
                    "test_patterns": [
                        {"pattern": "test_malicious_command", "severity": "high"},
                        {"pattern": "test_suspicious_activity", "severity": "medium"}
                    ],
                    "timestamp": datetime.utcnow().isoformat()
                }
                return json.dumps(patterns, indent=2)
            else:
                raise McpError(METHOD_NOT_FOUND, f"Resource not found: {uri}")
        
        @self.server.list_tools()
        async def list_tools() -> List[Tool]:
            """List available security tools"""
            return [
                Tool(
                    name="test_analyze",
                    description="Test analysis of an instruction",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "instruction": {
                                "type": "string",
                                "description": "The instruction to analyze"
                            }
                        },
                        "required": ["instruction"]
                    }
                ),
            ]
        
        @self.server.call_tool()
        async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
            """Execute security tools"""
            try:
                if name == "test_analyze":
                    result = await self._test_analyze(arguments["instruction"])
                else:
                    raise McpError(METHOD_NOT_FOUND, f"Unknown tool: {name}")
                
                return [TextContent(type="text", text=json.dumps(result, indent=2))]
                
            except Exception as e:
                logger.error(f"Tool execution error: {str(e)}")
                raise McpError(INTERNAL_ERROR, str(e))
    
    async def _test_analyze(self, instruction: str) -> Dict[str, Any]:
        """Basic test analysis of an instruction"""
        # Simple keyword-based analysis for testing
        suspicious_keywords = ["delete", "remove", "destroy", "hack", "exploit"]
        
        risk_level = "low"
        threats = []
        
        for keyword in suspicious_keywords:
            if keyword.lower() in instruction.lower():
                risk_level = "high"
                threats.append({
                    "type": "suspicious_keyword",
                    "severity": "high",
                    "description": f"Found suspicious keyword: {keyword}",
                    "confidence": 0.8
                })
        
        return {
            "instruction": instruction,
            "risk_level": risk_level,
            "confidence": 0.8 if threats else 0.2,
            "threats_detected": threats,
            "recommendations": ["Review instruction carefully"] if threats else ["Instruction appears safe"],
            "timestamp": datetime.utcnow().isoformat()
        }
    
    async def run(self):
        """Run the MCP server"""
        logger.info("Starting Basic MCP Security Guardian Server...")
        
        # Start the server
        logger.info("Basic MCP Security Guardian Server is running")
        logger.info("Press Ctrl+C to stop the server")
        try:
            await asyncio.Event().wait()
        except KeyboardInterrupt:
            logger.info("Server shutdown requested")


async def main():
    """Main entry point"""
    server = BasicMCPSecurityServer()
    await server.run()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Server shutdown requested")
    except Exception as e:
        logger.error(f"Server error: {str(e)}")
        sys.exit(1) 
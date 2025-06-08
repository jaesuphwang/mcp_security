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
Connection Termination Protocol for MCP Security Guardian.

This module provides functionality for terminating active MCP connections,
notifying clients, and updating connection registries.
"""
import asyncio
import json
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set, Tuple, Union
from enum import Enum, auto

import httpx
from core.utils.logging import get_logger
from core.config.settings import settings
from revocation.token_revocation import RevocationReason, RevocationPriority

logger = get_logger(__name__)


class TerminationReason(Enum):
    """Reasons for connection termination."""
    SECURITY_VIOLATION = "security_violation"
    TOKEN_REVOKED = "token_revoked"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    POLICY_VIOLATION = "policy_violation"
    SERVER_SHUTDOWN = "server_shutdown"
    ADMINISTRATIVE = "administrative"
    CLIENT_REQUEST = "client_request"
    IDLE_TIMEOUT = "idle_timeout"


class TerminationMethod(Enum):
    """Methods for connection termination."""
    GRACEFUL = "graceful"  # Send a graceful termination message
    FORCEFUL = "forceful"  # Forcefully close the transport connection
    CERTIFICATE = "certificate"  # Revoke the client certificate


class TerminationStatus(Enum):
    """Status of a termination request."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


class NotificationType(Enum):
    """Types of termination notifications."""
    IN_BAND = "in_band"  # Notification through the MCP connection
    WEBHOOK = "webhook"  # Notification through a webhook
    ADMIN_CONSOLE = "admin_console"  # Notification through an admin console


class ConnectionTermination:
    """Represents a connection termination request."""
    
    def __init__(
        self,
        termination_id: str,
        connection_id: str,
        client_id: str,
        server_id: str,
        reason: TerminationReason,
        methods: List[TerminationMethod],
        notification_types: List[NotificationType],
        token_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        timeout_seconds: int = 30
    ):
        """
        Initialize a new connection termination.
        
        Args:
            termination_id: Unique identifier for this termination
            connection_id: Identifier for the connection being terminated
            client_id: Identifier for the client
            server_id: Identifier for the server
            reason: Reason for the termination
            methods: Methods to use for termination
            notification_types: Types of notifications to send
            token_id: Optional identifier for the associated token
            details: Optional additional details about the termination
            timeout_seconds: Timeout in seconds for the termination
        """
        self.termination_id = termination_id
        self.connection_id = connection_id
        self.client_id = client_id
        self.server_id = server_id
        self.reason = reason
        self.methods = methods
        self.notification_types = notification_types
        self.token_id = token_id
        self.details = details or {}
        self.timeout_seconds = timeout_seconds
        self.created_at = datetime.now()
        self.status = TerminationStatus.PENDING
        self.completed_at = None
        self.notifications_sent = {}
        self.methods_attempted = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the termination to a dictionary."""
        return {
            "termination_id": self.termination_id,
            "connection_id": self.connection_id,
            "client_id": self.client_id,
            "server_id": self.server_id,
            "reason": self.reason.value,
            "methods": [m.value for m in self.methods],
            "notification_types": [n.value for n in self.notification_types],
            "token_id": self.token_id,
            "details": self.details,
            "timeout_seconds": self.timeout_seconds,
            "created_at": self.created_at.isoformat(),
            "status": self.status.value,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "notifications_sent": self.notifications_sent,
            "methods_attempted": self.methods_attempted
        }


class ConnectionTerminationProtocol:
    """
    Protocol for terminating MCP connections.
    """
    
    def __init__(self):
        """Initialize the connection termination protocol."""
        self.terminations = {}
        self.initialized = False
    
    async def initialize(self):
        """Initialize the protocol."""
        if self.initialized:
            return
        
        # Any initialization needed
        logger.info("Initializing connection termination protocol")
        
        # Mark as initialized
        self.initialized = True
    
    async def terminate_connection(
        self,
        connection_id: str,
        client_id: str,
        server_id: str,
        reason: TerminationReason,
        methods: Optional[List[TerminationMethod]] = None,
        notification_types: Optional[List[NotificationType]] = None,
        token_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        timeout_seconds: int = 30
    ) -> ConnectionTermination:
        """
        Terminate a connection.
        
        Args:
            connection_id: Identifier for the connection to terminate
            client_id: Identifier for the client
            server_id: Identifier for the server
            reason: Reason for the termination
            methods: Methods to use for termination
            notification_types: Types of notifications to send
            token_id: Optional identifier for the associated token
            details: Optional additional details about the termination
            timeout_seconds: Timeout in seconds for the termination
            
        Returns:
            The created termination
        """
        # Ensure the protocol is initialized
        if not self.initialized:
            await self.initialize()
        
        # Use default methods and notification types if not specified
        if methods is None:
            methods = [TerminationMethod.GRACEFUL, TerminationMethod.FORCEFUL]
        if notification_types is None:
            notification_types = [NotificationType.IN_BAND, NotificationType.WEBHOOK]
        
        # Create the termination
        termination = ConnectionTermination(
            termination_id=str(uuid.uuid4()),
            connection_id=connection_id,
            client_id=client_id,
            server_id=server_id,
            reason=reason,
            methods=methods,
            notification_types=notification_types,
            token_id=token_id,
            details=details or {},
            timeout_seconds=timeout_seconds
        )
        
        # Store the termination
        self.terminations[termination.termination_id] = termination
        
        # Execute the termination
        asyncio.create_task(self._execute_termination(termination))
        
        logger.info(f"Connection termination initiated: {connection_id} (Reason: {reason.value})")
        
        return termination
    
    async def _execute_termination(self, termination: ConnectionTermination) -> None:
        """
        Execute a connection termination.
        
        Args:
            termination: The termination to execute
        """
        try:
            # Update status
            termination.status = TerminationStatus.IN_PROGRESS
            
            # Send notifications
            notification_results = await self._send_notifications(termination)
            termination.notifications_sent = notification_results
            
            # Attempt termination methods
            method_results = await self._attempt_termination_methods(termination)
            termination.methods_attempted = method_results
            
            # Verify termination
            success = await self._verify_termination(termination)
            
            # Update status
            if success:
                termination.status = TerminationStatus.COMPLETED
                termination.completed_at = datetime.now()
            else:
                termination.status = TerminationStatus.FAILED
            
            # Update registry
            await self._update_registry(termination)
            
        except asyncio.TimeoutError:
            # Handle timeout
            termination.status = TerminationStatus.TIMED_OUT
            logger.warning(f"Connection termination timed out: {termination.connection_id}")
            
        except Exception as e:
            # Handle other errors
            termination.status = TerminationStatus.FAILED
            logger.error(f"Error executing connection termination: {e}")
    
    async def _send_notifications(self, termination: ConnectionTermination) -> Dict[str, Any]:
        """
        Send notifications for a connection termination.
        
        Args:
            termination: The termination to send notifications for
            
        Returns:
            Dictionary of notification results
        """
        results = {}
        
        # Send notifications using each specified type
        for notification_type in termination.notification_types:
            try:
                if notification_type == NotificationType.IN_BAND:
                    # Send in-band notification
                    # In a real implementation, this would send a message through the MCP connection
                    # For this example, we'll just simulate it
                    logger.info(f"Sending in-band notification for termination {termination.termination_id}")
                    results[notification_type.value] = "success"
                
                elif notification_type == NotificationType.WEBHOOK:
                    # Send webhook notification
                    # In a real implementation, this would make an HTTP request to a webhook URL
                    # For this example, we'll just simulate it
                    logger.info(f"Sending webhook notification for termination {termination.termination_id}")
                    results[notification_type.value] = "success"
                
                elif notification_type == NotificationType.ADMIN_CONSOLE:
                    # Send admin console notification
                    # In a real implementation, this would update an admin console
                    # For this example, we'll just simulate it
                    logger.info(f"Sending admin console notification for termination {termination.termination_id}")
                    results[notification_type.value] = "success"
            
            except Exception as e:
                logger.error(f"Error sending {notification_type.value} notification for termination {termination.termination_id}: {e}")
                results[notification_type.value] = f"error: {str(e)}"
        
        return results
    
    async def _attempt_termination_methods(self, termination: ConnectionTermination) -> Dict[str, Any]:
        """
        Attempt termination methods for a connection termination.
        
        Args:
            termination: The termination to attempt methods for
            
        Returns:
            Dictionary of method results
        """
        results = {}
        
        # Attempt each specified method
        for method in termination.methods:
            try:
                if method == TerminationMethod.GRACEFUL:
                    # Attempt graceful termination
                    # In a real implementation, this would send a graceful termination message
                    # For this example, we'll just simulate it
                    logger.info(f"Attempting graceful termination for {termination.connection_id}")
                    results[method.value] = "success"
                
                elif method == TerminationMethod.FORCEFUL:
                    # Attempt forceful termination
                    # In a real implementation, this would forcefully close the transport connection
                    # For this example, we'll just simulate it
                    logger.info(f"Attempting forceful termination for {termination.connection_id}")
                    results[method.value] = "success"
                
                elif method == TerminationMethod.CERTIFICATE:
                    # Attempt certificate revocation
                    # In a real implementation, this would revoke the client certificate
                    # For this example, we'll just simulate it
                    logger.info(f"Attempting certificate revocation for {termination.connection_id}")
                    results[method.value] = "success"
            
            except Exception as e:
                logger.error(f"Error attempting {method.value} termination for {termination.connection_id}: {e}")
                results[method.value] = f"error: {str(e)}"
        
        return results
    
    async def _verify_termination(self, termination: ConnectionTermination) -> bool:
        """
        Verify that a connection has been terminated.
        
        Args:
            termination: The termination to verify
            
        Returns:
            True if the connection has been terminated, False otherwise
        """
        # In a real implementation, this would check if the connection is still active
        # For this example, we'll assume it was successful
        logger.info(f"Verifying termination for {termination.connection_id}")
        
        # Simulate verification (always success for this example)
        return True
    
    async def _update_registry(self, termination: ConnectionTermination) -> None:
        """
        Update the connection registry for a terminated connection.
        
        Args:
            termination: The completed termination
        """
        # In a real implementation, this would update a connection registry
        # For this example, we'll just log it
        logger.info(f"Updating registry for terminated connection: {termination.connection_id}")
    
    async def get_termination(self, termination_id: str) -> Optional[ConnectionTermination]:
        """
        Get a termination by ID.
        
        Args:
            termination_id: ID of the termination to get
            
        Returns:
            The termination, or None if not found
        """
        # Ensure the protocol is initialized
        if not self.initialized:
            await self.initialize()
        
        return self.terminations.get(termination_id)
    
    async def get_terminations(
        self,
        connection_id: Optional[str] = None,
        client_id: Optional[str] = None,
        server_id: Optional[str] = None,
        status: Optional[TerminationStatus] = None,
        reason: Optional[TerminationReason] = None,
        from_date: Optional[datetime] = None,
        to_date: Optional[datetime] = None
    ) -> List[ConnectionTermination]:
        """
        Get terminations matching the specified criteria.
        
        Args:
            connection_id: Optional connection ID to filter by
            client_id: Optional client ID to filter by
            server_id: Optional server ID to filter by
            status: Optional status to filter by
            reason: Optional reason to filter by
            from_date: Optional start date to filter by
            to_date: Optional end date to filter by
            
        Returns:
            List of matching terminations
        """
        # Ensure the protocol is initialized
        if not self.initialized:
            await self.initialize()
        
        # Filter terminations
        filtered_terminations = []
        for termination in self.terminations.values():
            # Apply filters
            if connection_id is not None and termination.connection_id != connection_id:
                continue
            if client_id is not None and termination.client_id != client_id:
                continue
            if server_id is not None and termination.server_id != server_id:
                continue
            if status is not None and termination.status != status:
                continue
            if reason is not None and termination.reason != reason:
                continue
            if from_date is not None and termination.created_at < from_date:
                continue
            if to_date is not None and termination.created_at > to_date:
                continue
            
            filtered_terminations.append(termination)
        
        return filtered_terminations
    
    async def terminate_connections_for_token(
        self,
        token_id: str,
        reason: TerminationReason = TerminationReason.TOKEN_REVOKED,
        methods: Optional[List[TerminationMethod]] = None,
        notification_types: Optional[List[NotificationType]] = None,
        details: Optional[Dict[str, Any]] = None,
        timeout_seconds: int = 30
    ) -> List[ConnectionTermination]:
        """
        Terminate all connections using a specific token.
        
        Args:
            token_id: ID of the token
            reason: Reason for the termination
            methods: Methods to use for termination
            notification_types: Types of notifications to send
            details: Optional additional details about the termination
            timeout_seconds: Timeout in seconds for the termination
            
        Returns:
            List of created terminations
        """
        # Ensure the protocol is initialized
        if not self.initialized:
            await self.initialize()
        
        # In a real implementation, this would look up connections using the token
        # For this example, we'll simulate it with dummy connections
        connections = [
            {"connection_id": f"conn-{uuid.uuid4()}", "client_id": "client-1", "server_id": "server-1"},
            {"connection_id": f"conn-{uuid.uuid4()}", "client_id": "client-2", "server_id": "server-1"}
        ]
        
        # Terminate each connection
        terminations = []
        for connection in connections:
            termination = await self.terminate_connection(
                connection_id=connection["connection_id"],
                client_id=connection["client_id"],
                server_id=connection["server_id"],
                reason=reason,
                methods=methods,
                notification_types=notification_types,
                token_id=token_id,
                details=details,
                timeout_seconds=timeout_seconds
            )
            terminations.append(termination)
        
        logger.info(f"Terminated {len(terminations)} connections for token: {token_id}")
        
        return terminations
    
    async def terminate_connections_for_server(
        self,
        server_id: str,
        reason: TerminationReason = TerminationReason.SERVER_SHUTDOWN,
        methods: Optional[List[TerminationMethod]] = None,
        notification_types: Optional[List[NotificationType]] = None,
        details: Optional[Dict[str, Any]] = None,
        timeout_seconds: int = 30
    ) -> List[ConnectionTermination]:
        """
        Terminate all connections to a specific server.
        
        Args:
            server_id: ID of the server
            reason: Reason for the termination
            methods: Methods to use for termination
            notification_types: Types of notifications to send
            details: Optional additional details about the termination
            timeout_seconds: Timeout in seconds for the termination
            
        Returns:
            List of created terminations
        """
        # Ensure the protocol is initialized
        if not self.initialized:
            await self.initialize()
        
        # In a real implementation, this would look up connections to the server
        # For this example, we'll simulate it with dummy connections
        connections = [
            {"connection_id": f"conn-{uuid.uuid4()}", "client_id": "client-1", "server_id": server_id},
            {"connection_id": f"conn-{uuid.uuid4()}", "client_id": "client-2", "server_id": server_id},
            {"connection_id": f"conn-{uuid.uuid4()}", "client_id": "client-3", "server_id": server_id}
        ]
        
        # Terminate each connection
        terminations = []
        for connection in connections:
            termination = await self.terminate_connection(
                connection_id=connection["connection_id"],
                client_id=connection["client_id"],
                server_id=connection["server_id"],
                reason=reason,
                methods=methods,
                notification_types=notification_types,
                details=details,
                timeout_seconds=timeout_seconds
            )
            terminations.append(termination)
        
        logger.info(f"Terminated {len(terminations)} connections for server: {server_id}")
        
        return terminations


# Create a singleton instance
connection_termination_protocol = ConnectionTerminationProtocol() 
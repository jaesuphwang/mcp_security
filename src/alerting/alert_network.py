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
Alert Distribution Network for MCP Security Guardian.

This module provides functionality for generating and distributing security alerts,
sharing threat intelligence, and tracking alert acknowledgments across the MCP ecosystem.
"""
import asyncio
import json
import uuid
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set, Tuple, Union
from enum import Enum, auto

import httpx
from core.utils.logging import get_logger
from core.config.settings import get_settings

settings = get_settings()
from core.database.connections import get_db

logger = get_logger(__name__)


class AlertSeverity(Enum):
    """Severity levels for security alerts."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertCategory(Enum):
    """Categories of security alerts."""
    MALICIOUS_INSTRUCTION = "malicious_instruction"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    VULNERABILITY = "vulnerability"
    TOKEN_REVOCATION = "token_revocation"
    CONNECTION_TERMINATION = "connection_termination"
    SERVER_COMPROMISE = "server_compromise"
    POLICY_VIOLATION = "policy_violation"
    SYSTEM_ERROR = "system_error"


class SharingLevel(Enum):
    """Traffic Light Protocol (TLP) sharing levels for alerts."""
    RED = "TLP:RED"  # Not for disclosure, restricted to specific participants only
    AMBER = "TLP:AMBER"  # Limited disclosure, restricted to participants' organizations
    GREEN = "TLP:GREEN"  # Limited disclosure, restricted to the community
    WHITE = "TLP:WHITE"  # Disclosure is not limited


class AlertStatus(Enum):
    """Status of a security alert."""
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class DistributionStatus(Enum):
    """Status of alert distribution."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"


class SecurityAlert:
    """Represents a security alert in the MCP ecosystem."""
    
    def __init__(
        self,
        alert_id: str,
        title: str,
        description: str,
        severity: AlertSeverity,
        category: AlertCategory,
        sharing_level: SharingLevel,
        source_id: str,
        affected_entities: List[Dict[str, Any]],
        indicators: Optional[List[Dict[str, Any]]] = None,
        recommendations: Optional[List[str]] = None,
        references: Optional[List[Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        expiration: Optional[datetime] = None
    ):
        """
        Initialize a new security alert.
        
        Args:
            alert_id: Unique identifier for this alert
            title: Short title describing the alert
            description: Detailed description of the alert
            severity: Severity level of the alert
            category: Category of the alert
            sharing_level: Traffic Light Protocol (TLP) sharing level
            source_id: Identifier for the source of the alert
            affected_entities: List of entities affected by the alert
            indicators: Optional list of indicators related to the alert
            recommendations: Optional list of recommendations for handling the alert
            references: Optional list of references related to the alert
            metadata: Optional additional metadata about the alert
            expiration: Optional expiration time for the alert
        """
        self.alert_id = alert_id
        self.title = title
        self.description = description
        self.severity = severity
        self.category = category
        self.sharing_level = sharing_level
        self.source_id = source_id
        self.affected_entities = affected_entities
        self.indicators = indicators or []
        self.recommendations = recommendations or []
        self.references = references or []
        self.metadata = metadata or {}
        self.expiration = expiration or (datetime.now() + timedelta(days=30))
        self.created_at = datetime.now()
        self.updated_at = self.created_at
        self.status = AlertStatus.NEW
        self.acknowledgments = []
        self.distribution_status = DistributionStatus.PENDING
        self.distribution_targets = []
        self.distribution_results = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the alert to a dictionary."""
        return {
            "alert_id": self.alert_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category.value,
            "sharing_level": self.sharing_level.value,
            "source_id": self.source_id,
            "affected_entities": self.affected_entities,
            "indicators": self.indicators,
            "recommendations": self.recommendations,
            "references": self.references,
            "metadata": self.metadata,
            "expiration": self.expiration.isoformat(),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "status": self.status.value,
            "acknowledgments": self.acknowledgments,
            "distribution_status": self.distribution_status.value,
            "distribution_targets": self.distribution_targets,
            "distribution_results": self.distribution_results
        }


class AlertAcknowledgment:
    """Represents an acknowledgment of a security alert."""
    
    def __init__(
        self,
        acknowledgment_id: str,
        alert_id: str,
        entity_id: str,
        entity_type: str,
        status: AlertStatus,
        notes: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize a new alert acknowledgment.
        
        Args:
            acknowledgment_id: Unique identifier for this acknowledgment
            alert_id: Identifier for the alert being acknowledged
            entity_id: Identifier for the entity acknowledging the alert
            entity_type: Type of entity (e.g., "organization", "server")
            status: Status to set for the alert
            notes: Optional notes about the acknowledgment
            metadata: Optional additional metadata about the acknowledgment
        """
        self.acknowledgment_id = acknowledgment_id
        self.alert_id = alert_id
        self.entity_id = entity_id
        self.entity_type = entity_type
        self.status = status
        self.notes = notes
        self.metadata = metadata or {}
        self.created_at = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the acknowledgment to a dictionary."""
        return {
            "acknowledgment_id": self.acknowledgment_id,
            "alert_id": self.alert_id,
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "status": self.status.value,
            "notes": self.notes,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat()
        }


class DistributionTarget:
    """Represents a target for alert distribution."""
    
    def __init__(
        self,
        target_id: str,
        name: str,
        url: str,
        api_key: Optional[str] = None,
        sharing_levels: Optional[List[SharingLevel]] = None,
        categories: Optional[List[AlertCategory]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize a new distribution target.
        
        Args:
            target_id: Unique identifier for this target
            name: Name of the target
            url: URL for sending alerts to this target
            api_key: Optional API key for authentication
            sharing_levels: Optional list of sharing levels this target accepts
            categories: Optional list of categories this target accepts
            metadata: Optional additional metadata about this target
        """
        self.target_id = target_id
        self.name = name
        self.url = url
        self.api_key = api_key
        self.sharing_levels = sharing_levels or list(SharingLevel)
        self.categories = categories or list(AlertCategory)
        self.metadata = metadata or {}
        self.created_at = datetime.now()
        self.last_success = None
        self.last_failure = None
        self.success_count = 0
        self.failure_count = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the distribution target to a dictionary."""
        return {
            "target_id": self.target_id,
            "name": self.name,
            "url": self.url,
            "api_key": "***" if self.api_key else None,  # Don't include actual API key
            "sharing_levels": [sl.value for sl in self.sharing_levels],
            "categories": [c.value for c in self.categories],
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
            "last_success": self.last_success.isoformat() if self.last_success else None,
            "last_failure": self.last_failure.isoformat() if self.last_failure else None,
            "success_count": self.success_count,
            "failure_count": self.failure_count
        }


class AlertDistributionNetwork:
    """
    Network for distributing security alerts across the MCP ecosystem.
    """
    
    def __init__(self):
        """Initialize the alert distribution network."""
        self.alerts = {}
        self.targets = {}
        self.acknowledgments = {}
        self.db = None
        self.initialized = False
    
    async def initialize(self):
        """Initialize the network."""
        if self.initialized:
            return
        
        # In a real implementation, we would connect to a database here
        # but for simplicity, we'll just use in-memory storage
        logger.info("Initializing alert distribution network")
        
        # Add some default distribution targets
        target = DistributionTarget(
            target_id=str(uuid.uuid4()),
            name="MCP Security Hub",
            url="https://example.com/api/alerts",
            api_key=None,
            sharing_levels=[SharingLevel.GREEN, SharingLevel.WHITE],
            categories=None,
            metadata={"description": "Central MCP Security Hub for alert sharing"}
        )
        self.targets[target.target_id] = target
        
        # Mark as initialized
        self.initialized = True
    
    async def create_alert(
        self,
        title: str,
        description: str,
        severity: AlertSeverity,
        category: AlertCategory,
        sharing_level: SharingLevel,
        source_id: str,
        affected_entities: List[Dict[str, Any]],
        indicators: Optional[List[Dict[str, Any]]] = None,
        recommendations: Optional[List[str]] = None,
        references: Optional[List[Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        expiration: Optional[datetime] = None,
        distribute: bool = True
    ) -> SecurityAlert:
        """
        Create a new security alert.
        
        Args:
            title: Short title describing the alert
            description: Detailed description of the alert
            severity: Severity level of the alert
            category: Category of the alert
            sharing_level: Traffic Light Protocol (TLP) sharing level
            source_id: Identifier for the source of the alert
            affected_entities: List of entities affected by the alert
            indicators: Optional list of indicators related to the alert
            recommendations: Optional list of recommendations for handling the alert
            references: Optional list of references related to the alert
            metadata: Optional additional metadata about the alert
            expiration: Optional expiration time for the alert
            distribute: Whether to distribute the alert immediately
            
        Returns:
            The created alert
        """
        # Ensure the network is initialized
        if not self.initialized:
            await self.initialize()
        
        # Create the alert
        alert = SecurityAlert(
            alert_id=str(uuid.uuid4()),
            title=title,
            description=description,
            severity=severity,
            category=category,
            sharing_level=sharing_level,
            source_id=source_id,
            affected_entities=affected_entities,
            indicators=indicators,
            recommendations=recommendations,
            references=references,
            metadata=metadata,
            expiration=expiration
        )
        
        # Store the alert
        self.alerts[alert.alert_id] = alert
        
        # Store in the database (in a real implementation)
        # await self.db.store_alert(alert.to_dict())
        
        # Distribute the alert if requested
        if distribute:
            await self.distribute_alert(alert.alert_id)
        
        logger.info(f"Created alert: {alert.alert_id} - {alert.title} ({alert.severity.value})")
        
        return alert
    
    async def update_alert(
        self,
        alert_id: str,
        title: Optional[str] = None,
        description: Optional[str] = None,
        severity: Optional[AlertSeverity] = None,
        category: Optional[AlertCategory] = None,
        sharing_level: Optional[SharingLevel] = None,
        affected_entities: Optional[List[Dict[str, Any]]] = None,
        indicators: Optional[List[Dict[str, Any]]] = None,
        recommendations: Optional[List[str]] = None,
        references: Optional[List[Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        expiration: Optional[datetime] = None,
        status: Optional[AlertStatus] = None,
        distribute: bool = True
    ) -> Optional[SecurityAlert]:
        """
        Update an existing security alert.
        
        Args:
            alert_id: Identifier for the alert to update
            title: Optional new title
            description: Optional new description
            severity: Optional new severity level
            category: Optional new category
            sharing_level: Optional new sharing level
            affected_entities: Optional new affected entities
            indicators: Optional new indicators
            recommendations: Optional new recommendations
            references: Optional new references
            metadata: Optional new metadata
            expiration: Optional new expiration time
            status: Optional new status
            distribute: Whether to distribute the updated alert
            
        Returns:
            The updated alert, or None if not found
        """
        # Ensure the network is initialized
        if not self.initialized:
            await self.initialize()
        
        # Get the alert
        alert = self.alerts.get(alert_id)
        if not alert:
            logger.warning(f"Alert not found: {alert_id}")
            return None
        
        # Update the alert
        if title is not None:
            alert.title = title
        if description is not None:
            alert.description = description
        if severity is not None:
            alert.severity = severity
        if category is not None:
            alert.category = category
        if sharing_level is not None:
            alert.sharing_level = sharing_level
        if affected_entities is not None:
            alert.affected_entities = affected_entities
        if indicators is not None:
            alert.indicators = indicators
        if recommendations is not None:
            alert.recommendations = recommendations
        if references is not None:
            alert.references = references
        if metadata is not None:
            alert.metadata.update(metadata)
        if expiration is not None:
            alert.expiration = expiration
        if status is not None:
            alert.status = status
        
        # Update timestamp
        alert.updated_at = datetime.now()
        
        # Store in the database (in a real implementation)
        # await self.db.update_alert(alert.to_dict())
        
        # Distribute the updated alert if requested
        if distribute:
            await self.distribute_alert(alert.alert_id)
        
        logger.info(f"Updated alert: {alert.alert_id} - {alert.title} ({alert.severity.value})")
        
        return alert
    
    async def get_alert(self, alert_id: str) -> Optional[SecurityAlert]:
        """
        Get an alert by ID.
        
        Args:
            alert_id: ID of the alert to get
            
        Returns:
            The alert, or None if not found
        """
        # Ensure the network is initialized
        if not self.initialized:
            await self.initialize()
        
        return self.alerts.get(alert_id)
    
    async def get_alerts(
        self,
        severity: Optional[AlertSeverity] = None,
        category: Optional[AlertCategory] = None,
        sharing_level: Optional[SharingLevel] = None,
        status: Optional[AlertStatus] = None,
        source_id: Optional[str] = None,
        from_date: Optional[datetime] = None,
        to_date: Optional[datetime] = None,
        entity_id: Optional[str] = None
    ) -> List[SecurityAlert]:
        """
        Get alerts matching the specified criteria.
        
        Args:
            severity: Optional severity level to filter by
            category: Optional category to filter by
            sharing_level: Optional sharing level to filter by
            status: Optional status to filter by
            source_id: Optional source ID to filter by
            from_date: Optional start date to filter by
            to_date: Optional end date to filter by
            entity_id: Optional entity ID to filter by (affected entity)
            
        Returns:
            List of matching alerts
        """
        # Ensure the network is initialized
        if not self.initialized:
            await self.initialize()
        
        # Filter alerts
        filtered_alerts = []
        for alert in self.alerts.values():
            # Apply filters
            if severity is not None and alert.severity != severity:
                continue
            if category is not None and alert.category != category:
                continue
            if sharing_level is not None and alert.sharing_level != sharing_level:
                continue
            if status is not None and alert.status != status:
                continue
            if source_id is not None and alert.source_id != source_id:
                continue
            if from_date is not None and alert.created_at < from_date:
                continue
            if to_date is not None and alert.created_at > to_date:
                continue
            if entity_id is not None and not any(e.get("id") == entity_id for e in alert.affected_entities):
                continue
            
            filtered_alerts.append(alert)
        
        return filtered_alerts
    
    async def acknowledge_alert(
        self,
        alert_id: str,
        entity_id: str,
        entity_type: str,
        status: AlertStatus,
        notes: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Optional[AlertAcknowledgment]:
        """
        Acknowledge a security alert.
        
        Args:
            alert_id: ID of the alert to acknowledge
            entity_id: ID of the entity acknowledging the alert
            entity_type: Type of entity acknowledging the alert
            status: Status to set for the alert
            notes: Optional notes about the acknowledgment
            metadata: Optional additional metadata about the acknowledgment
            
        Returns:
            The created acknowledgment, or None if the alert was not found
        """
        # Ensure the network is initialized
        if not self.initialized:
            await self.initialize()
        
        # Get the alert
        alert = self.alerts.get(alert_id)
        if not alert:
            logger.warning(f"Alert not found: {alert_id}")
            return None
        
        # Create the acknowledgment
        acknowledgment = AlertAcknowledgment(
            acknowledgment_id=str(uuid.uuid4()),
            alert_id=alert_id,
            entity_id=entity_id,
            entity_type=entity_type,
            status=status,
            notes=notes,
            metadata=metadata
        )
        
        # Store the acknowledgment
        self.acknowledgments[acknowledgment.acknowledgment_id] = acknowledgment
        
        # Update the alert
        alert.status = status
        alert.updated_at = datetime.now()
        alert.acknowledgments.append(acknowledgment.to_dict())
        
        # Store in the database (in a real implementation)
        # await self.db.store_acknowledgment(acknowledgment.to_dict())
        # await self.db.update_alert(alert.to_dict())
        
        logger.info(f"Alert acknowledged: {alert_id} by {entity_id} ({entity_type}) - {status.value}")
        
        return acknowledgment
    
    async def add_distribution_target(
        self,
        name: str,
        url: str,
        api_key: Optional[str] = None,
        sharing_levels: Optional[List[SharingLevel]] = None,
        categories: Optional[List[AlertCategory]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> DistributionTarget:
        """
        Add a new distribution target.
        
        Args:
            name: Name of the target
            url: URL for sending alerts to this target
            api_key: Optional API key for authentication
            sharing_levels: Optional list of sharing levels this target accepts
            categories: Optional list of categories this target accepts
            metadata: Optional additional metadata about this target
            
        Returns:
            The created distribution target
        """
        # Ensure the network is initialized
        if not self.initialized:
            await self.initialize()
        
        # Create the target
        target = DistributionTarget(
            target_id=str(uuid.uuid4()),
            name=name,
            url=url,
            api_key=api_key,
            sharing_levels=sharing_levels,
            categories=categories,
            metadata=metadata
        )
        
        # Store the target
        self.targets[target.target_id] = target
        
        # Store in the database (in a real implementation)
        # await self.db.store_distribution_target(target.to_dict())
        
        logger.info(f"Added distribution target: {target.target_id} - {target.name}")
        
        return target
    
    async def remove_distribution_target(self, target_id: str) -> bool:
        """
        Remove a distribution target.
        
        Args:
            target_id: ID of the target to remove
            
        Returns:
            True if the target was removed, False if not found
        """
        # Ensure the network is initialized
        if not self.initialized:
            await self.initialize()
        
        # Remove the target
        if target_id in self.targets:
            del self.targets[target_id]
            
            # Remove from the database (in a real implementation)
            # await self.db.delete_distribution_target(target_id)
            
            logger.info(f"Removed distribution target: {target_id}")
            return True
        else:
            logger.warning(f"Distribution target not found: {target_id}")
            return False
    
    async def get_distribution_target(self, target_id: str) -> Optional[DistributionTarget]:
        """
        Get a distribution target by ID.
        
        Args:
            target_id: ID of the target to get
            
        Returns:
            The target, or None if not found
        """
        # Ensure the network is initialized
        if not self.initialized:
            await self.initialize()
        
        return self.targets.get(target_id)
    
    async def get_distribution_targets(
        self,
        sharing_level: Optional[SharingLevel] = None,
        category: Optional[AlertCategory] = None
    ) -> List[DistributionTarget]:
        """
        Get distribution targets matching the specified criteria.
        
        Args:
            sharing_level: Optional sharing level to filter by
            category: Optional category to filter by
            
        Returns:
            List of matching targets
        """
        # Ensure the network is initialized
        if not self.initialized:
            await self.initialize()
        
        # Filter targets
        filtered_targets = []
        for target in self.targets.values():
            # Apply filters
            if sharing_level is not None and sharing_level not in target.sharing_levels:
                continue
            if category is not None and category not in target.categories:
                continue
            
            filtered_targets.append(target)
        
        return filtered_targets
    
    async def distribute_alert(self, alert_id: str) -> Dict[str, Any]:
        """
        Distribute an alert to all appropriate targets.
        
        Args:
            alert_id: ID of the alert to distribute
            
        Returns:
            Dictionary of distribution results
        """
        # Ensure the network is initialized
        if not self.initialized:
            await self.initialize()
        
        # Get the alert
        alert = self.alerts.get(alert_id)
        if not alert:
            logger.warning(f"Alert not found: {alert_id}")
            return {"error": "Alert not found"}
        
        # Update distribution status
        alert.distribution_status = DistributionStatus.IN_PROGRESS
        
        # Get appropriate targets
        targets = await self.get_distribution_targets(
            sharing_level=alert.sharing_level,
            category=alert.category
        )
        
        # Update target list
        alert.distribution_targets = [target.target_id for target in targets]
        
        # Distribute the alert to each target
        results = {}
        success_count = 0
        failure_count = 0
        
        for target in targets:
            try:
                # In a real implementation, this would make an HTTP request to the target URL
                # For this example, we'll just simulate it
                logger.info(f"Distributing alert {alert_id} to target {target.target_id} - {target.name}")
                
                # Simulate successful distribution
                results[target.target_id] = {
                    "status": "success",
                    "timestamp": datetime.now().isoformat()
                }
                
                # Update target stats
                target.last_success = datetime.now()
                target.success_count += 1
                success_count += 1
                
            except Exception as e:
                logger.error(f"Error distributing alert {alert_id} to target {target.target_id}: {e}")
                results[target.target_id] = {
                    "status": "error",
                    "error": str(e),
                    "timestamp": datetime.now().isoformat()
                }
                
                # Update target stats
                target.last_failure = datetime.now()
                target.failure_count += 1
                failure_count += 1
        
        # Update distribution results
        alert.distribution_results = results
        
        # Update distribution status
        if failure_count == 0:
            alert.distribution_status = DistributionStatus.COMPLETED
        elif success_count == 0:
            alert.distribution_status = DistributionStatus.FAILED
        else:
            alert.distribution_status = DistributionStatus.PARTIAL
        
        # Update in the database (in a real implementation)
        # await self.db.update_alert(alert.to_dict())
        
        logger.info(f"Alert distribution completed: {alert_id} - Success: {success_count}, Failure: {failure_count}")
        
        return results
    
    async def cleanup_expired_alerts(self) -> int:
        """
        Remove expired alerts.
        
        Returns:
            The number of alerts removed
        """
        # Ensure the network is initialized
        if not self.initialized:
            await self.initialize()
        
        # Get current time
        now = datetime.now()
        
        # Find expired alerts
        expired_alerts = [a for a in self.alerts.values() if a.expiration < now]
        
        # Remove expired alerts
        for alert in expired_alerts:
            del self.alerts[alert.alert_id]
        
        # Remove from database (in a real implementation)
        # for alert in expired_alerts:
        #     await self.db.delete_alert(alert.alert_id)
        
        logger.info(f"Cleaned up {len(expired_alerts)} expired alerts")
        
        return len(expired_alerts)
    
    async def create_alert_from_vulnerability(
        self,
        vulnerability: Any,
        source_id: str,
        sharing_level: SharingLevel = SharingLevel.AMBER,
        distribute: bool = True
    ) -> SecurityAlert:
        """
        Create an alert from a detected vulnerability.
        
        Args:
            vulnerability: The vulnerability to create an alert from
            source_id: Identifier for the source of the alert
            sharing_level: Traffic Light Protocol (TLP) sharing level
            distribute: Whether to distribute the alert immediately
            
        Returns:
            The created alert
        """
        # Map vulnerability severity to alert severity
        severity_map = {
            "CRITICAL": AlertSeverity.CRITICAL,
            "HIGH": AlertSeverity.HIGH,
            "MEDIUM": AlertSeverity.MEDIUM,
            "LOW": AlertSeverity.LOW,
            "INFO": AlertSeverity.INFO
        }
        
        # Extract details from the vulnerability
        vuln_dict = vulnerability.to_dict()
        title = vuln_dict.get("title", "Security Vulnerability Detected")
        description = vuln_dict.get("description", "A security vulnerability was detected.")
        severity = severity_map.get(vuln_dict.get("security_level"), AlertSeverity.MEDIUM)
        
        # Create affected entities
        affected_entities = []
        if "server_id" in vuln_dict:
            affected_entities.append({
                "id": vuln_dict["server_id"],
                "type": "server",
                "name": f"Server {vuln_dict['server_id']}"
            })
        
        # Create the alert
        alert = await self.create_alert(
            title=title,
            description=description,
            severity=severity,
            category=AlertCategory.VULNERABILITY,
            sharing_level=sharing_level,
            source_id=source_id,
            affected_entities=affected_entities,
            indicators=[{"type": "vulnerability", "value": vuln_dict}],
            recommendations=[vuln_dict.get("remediation", "Review and address the vulnerability.")],
            metadata={"vulnerability_id": vuln_dict.get("vulnerability_id")},
            distribute=distribute
        )
        
        return alert
    
    async def create_alert_from_malicious_instruction(
        self,
        instruction_analysis: Any,
        source_id: str,
        sharing_level: SharingLevel = SharingLevel.AMBER,
        distribute: bool = True
    ) -> SecurityAlert:
        """
        Create an alert from a detected malicious instruction.
        
        Args:
            instruction_analysis: The instruction analysis result to create an alert from
            source_id: Identifier for the source of the alert
            sharing_level: Traffic Light Protocol (TLP) sharing level
            distribute: Whether to distribute the alert immediately
            
        Returns:
            The created alert
        """
        # Map threat type to alert category
        category_map = {
            "malicious_code_execution": AlertCategory.MALICIOUS_INSTRUCTION,
            "credential_theft": AlertCategory.MALICIOUS_INSTRUCTION,
            "data_exfiltration": AlertCategory.MALICIOUS_INSTRUCTION,
            "system_manipulation": AlertCategory.MALICIOUS_INSTRUCTION,
            "suspicious_behavior": AlertCategory.SUSPICIOUS_ACTIVITY
        }
        
        # Map risk level to alert severity
        severity_map = {
            "critical": AlertSeverity.CRITICAL,
            "high": AlertSeverity.HIGH,
            "medium": AlertSeverity.MEDIUM,
            "low": AlertSeverity.LOW
        }
        
        # Extract details from the instruction analysis
        analysis_dict = instruction_analysis.to_dict()
        threat_type = analysis_dict.get("threat_type", "suspicious_behavior")
        risk_level = analysis_dict.get("risk_level", "medium")
        
        title = f"Malicious Instruction Detected: {threat_type.replace('_', ' ').title()}"
        description = analysis_dict.get("explanation", "A potentially malicious instruction was detected.")
        
        # Create affected entities
        affected_entities = []
        if "client_id" in analysis_dict and "server_id" in analysis_dict:
            affected_entities.extend([
                {
                    "id": analysis_dict["client_id"],
                    "type": "client",
                    "name": f"Client {analysis_dict['client_id']}"
                },
                {
                    "id": analysis_dict["server_id"],
                    "type": "server",
                    "name": f"Server {analysis_dict['server_id']}"
                }
            ])
        
        # Create the alert
        alert = await self.create_alert(
            title=title,
            description=description,
            severity=severity_map.get(risk_level, AlertSeverity.MEDIUM),
            category=category_map.get(threat_type, AlertCategory.SUSPICIOUS_ACTIVITY),
            sharing_level=sharing_level,
            source_id=source_id,
            affected_entities=affected_entities,
            indicators=[{
                "type": "malicious_instruction",
                "value": analysis_dict
            }],
            recommendations=[
                "Review the instruction and context",
                "Consider revoking the connection or token if confirmed malicious",
                "Implement additional security controls to prevent similar attacks"
            ],
            metadata={
                "instruction_id": analysis_dict.get("instruction_id"),
                "session_id": analysis_dict.get("session_id")
            },
            distribute=distribute
        )
        
        return alert


# Create a singleton instance
alert_distribution_network = AlertDistributionNetwork() 
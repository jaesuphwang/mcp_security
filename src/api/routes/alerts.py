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
Alert routes for the MCP Security Guardian API.
"""
import logging
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, Query, status, BackgroundTasks
from pydantic import BaseModel

from core.config import Settings, get_settings
from core.models import (
    SecurityAlertRequest, 
    SecurityAlertResponse,
    RiskLevel,
    AlertCategory,
    AlertSeverity,
    AlertStatus,
    SharingLevel
)
from core.auth import get_current_user, get_admin_user, verify_optional_token, TokenData
from alerting.alert_manager import AlertManager

# Initialize router
router = APIRouter(prefix="/alerts", tags=["alerts"])

# Initialize logger
logger = logging.getLogger("mcp_security.api.routes.alerts")

# Initialize alert manager
alert_manager = AlertManager()


@router.post("/", response_model=SecurityAlertResponse)
async def create_alert(
    request: SecurityAlertRequest,
    background_tasks: BackgroundTasks,
    current_user: Dict[str, Any] = Depends(get_current_user),
    settings: Settings = Depends(get_settings)
):
    """
    Create a new security alert.
    
    The alert will be stored in the database and distributed according to its sharing level.
    Alerts can be about detected threats, vulnerabilities, or other security events.
    """
    try:
        # Log the request with tracking ID
        request_id = str(uuid.uuid4())
        logger.info(f"Security alert creation request received: {request_id}")
        
        # Validate request
        if not request.title or not request.description:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Alert title and description are required"
            )
        
        # Set source ID to user ID if not provided
        if not request.source_id:
            request.source_id = current_user.get("id")
        
        # Create the alert
        alert_result = await alert_manager.create_alert(
            title=request.title,
            description=request.description,
            severity=request.severity,
            source_id=request.source_id,
            affected_entities=request.affected_entities,
            metadata=request.metadata,
            created_by=current_user.get("id"),
            organization_id=current_user.get("organization_id")
        )
        
        # Distribute the alert in the background if requested
        # This might involve sending to webhooks, email, etc.
        if request.metadata and request.metadata.get("distribute", True):
            background_tasks.add_task(
                alert_manager.distribute_alert,
                alert_id=alert_result.alert_id
            )
        
        # Create response
        response = SecurityAlertResponse(
            alert_id=alert_result.alert_id,
            timestamp=datetime.utcnow().isoformat(),
            status="created",
            success=True
        )
        
        return response
        
    except Exception as e:
        logger.error(f"Error creating alert: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create alert: {str(e)}"
        )


@router.get("/", response_model=List[Dict[str, Any]])
async def get_alerts(
    request: Request,
    severity: Optional[RiskLevel] = None,
    category: Optional[AlertCategory] = None,
    status: Optional[AlertStatus] = None,
    source_id: Optional[str] = None,
    entity_id: Optional[str] = None,
    organization_id: Optional[str] = None,
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    sort_by: str = "created_at",
    sort_dir: str = "desc",
    current_user: Dict[str, Any] = Depends(get_current_user),
    settings: Settings = Depends(get_settings)
):
    """
    Get security alerts matching the specified criteria.
    
    Results can be filtered by severity, category, status, source, entity, and organization.
    Pagination is supported through limit and offset parameters.
    Sorting is supported through sort_by and sort_dir parameters.
    """
    try:
        # Enforce organization scope based on user's organization
        user_org_id = current_user.get("organization_id")
        
        # If user is not an admin and tries to query other organizations, restrict to their own
        if not current_user.get("role") == "admin" and organization_id and organization_id != user_org_id:
            organization_id = user_org_id
        elif not current_user.get("role") == "admin" and not organization_id:
            organization_id = user_org_id
        
        # Get alerts
        alerts = await alert_manager.get_alerts(
            severity=severity,
            category=category,
            status=status,
            source_id=source_id,
            entity_id=entity_id,
            organization_id=organization_id,
            limit=limit,
            offset=offset,
            sort_by=sort_by,
            sort_dir=sort_dir
        )
        
        # Convert to dictionaries
        return [alert.to_dict() for alert in alerts]
    
    except Exception as e:
        logger.error(f"Error getting alerts: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting alerts: {str(e)}"
        )


@router.get("/{alert_id}", response_model=Dict[str, Any])
async def get_alert(
    alert_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
    settings: Settings = Depends(get_settings)
):
    """
    Get a security alert by ID.
    
    Returns detailed information about a specific alert, including
    acknowledgments, related alerts, and any actions taken.
    """
    try:
        # Get the alert
        alert = await alert_manager.get_alert(alert_id)
        
        if not alert:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Alert not found: {alert_id}"
            )
        
        # Check if user has access to this alert
        user_org_id = current_user.get("organization_id")
        alert_org_id = getattr(alert, "organization_id", None)
        
        # Only admins can view alerts from other organizations
        if (
            not current_user.get("role") == "admin" and 
            alert_org_id and 
            user_org_id and 
            alert_org_id != user_org_id
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to view this alert"
            )
        
        return alert.to_dict()
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting alert: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting alert: {str(e)}"
        )


class AlertAcknowledgmentRequest(BaseModel):
    """Request model for acknowledging an alert."""
    status: AlertStatus
    notes: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


@router.post("/{alert_id}/acknowledge", response_model=Dict[str, Any])
async def acknowledge_alert(
    alert_id: str,
    request: AlertAcknowledgmentRequest,
    background_tasks: BackgroundTasks,
    current_user: Dict[str, Any] = Depends(get_current_user),
    settings: Settings = Depends(get_settings)
):
    """
    Acknowledge a security alert.
    
    Updates the status of an alert and records who acknowledged it.
    Optionally adds notes and additional metadata about the acknowledgment.
    """
    try:
        # Get the alert first to check if it exists
        alert = await alert_manager.get_alert(alert_id)
        
        if not alert:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Alert not found: {alert_id}"
            )
        
        # Check if user has access to this alert
        user_org_id = current_user.get("organization_id")
        alert_org_id = getattr(alert, "organization_id", None)
        
        # Only admins or users from the same organization can acknowledge alerts
        if (
            not current_user.get("role") == "admin" and 
            alert_org_id and 
            user_org_id and 
            alert_org_id != user_org_id
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to acknowledge this alert"
            )
        
        # Acknowledge the alert
        acknowledgment = await alert_manager.acknowledge_alert(
            alert_id=alert_id,
            entity_id=current_user.get("id"),
            entity_type="user",
            status=request.status,
            notes=request.notes,
            metadata=request.metadata
        )
        
        if not acknowledgment:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to acknowledge alert: {alert_id}"
            )
        
        # If status is RESOLVED, trigger any resolution actions in the background
        if request.status == AlertStatus.RESOLVED:
            background_tasks.add_task(
                alert_manager.process_alert_resolution,
                alert_id=alert_id,
                resolved_by=current_user.get("id"),
                notes=request.notes,
                metadata=request.metadata
            )
        
        # Get the updated alert
        updated_alert = await alert_manager.get_alert(alert_id)
        return updated_alert.to_dict()
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error acknowledging alert: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error acknowledging alert: {str(e)}"
        )


@router.get("/stats/summary", response_model=Dict[str, Any])
async def alert_stats(
    request: Request,
    time_range: str = Query("24h", description="Time range for stats (24h, 7d, 30d, all)"),
    organization_id: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
    settings: Settings = Depends(get_settings)
):
    """
    Get alert statistics summary.
    
    Returns counts of alerts by severity, category, and status for the specified time range.
    """
    try:
        # Enforce organization scope based on user's organization
        user_org_id = current_user.get("organization_id")
        
        # If user is not an admin and tries to query other organizations, restrict to their own
        if not current_user.get("role") == "admin" and organization_id and organization_id != user_org_id:
            organization_id = user_org_id
        elif not current_user.get("role") == "admin" and not organization_id:
            organization_id = user_org_id
        
        # Get alert stats
        stats = await alert_manager.get_alert_stats(
            time_range=time_range,
            organization_id=organization_id
        )
        
        return {
            "time_range": time_range,
            "organization_id": organization_id,
            "stats": stats,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Error getting alert stats: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting alert stats: {str(e)}"
        ) 
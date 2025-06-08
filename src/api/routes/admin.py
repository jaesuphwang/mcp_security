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
Admin routes for the MCP Security Guardian API.
"""
import logging
import os
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, Body, Query, status, BackgroundTasks
from pydantic import BaseModel, Field

from core.config import Settings, get_settings
from core.models import RiskLevel
from core.auth import get_admin_user
from detection_engine.detector import InstructionDetector
from alerting.alert_manager import AlertManager

# Initialize router
router = APIRouter(prefix="/admin", tags=["admin"])

# Initialize logger
logger = logging.getLogger("mcp_security.api.routes.admin")

# Initialize alert manager
alert_manager = AlertManager()

# Initialize detector
detector = InstructionDetector()


class SystemStatusResponse(BaseModel):
    """System status response model."""
    status: str = Field(..., description="System status")
    version: str = Field(..., description="System version")
    environment: str = Field(..., description="Environment")
    uptime_seconds: int = Field(..., description="Uptime in seconds")
    components: Dict[str, Dict[str, Any]] = Field(..., description="Component statuses")
    counters: Dict[str, int] = Field(..., description="System counters")
    timestamp: str = Field(..., description="Timestamp")


class ConfigUpdateRequest(BaseModel):
    """Configuration update request model."""
    key: str = Field(..., description="Configuration key")
    value: Any = Field(..., description="Configuration value")
    scope: str = Field("system", description="Configuration scope")
    description: Optional[str] = Field(None, description="Configuration description")


@router.get("/system/status", response_model=SystemStatusResponse)
async def system_status(
    request: Request,
    admin_user: Dict[str, Any] = Depends(get_admin_user),
    settings: Settings = Depends(get_settings)
):
    """
    Get system status information.
    
    Returns detailed system status information, including component statuses,
    system counters, and system uptime.
    
    This endpoint is only accessible to admin users.
    """
    try:
        # Get system uptime
        start_time = getattr(settings, "START_TIME", time.time())
        uptime_seconds = int(time.time() - start_time)
        
        # Get component statuses
        component_statuses = {
            "database": {
                "status": "healthy",
                "details": {
                    "postgresql": True,
                    "mongodb": True,
                    "redis": True
                }
            },
            "detection_engine": {
                "status": "healthy",
                "details": {
                    "pattern_matcher": detector.is_pattern_matcher_ready(),
                    "behavioral_analyzer": detector.is_behavioral_analyzer_ready(),
                    "llm_classifier": detector.is_llm_classifier_ready()
                }
            },
            "alerting": {
                "status": "healthy",
                "details": {
                    "alert_manager": alert_manager.is_ready()
                }
            }
        }
        
        # Update overall component statuses
        for component, data in component_statuses.items():
            component_statuses[component]["status"] = "healthy" if all(data["details"].values()) else "degraded"
        
        # Get system counters
        system_counters = {
            "total_alerts": await alert_manager.count_alerts(),
            "active_alerts": await alert_manager.count_alerts(status="active"),
            "total_patterns": detector.get_pattern_count(),
            "total_threats_detected": detector.get_threat_count()
        }
        
        return {
            "status": "healthy",
            "version": settings.VERSION,
            "environment": settings.ENVIRONMENT,
            "uptime_seconds": uptime_seconds,
            "components": component_statuses,
            "counters": system_counters,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error getting system status: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting system status: {str(e)}"
        )


@router.post("/config", response_model=Dict[str, Any])
async def update_config(
    request: ConfigUpdateRequest,
    admin_user: Dict[str, Any] = Depends(get_admin_user),
    settings: Settings = Depends(get_settings)
):
    """
    Update system configuration.
    
    Updates a specific configuration value in the system.
    This endpoint is only accessible to admin users.
    """
    try:
        # Validate configuration key
        if not request.key:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Configuration key is required"
            )
        
        # Check if the key is allowed to be updated
        allowed_keys = [
            "log_level",
            "alert_retention_days",
            "threat_intel_update_interval",
            "pattern_update_interval"
        ]
        
        if request.key not in allowed_keys:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Configuration key '{request.key}' cannot be updated through this API"
            )
        
        # Update configuration
        # This is a simplified example; in a real system you would update
        # the configuration in a database or config store
        result = {
            "key": request.key,
            "previous_value": getattr(settings, request.key.upper(), None),
            "new_value": request.value,
            "updated_at": datetime.utcnow().isoformat(),
            "updated_by": admin_user.get("id")
        }
        
        # Log configuration change
        logger.info(
            f"Configuration updated: {request.key} = {request.value}",
            extra={
                "admin_user": admin_user.get("id"),
                "previous_value": result["previous_value"],
                "new_value": request.value
            }
        )
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating configuration: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error updating configuration: {str(e)}"
        )


class ThreatPatternRequest(BaseModel):
    """Threat pattern request model."""
    name: str = Field(..., description="Pattern name")
    pattern_type: str = Field(..., description="Pattern type (regex, semantic, behavioral)")
    pattern_value: str = Field(..., description="Pattern value")
    description: str = Field(..., description="Pattern description")
    severity: RiskLevel = Field(..., description="Pattern severity")
    enabled: bool = Field(True, description="Whether the pattern is enabled")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")


@router.post("/patterns", response_model=Dict[str, Any])
async def create_threat_pattern(
    request: ThreatPatternRequest,
    admin_user: Dict[str, Any] = Depends(get_admin_user),
    settings: Settings = Depends(get_settings)
):
    """
    Create a new threat pattern.
    
    Adds a new pattern to the threat detection system.
    This endpoint is only accessible to admin users.
    """
    try:
        # Validate pattern type
        allowed_pattern_types = ["regex", "semantic", "behavioral"]
        if request.pattern_type not in allowed_pattern_types:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Pattern type must be one of {allowed_pattern_types}"
            )
        
        # Create pattern
        pattern_id = await detector.add_pattern(
            name=request.name,
            pattern_type=request.pattern_type,
            pattern_value=request.pattern_value,
            description=request.description,
            severity=request.severity,
            enabled=request.enabled,
            metadata=request.metadata,
            created_by=admin_user.get("id")
        )
        
        if not pattern_id:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create pattern"
            )
        
        # Get the created pattern
        pattern = await detector.get_pattern(pattern_id)
        
        return {
            "pattern_id": pattern_id,
            "name": pattern.name,
            "pattern_type": pattern.pattern_type,
            "description": pattern.description,
            "severity": pattern.severity,
            "enabled": pattern.enabled,
            "created_at": datetime.utcnow().isoformat(),
            "created_by": admin_user.get("id")
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating threat pattern: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error creating threat pattern: {str(e)}"
        )


@router.get("/patterns", response_model=List[Dict[str, Any]])
async def get_threat_patterns(
    request: Request,
    pattern_type: Optional[str] = None,
    severity: Optional[RiskLevel] = None,
    enabled: Optional[bool] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    admin_user: Dict[str, Any] = Depends(get_admin_user),
    settings: Settings = Depends(get_settings)
):
    """
    Get threat patterns.
    
    Returns a list of threat patterns used by the detection engine.
    Results can be filtered by pattern type, severity, and enabled status.
    This endpoint is only accessible to admin users.
    """
    try:
        # Get patterns
        patterns = await detector.get_patterns(
            pattern_type=pattern_type,
            severity=severity,
            enabled=enabled,
            limit=limit,
            offset=offset
        )
        
        # Convert to dictionaries
        return [
            {
                "pattern_id": pattern.id,
                "name": pattern.name,
                "pattern_type": pattern.pattern_type,
                "description": pattern.description,
                "severity": pattern.severity,
                "enabled": pattern.enabled,
                "false_positive_rate": pattern.false_positive_rate
            }
            for pattern in patterns
        ]
        
    except Exception as e:
        logger.error(f"Error getting threat patterns: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting threat patterns: {str(e)}"
        )


@router.delete("/patterns/{pattern_id}", response_model=Dict[str, Any])
async def delete_threat_pattern(
    pattern_id: str,
    admin_user: Dict[str, Any] = Depends(get_admin_user),
    settings: Settings = Depends(get_settings)
):
    """
    Delete a threat pattern.
    
    Removes a pattern from the threat detection system.
    This endpoint is only accessible to admin users.
    """
    try:
        # Check if pattern exists
        pattern = await detector.get_pattern(pattern_id)
        
        if not pattern:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Pattern not found: {pattern_id}"
            )
        
        # Delete pattern
        success = await detector.delete_pattern(pattern_id)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to delete pattern: {pattern_id}"
            )
        
        return {
            "pattern_id": pattern_id,
            "deleted": True,
            "deleted_at": datetime.utcnow().isoformat(),
            "deleted_by": admin_user.get("id")
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting threat pattern: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error deleting threat pattern: {str(e)}"
        )


@router.post("/reload", response_model=Dict[str, Any])
async def reload_system(
    request: Request,
    background_tasks: BackgroundTasks,
    admin_user: Dict[str, Any] = Depends(get_admin_user),
    settings: Settings = Depends(get_settings)
):
    """
    Reload system components.
    
    Reloads various system components, such as threat patterns,
    configuration, and models.
    This endpoint is only accessible to admin users.
    """
    try:
        # Queue reloads in background tasks
        background_tasks.add_task(detector.reload_patterns)
        background_tasks.add_task(detector.reload_models)
        
        return {
            "message": "System reload initiated",
            "components": ["threat_patterns", "models"],
            "initiated_at": datetime.utcnow().isoformat(),
            "initiated_by": admin_user.get("id")
        }
        
    except Exception as e:
        logger.error(f"Error reloading system: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error reloading system: {str(e)}"
        ) 
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

from fastapi import APIRouter, Depends, HTTPException, status, Query, BackgroundTasks, Request, Response, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Dict, List, Optional, Any
import uuid
import logging
from datetime import datetime
import json
import asyncio
import time
import redis.asyncio as redis

from src.core.config import Settings, get_settings
from src.core.auth import verify_jwt, get_current_user
from src.core.models import (
    InstructionAnalysisResponse,
    VulnerabilityScanResponse,
    TokenRevocationResponse,
    SecurityAlertResponse,
    RiskLevel,
    BulkScanRequest,
    BulkScanResponse
)
# Import secure input validation models
try:
    from src.core.security.input_validation import (
        SecureInstruction,
        SecureVulnerabilityScan,
        SecureTokenRevocation,
        SecureAlert,
        input_validator,
        validate_request_size
    )
    SECURE_VALIDATION_AVAILABLE = True
except ImportError:
    # Fallback to basic models if secure validation not available
    from src.core.models import (
        InstructionAnalysisRequest as SecureInstruction,
        VulnerabilityScanRequest as SecureVulnerabilityScan,
        TokenRevocationRequest as SecureTokenRevocation,
        SecurityAlertRequest as SecureAlert
    )
    SECURE_VALIDATION_AVAILABLE = False
    
    # Create dummy input_validator
    class DummyInputValidator:
        @staticmethod
        def validate_uuid(value):
            return value
    
    input_validator = DummyInputValidator()
# Import error handling decorators
from src.core.utils.error_handling import (
    handle_api_errors,
    handle_security_errors,
    rate_limit_error_handler,
    ErrorContext,
    log_and_raise
)
from src.detection_engine.detector import InstructionDetector
from src.vulnerability_scanning.scanner import VulnerabilityScanner
from src.revocation.token_revocation import TokenRevocationService
from src.alerting.alert_manager import AlertManager
from src.core.database import get_redis
from utils.rate_limiting import RateLimiter

# Initialize router and security components
router = APIRouter(prefix="/security", tags=["security"])
security = HTTPBearer()
logger = logging.getLogger("mcp_security.api.routes.security")

# Initialize security services
instruction_detector = InstructionDetector()
vulnerability_scanner = VulnerabilityScanner()
token_revocation_service = TokenRevocationService()
alert_manager = AlertManager()

# Initialize rate limiter
rate_limiter = RateLimiter()

@router.get("/health", status_code=status.HTTP_200_OK)
async def health_check(settings: Settings = Depends(get_settings)):
    """
    Health check endpoint for the security services.
    """
    try:
        # Check all required services
        detector_status = instruction_detector.check_health()
        scanner_status = vulnerability_scanner.check_health()
        revocation_status = token_revocation_service.check_health()
        alert_status = alert_manager.check_health()
        
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "version": settings.version,
            "environment": settings.environment,
            "services": {
                "detector": detector_status,
                "scanner": scanner_status,
                "revocation": revocation_status,
                "alert": alert_status
            }
        }
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return {
            "status": "unhealthy",
            "timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        }

@router.post("/analyze", response_model=InstructionAnalysisResponse)
@handle_security_errors
@rate_limit_error_handler
async def analyze_instruction(
    request: SecureInstruction,  # Use secure validation model
    background_tasks: BackgroundTasks,
    request_id: str = Header(None),
    x_forwarded_for: str = Header(None),
    user_agent: str = Header(None),
    current_user: Dict[str, Any] = Depends(get_current_user),
    redis_client: redis.Redis = Depends(get_redis),
    settings: Settings = Depends(get_settings)
):
    """
    Analyze an MCP instruction for security threats.
    
    This endpoint analyzes the provided instruction for potential security threats
    using multiple detection engines, including pattern matching, behavioral analysis,
    and machine learning classification.
    
    If a threat is detected, an alert is automatically generated.
    """
    # Generate request ID if not provided
    trace_id = request_id or str(uuid.uuid4())
    
    # Check rate limiting
    client_ip = x_forwarded_for or "unknown"
    
    # Apply rate limiting based on client IP and user ID
    rate_key = f"rate:analyze:{client_ip}:{current_user.get('id', 'anonymous')}"
    allowed, _ = await rate_limiter.check_rate_limit(
        redis_client,
        rate_key,
        max_requests=100,
        window_seconds=60,
    )
    if not allowed:
        logger.warning(
            f"Rate limit exceeded for instruction analysis",
            extra={
                "client_ip": client_ip,
                "user_id": current_user.get("id", "anonymous"),
                "trace_id": trace_id
            }
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please try again later."
        )
    
    # Start timing the request
    start_time = time.time()
    
    try:
        # Log the request
        logger.info(
            f"Analyzing instruction",
            extra={
                "trace_id": trace_id,
                "session_id": request.session_id,
                "client_ip": client_ip,
                "user_id": current_user.get("id", "anonymous"),
                "instruction_length": len(request.instruction)
            }
        )
        
        # Analyze the instruction using validated input
        with ErrorContext("instruction_analysis", trace_id=trace_id, session_id=request.session_id):
            analysis_result = await instruction_detector.analyze_instruction(
                instruction=request.instruction,
                session_id=request.session_id,
                context=request.context,
                user_id=current_user.get("id"),
                organization_id=current_user.get("organization_id"),
                trace_id=trace_id
            )
        
        # Log the analysis result
        log_level = logging.WARNING if analysis_result.is_threat else logging.INFO
        logger.log(
            log_level,
            f"Instruction analysis {'detected threat' if analysis_result.is_threat else 'completed'}",
            extra={
                "trace_id": trace_id,
                "session_id": request.session_id,
                "is_threat": analysis_result.is_threat,
                "confidence": analysis_result.confidence,
                "risk_level": analysis_result.risk_level,
                "analysis_time_ms": analysis_result.analysis_time_ms
            }
        )
        
        # Generate an alert if threat detected with high confidence
        if analysis_result.is_threat and analysis_result.confidence >= 0.7:
            # Create an alert from the malicious instruction in the background
            background_tasks.add_task(
                alert_manager.create_alert_from_malicious_instruction,
                instruction_analysis=analysis_result,
                source_id=f"mcp-security-{settings.INSTANCE_ID}",
                created_by="system"
            )
        
        # Calculate total processing time
        total_time_ms = int((time.time() - start_time) * 1000)
        
        # Append additional context to the response
        response_data = analysis_result.model_dump()
        response_data["trace_id"] = trace_id
        response_data["total_processing_time_ms"] = total_time_ms
        
        return InstructionAnalysisResponse(**response_data)
        
    except HTTPException:
        raise
    except Exception as e:
        log_and_raise(
            e,
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error analyzing instruction",
            trace_id=trace_id,
            session_id=request.session_id
        )

@router.post("/scan/vulnerabilities", status_code=status.HTTP_202_ACCEPTED, response_model=Dict[str, Any])
@handle_security_errors
@rate_limit_error_handler
async def scan_vulnerabilities(
    request: SecureVulnerabilityScan,  # Use secure validation model
    background_tasks: BackgroundTasks,
    request_id: str = Header(None),
    x_forwarded_for: str = Header(None),
    current_user: Dict[str, Any] = Depends(get_current_user),
    redis_client: redis.Redis = Depends(get_redis),
    settings: Settings = Depends(get_settings)
):
    """
    Scan an MCP server for vulnerabilities.
    
    This endpoint initiates a vulnerability scan on the specified MCP server.
    The scan can include connection security, capability auditing, and sandbox testing.
    
    The scan is performed asynchronously, and results are available through
    the scan ID returned in the response.
    """
    # Generate request ID if not provided
    trace_id = request_id or str(uuid.uuid4())
    
    # Check rate limiting
    client_ip = x_forwarded_for or "unknown"
    
    # Apply rate limiting based on client IP and user ID (stricter limits for scans)
    rate_key = f"rate:scan:{client_ip}:{current_user.get('id', 'anonymous')}"
    allowed, _ = await rate_limiter.check_rate_limit(
        redis_client,
        rate_key,
        max_requests=10,
        window_seconds=600,
    )
    if not allowed:
        logger.warning(
            f"Rate limit exceeded for vulnerability scan",
            extra={
                "client_ip": client_ip,
                "user_id": current_user.get("id", "anonymous"),
                "trace_id": trace_id
            }
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please try again later."
        )
    
    try:
        # Log the request
        logger.info(
            f"Scanning server for vulnerabilities",
            extra={
                "trace_id": trace_id,
                "target": request.server_id,
                "scan_type": request.scan_type,
                "client_ip": client_ip,
                "user_id": current_user.get("id", "anonymous")
            }
        )
        
        # Initialize the scan with validated input
        with ErrorContext("vulnerability_scan_init", trace_id=trace_id, target=request.server_id):
            # Map secure model fields to scanner parameters
            scan_types = request.include_tests if request.include_tests else ['connection_security', 'capability_audit']
            
            scan_id = await vulnerability_scanner.initialize_scan(
                target=request.target_url or request.server_id,
                scan_types=scan_types,
                scan_depth=3,  # Default depth
                timeout=300,  # Default timeout 5 minutes
                auth_token=None,  # Auth token should be retrieved from secure storage
                user_id=current_user.get("id"),
                organization_id=current_user.get("organization_id"),
                trace_id=trace_id
            )
        
        if not scan_id:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to initialize vulnerability scan"
            )
        
        # Start the scan in the background
        background_tasks.add_task(
            vulnerability_scanner.run_scan,
            scan_id=scan_id
        )
        
        # Calculate estimated completion time
        estimated_completion_seconds = 30 * len(scan_types)
        estimated_completion_time = datetime.utcnow().timestamp() + estimated_completion_seconds
        
        # Return scan information
        return {
            "scan_id": scan_id,
            "status": "accepted",
            "message": "Vulnerability scan started",
            "target": request.target_url or request.server_id,
            "scan_types": scan_types,
            "trace_id": trace_id,
            "estimated_completion_time": datetime.fromtimestamp(estimated_completion_time).isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        log_and_raise(
            e,
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error initiating vulnerability scan",
            trace_id=trace_id,
            target=request.server_id
        )

@router.get("/scan/vulnerabilities/{scan_id}", response_model=VulnerabilityScanResponse)
@handle_api_errors
async def get_vulnerability_scan(
    scan_id: str,
    request_id: str = Header(None),
    current_user: Dict[str, Any] = Depends(get_current_user),
    settings: Settings = Depends(get_settings)
):
    """
    Get the results of a vulnerability scan.
    
    This endpoint returns the results of a previously initiated vulnerability scan.
    """
    # Generate request ID if not provided
    trace_id = request_id or str(uuid.uuid4())
    
    try:
        # Log the request
        logger.info(
            f"Getting vulnerability scan results",
            extra={
                "trace_id": trace_id,
                "scan_id": scan_id,
                "user_id": current_user.get("id", "anonymous")
            }
        )
        
        # Validate scan_id format
        validated_scan_id = input_validator.validate_uuid(scan_id)
        
        # Get scan results
        scan_result = await vulnerability_scanner.get_scan_results(validated_scan_id)
        
        if not scan_result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Vulnerability scan not found: {scan_id}"
            )
        
        # Check if user has access to this scan
        scan_user_id = getattr(scan_result, "user_id", None)
        scan_org_id = getattr(scan_result, "organization_id", None)
        
        if (
            not current_user.get("role") == "admin" and
            scan_user_id and scan_user_id != current_user.get("id") and
            scan_org_id and scan_org_id != current_user.get("organization_id")
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to access this scan"
            )
        
        # Convert to response model
        response = VulnerabilityScanResponse(
            scan_id=scan_result.scan_id,
            target=scan_result.target,
            timestamp=scan_result.timestamp.isoformat(),
            findings=scan_result.findings,
            scan_duration_ms=scan_result.scan_duration_ms,
            total_vulnerabilities=len(scan_result.findings),
            risk_assessment=scan_result.risk_assessment
        )
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        log_and_raise(
            e,
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error getting vulnerability scan results",
            trace_id=trace_id,
            scan_id=scan_id
        )

@router.post("/revoke/token", status_code=status.HTTP_202_ACCEPTED, response_model=Dict[str, Any])
@handle_security_errors
@rate_limit_error_handler
async def revoke_token(
    request: SecureTokenRevocation,  # Use secure validation model
    background_tasks: BackgroundTasks,
    request_id: str = Header(None),
    x_forwarded_for: str = Header(None),
    current_user: Dict[str, Any] = Depends(get_current_user),
    redis_client: redis.Redis = Depends(get_redis),
    settings: Settings = Depends(get_settings)
):
    """
    Revoke a token.
    
    This endpoint revokes the specified token, preventing it from being used
    for authentication or authorization. Active connections using the token
    can also be terminated.
    """
    # Generate request ID if not provided
    trace_id = request_id or str(uuid.uuid4())
    
    # Check rate limiting
    client_ip = x_forwarded_for or "unknown"
    
    # Apply rate limiting based on client IP and user ID (strict limits for token revocation)
    rate_key = f"rate:revoke:{client_ip}:{current_user.get('id', 'anonymous')}"
    allowed, _ = await rate_limiter.check_rate_limit(
        redis_client,
        rate_key,
        max_requests=5,
        window_seconds=60,
    )
    if not allowed:
        logger.warning(
            f"Rate limit exceeded for token revocation",
            extra={
                "client_ip": client_ip,
                "user_id": current_user.get("id", "anonymous"),
                "trace_id": trace_id
            }
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please try again later."
        )
    
    try:
        # Log the request
        logger.info(
            f"Revoking token",
            extra={
                "trace_id": trace_id,
                "reason": request.reason,
                "user_id": current_user.get("id", "anonymous")
            }
        )
        
        # Create a background task for token revocation with validated input
        with ErrorContext("token_revocation", trace_id=trace_id, token=request.token[:10] + "..."):
            background_tasks.add_task(
                token_revocation_service.revoke_token,
                token_id=request.token,  # Using 'token' field from SecureTokenRevocation
                reason=request.reason,
                user_id=current_user.get("id"),
                details={"priority": request.priority},  # Include priority from secure model
                trace_id=trace_id
            )
        
        # Return response immediately
        return {
            "status": "accepted",
            "message": "Token revocation started",
            "token_id": request.token[:10] + "..." if len(request.token) > 10 else request.token,  # Mask token in response
            "reason": request.reason,
            "trace_id": trace_id,
            "initiated_by": current_user.get("id"),
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        log_and_raise(
            e,
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error initiating token revocation",
            trace_id=trace_id,
            token_masked=request.token[:10] + "..."
        )

@router.get("/revoke/token/{revocation_id}", response_model=TokenRevocationResponse)
@handle_api_errors
async def get_token_revocation(
    revocation_id: str,
    request_id: str = Header(None),
    current_user: Dict[str, Any] = Depends(get_current_user),
    settings: Settings = Depends(get_settings)
):
    """
    Get the status of a token revocation.
    
    This endpoint returns the status of a previously initiated token revocation.
    """
    # Generate request ID if not provided
    trace_id = request_id or str(uuid.uuid4())
    
    try:
        # Log the request
        logger.info(
            f"Getting token revocation status",
            extra={
                "trace_id": trace_id,
                "revocation_id": revocation_id,
                "user_id": current_user.get("id", "anonymous")
            }
        )
        
        # Validate revocation_id format
        validated_revocation_id = input_validator.validate_uuid(revocation_id)
        
        # Get revocation status
        revocation = await token_revocation_service.get_revocation(validated_revocation_id)
        
        if not revocation:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Token revocation not found: {revocation_id}"
            )
        
        # Check if user has access to this revocation
        revocation_user_id = getattr(revocation, "user_id", None)
        revocation_org_id = getattr(revocation, "organization_id", None)
        
        if (
            not current_user.get("role") == "admin" and
            revocation_user_id and revocation_user_id != current_user.get("id") and
            revocation_org_id and revocation_org_id != current_user.get("organization_id")
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to access this token revocation"
            )
        
        # Convert to response model
        response = TokenRevocationResponse(
            revocation_id=revocation.revocation_id,
            token_id=revocation.token_id,
            timestamp=revocation.revoked_at.isoformat(),
            status=revocation.status,
            success=revocation.status == "completed",
            message=revocation.message
        )
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        log_and_raise(
            e,
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error getting token revocation status",
            trace_id=trace_id,
            revocation_id=revocation_id
        )

@router.post("/bulk/scan", status_code=status.HTTP_202_ACCEPTED, response_model=BulkScanResponse)
@handle_security_errors
@rate_limit_error_handler
async def bulk_scan(
    request: BulkScanRequest,  # Keep original for bulk scan (complex validation)
    background_tasks: BackgroundTasks,
    request_id: str = Header(None),
    current_user: Dict[str, Any] = Depends(get_current_user),
    redis_client: redis.Redis = Depends(get_redis),
    settings: Settings = Depends(get_settings)
):
    """
    Perform a bulk security scan.
    
    This endpoint initiates a bulk security scan on multiple targets and/or instructions.
    The scan can include vulnerability scanning, instruction analysis, and token validation.
    
    The scan is performed asynchronously, and results are available through
    the scan ID returned in the response.
    """
    # Generate request ID if not provided
    trace_id = request_id or str(uuid.uuid4())
    
    # Only admins can use this endpoint
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can perform bulk scans"
        )
    
    try:
        # Log the request
        logger.info(
            f"Initiating bulk security scan",
            extra={
                "trace_id": trace_id,
                "targets_count": len(request.targets),
                "scan_types": request.scan_types,
                "user_id": current_user.get("id")
            }
        )
        
        # Validate bulk scan request
        with ErrorContext("bulk_scan_validation", trace_id=trace_id):
            # Validate targets
            for target in request.targets:
                if request.scan_types and 'vulnerability' in request.scan_types:
                    input_validator.validate_url(target)  # Validate as URL for vulnerability scans
            
            # Validate instructions if provided
            if request.scan_instructions:
                for instruction in request.scan_instructions:
                    if input_validator.check_sql_injection(instruction):
                        raise ValueError("Invalid instruction content detected")
                    if input_validator.check_xss(instruction):
                        raise ValueError("Invalid instruction content detected")
        
        # Initialize the bulk scan
        scan_id = str(uuid.uuid4())
        
        # Store scan metadata
        await redis_client.hset(
            f"bulk_scan:{scan_id}",
            mapping={
                "status": "pending",
                "targets_count": len(request.targets),
                "scan_types": ",".join(request.scan_types),
                "user_id": current_user.get("id"),
                "created_at": datetime.utcnow().isoformat(),
                "trace_id": trace_id
            }
        )
        
        # Set expiration for the scan metadata (7 days)
        await redis_client.expire(f"bulk_scan:{scan_id}", 604800)
        
        # Create a background task for the bulk scan
        background_tasks.add_task(
            perform_bulk_scan,
            scan_id=scan_id,
            targets=request.targets,
            scan_types=request.scan_types,
            scan_instructions=request.scan_instructions,
            scan_depth=request.scan_depth,
            timeout=request.timeout,
            auth_tokens=request.auth_tokens,
            user_id=current_user.get("id"),
            organization_id=current_user.get("organization_id"),
            trace_id=trace_id
        )
        
        # Calculate estimated completion time
        estimated_completion_seconds = (
            60 * len(request.targets) * len(request.scan_types) +
            5 * len(request.scan_instructions or [])
        )
        estimated_completion_time = datetime.utcnow().timestamp() + estimated_completion_seconds
        
        # Return scan information
        return BulkScanResponse(
            scan_id=scan_id,
            timestamp=datetime.utcnow().isoformat(),
            status="accepted",
            estimated_completion_time=datetime.fromtimestamp(estimated_completion_time).isoformat(),
            targets=request.targets
        )
        
    except HTTPException:
        raise
    except Exception as e:
        log_and_raise(
            e,
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error initiating bulk scan",
            trace_id=trace_id,
            targets_count=len(request.targets)
        )

# Helper function for bulk scanning
async def perform_bulk_scan(
    scan_id: str,
    targets: List[str],
    scan_types: List[str],
    scan_instructions: Optional[List[str]] = None,
    scan_depth: int = 3,
    timeout: Optional[int] = None,
    auth_tokens: Optional[Dict[str, str]] = None,
    user_id: Optional[str] = None,
    organization_id: Optional[str] = None,
    trace_id: Optional[str] = None
):
    """
    Perform a bulk security scan asynchronously.
    
    This function is meant to be run as a background task.
    """
    redis_client = get_redis()
    
    try:
        # Update scan status
        await redis_client.hset(
            f"bulk_scan:{scan_id}",
            "status",
            "in_progress"
        )
        
        # Initialize result storage
        results = {
            "vulnerability_scans": {},
            "instruction_analyses": {},
            "summary": {
                "total_targets": len(targets),
                "total_instructions": len(scan_instructions or []),
                "vulnerabilities_found": 0,
                "threats_detected": 0,
                "completion_time": None
            }
        }
        
        # Perform vulnerability scans
        if "vulnerability" in scan_types and targets:
            for target in targets:
                try:
                    # Get auth token for target if available
                    auth_token = auth_tokens.get(target) if auth_tokens else None
                    
                    # Initialize scan
                    target_scan_id = await vulnerability_scanner.initialize_scan(
                        target=target,
                        scan_types=["connection", "capabilities", "sandbox"],
                        scan_depth=scan_depth,
                        timeout=timeout,
                        auth_token=auth_token,
                        user_id=user_id,
                        organization_id=organization_id,
                        trace_id=trace_id
                    )
                    
                    # Run scan immediately (not as a background task)
                    await vulnerability_scanner.run_scan(target_scan_id)
                    
                    # Get scan results
                    scan_result = await vulnerability_scanner.get_scan_results(target_scan_id)
                    
                    # Store results
                    results["vulnerability_scans"][target] = {
                        "scan_id": target_scan_id,
                        "findings_count": len(scan_result.findings),
                        "risk_assessment": scan_result.risk_assessment,
                        "scan_duration_ms": scan_result.scan_duration_ms
                    }
                    
                    # Update summary
                    results["summary"]["vulnerabilities_found"] += len(scan_result.findings)
                    
                except Exception as e:
                    logger.error(
                        f"Error scanning target in bulk scan: {str(e)}",
                        extra={
                            "trace_id": trace_id,
                            "scan_id": scan_id,
                            "target": target,
                            "error": str(e)
                        }
                    )
                    
                    # Store error
                    results["vulnerability_scans"][target] = {
                        "error": str(e)
                    }
        
        # Perform instruction analyses
        if "instruction" in scan_types and scan_instructions:
            for i, instruction in enumerate(scan_instructions):
                try:
                    # Analyze instruction
                    analysis_result = await instruction_detector.analyze_instruction(
                        instruction=instruction,
                        session_id=f"bulk-scan-{scan_id}",
                        user_id=user_id,
                        organization_id=organization_id,
                        trace_id=trace_id
                    )
                    
                    # Store results
                    results["instruction_analyses"][f"instruction_{i+1}"] = {
                        "is_threat": analysis_result.is_threat,
                        "confidence": analysis_result.confidence,
                        "risk_level": analysis_result.risk_level,
                        "threat_type": analysis_result.threat_type,
                        "analysis_time_ms": analysis_result.analysis_time_ms
                    }
                    
                    # Update summary
                    if analysis_result.is_threat:
                        results["summary"]["threats_detected"] += 1
                        
                except Exception as e:
                    logger.error(
                        f"Error analyzing instruction in bulk scan: {str(e)}",
                        extra={
                            "trace_id": trace_id,
                            "scan_id": scan_id,
                            "instruction_index": i,
                            "error": str(e)
                        }
                    )
                    
                    # Store error
                    results["instruction_analyses"][f"instruction_{i+1}"] = {
                        "error": str(e)
                    }
        
        # Update summary
        results["summary"]["completion_time"] = datetime.utcnow().isoformat()
        
        # Store results
        await redis_client.hset(
            f"bulk_scan:{scan_id}",
            mapping={
                "status": "completed",
                "results": json.dumps(results),
                "completed_at": datetime.utcnow().isoformat()
            }
        )
        
        logger.info(
            f"Bulk scan completed",
            extra={
                "trace_id": trace_id,
                "scan_id": scan_id,
                "vulnerabilities_found": results["summary"]["vulnerabilities_found"],
                "threats_detected": results["summary"]["threats_detected"]
            }
        )
        
    except Exception as e:
        logger.error(
            f"Error performing bulk scan: {str(e)}",
            extra={
                "trace_id": trace_id,
                "scan_id": scan_id,
                "error": str(e)
            },
            exc_info=True
        )
        
        # Update scan status to failed
        await redis_client.hset(
            f"bulk_scan:{scan_id}",
            mapping={
                "status": "failed",
                "error": str(e),
                "completed_at": datetime.utcnow().isoformat()
            }
        ) 
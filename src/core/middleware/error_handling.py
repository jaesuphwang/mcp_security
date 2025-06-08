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
Comprehensive error handling middleware and utilities.
"""
import sys
import traceback
import json
from typing import Any, Dict, Optional, Union, Callable
from datetime import datetime
import uuid
from functools import wraps
import asyncio

from fastapi import Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from pydantic import ValidationError

from core.utils.logging import get_logger
from core.models.api import ErrorResponse, ErrorDetail

logger = get_logger(__name__)


class MCPSecurityError(Exception):
    """Base exception for MCP Security Guardian."""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.details = details or {}


class AuthenticationError(MCPSecurityError):
    """Authentication failed."""
    pass


class AuthorizationError(MCPSecurityError):
    """Authorization failed."""
    pass


class ValidationError(MCPSecurityError):
    """Input validation failed."""
    pass


class RateLimitError(MCPSecurityError):
    """Rate limit exceeded."""
    pass


class ResourceNotFoundError(MCPSecurityError):
    """Requested resource not found."""
    pass


class ConflictError(MCPSecurityError):
    """Resource conflict."""
    pass


class ExternalServiceError(MCPSecurityError):
    """External service error."""
    pass


class ConfigurationError(MCPSecurityError):
    """Configuration error."""
    pass


class SecurityViolationError(MCPSecurityError):
    """Security violation detected."""
    pass


def generate_error_id() -> str:
    """Generate a unique error ID for tracking."""
    return f"err_{uuid.uuid4().hex[:12]}"


async def error_handler_middleware(request: Request, call_next: Callable) -> JSONResponse:
    """
    Global error handling middleware.
    
    Catches all unhandled exceptions and returns structured error responses.
    """
    error_id = generate_error_id()
    request.state.error_id = error_id
    
    try:
        response = await call_next(request)
        return response
    except Exception as exc:
        # Log the full exception with traceback
        logger.error(
            f"Unhandled exception in request {request.url.path}",
            extra={
                "error_id": error_id,
                "method": request.method,
                "path": request.url.path,
                "client": request.client.host if request.client else None,
                "exception_type": type(exc).__name__,
                "exception_message": str(exc),
                "traceback": traceback.format_exc()
            }
        )
        
        # Return a generic error response
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": {
                    "code": "INTERNAL_SERVER_ERROR",
                    "message": "An unexpected error occurred",
                    "error_id": error_id,
                    "timestamp": datetime.utcnow().isoformat()
                }
            }
        )


async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Handle validation errors with detailed feedback."""
    error_id = getattr(request.state, 'error_id', generate_error_id())
    
    # Extract validation errors
    errors = []
    for error in exc.errors():
        field_path = ".".join(str(loc) for loc in error["loc"])
        errors.append({
            "field": field_path,
            "message": error["msg"],
            "type": error["type"]
        })
    
    logger.warning(
        f"Validation error in request {request.url.path}",
        extra={
            "error_id": error_id,
            "method": request.method,
            "path": request.url.path,
            "errors": errors
        }
    )
    
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": {
                "code": "VALIDATION_ERROR",
                "message": "Request validation failed",
                "error_id": error_id,
                "timestamp": datetime.utcnow().isoformat(),
                "details": errors
            }
        }
    )


async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    """Handle HTTP exceptions with consistent format."""
    error_id = getattr(request.state, 'error_id', generate_error_id())
    
    # Map status codes to error codes
    error_codes = {
        400: "BAD_REQUEST",
        401: "UNAUTHORIZED",
        403: "FORBIDDEN",
        404: "NOT_FOUND",
        405: "METHOD_NOT_ALLOWED",
        409: "CONFLICT",
        429: "TOO_MANY_REQUESTS",
        500: "INTERNAL_SERVER_ERROR",
        502: "BAD_GATEWAY",
        503: "SERVICE_UNAVAILABLE",
        504: "GATEWAY_TIMEOUT"
    }
    
    error_code = error_codes.get(exc.status_code, "ERROR")
    
    logger.warning(
        f"HTTP exception in request {request.url.path}",
        extra={
            "error_id": error_id,
            "method": request.method,
            "path": request.url.path,
            "status_code": exc.status_code,
            "detail": exc.detail
        }
    )
    
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": error_code,
                "message": exc.detail or "An error occurred",
                "error_id": error_id,
                "timestamp": datetime.utcnow().isoformat()
            }
        }
    )


async def mcp_security_exception_handler(request: Request, exc: MCPSecurityError) -> JSONResponse:
    """Handle custom MCP Security exceptions."""
    error_id = getattr(request.state, 'error_id', generate_error_id())
    
    # Map exception types to status codes and error codes
    exception_map = {
        AuthenticationError: (status.HTTP_401_UNAUTHORIZED, "AUTHENTICATION_ERROR"),
        AuthorizationError: (status.HTTP_403_FORBIDDEN, "AUTHORIZATION_ERROR"),
        ValidationError: (status.HTTP_400_BAD_REQUEST, "VALIDATION_ERROR"),
        RateLimitError: (status.HTTP_429_TOO_MANY_REQUESTS, "RATE_LIMIT_ERROR"),
        ResourceNotFoundError: (status.HTTP_404_NOT_FOUND, "RESOURCE_NOT_FOUND"),
        ConflictError: (status.HTTP_409_CONFLICT, "CONFLICT_ERROR"),
        ExternalServiceError: (status.HTTP_502_BAD_GATEWAY, "EXTERNAL_SERVICE_ERROR"),
        ConfigurationError: (status.HTTP_500_INTERNAL_SERVER_ERROR, "CONFIGURATION_ERROR"),
        SecurityViolationError: (status.HTTP_403_FORBIDDEN, "SECURITY_VIOLATION")
    }
    
    status_code, error_code = exception_map.get(
        type(exc),
        (status.HTTP_500_INTERNAL_SERVER_ERROR, "INTERNAL_ERROR")
    )
    
    logger.error(
        f"MCP Security exception in request {request.url.path}",
        extra={
            "error_id": error_id,
            "method": request.method,
            "path": request.url.path,
            "exception_type": type(exc).__name__,
            "message": str(exc),
            "details": exc.details
        }
    )
    
    response_content = {
        "error": {
            "code": error_code,
            "message": str(exc),
            "error_id": error_id,
            "timestamp": datetime.utcnow().isoformat()
        }
    }
    
    if exc.details:
        response_content["error"]["details"] = exc.details
    
    return JSONResponse(
        status_code=status_code,
        content=response_content
    )


def with_error_handling(func: Callable) -> Callable:
    """
    Decorator for consistent error handling in sync functions.
    
    Usage:
        @with_error_handling
        def my_function():
            # function code
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except MCPSecurityError:
            raise  # Re-raise our custom exceptions
        except Exception as e:
            logger.error(
                f"Error in {func.__name__}",
                extra={
                    "function": func.__name__,
                    "exception_type": type(e).__name__,
                    "exception_message": str(e),
                    "traceback": traceback.format_exc()
                }
            )
            raise MCPSecurityError(
                f"Error in {func.__name__}: {str(e)}",
                details={"original_exception": type(e).__name__}
            )
    
    return wrapper


def async_with_error_handling(func: Callable) -> Callable:
    """
    Decorator for consistent error handling in async functions.
    
    Usage:
        @async_with_error_handling
        async def my_async_function():
            # function code
    """
    @wraps(func)
    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except MCPSecurityError:
            raise  # Re-raise our custom exceptions
        except Exception as e:
            logger.error(
                f"Error in {func.__name__}",
                extra={
                    "function": func.__name__,
                    "exception_type": type(e).__name__,
                    "exception_message": str(e),
                    "traceback": traceback.format_exc()
                }
            )
            raise MCPSecurityError(
                f"Error in {func.__name__}: {str(e)}",
                details={"original_exception": type(e).__name__}
            )
    
    return wrapper


class CircuitBreaker:
    """
    Circuit breaker pattern for external service calls.
    
    Prevents cascading failures by temporarily disabling calls to failing services.
    """
    
    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        recovery_timeout: int = 60,
        expected_exception: type = Exception
    ):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        
        self._failure_count = 0
        self._last_failure_time = None
        self._state = "closed"  # closed, open, half-open
    
    async def call(self, func: Callable, *args, **kwargs):
        """Execute a function with circuit breaker protection."""
        if self._state == "open":
            if (datetime.utcnow() - self._last_failure_time).seconds > self.recovery_timeout:
                self._state = "half-open"
                logger.info(f"Circuit breaker {self.name} entering half-open state")
            else:
                raise ExternalServiceError(
                    f"Circuit breaker {self.name} is open",
                    details={"state": "open", "failures": self._failure_count}
                )
        
        try:
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)
            
            # Reset on success
            if self._state == "half-open":
                logger.info(f"Circuit breaker {self.name} closing after successful call")
            self._failure_count = 0
            self._state = "closed"
            
            return result
            
        except self.expected_exception as e:
            self._failure_count += 1
            self._last_failure_time = datetime.utcnow()
            
            if self._failure_count >= self.failure_threshold:
                self._state = "open"
                logger.error(
                    f"Circuit breaker {self.name} opening after {self._failure_count} failures",
                    extra={"last_error": str(e)}
                )
            
            raise ExternalServiceError(
                f"Service {self.name} call failed",
                details={
                    "state": self._state,
                    "failures": self._failure_count,
                    "error": str(e)
                }
            )


# Global circuit breakers for external services
circuit_breakers = {
    "llm_service": CircuitBreaker("llm_service", failure_threshold=3, recovery_timeout=30),
    "threat_intel": CircuitBreaker("threat_intel", failure_threshold=5, recovery_timeout=60),
    "sandbox": CircuitBreaker("sandbox", failure_threshold=2, recovery_timeout=120)
}


def get_circuit_breaker(service_name: str) -> CircuitBreaker:
    """Get or create a circuit breaker for a service."""
    if service_name not in circuit_breakers:
        circuit_breakers[service_name] = CircuitBreaker(service_name)
    return circuit_breakers[service_name]
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
MCP Security Guardian API Server.

This module provides the main FastAPI application for the MCP Security Guardian,
exposing endpoints for instruction analysis, vulnerability scanning, token revocation, and alerting.
"""
import asyncio
import json
import time
import uuid
import logging
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable, Awaitable, Union

from fastapi import FastAPI, HTTPException, Depends, Header, BackgroundTasks, Request, Response, status, WebSocket, WebSocketDisconnect
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.routing import APIRouter
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
import contextvars
import uvicorn
import asyncpg
from pydantic import BaseModel, Field

from core.config import Settings, get_settings
from core.database import check_database_connections, close_connections
from core.logging.enhanced_logging import setup_logging, get_logger, LogContext, audit_log
from core.utils.request_context import RequestIdMiddleware, request_id_contextvar
from core.middleware.error_handling import (
    error_handler_middleware,
    validation_exception_handler,
    http_exception_handler,
    mcp_security_exception_handler,
    MCPSecurityError
)
from core.security.input_validation import validate_request_size
from core.models import (
    HealthResponse,
    MetricsResponse,
    ErrorResponse
)
# Import route modules
from api.routes import security, monitoring, alerts, admin

# Initialize context vars
request_start_time = contextvars.ContextVar("request_start_time", default=None)
request_id_var = contextvars.ContextVar("request_id", default=None)

# Configure structured logging
logger = get_logger(__name__)


def get_request_logger():
    """
    Get a logger with request context.
    """
    from core.logging_config import get_request_logger as get_configured_logger
    request_id = request_id_var.get()
    trace_id = request_id  # Use request_id as trace_id
    return get_configured_logger(__name__, request_id=request_id, trace_id=trace_id)

# Initialize request counter metrics
REQUEST_COUNT = Counter(
    "http_requests_total", 
    "Total count of HTTP requests", 
    ["method", "endpoint", "status"]
)
REQUEST_LATENCY = Histogram(
    "http_request_duration_seconds", 
    "HTTP request latency in seconds",
    ["method", "endpoint"]
)
ACTIVE_REQUESTS = Counter(
    "http_requests_active", 
    "Active HTTP requests",
    ["method"]
)

# Request tracking middleware
class RequestTrackingMiddleware(BaseHTTPMiddleware):
    """Middleware to track and log requests."""
    
    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        # Generate request ID if not already present
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request_id_var.set(request_id)
        
        # Set start time
        start_time = time.time()
        request_start_time.set(start_time)
        
        # Increment active requests counter
        ACTIVE_REQUESTS.labels(method=request.method).inc()
        
        # Get logger with request context
        log = get_request_logger()
        
        # Log request
        log.info(
            f"Request started",
            extra={
                "http": {
                    "method": request.method,
                    "url": str(request.url),
                    "version": request.scope.get("http_version", ""),
                    "request_id": request_id,
                },
                "client": {
                    "ip": request.client.host if request.client else None,
                },
                "user_agent": request.headers.get("user-agent"),
            },
        )
        
        try:
            # Process request
            response = await call_next(request)
            
            # Add request ID header to response
            response.headers["X-Request-ID"] = request_id
            
            # Calculate duration
            duration = time.time() - start_time
            
            # Update metrics
            REQUEST_COUNT.labels(
                method=request.method,
                endpoint=request.scope["path"],
                status=response.status_code,
            ).inc()
            REQUEST_LATENCY.labels(
                method=request.method,
                endpoint=request.scope["path"],
            ).observe(duration)
            
            # Log response
            log.info(
                f"Request completed",
                extra={
                    "http": {
                        "method": request.method,
                        "url": str(request.url),
                        "status_code": response.status_code,
                        "request_id": request_id,
                    },
                    "duration": duration,
                },
            )
            
            return response
            
        except Exception as e:
            # Log exception
            log.exception(
                f"Request failed: {str(e)}",
                extra={
                    "http": {
                        "method": request.method,
                        "url": str(request.url),
                        "request_id": request_id,
                    },
                    "error": {
                        "type": type(e).__name__,
                        "message": str(e),
                    },
                    "duration": time.time() - start_time,
                },
            )
            
            # Re-raise for FastAPI exception handlers
            raise
        finally:
            # Decrement active requests counter
            ACTIVE_REQUESTS.labels(method=request.method).dec()


class ErrorLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware to log unhandled exceptions."""
    
    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        try:
            return await call_next(request)
        except Exception as e:
            # Get logger with request context
            log = get_request_logger()
            
            # Log exception details
            log.exception(
                f"Unhandled exception: {str(e)}",
                extra={
                    "http": {
                        "method": request.method,
                        "url": str(request.url),
                        "request_id": request_id_var.get(),
                    },
                    "error": {
                        "type": type(e).__name__,
                        "message": str(e),
                        "traceback": True,
                    },
                },
            )
            
            # Return JSON error response
            if isinstance(e, HTTPException):
                return JSONResponse(
                    status_code=e.status_code,
                    content={
                        "error": {
                            "code": e.status_code,
                            "message": e.detail,
                            "request_id": request_id_var.get(),
                        }
                    },
                )
            else:
                return JSONResponse(
                    status_code=500,
                    content={
                        "error": {
                            "code": 500,
                            "message": "Internal server error",
                            "request_id": request_id_var.get(),
                        }
                    },
                )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifecycle management for the application.
    """
    # Startup
    settings = get_settings()
    
    # Setup enhanced logging
    setup_logging(
        log_level=settings.log_level,
        log_format=settings.log_format,
        log_file=settings.log_file if hasattr(settings, 'log_file') else None,
        enable_async=True
    )
    
    logger.info("Starting MCP Security Guardian API")
    
    # Check database connections
    connection_status = check_database_connections()
    for db_name, status in connection_status.items():
        if status:
            logger.info(f"Successfully connected to {db_name}")
        else:
            logger.warning(f"Failed to connect to {db_name}")
    
    # Initialize any async resources here
    settings = get_settings()
    
    # Create the database pool
    try:
        # This would be used for direct PostgreSQL access if needed
        app.state.pg_pool = await asyncpg.create_pool(
            dsn=settings.postgres_dsn,
            min_size=settings.POSTGRES_POOL_MIN_SIZE,
            max_size=settings.POSTGRES_POOL_MAX_SIZE,
            command_timeout=60
        )
        logger.info("PostgreSQL connection pool created")
    except Exception as e:
        logger.error(f"Failed to create PostgreSQL connection pool: {str(e)}")
        app.state.pg_pool = None
    
    # Wait for FastAPI startup
    logger.info(f"MCP Security Guardian API started in {settings.ENVIRONMENT} mode")
    
    yield
    
    # Shutdown
    logger.info("Shutting down MCP Security Guardian API")
    
    # Close the database pool
    if hasattr(app.state, "pg_pool") and app.state.pg_pool:
        await app.state.pg_pool.close()
        logger.info("PostgreSQL connection pool closed")
    
    # Close other connections
    close_connections()
    
    logger.info("All connections closed")


# Create FastAPI application with lifecycle management
app = FastAPI(
    title="MCP Security Guardian",
    description="Security monitoring and protection system for MCP servers",
    version="1.0.0",
    docs_url=None,  # Disable default docs
    redoc_url=None,  # Disable default redoc
    lifespan=lifespan,
)

# Add middleware in correct order (bottom to top execution)
settings = get_settings()

# CORS must be added first (executed last)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.API_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID", "X-API-Version", "X-RateLimit-Remaining", "X-RateLimit-Reset"],
)

# Add custom middleware
app.add_middleware(ErrorLoggingMiddleware)
app.add_middleware(RequestTrackingMiddleware)
app.add_middleware(RequestIdMiddleware)

# Add error handlers
app.add_exception_handler(RequestValidationError, validation_exception_handler)
app.add_exception_handler(StarletteHTTPException, http_exception_handler)
app.add_exception_handler(MCPSecurityError, mcp_security_exception_handler)

# Include routers with API versioning
v1_router = APIRouter(prefix="/api/v1")
v1_router.include_router(security.router)
v1_router.include_router(monitoring.router)
v1_router.include_router(alerts.router)
v1_router.include_router(admin.router)

# Add v1 router to the main app
app.include_router(v1_router)

# Add compatibility router at root level (no /api/v1 prefix)
# This allows older clients to continue working without changes
compat_router = APIRouter(prefix="/api")
compat_router.include_router(security.router)
compat_router.include_router(monitoring.router)
compat_router.include_router(alerts.router)
compat_router.include_router(admin.router)

app.include_router(compat_router)


# Health check endpoint at root level for load balancers
@app.get("/health", response_model=HealthResponse, tags=["Monitoring"])
async def health_check():
    """
    Basic health check endpoint for load balancers and monitoring systems.
    
    Returns a 200 OK response if the API is running.
    Does not check dependent services for faster response.
    """
    return {
        "status": "healthy",
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "timestamp": datetime.utcnow().isoformat()
    }


# Full health check with dependency checking
@app.get("/health/full", response_model=Dict[str, Any], tags=["Monitoring"])
async def full_health_check():
    """
    Comprehensive health check endpoint that checks all dependencies.
    """
    # Check database connections
    connection_status = check_database_connections()
    
    # Check overall health based on critical services
    is_healthy = all([
        connection_status.get("postgresql", False),
        connection_status.get("redis", False)
    ])
    
    return {
        "status": "healthy" if is_healthy else "unhealthy",
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "timestamp": datetime.utcnow().isoformat(),
        "services": connection_status
    }


# Prometheus metrics endpoint
@app.get("/metrics", tags=["Monitoring"])
async def metrics():
    """
    Prometheus metrics endpoint.
    """
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


# Custom OpenAPI endpoint that adds security requirements
@app.get("/openapi.json", include_in_schema=False)
async def get_open_api_endpoint():
    """Custom OpenAPI schema with security requirements."""
    return get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )


# Swagger UI with custom settings
@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html(req: Request):
    """Custom Swagger UI."""
    return get_swagger_ui_html(
        openapi_url="/openapi.json",
        title=app.title + " - API Documentation",
        swagger_js_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js",
        swagger_css_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css",
        swagger_favicon_url="/static/favicon.ico",
    )


# Redirect root to docs
@app.get("/", include_in_schema=False)
async def redirect_to_docs():
    """Redirect root path to API documentation."""
    return JSONResponse(
        content={
            "name": "MCP Security Guardian API",
            "version": settings.VERSION,
            "documentation": "/docs",
            "health": "/health"
        }
    )


# Global exception handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Handle HTTP exceptions with consistent format."""
    log = get_request_logger()
    log.warning(
        f"HTTP error: {exc.detail}",
        extra={
            "http": {
                "method": request.method,
                "url": str(request.url),
                "status_code": exc.status_code,
                "request_id": request_id_var.get(),
            },
            "error": {
                "type": "HTTPException",
                "message": exc.detail,
            },
        },
    )
    
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            error=True,
            code=exc.status_code,
            message=exc.detail,
            request_id=request_id_var.get()
        ).dict(),
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle all other exceptions with consistent format."""
    log = get_request_logger()
    log.exception(
        f"Unhandled exception: {str(exc)}",
        extra={
            "http": {
                "method": request.method,
                "url": str(request.url),
                "request_id": request_id_var.get(),
            },
            "error": {
                "type": type(exc).__name__,
                "message": str(exc),
            },
        },
    )
    
    # In production, don't return the exception details to the client
    # Instead, return a generic error message and log the details
    if settings.ENVIRONMENT == "production":
        error_message = "An internal server error occurred"
    else:
        error_message = f"{type(exc).__name__}: {str(exc)}"
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=ErrorResponse(
            error=True,
            code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            message=error_message,
            request_id=request_id_var.get()
        ).dict(),
    )


# Run the application directly if this file is executed
if __name__ == "__main__":
    uvicorn.run(
        "api.main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        log_level=settings.LOG_LEVEL.lower(),
        workers=settings.API_WORKERS,
        reload=settings.DEBUG,
        timeout_keep_alive=settings.API_TIMEOUT,
        access_log=True,
    ) 
"""
Request context utilities for MCP Security Guardian.

This module provides utilities for maintaining request context across asynchronous
operations, such as tracking request IDs throughout the request processing lifecycle.
"""
import uuid
import contextvars
from typing import Optional

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

# Create a context variable for storing request IDs
request_id_contextvar = contextvars.ContextVar("request_id", default=None)


class RequestIdMiddleware(BaseHTTPMiddleware):
    """
    Middleware for extracting request IDs from headers or generating new ones.
    
    This middleware:
    1. Extracts the request ID from the X-Request-ID header if present
    2. Generates a new request ID if not present
    3. Sets the request ID in a context variable for access throughout the request lifecycle
    4. Adds the request ID to the response headers
    """
    
    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        """
        Process the request and set the request ID context.
        
        Args:
            request: The incoming request
            call_next: The next middleware or endpoint handler
            
        Returns:
            The response from the next middleware or endpoint
        """
        # Get or generate request ID
        request_id = request.headers.get("X-Request-ID")
        if not request_id:
            request_id = str(uuid.uuid4())
        
        # Set request ID in context
        token = request_id_contextvar.set(request_id)
        
        try:
            # Process the request
            response = await call_next(request)
            
            # Add request ID to response headers
            response.headers["X-Request-ID"] = request_id
            
            return response
        finally:
            # Reset the context variable
            request_id_contextvar.reset(token)


def get_request_id() -> Optional[str]:
    """
    Get the current request ID from the context.
    
    Returns:
        The current request ID, or None if not set
    """
    return request_id_contextvar.get() 
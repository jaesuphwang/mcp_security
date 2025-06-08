"""
Error handling decorators and utilities for MCP Security Guardian.
"""
import functools
import logging
import traceback
from typing import Any, Callable, TypeVar, Union
from fastapi import HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import ValidationError

logger = logging.getLogger(__name__)

F = TypeVar('F', bound=Callable[..., Any])


def handle_api_errors(func: F) -> F:
    """
    Decorator to handle common API errors and convert them to appropriate HTTP responses.
    
    Handles:
    - Pydantic validation errors
    - HTTP exceptions
    - Generic exceptions
    """
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except ValidationError as e:
            # Log validation error
            logger.warning(
                f"Validation error in {func.__name__}: {str(e)}",
                extra={
                    "errors": e.errors(),
                    "function": func.__name__
                }
            )
            # Return 422 with detailed validation errors
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "message": "Validation error",
                    "errors": e.errors()
                }
            )
        except HTTPException:
            # Re-raise HTTP exceptions as-is
            raise
        except ValueError as e:
            # Log value error
            logger.error(
                f"Value error in {func.__name__}: {str(e)}",
                extra={"function": func.__name__}
            )
            # Return 400 for value errors
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e)
            )
        except Exception as e:
            # Log unexpected error with traceback
            logger.error(
                f"Unexpected error in {func.__name__}: {str(e)}",
                extra={
                    "function": func.__name__,
                    "traceback": traceback.format_exc()
                },
                exc_info=True
            )
            # Return 500 for unexpected errors
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An unexpected error occurred"
            )
    
    return wrapper


def handle_security_errors(func: F) -> F:
    """
    Decorator specifically for security-related endpoints.
    
    Provides additional logging and sanitization for security errors.
    """
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except ValidationError as e:
            # Log potential security validation issues
            logger.warning(
                f"Security validation error in {func.__name__}",
                extra={
                    "function": func.__name__,
                    "error_count": len(e.errors())
                }
            )
            # Return sanitized error (don't expose internal details)
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Invalid request format"
            )
        except HTTPException as e:
            # Log security-related HTTP exceptions
            if e.status_code in [401, 403]:
                logger.warning(
                    f"Authentication/Authorization error in {func.__name__}",
                    extra={
                        "function": func.__name__,
                        "status_code": e.status_code
                    }
                )
            raise
        except Exception as e:
            # Log security error without exposing details
            logger.error(
                f"Security error in {func.__name__}",
                extra={
                    "function": func.__name__,
                    "error_type": type(e).__name__
                },
                exc_info=True
            )
            # Return generic error for security endpoints
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Security operation failed"
            )
    
    return wrapper


def rate_limit_error_handler(func: F) -> F:
    """
    Decorator to handle rate limiting errors gracefully.
    """
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except HTTPException as e:
            if e.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
                # Add retry-after header if not present
                headers = getattr(e, 'headers', {})
                if 'Retry-After' not in headers:
                    headers['Retry-After'] = '60'  # Default to 60 seconds
                e.headers = headers
            raise
        except Exception as e:
            logger.error(f"Error in rate limit handler: {str(e)}", exc_info=True)
            raise
    
    return wrapper


class ErrorContext:
    """Context manager for error handling with additional context."""
    
    def __init__(self, operation: str, **context):
        self.operation = operation
        self.context = context
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            logger.error(
                f"Error during {self.operation}: {str(exc_val)}",
                extra={
                    "operation": self.operation,
                    "context": self.context,
                    "error_type": exc_type.__name__
                },
                exc_info=True
            )
        return False  # Don't suppress the exception


def log_and_raise(
    error: Exception,
    status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
    detail: str = None,
    **log_extra
):
    """
    Log an error and raise an HTTP exception.
    
    Args:
        error: The original exception
        status_code: HTTP status code to return
        detail: Error detail message (defaults to str(error))
        **log_extra: Additional context to log
    """
    logger.error(
        f"Error occurred: {str(error)}",
        extra={
            "error_type": type(error).__name__,
            **log_extra
        },
        exc_info=True
    )
    
    raise HTTPException(
        status_code=status_code,
        detail=detail or str(error)
    )


# Export all decorators and utilities
__all__ = [
    'handle_api_errors',
    'handle_security_errors',
    'rate_limit_error_handler',
    'ErrorContext',
    'log_and_raise'
]
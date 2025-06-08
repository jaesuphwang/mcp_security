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
Enhanced logging configuration with structured logging, correlation IDs, and security features.
"""
import logging
import json
import sys
import os
from typing import Any, Dict, Optional
from datetime import datetime
from contextvars import ContextVar
import traceback
from pythonjsonlogger import jsonlogger
import asyncio
from functools import wraps

# Context variables for request tracking
request_id_context: ContextVar[Optional[str]] = ContextVar('request_id', default=None)
user_id_context: ContextVar[Optional[str]] = ContextVar('user_id', default=None)
organization_id_context: ContextVar[Optional[str]] = ContextVar('organization_id', default=None)


class SecurityFilter(logging.Filter):
    """Filter to redact sensitive information from logs."""
    
    SENSITIVE_FIELDS = {
        'password', 'secret', 'token', 'api_key', 'authorization',
        'credit_card', 'ssn', 'private_key', 'access_token',
        'refresh_token', 'jwt', 'session_id', 'cookie'
    }
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Redact sensitive information from log records."""
        # Redact from message
        if hasattr(record, 'msg'):
            record.msg = self._redact_message(str(record.msg))
        
        # Redact from args
        if hasattr(record, 'args') and record.args:
            record.args = tuple(self._redact_value(arg) for arg in record.args)
        
        # Redact from extra fields
        for field in dir(record):
            if field.startswith('_') or field in logging.LogRecord.__dict__:
                continue
            
            value = getattr(record, field)
            if isinstance(value, (dict, list, str)):
                setattr(record, field, self._redact_value(value))
        
        return True
    
    def _redact_message(self, message: str) -> str:
        """Redact sensitive patterns from message string."""
        import re
        
        # Redact common patterns
        patterns = [
            (r'(?i)(password|secret|token|api_key)\s*[=:]\s*["\']?([^"\'\s]+)', r'\1=***REDACTED***'),
            (r'(?i)authorization:\s*bearer\s+(\S+)', 'Authorization: Bearer ***REDACTED***'),
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '***EMAIL***'),
            (r'\b(?:\d{4}[-\s]?){3}\d{4}\b', '***CARD***'),  # Credit card pattern
        ]
        
        for pattern, replacement in patterns:
            message = re.sub(pattern, replacement, message)
        
        return message
    
    def _redact_value(self, value: Any) -> Any:
        """Recursively redact sensitive values."""
        if isinstance(value, dict):
            return {
                k: '***REDACTED***' if any(s in k.lower() for s in self.SENSITIVE_FIELDS) else self._redact_value(v)
                for k, v in value.items()
            }
        elif isinstance(value, list):
            return [self._redact_value(item) for item in value]
        elif isinstance(value, str):
            return self._redact_message(value)
        else:
            return value


class ContextualFormatter(jsonlogger.JsonFormatter):
    """Custom JSON formatter that includes context variables."""
    
    def add_fields(self, log_record: Dict[str, Any], record: logging.LogRecord, message_dict: Dict[str, Any]):
        """Add custom fields to log record."""
        super().add_fields(log_record, record, message_dict)
        
        # Add timestamp
        log_record['timestamp'] = datetime.utcnow().isoformat()
        
        # Add context variables
        log_record['request_id'] = request_id_context.get()
        log_record['user_id'] = user_id_context.get()
        log_record['organization_id'] = organization_id_context.get()
        
        # Add application metadata
        log_record['service'] = 'mcp-security-guardian'
        log_record['environment'] = os.getenv('ENVIRONMENT', 'development')
        log_record['instance_id'] = os.getenv('INSTANCE_ID', 'unknown')
        
        # Add error details if exception
        if record.exc_info:
            log_record['exception'] = {
                'type': record.exc_info[0].__name__,
                'message': str(record.exc_info[1]),
                'traceback': traceback.format_exception(*record.exc_info)
            }
        
        # Remove internal fields
        for field in ['msg', 'args', 'created', 'msecs', 'relativeCreated', 'exc_info', 'exc_text']:
            log_record.pop(field, None)


class AsyncHandler(logging.Handler):
    """Async log handler for non-blocking logging."""
    
    def __init__(self, handler: logging.Handler):
        super().__init__()
        self.handler = handler
        self.queue = asyncio.Queue(maxsize=10000)
        self._task = None
        self._running = False
    
    def emit(self, record: logging.LogRecord):
        """Queue log record for async processing."""
        try:
            self.queue.put_nowait(record)
            if not self._running:
                self._start_worker()
        except asyncio.QueueFull:
            # If queue is full, fall back to sync logging
            self.handler.emit(record)
    
    def _start_worker(self):
        """Start the async worker task."""
        if self._task is None or self._task.done():
            self._running = True
            self._task = asyncio.create_task(self._worker())
    
    async def _worker(self):
        """Process queued log records."""
        while self._running or not self.queue.empty():
            try:
                record = await asyncio.wait_for(self.queue.get(), timeout=1.0)
                self.handler.emit(record)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                # Log to stderr if handler fails
                print(f"Logging error: {e}", file=sys.stderr)
    
    def close(self):
        """Close the handler and wait for queue to empty."""
        self._running = False
        if self._task:
            asyncio.create_task(self._task)
        self.handler.close()
        super().close()


def setup_logging(
    log_level: str = "INFO",
    log_format: str = "json",
    log_file: Optional[str] = None,
    enable_async: bool = True
):
    """
    Set up enhanced logging configuration.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_format: Log format ('json' or 'text')
        log_file: Optional log file path
        enable_async: Enable async logging
    """
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper()))
    
    # Remove existing handlers
    root_logger.handlers.clear()
    
    # Create security filter
    security_filter = SecurityFilter()
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.addFilter(security_filter)
    
    if log_format == "json":
        formatter = ContextualFormatter(
            '%(timestamp)s %(level)s %(name)s %(message)s',
            json_ensure_ascii=False
        )
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - [%(request_id)s] - %(message)s'
        )
    
    console_handler.setFormatter(formatter)
    
    # Add async wrapper if enabled
    if enable_async:
        console_handler = AsyncHandler(console_handler)
    
    root_logger.addHandler(console_handler)
    
    # File handler if specified
    if log_file:
        from logging.handlers import RotatingFileHandler
        
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=100 * 1024 * 1024,  # 100MB
            backupCount=10
        )
        file_handler.addFilter(security_filter)
        file_handler.setFormatter(formatter)
        
        if enable_async:
            file_handler = AsyncHandler(file_handler)
        
        root_logger.addHandler(file_handler)
    
    # Configure third-party loggers
    logging.getLogger('uvicorn').setLevel(logging.WARNING)
    logging.getLogger('fastapi').setLevel(logging.INFO)
    logging.getLogger('sqlalchemy.engine').setLevel(logging.WARNING)
    logging.getLogger('aioredis').setLevel(logging.WARNING)
    
    # Disable noisy loggers
    logging.getLogger('asyncio').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    
    logger = logging.getLogger(__name__)
    logger.info(
        "Logging configured",
        extra={
            "log_level": log_level,
            "log_format": log_format,
            "log_file": log_file,
            "async_enabled": enable_async
        }
    )


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance with the given name.
    
    Args:
        name: Logger name (usually __name__)
        
    Returns:
        Logger instance
    """
    return logging.getLogger(name)


def log_execution_time(func):
    """Decorator to log function execution time."""
    @wraps(func)
    async def async_wrapper(*args, **kwargs):
        logger = get_logger(func.__module__)
        start_time = asyncio.get_event_loop().time()
        
        try:
            result = await func(*args, **kwargs)
            execution_time = asyncio.get_event_loop().time() - start_time
            
            logger.debug(
                f"Function {func.__name__} completed",
                extra={
                    "function": func.__name__,
                    "execution_time_ms": round(execution_time * 1000, 2)
                }
            )
            
            return result
        except Exception as e:
            execution_time = asyncio.get_event_loop().time() - start_time
            
            logger.error(
                f"Function {func.__name__} failed",
                extra={
                    "function": func.__name__,
                    "execution_time_ms": round(execution_time * 1000, 2),
                    "error": str(e)
                }
            )
            raise
    
    @wraps(func)
    def sync_wrapper(*args, **kwargs):
        logger = get_logger(func.__module__)
        import time
        start_time = time.time()
        
        try:
            result = func(*args, **kwargs)
            execution_time = time.time() - start_time
            
            logger.debug(
                f"Function {func.__name__} completed",
                extra={
                    "function": func.__name__,
                    "execution_time_ms": round(execution_time * 1000, 2)
                }
            )
            
            return result
        except Exception as e:
            execution_time = time.time() - start_time
            
            logger.error(
                f"Function {func.__name__} failed",
                extra={
                    "function": func.__name__,
                    "execution_time_ms": round(execution_time * 1000, 2),
                    "error": str(e)
                }
            )
            raise
    
    if asyncio.iscoroutinefunction(func):
        return async_wrapper
    else:
        return sync_wrapper


def audit_log(
    action: str,
    entity_type: str,
    entity_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    result: str = "success"
):
    """
    Create an audit log entry.
    
    Args:
        action: Action performed (e.g., 'create', 'update', 'delete', 'access')
        entity_type: Type of entity (e.g., 'user', 'token', 'alert')
        entity_id: ID of the entity
        details: Additional details
        result: Result of the action ('success' or 'failure')
    """
    audit_logger = get_logger('audit')
    
    audit_logger.info(
        f"Audit: {action} {entity_type}",
        extra={
            "audit": True,
            "action": action,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "details": details or {},
            "result": result,
            "timestamp": datetime.utcnow().isoformat()
        }
    )


class LogContext:
    """Context manager for adding contextual information to logs."""
    
    def __init__(self, **kwargs):
        self.context = kwargs
        self.tokens = []
    
    def __enter__(self):
        for key, value in self.context.items():
            if key == 'request_id':
                self.tokens.append(request_id_context.set(value))
            elif key == 'user_id':
                self.tokens.append(user_id_context.set(value))
            elif key == 'organization_id':
                self.tokens.append(organization_id_context.set(value))
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        for token in self.tokens:
            request_id_context.reset(token)
"""
Logging configuration for the MCP Security Guardian Tool.

This module provides a comprehensive logging configuration for production deployments,
including structured JSON logging, log rotation, and performance optimization.
"""
import logging
import logging.config
import os
import sys
import time
from datetime import datetime
from functools import lru_cache
from typing import Dict, Any, Optional

# JSON logging packages - install if needed:
# pip install python-json-logger json-log-formatter
try:
    import json_log_formatter
    from pythonjsonlogger import jsonlogger
    JSON_LOGGING_AVAILABLE = True
except ImportError:
    JSON_LOGGING_AVAILABLE = False

from core.config import get_settings

# Custom JSON formatter with extra fields
if JSON_LOGGING_AVAILABLE:
    class CustomJsonFormatter(jsonlogger.JsonFormatter):
        """
        Custom JSON formatter that adds additional fields to log records.
        """
        def add_fields(self, log_record: Dict[str, Any], record: logging.LogRecord, message_dict: Dict[str, Any]) -> None:
        """
        Add standard fields to the log record.
        """
        super().add_fields(log_record, record, message_dict)
        
        # Add timestamp with timezone
        log_record['timestamp'] = datetime.utcnow().isoformat() + 'Z'
        log_record['level'] = record.levelname
        log_record['logger'] = record.name
        
        # Add environment and instance information
        settings = get_settings()
        log_record['environment'] = settings.ENVIRONMENT
        log_record['instance_id'] = settings.INSTANCE_ID
        
        # Add process and thread information
        log_record['process'] = record.process
        log_record['process_name'] = record.processName
        log_record['thread'] = record.thread
        log_record['thread_name'] = record.threadName
        
        # Add stack trace for errors and exceptions
        if record.exc_info:
            log_record['exception'] = self.formatException(record.exc_info)
        
        # Add custom fields from kwargs
        for key, value in message_dict.items():
            if key not in log_record:
                log_record[key] = value
else:
    # Fallback when JSON logging is not available
    class CustomJsonFormatter:
        pass


class RequestIdAdapter(logging.LoggerAdapter):
    """
    Adapter to add request_id to all log messages.
    """
    def process(self, msg: str, kwargs: Dict[str, Any]) -> tuple:
        """
        Process the log message to add request_id.
        """
        request_id = self.extra.get('request_id')
        trace_id = self.extra.get('trace_id')
        
        # Add extra fields
        extra = kwargs.get('extra', {})
        if request_id:
            extra['request_id'] = request_id
        if trace_id:
            extra['trace_id'] = trace_id
        
        # Update kwargs
        kwargs['extra'] = extra
        
        return msg, kwargs


class SecurityEventAdapter(RequestIdAdapter):
    """
    Adapter to add security event information to log messages.
    """
    def process(self, msg: str, kwargs: Dict[str, Any]) -> tuple:
        """
        Process the log message to add security event information.
        """
        # Add standard request fields
        msg, kwargs = super().process(msg, kwargs)
        
        # Add security event fields
        extra = kwargs.get('extra', {})
        extra['security_event'] = True
        extra['security_category'] = self.extra.get('security_category', 'general')
        extra['event_severity'] = self.extra.get('event_severity', 'info')
        
        # Update kwargs
        kwargs['extra'] = extra
        
        return msg, kwargs


@lru_cache(maxsize=1)
def get_logging_config(
    log_level: str = None,
    log_format: str = None,
    log_dir: str = None,
    environment: str = None
) -> Dict[str, Any]:
    """
    Get logging configuration.
    
    Args:
        log_level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_format: Log format (json or text)
        log_dir: Directory to store log files
        environment: Environment (development, production, testing)
        
    Returns:
        Logging configuration dictionary.
    """
    # Get settings
    settings = get_settings()
    
    # Use provided values or defaults from settings
    log_level = log_level or settings.LOG_LEVEL or "INFO"
    log_format = log_format or settings.LOG_FORMAT or "json"
    log_dir = log_dir or settings.LOG_DIR or "logs"
    environment = environment or settings.ENVIRONMENT or "development"
    
    # Create log directory if it doesn't exist
    os.makedirs(log_dir, exist_ok=True)
    
    # Determine formatters based on log format
    if log_format.lower() == "json" and JSON_LOGGING_AVAILABLE:
        formatter_class = "core.logging_config.CustomJsonFormatter"
        formatter_format = "%(timestamp)s %(level)s %(logger)s %(message)s"
    else:
        formatter_class = "logging.Formatter"
        formatter_format = "%(asctime)s - %(levelname)s - [%(name)s] - %(message)s"
        if log_format.lower() == "json" and not JSON_LOGGING_AVAILABLE:
            import warnings
            warnings.warn("JSON logging requested but packages not available. Using text format.")
    
    # Determine log file paths
    general_log_path = os.path.join(log_dir, "mcp_security.log")
    error_log_path = os.path.join(log_dir, "mcp_security_error.log")
    security_log_path = os.path.join(log_dir, "mcp_security_security.log")
    
    # Determine rotation settings based on environment
    if environment.lower() == "production":
        rotation_class = "logging.handlers.TimedRotatingFileHandler"
        rotation_params = {
            "when": "midnight",
            "interval": 1,
            "backupCount": 30
        }
    else:
        rotation_class = "logging.handlers.RotatingFileHandler"
        rotation_params = {
            "maxBytes": 10485760,  # 10 MB
            "backupCount": 5
        }
    
    # Build logging config
    logging_config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "standard": {
                "()": formatter_class,
                "format": formatter_format
            },
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "level": log_level,
                "formatter": "standard",
                "stream": "ext://sys.stdout"
            },
            "file": {
                "class": rotation_class,
                "level": log_level,
                "formatter": "standard",
                "filename": general_log_path,
                **rotation_params
            },
            "error_file": {
                "class": rotation_class,
                "level": "ERROR",
                "formatter": "standard",
                "filename": error_log_path,
                **rotation_params
            },
            "security_file": {
                "class": rotation_class,
                "level": log_level,
                "formatter": "standard",
                "filename": security_log_path,
                **rotation_params
            }
        },
        "loggers": {
            "": {
                "handlers": ["console", "file", "error_file"],
                "level": log_level,
                "propagate": False
            },
            "mcp_security": {
                "handlers": ["console", "file", "error_file"],
                "level": log_level,
                "propagate": False
            },
            "mcp_security.security": {
                "handlers": ["console", "security_file", "error_file"],
                "level": log_level,
                "propagate": False
            },
            "mcp_security.api": {
                "handlers": ["console", "file", "error_file"],
                "level": log_level,
                "propagate": False
            },
            "uvicorn": {
                "handlers": ["console", "file"],
                "level": log_level,
                "propagate": False
            },
            "uvicorn.access": {
                "handlers": ["console", "file"],
                "level": log_level,
                "propagate": False
            },
            "uvicorn.error": {
                "handlers": ["console", "error_file"],
                "level": "ERROR",
                "propagate": False
            }
        }
    }
    
    return logging_config


def setup_logging() -> None:
    """
    Set up logging configuration.
    """
    logging_config = get_logging_config()
    logging.config.dictConfig(logging_config)


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger with the specified name.
    
    Args:
        name: Logger name
        
    Returns:
        Logger object.
    """
    return logging.getLogger(name)


def get_request_logger(
    name: str,
    request_id: Optional[str] = None,
    trace_id: Optional[str] = None
) -> logging.LoggerAdapter:
    """
    Get a logger adapter with request ID.
    
    Args:
        name: Logger name
        request_id: Request ID
        trace_id: Trace ID
        
    Returns:
        Logger adapter with request ID.
    """
    logger = logging.getLogger(name)
    extra = {}
    if request_id:
        extra['request_id'] = request_id
    if trace_id:
        extra['trace_id'] = trace_id
    
    return RequestIdAdapter(logger, extra)


def get_security_logger(
    name: str,
    request_id: Optional[str] = None,
    trace_id: Optional[str] = None,
    security_category: str = "general",
    event_severity: str = "info"
) -> logging.LoggerAdapter:
    """
    Get a logger adapter for security events.
    
    Args:
        name: Logger name
        request_id: Request ID
        trace_id: Trace ID
        security_category: Security category (e.g., "threat", "vulnerability", "token")
        event_severity: Event severity (e.g., "critical", "high", "medium", "low", "info")
        
    Returns:
        Logger adapter for security events.
    """
    logger = logging.getLogger(f"mcp_security.security.{name}")
    extra = {
        'security_category': security_category,
        'event_severity': event_severity
    }
    if request_id:
        extra['request_id'] = request_id
    if trace_id:
        extra['trace_id'] = trace_id
    
    return SecurityEventAdapter(logger, extra) 
"""
Logging utilities for MCP Security Guardian Tool.
"""
import logging
import sys
import os
from typing import Any, Dict, Optional

from core.config.settings import settings


def configure_logging() -> None:
    """
    Configure the global logging settings.
    
    This sets up the root logger with the appropriate log level,
    formatter, and handlers based on the application settings.
    """
    # Get root logger
    root_logger = logging.getLogger()
    
    # Clear existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Set log level from settings
    root_logger.setLevel(getattr(logging, settings.LOG_LEVEL))
    
    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    
    # Create formatter
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    console_handler.setFormatter(formatter)
    
    # Add handler to root logger
    root_logger.addHandler(console_handler)
    
    # Add file handler if log file is specified
    if settings.LOG_FILE:
        # Create directory if it doesn't exist
        log_dir = os.path.dirname(settings.LOG_FILE)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        # Create file handler
        file_handler = logging.FileHandler(settings.LOG_FILE)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)


def get_logger(name: str, level: Optional[str] = None) -> logging.Logger:
    """
    Get a configured logger instance.

    Args:
        name: Logger name.
        level: Log level (overrides settings.LOG_LEVEL if provided).

    Returns:
        Configured logger instance.
    """
    logger = logging.getLogger(name)
    
    # Set log level from settings or parameter
    log_level = level or settings.LOG_LEVEL
    logger.setLevel(getattr(logging, log_level))
    
    # Create handler if not already configured
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        
        # Create formatter
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        handler.setFormatter(formatter)
        
        # Add handler to logger
        logger.addHandler(handler)
    
    return logger


# Create default logger
logger = get_logger("mcp_guardian")


def log_event(
    event_type: str, 
    message: str, 
    level: str = "INFO", 
    details: Optional[Dict[str, Any]] = None
) -> None:
    """
    Log an event with structured data.

    Args:
        event_type: Type of event (e.g., "security", "system", "user").
        message: Event message.
        level: Log level (default: "INFO").
        details: Additional event details.
    """
    log_method = getattr(logger, level.lower())
    
    # Create structured log message
    log_data = {
        "event_type": event_type,
        "message": message,
    }
    
    if details:
        log_data["details"] = details
    
    log_method(log_data) 
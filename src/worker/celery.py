"""
Celery worker configuration for the MCP Security Guardian Tool.

This module configures Celery for background task processing, including
task routing, error handling, and monitoring.
"""
import os
import sys
from datetime import timedelta
from typing import Dict, Any

from celery import Celery, Task, signals
from celery.schedules import crontab
import logging

from core.config import get_settings
from core.logging_config import setup_logging, get_logger

# Initialize logging
setup_logging()
logger = get_logger("mcp_security.worker")

# Get settings
settings = get_settings()

# Create Celery app
app = Celery(
    "mcp_security",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=[
        "worker.tasks.threat_intelligence",
        "worker.tasks.vulnerability_scanning",
        "worker.tasks.token_revocation",
        "worker.tasks.alert_distribution",
        "worker.tasks.maintenance"
    ]
)

# Configure Celery app
app.conf.update(
    # Main settings
    worker_concurrency=settings.CELERY_WORKER_CONCURRENCY or 4,
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    worker_max_tasks_per_child=1000,
    worker_prefetch_multiplier=1,
    
    # Task execution settings
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    task_track_started=True,
    task_time_limit=3600,  # 1 hour
    task_soft_time_limit=1800,  # 30 minutes
    
    # Results settings
    result_expires=86400 * 7,  # 7 days
    
    # Error handling
    task_default_rate_limit="100/m",
    broker_connection_retry=True,
    broker_connection_retry_on_startup=True,
    broker_connection_max_retries=10,
    broker_connection_timeout=5,
    
    # Security settings
    security_key=settings.JWT_SECRET,
    task_default_queue="default",
    
    # Task routes for different queues
    task_routes={
        "worker.tasks.threat_intelligence.*": {"queue": "threat_intelligence"},
        "worker.tasks.vulnerability_scanning.*": {"queue": "vulnerability_scanning"},
        "worker.tasks.token_revocation.*": {"queue": "token_revocation"},
        "worker.tasks.alert_distribution.*": {"queue": "alert_distribution"},
        "worker.tasks.maintenance.*": {"queue": "maintenance"},
    },
    
    # Scheduled tasks
    beat_schedule={
        "update-threat-intelligence": {
            "task": "worker.tasks.threat_intelligence.update_threat_intelligence",
            "schedule": crontab(minute=0, hour="*/6"),  # Every 6 hours
            "args": (),
            "options": {"queue": "threat_intelligence"}
        },
        "cleanup-expired-tokens": {
            "task": "worker.tasks.token_revocation.cleanup_expired_tokens",
            "schedule": crontab(minute=30, hour="*/4"),  # Every 4 hours
            "args": (),
            "options": {"queue": "token_revocation"}
        },
        "prune-old-logs": {
            "task": "worker.tasks.maintenance.prune_old_logs",
            "schedule": crontab(minute=0, hour=2),  # Daily at 2 AM
            "args": (settings.LOG_RETENTION_DAYS or 90,),
            "options": {"queue": "maintenance"}
        },
        "archive-old-alerts": {
            "task": "worker.tasks.maintenance.archive_old_alerts",
            "schedule": crontab(minute=0, hour=3),  # Daily at 3 AM
            "args": (settings.ALERT_RETENTION_DAYS or 90,),
            "options": {"queue": "maintenance"}
        },
        "update-patterns": {
            "task": "worker.tasks.threat_intelligence.update_patterns",
            "schedule": crontab(minute=0, hour="*/12"),  # Every 12 hours
            "args": (),
            "options": {"queue": "threat_intelligence"}
        }
    }
)

# Configure task annotations for retries and backoff
class BaseTaskWithRetry(Task):
    """Base task with retry logic."""
    
    autoretry_for = (Exception,)
    retry_kwargs = {"max_retries": 5, "countdown": 5}
    retry_backoff = True
    retry_backoff_max = 600  # 10 minutes
    retry_jitter = True
    
    def on_failure(self, exc, task_id, args, kwargs, einfo):
        """Handle task failure."""
        logger.error(
            f"Task {self.name}[{task_id}] failed: {str(exc)}",
            extra={
                "task_id": task_id,
                "args": args,
                "kwargs": kwargs,
                "exception": str(exc),
                "traceback": einfo.traceback
            },
            exc_info=True
        )
        super().on_failure(exc, task_id, args, kwargs, einfo)


# Annotations applied to all tasks
app.Task = BaseTaskWithRetry


# Configure logging for Celery tasks
@signals.setup_logging.connect
def setup_celery_logging(**kwargs):
    """Set up Celery logging."""
    setup_logging()


# Task for processing signals
@signals.task_received.connect
def task_received_handler(request, **kwargs):
    """Log when a task is received."""
    logger.debug(
        f"Task received: {request.name}[{request.id}]",
        extra={"task_id": request.id, "task_name": request.name}
    )


@signals.task_success.connect
def task_success_handler(sender, result, **kwargs):
    """Log when a task succeeds."""
    logger.info(
        f"Task succeeded: {sender.name}[{sender.request.id}]",
        extra={"task_id": sender.request.id, "task_name": sender.name}
    )


@signals.task_failure.connect
def task_failure_handler(sender, task_id, exception, traceback, **kwargs):
    """Log when a task fails."""
    logger.error(
        f"Task failed: {sender.name}[{task_id}] - {str(exception)}",
        extra={
            "task_id": task_id,
            "task_name": sender.name,
            "exception": str(exception),
            "traceback": traceback
        }
    )


@signals.worker_ready.connect
def worker_ready_handler(sender, **kwargs):
    """Log when a worker is ready."""
    logger.info(f"Worker ready: {sender.hostname}")


@signals.worker_shutdown.connect
def worker_shutdown_handler(sender, **kwargs):
    """Log when a worker is shutting down."""
    logger.info(f"Worker shutting down: {sender.hostname}")


if __name__ == "__main__":
    app.start() 
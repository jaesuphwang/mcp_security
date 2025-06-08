"""
Maintenance tasks for the MCP Security Guardian Tool.

This module contains Celery tasks for database maintenance, log rotation,
and other system housekeeping activities.
"""
import os
import time
import glob
import shutil
from datetime import datetime, timedelta
import logging
from pathlib import Path
import zipfile

from worker.celery import app
from core.logging_config import get_logger
from core.config import get_settings
from core.database import get_db, get_mongodb, get_redis, get_neo4j_session

# Initialize logger
logger = get_logger("mcp_security.worker.maintenance")


@app.task(name="worker.tasks.maintenance.prune_old_logs")
def prune_old_logs(retention_days=90):
    """
    Remove log files older than the specified retention period.
    
    Args:
        retention_days: Number of days to keep logs (default: 90)
    
    Returns:
        Dictionary with task results.
    """
    settings = get_settings()
    log_dir = settings.LOG_DIR or "logs"
    log_archive_dir = os.path.join(log_dir, "archives")
    
    # Create archive directory if it doesn't exist
    os.makedirs(log_archive_dir, exist_ok=True)
    
    # Get current timestamp
    now = datetime.utcnow()
    cutoff_date = now - timedelta(days=retention_days)
    
    # Format cutoff date for logging
    cutoff_date_str = cutoff_date.strftime("%Y-%m-%d")
    logger.info(
        f"Pruning logs older than {cutoff_date_str}",
        extra={"retention_days": retention_days, "cutoff_date": cutoff_date_str}
    )
    
    # Track statistics
    stats = {
        "archived_files": 0,
        "deleted_files": 0,
        "archived_bytes": 0,
        "deleted_bytes": 0,
        "errors": 0
    }
    
    try:
        # Get all log files
        log_files = glob.glob(os.path.join(log_dir, "*.log*"))
        
        # Process each log file
        for log_file in log_files:
            file_path = Path(log_file)
            
            # Skip directories and archive directory
            if file_path.is_dir() or str(file_path).startswith(log_archive_dir):
                continue
            
            # Get file modification time
            file_mtime = datetime.fromtimestamp(file_path.stat().st_mtime)
            
            # If file is older than cutoff date
            if file_mtime < cutoff_date:
                file_size = file_path.stat().st_size
                
                try:
                    # Determine if this is a rotated log file (has date extension)
                    is_rotated = any(ext in file_path.name for ext in [".gz", ".1", ".2", ".old"])
                    
                    if is_rotated:
                        # Delete rotated log files
                        file_path.unlink()
                        stats["deleted_files"] += 1
                        stats["deleted_bytes"] += file_size
                        logger.debug(f"Deleted old log file: {file_path}")
                    else:
                        # Archive main log files
                        archive_name = f"{file_path.stem}_{file_mtime.strftime('%Y%m%d')}.zip"
                        archive_path = os.path.join(log_archive_dir, archive_name)
                        
                        # Create zip archive
                        with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                            zipf.write(file_path, arcname=file_path.name)
                        
                        # Verify archive was created
                        if os.path.exists(archive_path):
                            # Clear the original log file but keep it
                            with open(file_path, 'w') as f:
                                f.write(f"# Log archived to {archive_name} on {now.isoformat()}\n")
                            
                            stats["archived_files"] += 1
                            stats["archived_bytes"] += file_size
                            logger.debug(f"Archived log file to {archive_path}")
                        else:
                            logger.error(f"Failed to create archive for {file_path}")
                            stats["errors"] += 1
                
                except Exception as e:
                    logger.error(f"Error processing log file {file_path}: {str(e)}", exc_info=True)
                    stats["errors"] += 1
        
        # Delete old archives (keep only last 6 months of archives)
        archive_retention_days = 180
        archive_cutoff_date = now - timedelta(days=archive_retention_days)
        archive_files = glob.glob(os.path.join(log_archive_dir, "*.zip"))
        
        for archive_file in archive_files:
            archive_path = Path(archive_file)
            archive_mtime = datetime.fromtimestamp(archive_path.stat().st_mtime)
            
            if archive_mtime < archive_cutoff_date:
                try:
                    archive_size = archive_path.stat().st_size
                    archive_path.unlink()
                    stats["deleted_files"] += 1
                    stats["deleted_bytes"] += archive_size
                    logger.debug(f"Deleted old archive: {archive_path}")
                except Exception as e:
                    logger.error(f"Error deleting archive {archive_path}: {str(e)}", exc_info=True)
                    stats["errors"] += 1
        
        # Log results
        logger.info(
            f"Log pruning completed: Archived {stats['archived_files']} files, "
            f"deleted {stats['deleted_files']} files",
            extra={
                "archived_files": stats["archived_files"],
                "deleted_files": stats["deleted_files"],
                "archived_bytes": stats["archived_bytes"],
                "deleted_bytes": stats["deleted_bytes"],
                "errors": stats["errors"]
            }
        )
        
        return {
            "success": True,
            "message": "Log pruning completed successfully",
            "stats": stats
        }
        
    except Exception as e:
        logger.error(f"Error pruning logs: {str(e)}", exc_info=True)
        return {
            "success": False,
            "message": f"Error pruning logs: {str(e)}",
            "stats": stats
        }


@app.task(name="worker.tasks.maintenance.archive_old_alerts")
def archive_old_alerts(retention_days=90):
    """
    Archive alerts older than the specified retention period.
    
    Args:
        retention_days: Number of days to keep alerts (default: 90)
    
    Returns:
        Dictionary with task results.
    """
    # Get settings
    settings = get_settings()
    
    # Get current timestamp
    now = datetime.utcnow()
    cutoff_date = now - timedelta(days=retention_days)
    
    # Track statistics
    stats = {
        "archived_alerts": 0,
        "deleted_alerts": 0,
        "errors": 0
    }
    
    try:
        # Connect to MongoDB for alerts
        mongodb = get_mongodb()
        db = mongodb.get_database()
        
        # Archive alerts
        alerts_collection = db.security_alerts
        archived_alerts_collection = db.archived_security_alerts
        
        # Ensure indexes on archived collection
        archived_alerts_collection.create_index("alert_id", unique=True)
        archived_alerts_collection.create_index("created_at")
        archived_alerts_collection.create_index("status")
        
        # Find alerts older than cutoff date
        old_alerts_cursor = alerts_collection.find({
            "created_at": {"$lt": cutoff_date}
        })
        
        # Process each alert
        for alert in old_alerts_cursor:
            try:
                # Copy alert to archive collection
                result = archived_alerts_collection.insert_one(alert)
                
                if result.inserted_id:
                    # Delete from main collection
                    delete_result = alerts_collection.delete_one({"_id": alert["_id"]})
                    
                    if delete_result.deleted_count > 0:
                        stats["archived_alerts"] += 1
                    else:
                        logger.warning(
                            f"Failed to delete alert after archiving: {alert['_id']}",
                            extra={"alert_id": str(alert.get("alert_id"))}
                        )
                        stats["errors"] += 1
                else:
                    logger.warning(
                        f"Failed to archive alert: {alert['_id']}",
                        extra={"alert_id": str(alert.get("alert_id"))}
                    )
                    stats["errors"] += 1
                    
            except Exception as e:
                logger.error(
                    f"Error archiving alert {alert.get('alert_id')}: {str(e)}",
                    extra={"alert_id": str(alert.get("alert_id"))},
                    exc_info=True
                )
                stats["errors"] += 1
        
        # Find alerts older than cutoff date * 3 in archive
        very_old_cutoff_date = now - timedelta(days=retention_days * 3)
        very_old_alerts_cursor = archived_alerts_collection.find({
            "created_at": {"$lt": very_old_cutoff_date}
        })
        
        # Delete very old archived alerts
        for alert in very_old_alerts_cursor:
            try:
                delete_result = archived_alerts_collection.delete_one({"_id": alert["_id"]})
                if delete_result.deleted_count > 0:
                    stats["deleted_alerts"] += 1
            except Exception as e:
                logger.error(
                    f"Error deleting archived alert {alert.get('alert_id')}: {str(e)}",
                    extra={"alert_id": str(alert.get("alert_id"))},
                    exc_info=True
                )
                stats["errors"] += 1
        
        # Log results
        logger.info(
            f"Alert archiving completed: Archived {stats['archived_alerts']} alerts, "
            f"deleted {stats['deleted_alerts']} alerts",
            extra={
                "archived_alerts": stats["archived_alerts"],
                "deleted_alerts": stats["deleted_alerts"],
                "errors": stats["errors"]
            }
        )
        
        return {
            "success": True,
            "message": "Alert archiving completed successfully",
            "stats": stats
        }
        
    except Exception as e:
        logger.error(f"Error archiving alerts: {str(e)}", exc_info=True)
        return {
            "success": False,
            "message": f"Error archiving alerts: {str(e)}",
            "stats": stats
        }


@app.task(name="worker.tasks.maintenance.vacuum_database")
def vacuum_database():
    """
    Run VACUUM on PostgreSQL database to optimize performance.
    
    Returns:
        Dictionary with task results.
    """
    try:
        # Get database session
        db = next(get_db())
        
        # Run VACUUM ANALYZE
        db.execute("VACUUM ANALYZE")
        
        logger.info("Database vacuum completed successfully")
        return {
            "success": True,
            "message": "Database vacuum completed successfully"
        }
        
    except Exception as e:
        logger.error(f"Error running database vacuum: {str(e)}", exc_info=True)
        return {
            "success": False,
            "message": f"Error running database vacuum: {str(e)}"
        }


@app.task(name="worker.tasks.maintenance.cleanup_redis")
def cleanup_redis():
    """
    Clean up expired keys in Redis and perform maintenance.
    
    Returns:
        Dictionary with task results.
    """
    try:
        # Get Redis client
        redis_client = get_redis()
        
        # Track statistics
        stats = {
            "expired_keys": 0,
            "errors": 0
        }
        
        # Clean up rate limit keys (older than 1 day)
        pattern = "rate:*"
        keys = redis_client.keys(pattern)
        
        for key in keys:
            try:
                # Get TTL
                ttl = redis_client.ttl(key)
                
                # If TTL is -1 (no expiration) or very long, set to 1 day
                if ttl == -1 or ttl > 86400:
                    redis_client.expire(key, 86400)
                    stats["expired_keys"] += 1
                    
            except Exception as e:
                logger.error(f"Error cleaning up Redis key {key}: {str(e)}", exc_info=True)
                stats["errors"] += 1
        
        # Log results
        logger.info(
            f"Redis cleanup completed: Set expiration on {stats['expired_keys']} keys",
            extra={
                "expired_keys": stats["expired_keys"],
                "errors": stats["errors"]
            }
        )
        
        return {
            "success": True,
            "message": "Redis cleanup completed successfully",
            "stats": stats
        }
        
    except Exception as e:
        logger.error(f"Error cleaning up Redis: {str(e)}", exc_info=True)
        return {
            "success": False,
            "message": f"Error cleaning up Redis: {str(e)}"
        }


@app.task(name="worker.tasks.maintenance.monitor_system_health")
def monitor_system_health():
    """
    Monitor system health and report issues.
    
    Returns:
        Dictionary with task results.
    """
    import psutil
    
    try:
        # Track metrics
        metrics = {
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage('/').percent,
            "open_files": len(psutil.Process().open_files()),
            "connections": len(psutil.Process().connections()),
            "threads": psutil.Process().num_threads(),
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Check thresholds
        warnings = []
        
        if metrics["cpu_percent"] > 80:
            warnings.append(f"High CPU usage: {metrics['cpu_percent']}%")
        
        if metrics["memory_percent"] > 80:
            warnings.append(f"High memory usage: {metrics['memory_percent']}%")
        
        if metrics["disk_percent"] > 80:
            warnings.append(f"High disk usage: {metrics['disk_percent']}%")
        
        # Log results
        if warnings:
            logger.warning(
                f"System health warnings: {', '.join(warnings)}",
                extra=metrics
            )
        else:
            logger.info(
                "System health check passed",
                extra=metrics
            )
        
        return {
            "success": True,
            "message": "System health check completed",
            "metrics": metrics,
            "warnings": warnings
        }
        
    except Exception as e:
        logger.error(f"Error monitoring system health: {str(e)}", exc_info=True)
        return {
            "success": False,
            "message": f"Error monitoring system health: {str(e)}"
        } 
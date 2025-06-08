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
Monitoring routes for the MCP Security Guardian API.
"""
import logging
import platform
import psutil
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST

from core.config import Settings, get_settings
from core.database import check_database_connections
from core.models import HealthResponse, MetricsResponse
from core.auth import get_admin_user, verify_optional_token, TokenData

# Initialize router
router = APIRouter(prefix="/monitoring", tags=["monitoring"])

# Initialize logger
logger = logging.getLogger("mcp_security.api.routes.monitoring")

# Initialize metrics
API_HEALTH_CHECK = Counter("api_health_check", "API health check requests", ["status"])
DB_HEALTH_CHECK = Counter("db_health_check", "Database health check requests", ["status", "database"])
SYSTEM_MEMORY = Gauge("system_memory_usage_bytes", "System memory usage in bytes", ["type"])
SYSTEM_CPU = Gauge("system_cpu_usage_percent", "System CPU usage percentage")
SYSTEM_DISK = Gauge("system_disk_usage_bytes", "System disk usage in bytes", ["type", "mount"])
PROCESS_MEMORY = Gauge("process_memory_usage_bytes", "Process memory usage in bytes", ["type"])
PROCESS_CPU = Gauge("process_cpu_usage_percent", "Process CPU usage percentage")


@router.get("/health", response_model=HealthResponse, tags=["monitoring"])
async def health_check(request: Request, settings: Settings = Depends(get_settings)):
    """
    Basic health check endpoint for load balancers and monitoring systems.
    
    Returns a 200 OK response if the API is running.
    Does not check dependent services for faster response.
    """
    API_HEALTH_CHECK.labels(status="healthy").inc()
    
    return {
        "status": "healthy",
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/health/full", response_model=Dict[str, Any], tags=["monitoring"])
async def full_health_check(
    request: Request, 
    settings: Settings = Depends(get_settings)
):
    """
    Comprehensive health check endpoint that checks all dependencies.
    """
    start_time = time.time()
    
    # Check database connections
    connection_status = check_database_connections()
    
    # Check overall health based on critical services
    is_healthy = all([
        connection_status.get("postgresql", False),
        connection_status.get("redis", False)
    ])
    
    # Update metrics for database connections
    for db_name, status in connection_status.items():
        DB_HEALTH_CHECK.labels(
            status="healthy" if status else "unhealthy", 
            database=db_name
        ).inc()
    
    health_status = "healthy" if is_healthy else "unhealthy"
    API_HEALTH_CHECK.labels(status=health_status).inc()
    
    # Collect system metrics
    collect_system_metrics()
    
    # Get API uptime
    api_uptime = {
        "server_uptime": get_system_uptime(),
        "response_time_ms": int((time.time() - start_time) * 1000)
    }
    
    return {
        "status": health_status,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "timestamp": datetime.utcnow().isoformat(),
        "services": connection_status,
        "system": {
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "uptime": api_uptime
        }
    }


@router.get("/metrics", tags=["monitoring"])
async def metrics(
    request: Request,
    token_data: Optional[TokenData] = Depends(verify_optional_token),
    settings: Settings = Depends(get_settings)
):
    """
    Prometheus metrics endpoint.
    
    Returns metrics in Prometheus format for scraping.
    """
    # Collect latest metrics
    collect_system_metrics()
    
    # Return metrics in Prometheus format
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST
    )


@router.get("/stats", response_model=MetricsResponse, tags=["monitoring"])
async def stats(
    request: Request,
    user: Dict[str, Any] = Depends(get_admin_user),
    settings: Settings = Depends(get_settings)
):
    """
    System statistics endpoint for administrators.
    
    Returns detailed system statistics and performance metrics.
    Requires admin authentication.
    """
    # Collect latest metrics
    collect_system_metrics()
    
    # Get memory info
    memory = psutil.virtual_memory()
    swap = psutil.swap_memory()
    
    # Get CPU info
    cpu_percent = psutil.cpu_percent(interval=0.1)
    cpu_count = psutil.cpu_count()
    cpu_freq = psutil.cpu_freq()
    
    # Get disk info
    disk_partitions = []
    for partition in psutil.disk_partitions():
        try:
            usage = psutil.disk_usage(partition.mountpoint)
            disk_partitions.append({
                "device": partition.device,
                "mountpoint": partition.mountpoint,
                "fstype": partition.fstype,
                "total_gb": round(usage.total / (1024**3), 2),
                "used_gb": round(usage.used / (1024**3), 2),
                "free_gb": round(usage.free / (1024**3), 2),
                "percent": usage.percent
            })
        except (PermissionError, OSError):
            # Skip partitions that can't be accessed
            pass
    
    # Get network info
    net_io_counters = psutil.net_io_counters()
    
    # Get process info
    process = psutil.Process()
    process_memory = process.memory_info()
    
    # Compile stats
    stats = {
        "system": {
            "cpu": {
                "percent": cpu_percent,
                "count": cpu_count,
                "frequency_mhz": cpu_freq.current if cpu_freq else None
            },
            "memory": {
                "total_gb": round(memory.total / (1024**3), 2),
                "available_gb": round(memory.available / (1024**3), 2),
                "used_gb": round(memory.used / (1024**3), 2),
                "percent": memory.percent,
                "swap_total_gb": round(swap.total / (1024**3), 2),
                "swap_used_gb": round(swap.used / (1024**3), 2),
                "swap_percent": swap.percent
            },
            "disk": disk_partitions,
            "network": {
                "bytes_sent": net_io_counters.bytes_sent,
                "bytes_recv": net_io_counters.bytes_recv,
                "packets_sent": net_io_counters.packets_sent,
                "packets_recv": net_io_counters.packets_recv,
                "errin": net_io_counters.errin,
                "errout": net_io_counters.errout,
                "dropin": net_io_counters.dropin,
                "dropout": net_io_counters.dropout
            },
            "uptime": get_system_uptime()
        },
        "process": {
            "pid": process.pid,
            "cpu_percent": process.cpu_percent(),
            "memory_rss_mb": round(process_memory.rss / (1024**2), 2),
            "memory_vms_mb": round(process_memory.vms / (1024**2), 2),
            "threads": process.num_threads(),
            "open_files": len(process.open_files()),
            "connections": len(process.connections()),
            "uptime_seconds": time.time() - process.create_time()
        }
    }
    
    return {
        "metrics": stats,
        "timestamp": datetime.utcnow().isoformat()
    }


def collect_system_metrics():
    """Collect system metrics for Prometheus."""
    try:
        # System memory metrics
        memory = psutil.virtual_memory()
        SYSTEM_MEMORY.labels(type="total").set(memory.total)
        SYSTEM_MEMORY.labels(type="available").set(memory.available)
        SYSTEM_MEMORY.labels(type="used").set(memory.used)
        
        # System CPU metrics
        SYSTEM_CPU.set(psutil.cpu_percent())
        
        # System disk metrics
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                SYSTEM_DISK.labels(type="total", mount=partition.mountpoint).set(usage.total)
                SYSTEM_DISK.labels(type="used", mount=partition.mountpoint).set(usage.used)
                SYSTEM_DISK.labels(type="free", mount=partition.mountpoint).set(usage.free)
            except (PermissionError, OSError):
                # Skip partitions that can't be accessed
                pass
        
        # Process metrics
        process = psutil.Process()
        memory_info = process.memory_info()
        PROCESS_MEMORY.labels(type="rss").set(memory_info.rss)
        PROCESS_MEMORY.labels(type="vms").set(memory_info.vms)
        PROCESS_CPU.set(process.cpu_percent())
    except Exception as e:
        logger.error(f"Error collecting system metrics: {str(e)}")


def get_system_uptime() -> Dict[str, int]:
    """Get system uptime in a structured format."""
    uptime_seconds = time.time() - psutil.boot_time()
    
    # Convert to days, hours, minutes, seconds
    days = int(uptime_seconds // (24 * 3600))
    uptime_seconds %= (24 * 3600)
    hours = int(uptime_seconds // 3600)
    uptime_seconds %= 3600
    minutes = int(uptime_seconds // 60)
    seconds = int(uptime_seconds % 60)
    
    return {
        "days": days,
        "hours": hours,
        "minutes": minutes,
        "seconds": seconds,
        "total_seconds": int(time.time() - psutil.boot_time())
    } 
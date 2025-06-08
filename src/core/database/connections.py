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
Database connection management for MCP Security Guardian Tool.
"""
import logging
import time
from contextlib import contextmanager
from typing import Any, Dict, Generator, Optional, List, Callable, TypeVar
import redis
from redis.sentinel import Sentinel
from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError, OperationalError
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from neo4j import GraphDatabase, Driver, Session as Neo4jSession
from clickhouse_driver import Client as ClickHouseClient
import pymongo.errors
from functools import wraps
import backoff

from core.config import Settings, get_settings

# Set up logging
logger = logging.getLogger("mcp_security.database")

# Type variables for generic functions
T = TypeVar('T')

# Create settings
settings = get_settings()

# SQLAlchemy setup with connection pooling
engine = create_engine(
    settings.postgres_dsn,
    pool_pre_ping=True,  # Check connection health before using it
    pool_size=settings.POSTGRES_POOL_MAX_SIZE,
    max_overflow=10,
    pool_timeout=30,
    pool_recycle=1800,  # Recycle connections after 30 minutes
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# Retry decorator for database operations
def retry_db_operation(max_retries: int = 3, retry_delay: int = 1):
    """
    Decorator to retry database operations with exponential backoff.
    
    Args:
        max_retries: Maximum number of retry attempts
        retry_delay: Initial delay between retries in seconds
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            retries = 0
            last_exception = None
            
            while retries < max_retries:
                try:
                    return func(*args, **kwargs)
                except (SQLAlchemyError, redis.RedisError, pymongo.errors.PyMongoError) as e:
                    last_exception = e
                    wait_time = retry_delay * (2 ** retries)  # Exponential backoff
                    logger.warning(
                        f"Database operation failed (attempt {retries+1}/{max_retries}): {str(e)}. "
                        f"Retrying in {wait_time}s..."
                    )
                    time.sleep(wait_time)
                    retries += 1
            
            # If we get here, all retries have failed
            logger.error(f"Database operation failed after {max_retries} attempts: {str(last_exception)}")
            raise last_exception
            
        return wrapper
    return decorator


def get_db() -> Generator[Session, None, None]:
    """
    Get a SQLAlchemy database session.

    Yields:
        Session: A SQLAlchemy database session.
    """
    db = SessionLocal()
    try:
        yield db
    except SQLAlchemyError as e:
        db.rollback()
        logger.error(f"SQLAlchemy error during session: {str(e)}")
        raise
    finally:
        db.close()


@contextmanager
def get_db_context() -> Generator[Session, None, None]:
    """
    Context manager version of get_db.
    
    Yields:
        Session: A SQLAlchemy database session.
    """
    db = SessionLocal()
    try:
        yield db
    except SQLAlchemyError as e:
        db.rollback()
        logger.error(f"SQLAlchemy error during session: {str(e)}")
        raise
    finally:
        db.close()


# MongoDB setup with connection pooling
mongodb_client = AsyncIOMotorClient(
    settings.MONGODB_URI,
    maxPoolSize=settings.MONGODB_MAX_POOL_SIZE,
    minPoolSize=settings.MONGODB_MIN_POOL_SIZE,
    connectTimeoutMS=5000,
    socketTimeoutMS=30000,
    serverSelectionTimeoutMS=5000,
    retryWrites=True,
    retryReads=True,
)


def get_mongodb() -> AsyncIOMotorDatabase:
    """
    Get a MongoDB database.

    Returns:
        AsyncIOMotorDatabase: A MongoDB database.
    """
    # Extract database name from URI
    db_name = settings.MONGODB_DB
    return mongodb_client[db_name]


# Redis setup with health check
if settings.REDIS_PASSWORD and ":" in settings.REDIS_PASSWORD:
    # Redis Sentinel configuration (format: master_name:sentinel_host1:port,sentinel_host2:port)
    sentinel_parts = settings.REDIS_PASSWORD.split(":")
    master_name = sentinel_parts[0]
    sentinel_hosts = [
        (host.split(":")[0], int(host.split(":")[1]))
        for host in sentinel_parts[1].split(",")
    ]
    
    sentinel = Sentinel(
        sentinel_hosts,
        socket_timeout=1.0,
        password=settings.REDIS_PASSWORD,
        db=settings.REDIS_DB,
        ssl=settings.REDIS_SSL,
    )
    redis_client = sentinel.master_for(
        master_name,
        socket_timeout=1.0,
        password=settings.REDIS_PASSWORD,
        db=settings.REDIS_DB,
        ssl=settings.REDIS_SSL,
        decode_responses=True,
    )
else:
    # Standard Redis configuration
    redis_client = redis.Redis.from_url(
        settings.redis_url,
        socket_timeout=1.0,
        socket_connect_timeout=1.0,
        socket_keepalive=True,
        health_check_interval=30,
        max_connections=settings.REDIS_MAX_CONNECTIONS,
        decode_responses=True,
    )


@retry_db_operation(max_retries=3, retry_delay=1)
def get_redis() -> redis.Redis:
    """
    Get a Redis client with health check.

    Returns:
        redis.Redis: A Redis client.
    """
    # Verify connection is healthy
    redis_client.ping()
    return redis_client


# Neo4j setup with connection pooling
neo4j_driver: Optional[Driver] = None


def get_neo4j() -> Driver:
    """
    Get a Neo4j driver.

    Returns:
        Driver: A Neo4j driver.
    """
    global neo4j_driver
    if neo4j_driver is None or not neo4j_driver.verify_connectivity():
        if neo4j_driver is not None:
            try:
                neo4j_driver.close()
            except Exception:
                pass
                
        neo4j_driver = GraphDatabase.driver(
            settings.NEO4J_URI,
            auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD),
            max_connection_lifetime=3600,  # 1 hour
            max_connection_pool_size=settings.NEO4J_MAX_CONNECTION_POOL_SIZE,
            connection_acquisition_timeout=60,
        )
    return neo4j_driver


@contextmanager
def get_neo4j_session(database: Optional[str] = None) -> Generator[Neo4jSession, None, None]:
    """
    Context manager to get a Neo4j session.
    
    Args:
        database: Optional database name to use
        
    Yields:
        Neo4jSession: A Neo4j session
    """
    driver = get_neo4j()
    session = driver.session(database=database or settings.NEO4J_DATABASE)
    try:
        yield session
    finally:
        session.close()


# ClickHouse setup
clickhouse_client: Optional[ClickHouseClient] = None


def get_clickhouse() -> ClickHouseClient:
    """
    Get a ClickHouse client.

    Returns:
        ClickHouseClient: A ClickHouse client.
    """
    global clickhouse_client
    if clickhouse_client is None:
        clickhouse_client = ClickHouseClient(
            host=settings.CLICKHOUSE_HOST,
            port=settings.CLICKHOUSE_PORT,
            user=settings.CLICKHOUSE_USER,
            password=settings.CLICKHOUSE_PASSWORD,
            database=settings.CLICKHOUSE_DB,
            connect_timeout=10,
            send_receive_timeout=30,
            compression=True,
            secure=settings.CLICKHOUSE_SECURE,
        )
    return clickhouse_client


def check_database_connections() -> Dict[str, bool]:
    """
    Check connections to all databases.
    
    Returns:
        Dict[str, bool]: Dictionary of database name to connection status
    """
    results = {}
    
    # Check PostgreSQL
    try:
        with engine.connect() as conn:
            conn.execute("SELECT 1")
        results["postgresql"] = True
    except Exception as e:
        logger.error(f"PostgreSQL connection check failed: {str(e)}")
        results["postgresql"] = False
    
    # Check MongoDB
    try:
        # This is async, but we can use the client's address property to check connection
        mongodb_client.address
        results["mongodb"] = True
    except Exception as e:
        logger.error(f"MongoDB connection check failed: {str(e)}")
        results["mongodb"] = False
    
    # Check Redis
    try:
        redis_client.ping()
        results["redis"] = True
    except Exception as e:
        logger.error(f"Redis connection check failed: {str(e)}")
        results["redis"] = False
    
    # Check Neo4j
    try:
        driver = get_neo4j()
        driver.verify_connectivity()
        results["neo4j"] = True
    except Exception as e:
        logger.error(f"Neo4j connection check failed: {str(e)}")
        results["neo4j"] = False
    
    # Check ClickHouse
    try:
        client = get_clickhouse()
        client.execute("SELECT 1")
        results["clickhouse"] = True
    except Exception as e:
        logger.error(f"ClickHouse connection check failed: {str(e)}")
        results["clickhouse"] = False
    
    return results


def close_connections() -> None:
    """
    Close all database connections.
    """
    global neo4j_driver, clickhouse_client
    
    # Close PostgreSQL connection pool
    engine.dispose()
    
    # Close MongoDB connection
    try:
        mongodb_client.close()
    except Exception as e:
        logger.error(f"Error closing MongoDB connection: {str(e)}")
    
    # Close Redis connection
    try:
        redis_client.close()
    except Exception as e:
        logger.error(f"Error closing Redis connection: {str(e)}")
    
    # Close Neo4j connection
    if neo4j_driver is not None:
        try:
            neo4j_driver.close()
            neo4j_driver = None
        except Exception as e:
            logger.error(f"Error closing Neo4j connection: {str(e)}")
    
    # ClickHouse has no explicit close method
    clickhouse_client = None 
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
Configuration settings for the MCP Security Guardian Tool.
"""
import os
import secrets
import warnings
from functools import lru_cache
from typing import Dict, List, Optional, Union, Any
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import validator, Field


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    Provides secure defaults and validation for production deployments.
    """
    model_config = SettingsConfigDict(
        env_file=".env", 
        env_file_encoding="utf-8", 
        extra="ignore",
        env_prefix="MCP_",
        case_sensitive=False
    )

    # Application Settings
    APP_NAME: str = "MCP Security Guardian"
    VERSION: str = "0.1.0"
    ENVIRONMENT: str = Field(
        default="development",
        description="Application environment (development, staging, production)"
    )
    LOG_LEVEL: str = Field(
        default="INFO",
        description="Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)"
    )
    LOG_FORMAT: str = Field(
        default="json" if os.environ.get("MCP_ENVIRONMENT") == "production" else "text",
        description="Log format (text, json)"
    )
    LOG_FILE: Optional[str] = Field(
        default=None, 
        description="Log file path. If not set, logs to stdout"
    )
    INSTANCE_ID: str = Field(
        default=os.environ.get("HOSTNAME", "dev01"),
        description="Unique instance identifier"
    )
    SECRET_KEY: str = Field(
        default_factory=lambda: secrets.token_urlsafe(32),
        description="Secret key for cryptographic operations"
    )
    DEBUG: bool = Field(
        default=False,
        description="Enable debug mode (automatically set to True in development)"
    )

    # API Gateway
    API_PORT: int = Field(
        default=8000,
        description="Port to run the API server on"
    )
    API_HOST: str = Field(
        default="0.0.0.0",
        description="Host to bind the API server to"
    )
    API_CORS_ORIGINS: List[str] = Field(
        default=["http://localhost:3000", "http://localhost:8000"],
        description="List of allowed CORS origins"
    )
    API_WORKERS: int = Field(
        default=min(os.cpu_count() or 1, 8),
        description="Number of worker processes for the API server"
    )
    API_TIMEOUT: int = Field(
        default=60,
        description="Timeout for API requests in seconds"
    )
    API_ROOT_PATH: str = Field(
        default="",
        description="Root path for the API (useful for reverse proxies)"
    )
    
    # Database Settings - PostgreSQL
    POSTGRES_HOST: str = Field(
        default="localhost",
        description="PostgreSQL host"
    )
    POSTGRES_PORT: int = Field(
        default=5432,
        description="PostgreSQL port"
    )
    POSTGRES_USER: str = Field(
        default="postgres",
        description="PostgreSQL username"
    )
    POSTGRES_PASSWORD: str = Field(
        default="postgres",
        description="PostgreSQL password"
    )
    POSTGRES_DB: str = Field(
        default="mcp_guardian",
        description="PostgreSQL database name"
    )
    POSTGRES_SSL: bool = Field(
        default=False,
        description="Enable SSL for PostgreSQL connection"
    )
    POSTGRES_POOL_MIN_SIZE: int = Field(
        default=1,
        description="Minimum connection pool size"
    )
    POSTGRES_POOL_MAX_SIZE: int = Field(
        default=10,
        description="Maximum connection pool size"
    )

    @property
    def postgres_dsn(self) -> str:
        """
        PostgreSQL connection string.
        """
        ssl = "?sslmode=require" if self.POSTGRES_SSL else ""
        return f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}{ssl}"

    # MongoDB
    MONGODB_URI: str = Field(
        default="mongodb://localhost:27017/mcp_guardian",
        description="MongoDB connection URI"
    )
    MONGODB_DB: str = Field(
        default="mcp_guardian",
        description="MongoDB database name"
    )
    MONGODB_MAX_POOL_SIZE: int = Field(
        default=100,
        description="Maximum MongoDB connection pool size"
    )
    MONGODB_MIN_POOL_SIZE: int = Field(
        default=10,
        description="Minimum MongoDB connection pool size"
    )
    
    @validator("MONGODB_URI")
    def validate_mongodb_uri(cls, v: str, values: Dict[str, Any]) -> str:
        """Validate MongoDB URI and ensure it has the correct database name"""
        from urllib.parse import urlparse
        
        # Get the base URI without the database name
        parsed = urlparse(v)
        if not parsed.path or parsed.path == "/":
            # If no database is specified in the URI, append the configured database
            db_name = values.get("MONGODB_DB", "mcp_guardian")
            base_uri = v.rstrip('/')
            return f"{base_uri}/{db_name}"
        return v

    # Redis
    REDIS_HOST: str = Field(
        default="localhost",
        description="Redis host"
    )
    REDIS_PORT: int = Field(
        default=6379,
        description="Redis port"
    )
    REDIS_PASSWORD: Optional[str] = Field(
        default=None,
        description="Redis password"
    )
    REDIS_DB: int = Field(
        default=0,
        description="Redis database index"
    )
    REDIS_SSL: bool = Field(
        default=False,
        description="Enable SSL for Redis connection"
    )
    REDIS_MAX_CONNECTIONS: int = Field(
        default=10,
        description="Maximum Redis connections"
    )

    @property
    def redis_url(self) -> str:
        """
        Redis connection URL.
        """
        auth = f":{self.REDIS_PASSWORD}@" if self.REDIS_PASSWORD else ""
        protocol = "rediss" if self.REDIS_SSL else "redis"
        return f"{protocol}://{auth}{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"

    # Neo4j
    NEO4J_URI: str = Field(
        default="neo4j://localhost:7687",
        description="Neo4j connection URI"
    )
    NEO4J_USER: str = Field(
        default="neo4j",
        description="Neo4j username"
    )
    NEO4J_PASSWORD: str = Field(
        default="password",
        description="Neo4j password"
    )
    NEO4J_DATABASE: str = Field(
        default="neo4j",
        description="Neo4j database name"
    )
    NEO4J_MAX_CONNECTION_POOL_SIZE: int = Field(
        default=100,
        description="Maximum Neo4j connection pool size"
    )

    # ClickHouse
    CLICKHOUSE_HOST: str = Field(
        default="localhost",
        description="ClickHouse host"
    )
    CLICKHOUSE_PORT: int = Field(
        default=9000,
        description="ClickHouse port"
    )
    CLICKHOUSE_USER: str = Field(
        default="default",
        description="ClickHouse username"
    )
    CLICKHOUSE_PASSWORD: Optional[str] = Field(
        default=None,
        description="ClickHouse password"
    )
    CLICKHOUSE_DB: str = Field(
        default="mcp_analytics",
        description="ClickHouse database name"
    )
    CLICKHOUSE_SECURE: bool = Field(
        default=False,
        description="Enable SSL for ClickHouse connection"
    )

    # Kafka
    KAFKA_BOOTSTRAP_SERVERS: str = Field(
        default="localhost:9092",
        description="Kafka bootstrap servers (comma-separated list)"
    )
    KAFKA_SECURITY_PROTOCOL: str = Field(
        default="PLAINTEXT",
        description="Kafka security protocol (PLAINTEXT, SSL, SASL_PLAINTEXT, SASL_SSL)"
    )
    KAFKA_SASL_MECHANISM: Optional[str] = Field(
        default=None,
        description="Kafka SASL mechanism (PLAIN, SCRAM-SHA-256, SCRAM-SHA-512)"
    )
    KAFKA_SASL_USERNAME: Optional[str] = Field(
        default=None,
        description="Kafka SASL username"
    )
    KAFKA_SASL_PASSWORD: Optional[str] = Field(
        default=None,
        description="Kafka SASL password"
    )
    KAFKA_SSL_CAFILE: Optional[str] = Field(
        default=None,
        description="Path to CA certificate for Kafka SSL"
    )
    KAFKA_SSL_CERTFILE: Optional[str] = Field(
        default=None,
        description="Path to client certificate for Kafka SSL"
    )
    KAFKA_SSL_KEYFILE: Optional[str] = Field(
        default=None,
        description="Path to client key for Kafka SSL"
    )
    KAFKA_SSL_PASSWORD: Optional[str] = Field(
        default=None,
        description="Password for Kafka SSL key file"
    )

    # LLM Integration
    LLM_PROVIDER: str = Field(
        default="openai",
        description="LLM provider (openai, anthropic, local)"
    )
    LLM_API_KEY: Optional[str] = Field(
        default=None,
        description="LLM API key"
    )
    LLM_MODEL: str = Field(
        default="gpt-4",
        description="LLM model name"
    )
    LLM_API_URL: Optional[str] = Field(
        default=None,
        description="Custom LLM API URL for self-hosted models"
    )
    LLM_TIMEOUT: int = Field(
        default=30,
        description="LLM API request timeout in seconds"
    )
    LLM_MAX_TOKENS: int = Field(
        default=1000,
        description="Maximum tokens for LLM response"
    )
    LLM_TEMPERATURE: float = Field(
        default=0.1,
        description="Temperature parameter for LLM (0.0-1.0)"
    )

    # Security Settings
    JWT_SECRET: str = Field(
        default_factory=lambda: secrets.token_urlsafe(32),
        description="Secret key for JWT tokens"
    )
    JWT_ALGORITHM: str = Field(
        default="RS256",
        description="Algorithm for JWT tokens"
    )
    JWT_EXPIRES_MINUTES: int = Field(
        default=60,
        description="JWT token expiration time in minutes"
    )
    REFRESH_TOKEN_EXPIRES_DAYS: int = Field(
        default=7,
        description="Refresh token expiration time in days"
    )
    PASSWORD_HASH_ALGORITHM: str = Field(
        default="bcrypt",
        description="Algorithm for password hashing"
    )
    PASSWORD_RESET_TOKEN_EXPIRES_HOURS: int = Field(
        default=24,
        description="Password reset token expiration time in hours"
    )
    MIN_PASSWORD_LENGTH: int = Field(
        default=12,
        description="Minimum password length"
    )

    # Detection Engine Settings
    MIN_CONFIDENCE_FOR_ALERT: float = Field(
        default=0.6,
        description="Minimum confidence score to generate an alert"
    )
    DEFAULT_SCAN_TIMEOUT: int = Field(
        default=300,
        description="Default timeout for vulnerability scans in seconds"
    )
    MAX_SCAN_DEPTH: int = Field(
        default=5,
        description="Maximum depth for vulnerability scans"
    )
    PATTERN_MATCH_THRESHOLD: float = Field(
        default=0.8,
        description="Threshold for pattern matching"
    )
    BEHAVIORAL_ANALYSIS_ENABLED: bool = Field(
        default=True,
        description="Enable behavioral analysis"
    )
    LLM_CLASSIFICATION_ENABLED: bool = Field(
        default=True,
        description="Enable LLM-based classification"
    )
    TRAFFIC_ANALYSIS_ENABLED: bool = Field(
        default=True,
        description="Enable traffic analysis"
    )

    # Threat Intelligence
    STIX_TAXII_ENABLED: bool = Field(
        default=False,
        description="Enable STIX/TAXII integration"
    )
    STIX_TAXII_ENDPOINT: Optional[str] = Field(
        default=None,
        description="STIX/TAXII endpoint URL"
    )
    STIX_TAXII_USERNAME: Optional[str] = Field(
        default=None,
        description="STIX/TAXII username"
    )
    STIX_TAXII_PASSWORD: Optional[str] = Field(
        default=None,
        description="STIX/TAXII password"
    )
    STIX_TAXII_COLLECTION_ID: Optional[str] = Field(
        default=None,
        description="STIX/TAXII collection ID"
    )
    THREAT_INTELLIGENCE_UPDATE_INTERVAL: int = Field(
        default=3600,
        description="Threat intelligence update interval in seconds"
    )

    # Email Notifications
    EMAIL_ENABLED: bool = Field(
        default=False,
        description="Enable email notifications"
    )
    SMTP_SERVER: Optional[str] = Field(
        default=None,
        description="SMTP server"
    )
    SMTP_PORT: int = Field(
        default=587,
        description="SMTP port"
    )
    SMTP_USERNAME: Optional[str] = Field(
        default=None,
        description="SMTP username"
    )
    SMTP_PASSWORD: Optional[str] = Field(
        default=None,
        description="SMTP password"
    )
    EMAIL_FROM: Optional[str] = Field(
        default=None,
        description="Email sender address"
    )
    SMTP_TLS: bool = Field(
        default=True,
        description="Enable TLS for SMTP"
    )

    # Monitoring
    PROMETHEUS_METRICS_ENABLED: bool = Field(
        default=True,
        description="Enable Prometheus metrics"
    )
    PROMETHEUS_METRICS_PORT: int = Field(
        default=9090,
        description="Prometheus metrics port"
    )
    TELEMETRY_ENABLED: bool = Field(
        default=True,
        description="Enable telemetry"
    )
    APM_ENABLED: bool = Field(
        default=False,
        description="Enable Application Performance Monitoring"
    )
    APM_SERVER_URL: Optional[str] = Field(
        default=None,
        description="APM server URL"
    )
    APM_SERVICE_NAME: str = Field(
        default="mcp-guardian",
        description="APM service name"
    )
    APM_ENVIRONMENT: Optional[str] = Field(
        default=None,
        description="APM environment"
    )
    HEALTH_CHECK_INTERVAL: int = Field(
        default=60,
        description="Health check interval in seconds"
    )

    @validator("DEBUG", pre=True, always=True)
    def set_debug_based_on_env(cls, v: bool, values: Dict[str, Any]) -> bool:
        """Set DEBUG based on ENVIRONMENT if not explicitly provided"""
        if v is not None:
            return v
        return values.get("ENVIRONMENT", "development").lower() == "development"

    @validator("APM_ENVIRONMENT", pre=True, always=True)
    def set_apm_environment(cls, v: Optional[str], values: Dict[str, Any]) -> Optional[str]:
        """Set APM_ENVIRONMENT to ENVIRONMENT if not explicitly provided"""
        if v:
            return v
        return values.get("ENVIRONMENT")

    @property
    def kafka_config(self) -> Dict[str, str]:
        """
        Kafka client configuration.
        """
        config = {
            "bootstrap.servers": self.KAFKA_BOOTSTRAP_SERVERS,
            "security.protocol": self.KAFKA_SECURITY_PROTOCOL,
        }

        if self.KAFKA_SASL_MECHANISM:
            config.update({
                "sasl.mechanism": self.KAFKA_SASL_MECHANISM,
                "sasl.username": self.KAFKA_SASL_USERNAME,
                "sasl.password": self.KAFKA_SASL_PASSWORD,
            })

        if self.KAFKA_SSL_CAFILE:
            config.update({
                "ssl.ca.location": self.KAFKA_SSL_CAFILE,
            })

        if self.KAFKA_SSL_CERTFILE:
            config.update({
                "ssl.certificate.location": self.KAFKA_SSL_CERTFILE,
            })

        if self.KAFKA_SSL_KEYFILE:
            config.update({
                "ssl.key.location": self.KAFKA_SSL_KEYFILE,
            })

        if self.KAFKA_SSL_PASSWORD:
            config.update({
                "ssl.key.password": self.KAFKA_SSL_PASSWORD,
            })

        return config

    def get_db_uri(self, db_type: str) -> str:
        """
        Get a database URI based on the database type.
        
        Args:
            db_type: One of 'postgres', 'mongodb', 'redis', 'neo4j'
        
        Returns:
            str: Database connection URI
        """
        if db_type == "postgres":
            return self.postgres_dsn
        elif db_type == "mongodb":
            return self.MONGODB_URI
        elif db_type == "redis":
            return self.redis_url
        elif db_type == "neo4j":
            return self.NEO4J_URI
        else:
            raise ValueError(f"Unknown database type: {db_type}")

    def validate_for_production(self) -> List[str]:
        """
        Validate settings for production environment.
        Returns a list of warnings if any security concerns are found.
        
        Returns:
            List[str]: List of warnings
        """
        warnings_list = []
        
        if self.ENVIRONMENT == "production":
            # Check for default/insecure values in production
            if self.SECRET_KEY == "insecure-secret-key-change-in-production":
                msg = "Using default SECRET_KEY in production"
                warnings.warn(msg)
                warnings_list.append(msg)
                
            if self.JWT_SECRET == "insecure-jwt-secret-change-in-production":
                msg = "Using default JWT_SECRET in production"
                warnings.warn(msg)
                warnings_list.append(msg)
                
            if self.POSTGRES_PASSWORD == "postgres" and not self.DEBUG:
                msg = "Using default database password in production"
                warnings.warn(msg)
                warnings_list.append(msg)
                
            if self.NEO4J_PASSWORD == "password" and not self.DEBUG:
                msg = "Using default Neo4j password in production"
                warnings.warn(msg)
                warnings_list.append(msg)
                
            if not self.POSTGRES_SSL:
                msg = "PostgreSQL SSL is disabled in production"
                warnings.warn(msg)
                warnings_list.append(msg)
                
            if not self.REDIS_SSL and self.REDIS_PASSWORD:
                msg = "Redis SSL is disabled but password is set in production"
                warnings.warn(msg)
                warnings_list.append(msg)
                
            if self.API_CORS_ORIGINS == ["http://localhost:3000", "http://localhost:8000"]:
                msg = "Using default CORS origins in production"
                warnings.warn(msg)
                warnings_list.append(msg)
                
            if self.DEBUG:
                msg = "DEBUG mode is enabled in production"
                warnings.warn(msg)
                warnings_list.append(msg)
        return warnings_list


@lru_cache
def get_settings() -> Settings:
    """
    Get settings instance with caching.
    
    Returns:
        Settings: Application settings
    """
    return Settings() 
"""
Models for the MCP Traffic Analyzer.
"""
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any, Set
from uuid import UUID

from pydantic import Field, validator
from sqlalchemy import Column, DateTime, Enum as SQLEnum, Float, ForeignKey, Integer, String, Text, Boolean, JSON, Table
from sqlalchemy.dialects.postgresql import JSONB, UUID as SQLUUID, ARRAY
from sqlalchemy.orm import relationship

from core.database.connections import Base
from core.models.base import UUIDModel, BaseSchema, UUIDSchema, MongoBaseDocument
from detection_engine.instruction_analysis.models import ThreatType, RiskLevel


class MessageDirection(str, Enum):
    """
    Enumeration of message directions.
    """
    CLIENT_TO_SERVER = "client_to_server"
    SERVER_TO_CLIENT = "server_to_client"


class MessageType(str, Enum):
    """
    Enumeration of MCP message types.
    """
    INSTRUCTION = "instruction"
    RESPONSE = "response"
    ERROR = "error"
    HANDSHAKE = "handshake"
    CAPABILITY_REQUEST = "capability_request"
    CAPABILITY_RESPONSE = "capability_response"
    TOKEN_REFRESH = "token_refresh"
    HEARTBEAT = "heartbeat"
    TERMINATION = "termination"
    OTHER = "other"


class AnomalyType(str, Enum):
    """
    Enumeration of traffic anomaly types.
    """
    VOLUME_SPIKE = "volume_spike"
    UNUSUAL_PATTERN = "unusual_pattern"
    IRREGULAR_TIMING = "irregular_timing"
    PROTOCOL_VIOLATION = "protocol_violation"
    SUSPICIOUS_CONTENT = "suspicious_content"
    UNAUTHORIZED_CAPABILITY = "unauthorized_capability"
    OTHER = "other"


# SQLAlchemy Models
class TrafficBaseline(UUIDModel):
    """
    Model for traffic baseline data.
    """
    __tablename__ = "traffic_baselines"

    client_id = Column(String(255), nullable=True, index=True)
    server_id = Column(String(255), nullable=True, index=True)
    
    # Baseline metrics
    avg_message_rate = Column(Float, nullable=False)  # Messages per minute
    avg_message_size = Column(Float, nullable=False)  # Bytes
    avg_instruction_length = Column(Float, nullable=False)  # Characters
    
    # Message type distribution (percentage)
    message_type_distribution = Column(JSONB, nullable=False)
    
    # Time-based patterns
    hourly_patterns = Column(JSONB, nullable=True)
    daily_patterns = Column(JSONB, nullable=True)
    
    # Learning period
    learning_start = Column(DateTime, nullable=False)
    learning_end = Column(DateTime, nullable=False)
    sample_count = Column(Integer, nullable=False)
    
    # Status
    is_active = Column(Boolean, default=True, nullable=False)
    last_updated = Column(DateTime, nullable=False, default=datetime.utcnow)


class TrafficAlert(UUIDModel):
    """
    Model for traffic alerts.
    """
    __tablename__ = "traffic_alerts"

    client_id = Column(String(255), nullable=True, index=True)
    server_id = Column(String(255), nullable=True, index=True)
    session_id = Column(String(255), nullable=True, index=True)
    
    # Alert details
    anomaly_type = Column(SQLEnum(AnomalyType), nullable=False)
    risk_level = Column(SQLEnum(RiskLevel), nullable=False)
    confidence = Column(Float, nullable=False)
    
    # Metrics that triggered the alert
    observed_value = Column(Float, nullable=True)
    baseline_value = Column(Float, nullable=True)
    deviation_percent = Column(Float, nullable=True)
    
    # Time window
    time_window_start = Column(DateTime, nullable=False)
    time_window_end = Column(DateTime, nullable=False)
    
    # Alert metadata
    message_count = Column(Integer, nullable=True)
    has_sample_messages = Column(Boolean, default=False, nullable=False)
    sample_messages = Column(JSONB, nullable=True)
    
    # Status
    is_resolved = Column(Boolean, default=False, nullable=False)
    resolution_notes = Column(Text, nullable=True)
    resolved_by = Column(String(255), nullable=True)
    resolved_at = Column(DateTime, nullable=True)


class MessageSummary(UUIDModel):
    """
    Model for summarized message data used in analysis.
    """
    __tablename__ = "message_summaries"

    client_id = Column(String(255), nullable=True, index=True)
    server_id = Column(String(255), nullable=True, index=True)
    session_id = Column(String(255), nullable=True, index=True)
    
    # Time window
    time_window = Column(String(255), nullable=False, index=True)  # Format: YYYY-MM-DD-HH or YYYY-MM-DD
    
    # Message counts
    total_messages = Column(Integer, nullable=False, default=0)
    message_type_counts = Column(JSONB, nullable=False)
    
    # Size metrics
    avg_message_size = Column(Float, nullable=False)
    total_message_size = Column(Float, nullable=False)
    
    # Message frequency
    avg_message_interval = Column(Float, nullable=True)  # Seconds
    
    # Content metrics
    unique_instructions = Column(Integer, nullable=True)
    instruction_similarity = Column(Float, nullable=True)  # 0-1
    
    # Additional metrics
    unique_capabilities_used = Column(Integer, nullable=True)
    capability_frequency = Column(JSONB, nullable=True)


# Pydantic Models
class BaselineData(BaseSchema):
    """
    Base schema for traffic baseline data.
    """
    client_id: Optional[str] = Field(None, description="Client identifier")
    server_id: Optional[str] = Field(None, description="Server identifier")
    avg_message_rate: float = Field(..., description="Average messages per minute")
    avg_message_size: float = Field(..., description="Average message size in bytes")
    avg_instruction_length: float = Field(..., description="Average instruction length in characters")
    message_type_distribution: Dict[str, float] = Field(..., description="Distribution of message types")
    hourly_patterns: Optional[Dict[str, Any]] = Field(None, description="Hourly traffic patterns")
    daily_patterns: Optional[Dict[str, Any]] = Field(None, description="Daily traffic patterns")
    learning_start: datetime = Field(..., description="Start of learning period")
    learning_end: datetime = Field(..., description="End of learning period")
    sample_count: int = Field(..., description="Number of samples used")
    is_active: bool = Field(True, description="Whether the baseline is active")
    last_updated: datetime = Field(..., description="When the baseline was last updated")


class BaselineResponse(BaselineData, UUIDSchema):
    """
    Schema for baseline response.
    """
    pass


class AlertData(BaseSchema):
    """
    Base schema for traffic alerts.
    """
    client_id: Optional[str] = Field(None, description="Client identifier")
    server_id: Optional[str] = Field(None, description="Server identifier")
    session_id: Optional[str] = Field(None, description="Session identifier")
    anomaly_type: AnomalyType = Field(..., description="Type of anomaly detected")
    risk_level: RiskLevel = Field(..., description="Risk level of the alert")
    confidence: float = Field(..., description="Confidence score (0-1)")
    observed_value: Optional[float] = Field(None, description="Observed metric value")
    baseline_value: Optional[float] = Field(None, description="Baseline metric value")
    deviation_percent: Optional[float] = Field(None, description="Percent deviation from baseline")
    time_window_start: datetime = Field(..., description="Start of time window")
    time_window_end: datetime = Field(..., description="End of time window")
    message_count: Optional[int] = Field(None, description="Number of messages in window")
    has_sample_messages: bool = Field(False, description="Whether sample messages are included")
    sample_messages: Optional[List[Dict[str, Any]]] = Field(None, description="Sample messages")
    is_resolved: bool = Field(False, description="Whether the alert has been resolved")
    resolution_notes: Optional[str] = Field(None, description="Notes on alert resolution")
    resolved_by: Optional[str] = Field(None, description="User who resolved the alert")
    resolved_at: Optional[datetime] = Field(None, description="When the alert was resolved")


class AlertResponse(AlertData, UUIDSchema):
    """
    Schema for alert response.
    """
    pass


class MessageData(BaseSchema):
    """
    Schema for MCP message data.
    """
    message_id: str = Field(..., description="Message identifier")
    client_id: Optional[str] = Field(None, description="Client identifier")
    server_id: Optional[str] = Field(None, description="Server identifier")
    session_id: Optional[str] = Field(None, description="Session identifier")
    timestamp: datetime = Field(..., description="Message timestamp")
    direction: MessageDirection = Field(..., description="Message direction")
    message_type: MessageType = Field(..., description="Message type")
    size_bytes: int = Field(..., description="Message size in bytes")
    content: Dict[str, Any] = Field(..., description="Message content")
    
    @validator("content")
    def sanitize_content(cls, v):
        """
        Sanitize sensitive content from messages.
        """
        # Remove sensitive fields if present
        if v and isinstance(v, dict):
            sensitive_fields = ["token", "password", "secret", "key", "credential"]
            for field in sensitive_fields:
                if field in v:
                    v[field] = "[REDACTED]"
        return v


class MessageSummaryData(BaseSchema):
    """
    Schema for message summary data.
    """
    client_id: Optional[str] = Field(None, description="Client identifier")
    server_id: Optional[str] = Field(None, description="Server identifier")
    session_id: Optional[str] = Field(None, description="Session identifier")
    time_window: str = Field(..., description="Time window (e.g., '2023-05-10-14')")
    total_messages: int = Field(..., description="Total messages in window")
    message_type_counts: Dict[str, int] = Field(..., description="Message counts by type")
    avg_message_size: float = Field(..., description="Average message size in bytes")
    total_message_size: float = Field(..., description="Total message size in bytes")
    avg_message_interval: Optional[float] = Field(None, description="Average interval between messages (seconds)")
    unique_instructions: Optional[int] = Field(None, description="Number of unique instructions")
    instruction_similarity: Optional[float] = Field(None, description="Similarity score between instructions (0-1)")
    unique_capabilities_used: Optional[int] = Field(None, description="Number of unique capabilities used")
    capability_frequency: Optional[Dict[str, int]] = Field(None, description="Frequency of capability usage")


class MessageSummaryResponse(MessageSummaryData, UUIDSchema):
    """
    Schema for message summary response.
    """
    pass


class TrafficAnalysisResult(BaseSchema):
    """
    Schema for traffic analysis result.
    """
    is_anomalous: bool = Field(..., description="Whether anomalous traffic was detected")
    anomaly_types: List[AnomalyType] = Field(default_factory=list, description="Types of anomalies detected")
    risk_level: Optional[RiskLevel] = Field(None, description="Overall risk level")
    confidence: float = Field(..., description="Confidence score (0-1)")
    alerts: List[AlertData] = Field(default_factory=list, description="Generated alerts")
    metrics: Dict[str, Any] = Field(..., description="Traffic metrics analyzed")
    baseline_deviation: Dict[str, float] = Field(..., description="Deviation from baseline for key metrics")
    time_window: Dict[str, datetime] = Field(..., description="Time window analyzed")
    message_count: int = Field(..., description="Number of messages analyzed") 
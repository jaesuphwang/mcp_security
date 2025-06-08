"""
Models for the Instruction Analysis Engine.
"""
from datetime import datetime
import enum
from typing import Dict, List, Optional, Union, Any
from uuid import UUID

from pydantic import Field
from sqlalchemy import Column, DateTime, Enum, Float, ForeignKey, Integer, String, Text, Boolean
from sqlalchemy.dialects.postgresql import JSONB, UUID as SQLUUID
from sqlalchemy.orm import relationship

from core.database.connections import Base
from core.models.base import UUIDModel, BaseSchema, UUIDSchema, MongoBaseDocument


class ThreatType(str, enum.Enum):
    """
    Enumeration of threat types.
    """
    MALICIOUS_CODE_EXECUTION = "malicious_code_execution"
    REMOTE_ACCESS_CONTROL = "remote_access_control"
    CREDENTIAL_THEFT = "credential_theft"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DENIAL_OF_SERVICE = "denial_of_service"
    UNKNOWN = "unknown"


class RiskLevel(str, enum.Enum):
    """
    Enumeration of risk levels.
    """
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DetectionSource(str, enum.Enum):
    """
    Enumeration of detection sources.
    """
    PATTERN_MATCHING = "pattern_matching"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"
    SEMANTIC_ANALYSIS = "semantic_analysis"
    LLM_CLASSIFICATION = "llm_classification"
    TRAFFIC_ANALYSIS = "traffic_analysis"
    MANUAL = "manual"


# SQLAlchemy Models
class DetectionPattern(UUIDModel):
    """
    Model for a detection pattern.
    """
    __tablename__ = "detection_patterns"

    name = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    pattern = Column(Text, nullable=False)
    is_regex = Column(Boolean, default=True, nullable=False)
    threat_type = Column(Enum(ThreatType), nullable=False)
    risk_level = Column(Enum(RiskLevel), nullable=False)
    confidence = Column(Float, nullable=False, default=0.8)
    enabled = Column(Boolean, default=True, nullable=False)
    
    # Metadata
    version = Column(Integer, nullable=False, default=1)
    created_by = Column(String(255), nullable=True)
    last_updated_by = Column(String(255), nullable=True)


class DetectionRule(UUIDModel):
    """
    Model for a detection rule (combination of patterns and logic).
    """
    __tablename__ = "detection_rules"

    name = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    rule_logic = Column(Text, nullable=False)  # Could be a JSON string or DSL
    threat_type = Column(Enum(ThreatType), nullable=False)
    risk_level = Column(Enum(RiskLevel), nullable=False)
    confidence = Column(Float, nullable=False, default=0.8)
    enabled = Column(Boolean, default=True, nullable=False)
    
    # Metadata
    version = Column(Integer, nullable=False, default=1)
    created_by = Column(String(255), nullable=True)
    last_updated_by = Column(String(255), nullable=True)


class DetectionEvent(UUIDModel):
    """
    Model for a detection event.
    """
    __tablename__ = "detection_events"

    instruction_id = Column(String(255), nullable=False, index=True)
    session_id = Column(String(255), nullable=True, index=True)
    client_id = Column(String(255), nullable=True, index=True)
    server_id = Column(String(255), nullable=True, index=True)
    
    threat_type = Column(Enum(ThreatType), nullable=False)
    risk_level = Column(Enum(RiskLevel), nullable=False)
    confidence = Column(Float, nullable=False)
    
    # Detection details
    detection_source = Column(Enum(DetectionSource), nullable=False)
    triggered_by = Column(String(255), nullable=True)  # Pattern/rule ID or name
    instruction_content = Column(Text, nullable=True)
    analysis_result = Column(JSONB, nullable=True)
    
    # Status
    reviewed = Column(Boolean, default=False, nullable=False)
    review_result = Column(Boolean, nullable=True)  # True for confirmed threat, False for false positive
    review_notes = Column(Text, nullable=True)
    reviewed_by = Column(String(255), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)


# Pydantic Models
class PatternBase(BaseSchema):
    """
    Base schema for detection patterns.
    """
    name: str = Field(..., description="Name of the pattern")
    description: Optional[str] = Field(None, description="Description of the pattern")
    pattern: str = Field(..., description="The pattern string")
    is_regex: bool = Field(True, description="Whether the pattern is a regex")
    threat_type: ThreatType = Field(..., description="Type of threat")
    risk_level: RiskLevel = Field(..., description="Risk level")
    confidence: float = Field(0.8, description="Confidence score (0-1)")
    enabled: bool = Field(True, description="Whether the pattern is enabled")
    version: int = Field(1, description="Pattern version")


class PatternCreate(PatternBase):
    """
    Schema for creating a detection pattern.
    """
    created_by: Optional[str] = Field(None, description="User who created the pattern")


class PatternUpdate(BaseSchema):
    """
    Schema for updating a detection pattern.
    """
    name: Optional[str] = Field(None, description="Name of the pattern")
    description: Optional[str] = Field(None, description="Description of the pattern")
    pattern: Optional[str] = Field(None, description="The pattern string")
    is_regex: Optional[bool] = Field(None, description="Whether the pattern is a regex")
    threat_type: Optional[ThreatType] = Field(None, description="Type of threat")
    risk_level: Optional[RiskLevel] = Field(None, description="Risk level")
    confidence: Optional[float] = Field(None, description="Confidence score (0-1)")
    enabled: Optional[bool] = Field(None, description="Whether the pattern is enabled")
    version: Optional[int] = Field(None, description="Pattern version")
    last_updated_by: Optional[str] = Field(None, description="User who last updated the pattern")


class PatternResponse(PatternBase, UUIDSchema):
    """
    Schema for pattern response.
    """
    created_by: Optional[str] = Field(None, description="User who created the pattern")
    last_updated_by: Optional[str] = Field(None, description="User who last updated the pattern")


class RuleBase(BaseSchema):
    """
    Base schema for detection rules.
    """
    name: str = Field(..., description="Name of the rule")
    description: Optional[str] = Field(None, description="Description of the rule")
    rule_logic: str = Field(..., description="The rule logic")
    threat_type: ThreatType = Field(..., description="Type of threat")
    risk_level: RiskLevel = Field(..., description="Risk level")
    confidence: float = Field(0.8, description="Confidence score (0-1)")
    enabled: bool = Field(True, description="Whether the rule is enabled")
    version: int = Field(1, description="Rule version")


class RuleCreate(RuleBase):
    """
    Schema for creating a detection rule.
    """
    created_by: Optional[str] = Field(None, description="User who created the rule")


class RuleUpdate(BaseSchema):
    """
    Schema for updating a detection rule.
    """
    name: Optional[str] = Field(None, description="Name of the rule")
    description: Optional[str] = Field(None, description="Description of the rule")
    rule_logic: Optional[str] = Field(None, description="The rule logic")
    threat_type: Optional[ThreatType] = Field(None, description="Type of threat")
    risk_level: Optional[RiskLevel] = Field(None, description="Risk level")
    confidence: Optional[float] = Field(None, description="Confidence score (0-1)")
    enabled: Optional[bool] = Field(None, description="Whether the rule is enabled")
    version: Optional[int] = Field(None, description="Rule version")
    last_updated_by: Optional[str] = Field(None, description="User who last updated the rule")


class RuleResponse(RuleBase, UUIDSchema):
    """
    Schema for rule response.
    """
    created_by: Optional[str] = Field(None, description="User who created the rule")
    last_updated_by: Optional[str] = Field(None, description="User who last updated the rule")


class EventBase(BaseSchema):
    """
    Base schema for detection events.
    """
    instruction_id: str = Field(..., description="ID of the instruction")
    session_id: Optional[str] = Field(None, description="ID of the session")
    client_id: Optional[str] = Field(None, description="ID of the client")
    server_id: Optional[str] = Field(None, description="ID of the server")
    
    threat_type: ThreatType = Field(..., description="Type of threat")
    risk_level: RiskLevel = Field(..., description="Risk level")
    confidence: float = Field(..., description="Confidence score (0-1)")
    
    detection_source: DetectionSource = Field(..., description="Source of the detection")
    triggered_by: Optional[str] = Field(None, description="ID or name of the pattern/rule that triggered the detection")
    instruction_content: Optional[str] = Field(None, description="Content of the instruction")
    analysis_result: Optional[Dict[str, Any]] = Field(None, description="Result of the analysis")


class EventCreate(EventBase):
    """
    Schema for creating a detection event.
    """
    pass


class EventUpdate(BaseSchema):
    """
    Schema for updating a detection event.
    """
    reviewed: Optional[bool] = Field(None, description="Whether the event has been reviewed")
    review_result: Optional[bool] = Field(None, description="Result of the review")
    review_notes: Optional[str] = Field(None, description="Notes from the review")
    reviewed_by: Optional[str] = Field(None, description="User who reviewed the event")
    reviewed_at: Optional[datetime] = Field(None, description="Time of review")


class EventResponse(EventBase, UUIDSchema):
    """
    Schema for event response.
    """
    reviewed: bool = Field(..., description="Whether the event has been reviewed")
    review_result: Optional[bool] = Field(None, description="Result of the review")
    review_notes: Optional[str] = Field(None, description="Notes from the review")
    reviewed_by: Optional[str] = Field(None, description="User who reviewed the event")
    reviewed_at: Optional[datetime] = Field(None, description="Time of review")


# For MongoDB - Pattern Storage
class MongoPattern(MongoBaseDocument):
    """
    MongoDB document for storing patterns.
    """
    name: str = Field(..., description="Name of the pattern")
    description: Optional[str] = Field(None, description="Description of the pattern")
    pattern: str = Field(..., description="The pattern string")
    is_regex: bool = Field(True, description="Whether the pattern is a regex")
    threat_type: ThreatType = Field(..., description="Type of threat")
    risk_level: RiskLevel = Field(..., description="Risk level")
    confidence: float = Field(0.8, description="Confidence score (0-1)")
    enabled: bool = Field(True, description="Whether the pattern is enabled")
    
    # Vector representation for semantic matching
    vector: Optional[List[float]] = Field(None, description="Vector representation of the pattern")
    
    # Metadata
    version: int = Field(1, description="Pattern version")
    created_by: Optional[str] = Field(None, description="User who created the pattern")
    last_updated_by: Optional[str] = Field(None, description="User who last updated the pattern")


# Analysis Request/Response Models
class AnalysisRequest(BaseSchema):
    """
    Request model for instruction analysis.
    """
    instruction_id: str = Field(..., description="ID of the instruction")
    session_id: Optional[str] = Field(None, description="ID of the session")
    client_id: Optional[str] = Field(None, description="ID of the client")
    server_id: Optional[str] = Field(None, description="ID of the server")
    instruction_content: str = Field(..., description="Content of the instruction")
    context: Optional[Dict[str, Any]] = Field(None, description="Additional context")


class AnalysisResult(BaseSchema):
    """
    Result of an analysis component.
    """
    component: str = Field(..., description="Name of the analysis component")
    result: Dict[str, Any] = Field(..., description="Analysis result")
    is_threat: bool = Field(..., description="Whether a threat was detected")
    confidence: float = Field(..., description="Confidence score (0-1)")
    threat_type: Optional[ThreatType] = Field(None, description="Type of threat if detected")
    risk_level: Optional[RiskLevel] = Field(None, description="Risk level if a threat was detected")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional details")


class AnalysisResponse(BaseSchema):
    """
    Response model for instruction analysis.
    """
    instruction_id: str = Field(..., description="ID of the instruction")
    is_threat: bool = Field(..., description="Whether a threat was detected")
    threat_type: Optional[ThreatType] = Field(None, description="Type of threat if detected")
    risk_level: Optional[RiskLevel] = Field(None, description="Risk level if a threat was detected")
    confidence: float = Field(..., description="Overall confidence score (0-1)")
    analysis_results: List[AnalysisResult] = Field(..., description="Results from each analysis component")
    event_id: Optional[UUID] = Field(None, description="ID of the created event if a threat was detected") 
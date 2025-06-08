"""
Models for the LLM-based instruction classifier.
"""
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any, Union
from uuid import UUID

from pydantic import Field
from sqlalchemy import Column, DateTime, Enum as SQLEnum, Float, ForeignKey, Integer, String, Text, Boolean, JSON
from sqlalchemy.dialects.postgresql import UUID as SQLUUID, JSONB
from sqlalchemy.orm import relationship

from core.database.connections import Base
from core.models.base import UUIDModel, BaseSchema, UUIDSchema, MongoBaseDocument
from detection_engine.instruction_analysis.models import ThreatType, RiskLevel


class ClassifierProvider(str, Enum):
    """
    Enumeration of LLM classifier providers.
    """
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    HUGGINGFACE = "huggingface"
    LOCAL = "local"
    OTHER = "other"


class ClassifierModel(str, Enum):
    """
    Enumeration of LLM classifier models.
    """
    GPT_4 = "gpt-4"
    GPT_4_TURBO = "gpt-4-turbo"
    GPT_3_5_TURBO = "gpt-3.5-turbo"
    CLAUDE_2 = "claude-2"
    CLAUDE_INSTANT = "claude-instant"
    LLAMA_2 = "llama-2"
    OTHER = "other"


# SQLAlchemy Models
class ClassifierPrompt(UUIDModel):
    """
    Model for an LLM classifier prompt template.
    """
    __tablename__ = "classifier_prompts"

    name = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    prompt_template = Column(Text, nullable=False)
    system_message = Column(Text, nullable=True)
    provider = Column(SQLEnum(ClassifierProvider), nullable=False)
    model = Column(SQLEnum(ClassifierModel), nullable=False)
    
    # Configuration
    temperature = Column(Float, nullable=False, default=0.0)
    max_tokens = Column(Integer, nullable=True)
    enabled = Column(Boolean, default=True, nullable=False)
    is_default = Column(Boolean, default=False, nullable=False)
    
    # Response parsing
    response_format = Column(JSONB, nullable=True)  # JSON schema or structure for parsing
    
    # Performance metrics
    avg_latency_ms = Column(Float, nullable=True)
    accuracy = Column(Float, nullable=True)
    false_positive_rate = Column(Float, nullable=True)
    false_negative_rate = Column(Float, nullable=True)
    
    # Metadata
    version = Column(Integer, nullable=False, default=1)
    created_by = Column(String(255), nullable=True)
    last_updated_by = Column(String(255), nullable=True)


class ClassifierFeedback(UUIDModel):
    """
    Model for feedback on classifier results.
    """
    __tablename__ = "classifier_feedback"

    classification_id = Column(String(255), nullable=False, index=True)
    instruction_id = Column(String(255), nullable=False, index=True)
    prompt_id = Column(SQLUUID(as_uuid=True), ForeignKey("classifier_prompts.id"), nullable=True)
    
    # Original classification
    original_classification = Column(SQLEnum(ThreatType), nullable=False)
    original_risk_level = Column(SQLEnum(RiskLevel), nullable=False)
    original_confidence = Column(Float, nullable=False)
    
    # Feedback
    is_correct = Column(Boolean, nullable=False)
    correct_classification = Column(SQLEnum(ThreatType), nullable=True)
    correct_risk_level = Column(SQLEnum(RiskLevel), nullable=True)
    feedback_notes = Column(Text, nullable=True)
    
    # Metadata
    submitted_by = Column(String(255), nullable=False)
    
    # Relationships
    prompt = relationship("ClassifierPrompt")


# Pydantic Models
class PromptBase(BaseSchema):
    """
    Base schema for classifier prompts.
    """
    name: str = Field(..., description="Name of the prompt template")
    description: Optional[str] = Field(None, description="Description of the prompt template")
    prompt_template: str = Field(..., description="The prompt template text")
    system_message: Optional[str] = Field(None, description="System message for the LLM")
    provider: ClassifierProvider = Field(..., description="LLM provider")
    model: ClassifierModel = Field(..., description="LLM model")
    temperature: float = Field(0.0, description="Temperature for sampling")
    max_tokens: Optional[int] = Field(None, description="Maximum tokens in response")
    enabled: bool = Field(True, description="Whether the prompt is enabled")
    is_default: bool = Field(False, description="Whether this is the default prompt")
    response_format: Optional[Dict[str, Any]] = Field(None, description="Response format schema")
    version: int = Field(1, description="Prompt version")


class PromptCreate(PromptBase):
    """
    Schema for creating a classifier prompt.
    """
    created_by: Optional[str] = Field(None, description="User who created the prompt")


class PromptUpdate(BaseSchema):
    """
    Schema for updating a classifier prompt.
    """
    name: Optional[str] = Field(None, description="Name of the prompt template")
    description: Optional[str] = Field(None, description="Description of the prompt template")
    prompt_template: Optional[str] = Field(None, description="The prompt template text")
    system_message: Optional[str] = Field(None, description="System message for the LLM")
    provider: Optional[ClassifierProvider] = Field(None, description="LLM provider")
    model: Optional[ClassifierModel] = Field(None, description="LLM model")
    temperature: Optional[float] = Field(None, description="Temperature for sampling")
    max_tokens: Optional[int] = Field(None, description="Maximum tokens in response")
    enabled: Optional[bool] = Field(None, description="Whether the prompt is enabled")
    is_default: Optional[bool] = Field(None, description="Whether this is the default prompt")
    response_format: Optional[Dict[str, Any]] = Field(None, description="Response format schema")
    version: Optional[int] = Field(None, description="Prompt version")
    avg_latency_ms: Optional[float] = Field(None, description="Average latency in milliseconds")
    accuracy: Optional[float] = Field(None, description="Accuracy metric")
    false_positive_rate: Optional[float] = Field(None, description="False positive rate")
    false_negative_rate: Optional[float] = Field(None, description="False negative rate")
    last_updated_by: Optional[str] = Field(None, description="User who last updated the prompt")


class PromptResponse(PromptBase, UUIDSchema):
    """
    Schema for prompt response.
    """
    avg_latency_ms: Optional[float] = Field(None, description="Average latency in milliseconds")
    accuracy: Optional[float] = Field(None, description="Accuracy metric")
    false_positive_rate: Optional[float] = Field(None, description="False positive rate")
    false_negative_rate: Optional[float] = Field(None, description="False negative rate")
    created_by: Optional[str] = Field(None, description="User who created the prompt")
    last_updated_by: Optional[str] = Field(None, description="User who last updated the prompt")


class FeedbackBase(BaseSchema):
    """
    Base schema for classifier feedback.
    """
    classification_id: str = Field(..., description="ID of the classification")
    instruction_id: str = Field(..., description="ID of the instruction")
    prompt_id: Optional[UUID] = Field(None, description="ID of the prompt used")
    original_classification: ThreatType = Field(..., description="Original threat type classification")
    original_risk_level: RiskLevel = Field(..., description="Original risk level")
    original_confidence: float = Field(..., description="Original confidence score")
    is_correct: bool = Field(..., description="Whether the classification was correct")
    correct_classification: Optional[ThreatType] = Field(None, description="Correct threat type if original was wrong")
    correct_risk_level: Optional[RiskLevel] = Field(None, description="Correct risk level if original was wrong")
    feedback_notes: Optional[str] = Field(None, description="Additional feedback notes")
    submitted_by: str = Field(..., description="User who submitted the feedback")


class FeedbackCreate(FeedbackBase):
    """
    Schema for creating classifier feedback.
    """
    pass


class FeedbackResponse(FeedbackBase, UUIDSchema):
    """
    Schema for feedback response.
    """
    pass


# Classification Request/Response Models
class ClassificationRequest(BaseSchema):
    """
    Request model for instruction classification.
    """
    instruction_id: str = Field(..., description="ID of the instruction")
    instruction_content: str = Field(..., description="Content of the instruction")
    context: Optional[Dict[str, Any]] = Field(None, description="Additional context")
    prompt_id: Optional[UUID] = Field(None, description="ID of specific prompt to use (uses default if not provided)")


class ClassificationResponse(BaseSchema):
    """
    Response model for instruction classification.
    """
    classification_id: str = Field(..., description="ID of the classification")
    instruction_id: str = Field(..., description="ID of the instruction")
    is_threat: bool = Field(..., description="Whether the instruction was classified as a threat")
    threat_type: Optional[ThreatType] = Field(None, description="Type of threat if detected")
    risk_level: Optional[RiskLevel] = Field(None, description="Risk level if a threat was detected")
    confidence: float = Field(..., description="Confidence score (0-1)")
    reasoning: str = Field(..., description="Reasoning behind the classification")
    prompt_id: UUID = Field(..., description="ID of the prompt used")
    model: ClassifierModel = Field(..., description="Model used for classification")
    provider: ClassifierProvider = Field(..., description="Provider used for classification")
    latency_ms: float = Field(..., description="Latency in milliseconds")
    raw_response: Optional[Dict[str, Any]] = Field(None, description="Raw response from the LLM") 
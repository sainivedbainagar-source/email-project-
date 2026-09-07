"""Pydantic schemas and models for AI-powered email content analysis."""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class AIAnalysisStatus(str, Enum):
    """Execution status of the AI content analysis service."""

    COMPLETED = "completed"
    NOT_CHECKED = "not_checked"
    UNAVAILABLE = "unavailable"


class ContentThreatLevel(str, Enum):
    """Categorization of overall content threat severity."""

    BENIGN = "benign"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"
    NOT_CHECKED = "not_checked"


class AIContentAnalysis(BaseModel):
    """Structured report produced by the AI content analysis engine."""

    status: AIAnalysisStatus = Field(
        default=AIAnalysisStatus.NOT_CHECKED,
        description="Execution status of the AI analysis (completed, not_checked, unavailable).",
    )
    overall_threat_level: ContentThreatLevel = Field(
        default=ContentThreatLevel.NOT_CHECKED,
        description="Overall threat level determined from subject and body analysis.",
    )
    phishing_indicators: List[str] = Field(
        default_factory=list,
        description="Specific phishing tactics, misleading statements, or deceptive links detected.",
    )
    urgency_pressure_tactics: List[str] = Field(
        default_factory=list,
        description="Pressure tactics, artificial urgency, or threat of negative consequences.",
    )
    impersonation_detected: bool = Field(
        default=False,
        description="Whether the sender attempts to impersonate an organization, executive, or brand.",
    )
    impersonated_entities: List[str] = Field(
        default_factory=list,
        description="Names of organizations, brands, or executives being impersonated.",
    )
    credential_harvesting_detected: bool = Field(
        default=False,
        description="Whether the content attempts to harvest login credentials, passwords, or tokens.",
    )
    financial_requests_detected: bool = Field(
        default=False,
        description="Whether the content solicits financial payments, wire transfers, or gift cards.",
    )
    social_engineering_patterns: List[str] = Field(
        default_factory=list,
        description="Psychological triggers and manipulation patterns identified in the message.",
    )
    summary: Optional[str] = Field(
        default=None,
        description="Analytical rationale and narrative summary from the AI model.",
    )
    provider: str = Field(
        default="groq",
        description="AI/LLM provider name (e.g. groq).",
    )
    model: Optional[str] = Field(
        default=None,
        description="Specific model identifier utilized for evaluation.",
    )
    error_message: Optional[str] = Field(
        default=None,
        description="Diagnostic information if the AI service was unavailable or encountered an error.",
    )

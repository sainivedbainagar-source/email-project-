"""Pydantic schemas and models for deterministic risk scoring."""

from enum import Enum
from typing import List
from pydantic import BaseModel, Field


class ThreatLevel(str, Enum):
    """Categorization of overall email threat severity mapped from numerical risk score."""

    LOW = "low"            # 0–24
    MEDIUM = "medium"      # 25–49
    HIGH = "high"          # 50–74
    CRITICAL = "critical"  # 75–100


class RiskFactor(BaseModel):
    """Individual rule or evidence item contributing points to the overall risk score."""

    factor: str = Field(..., description="Unique identifier or name of the risk factor rule.")
    points: int = Field(..., description="Points added to the aggregate risk score.")
    reason: str = Field(..., description="Human-readable explanation and evidence supporting this risk factor.")


class RiskScore(BaseModel):
    """Consolidated deterministic risk assessment for the analyzed email."""

    score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Calculated composite risk score bounded between 0 and 100.",
    )
    threat_level: ThreatLevel = Field(
        ...,
        description="Mapped severity threat level (low: 0-24, medium: 25-49, high: 50-74, critical: 75-100).",
    )
    factors: List[RiskFactor] = Field(
        default_factory=list,
        description="Itemized list of all triggered risk factors with point weights and reasons.",
    )
    summary: str = Field(
        ...,
        description="Executive summary explaining the composite risk determination.",
    )

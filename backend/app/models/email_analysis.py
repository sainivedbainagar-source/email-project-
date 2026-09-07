"""Pydantic schemas and models for email analysis and header forensics."""

from typing import List, Optional
from pydantic import AliasChoices, BaseModel, ConfigDict, Field

from app.models.ai_analysis import AIContentAnalysis
from app.models.graph import InvestigationGraph
from app.models.risk_scoring import RiskScore, ThreatLevel
from app.models.threat_intel import ThreatIntelligenceReport


class EmailAnalysisRequest(BaseModel):
    """Request model containing raw email content for analysis."""

    raw_email: str = Field(
        ...,
        description="Raw RFC 822 / RFC 2822 / RFC 5322 email text string.",
        examples=[
            "From: sender@example.com\nTo: recipient@example.com\nSubject: Test\n\nHello world"
        ],
    )


class AuthenticationResult(BaseModel):
    """Structured email authentication results (SPF, DKIM, DMARC)."""

    spf: str = Field(
        default="none",
        description="SPF verification result (e.g. pass, fail, softfail, neutral, none).",
    )
    dkim: str = Field(
        default="none",
        description="DKIM verification result (e.g. pass, fail, none).",
    )
    dmarc: str = Field(
        default="none",
        description="DMARC verification result (e.g. pass, fail, none).",
    )
    details: Optional[str] = Field(
        default=None,
        description="Raw authentication header summary or details.",
    )


class HeaderMismatch(BaseModel):
    """Flags and descriptions for discrepancies among email headers."""

    has_mismatch: bool = Field(
        default=False,
        description="True if any significant header discrepancy was detected.",
    )
    from_reply_to_mismatch: bool = Field(
        default=False,
        description="True if From domain differs from Reply-To domain.",
    )
    from_return_path_mismatch: bool = Field(
        default=False,
        description="True if From domain differs from Return-Path domain.",
    )
    indicators: List[str] = Field(
        default_factory=list,
        description="Human-readable mismatch and forensic indicator descriptions.",
    )


class HeaderForensics(BaseModel):
    """Domain and network forensic metadata extracted from headers."""

    from_domain: Optional[str] = Field(
        default=None,
        description="Extracted domain of the From sender address.",
    )
    reply_to_domain: Optional[str] = Field(
        default=None,
        description="Extracted domain of the Reply-To address.",
    )
    return_path_domain: Optional[str] = Field(
        default=None,
        description="Extracted domain of the Return-Path envelope sender.",
    )
    received_ips: List[str] = Field(
        default_factory=list,
        description="Validated IP addresses extracted from Received transit headers.",
    )
    mismatches: HeaderMismatch = Field(
        default_factory=HeaderMismatch,
        description="Detailed header mismatch indicators.",
    )


class EmailAnalysisResponse(BaseModel):
    """Response model with extracted email headers, body, URLs, authentication, and forensics."""

    from_: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices("from", "from_", "From"),
        serialization_alias="from",
        description="Sender email address from the From header.",
    )
    to: Optional[str] = Field(
        default=None,
        description="Recipient email address from the To header.",
    )
    subject: Optional[str] = Field(
        default=None,
        description="Email subject line.",
    )
    date: Optional[str] = Field(
        default=None,
        description="Date and time when the email was sent.",
    )
    reply_to: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices("reply_to", "reply-to", "Reply-To"),
        serialization_alias="reply_to",
        description="Reply-To header address.",
    )
    return_path: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices("return_path", "return-path", "Return-Path"),
        serialization_alias="return_path",
        description="Return-Path header address.",
    )
    message_id: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices("message_id", "message-id", "Message-ID"),
        serialization_alias="message_id",
        description="Unique Message-ID header.",
    )
    received: List[str] = Field(
        default_factory=list,
        description="List of Received headers tracking the message transit hops.",
    )
    body: str = Field(
        default="",
        description="Extracted email body content.",
    )
    urls: List[str] = Field(
        default_factory=list,
        description="List of unique URLs extracted from the email body.",
    )

    # Deterministic Authentication results
    spf: str = Field(
        default="none",
        description="Deterministic SPF result (pass, fail, softfail, neutral, none).",
    )
    dkim: str = Field(
        default="none",
        description="Deterministic DKIM result (pass, fail, none).",
    )
    dmarc: str = Field(
        default="none",
        description="Deterministic DMARC result (pass, fail, none).",
    )

    # Domain forensics & IP addresses
    from_domain: Optional[str] = Field(
        default=None,
        description="Domain parsed from the From header.",
    )
    reply_to_domain: Optional[str] = Field(
        default=None,
        description="Domain parsed from the Reply-To header.",
    )
    return_path_domain: Optional[str] = Field(
        default=None,
        description="Domain parsed from the Return-Path header.",
    )
    received_ips: List[str] = Field(
        default_factory=list,
        description="IP addresses parsed from Received headers.",
    )
    mismatch_indicators: List[str] = Field(
        default_factory=list,
        description="List of detected header discrepancies and warning indicators.",
    )

    # Structured sub-models for granular access
    authentication: AuthenticationResult = Field(
        default_factory=AuthenticationResult,
        description="Structured authentication details.",
    )
    forensics: HeaderForensics = Field(
        default_factory=HeaderForensics,
        description="Structured header forensic details.",
    )
    threat_intelligence: ThreatIntelligenceReport = Field(
        default_factory=ThreatIntelligenceReport,
        description="Deterministic threat intelligence report for extracted IPs and domains.",
    )
    ai_analysis: AIContentAnalysis = Field(
        default_factory=AIContentAnalysis,
        description="AI-powered analysis of email subject and body content.",
    )
    risk_score: RiskScore = Field(
        default_factory=lambda: RiskScore(
            score=0,
            threat_level=ThreatLevel.LOW,
            factors=[],
            summary="Clean email with no elevated risk indicators.",
        ),
        description="Deterministic risk score and itemized threat factors.",
    )
    investigation_graph: InvestigationGraph = Field(
        default_factory=lambda: InvestigationGraph(
            nodes=[],
            edges=[],
            summary="Empty investigation graph.",
        ),
        description="Deterministic graph correlation connecting message entities, domains, URLs, and IPs.",
    )

    model_config = ConfigDict(
        populate_by_name=True,
    )

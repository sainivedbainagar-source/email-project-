"""Pydantic schemas and models for comprehensive forensic report generation."""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.models.risk_scoring import ThreatLevel


class FindingSeverity(str, Enum):
    """Severity classification for an individual forensic report finding."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingCategory(str, Enum):
    """Domain category for forensic findings."""

    AUTHENTICATION = "authentication"
    HEADER_FORENSICS = "header_forensics"
    CONTENT_ANALYSIS = "content_analysis"
    THREAT_INTELLIGENCE = "threat_intelligence"
    INFRASTRUCTURE = "infrastructure"
    GRAPH_CORRELATION = "graph_correlation"


class ActionPriority(str, Enum):
    """Urgency priority for recommended remediation actions."""

    IMMEDIATE = "immediate"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class EvidenceType(str, Enum):
    """Classification of raw forensic evidence artifacts."""

    HEADER = "header"
    BODY_CONTENT = "body_content"
    URL = "url"
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    AI_INFERENCE = "ai_inference"
    GRAPH_LINKAGE = "graph_linkage"


class EmailMetadata(BaseModel):
    """Key metadata elements extracted from the subject email."""

    message_id: Optional[str] = Field(default=None, description="Message-ID header value.")
    date: Optional[str] = Field(default=None, description="Date header value.")
    subject: Optional[str] = Field(default=None, description="Email subject line.")
    from_address: Optional[str] = Field(default=None, description="Full From header address.")
    to_address: Optional[str] = Field(default=None, description="Full To header address.")
    reply_to_address: Optional[str] = Field(default=None, description="Full Reply-To header address.")
    return_path_address: Optional[str] = Field(default=None, description="Full Return-Path envelope address.")


class ReportEvidence(BaseModel):
    """Atomic piece of factual, observable evidence extracted from email artifacts."""

    id: str = Field(..., description="Unique evidence identifier (e.g. 'EVD-001').")
    type: EvidenceType = Field(..., description="Classification category of this evidence artifact.")
    source: str = Field(..., description="Originating header or component where evidence was observed.")
    raw_value: str = Field(..., description="Exact string or representation of the observed artifact.")
    description: str = Field(..., description="Objective, factual description of the observed artifact.")


class ReportFinding(BaseModel):
    """Explainable forensic finding derived strictly from observed evidence."""

    id: str = Field(..., description="Unique finding identifier (e.g. 'FND-001').")
    title: str = Field(..., description="Concise, descriptive title of the forensic finding.")
    category: FindingCategory = Field(..., description="Categorical classification of the finding.")
    severity: FindingSeverity = Field(..., description="Assessed severity level.")
    description: str = Field(..., description="Detailed, explainable analysis of why this finding was raised.")
    evidence_ids: List[str] = Field(
        default_factory=list,
        description="IDs of supporting ReportEvidence items establishing strict traceability.",
    )
    mitigation_hint: Optional[str] = Field(
        default=None,
        description="Optional tactical hint or operational takeaway.",
    )


class RecommendedAction(BaseModel):
    """Prescriptive operational remediation step tailored to findings and threat severity."""

    id: str = Field(..., description="Unique action identifier (e.g. 'ACT-001').")
    priority: ActionPriority = Field(..., description="Urgency priority of the recommendation.")
    action: str = Field(..., description="Concrete action to be executed.")
    rationale: str = Field(..., description="Forensic justification for the recommendation.")
    target_audience: str = Field(
        ...,
        description="Primary stakeholder role responsible for action (SOC Analyst, Mail Administrator, End User).",
    )


class ReportSummary(BaseModel):
    """High-level executive overview of the forensic investigation."""

    threat_level: ThreatLevel = Field(..., description="Overall assessed threat level (low, medium, high, critical).")
    risk_score: int = Field(..., ge=0, le=100, description="Numerical deterministic risk score from 0 to 100.")
    summary_text: str = Field(..., description="Cohesive narrative summary for decision makers.")
    key_findings_count: int = Field(..., description="Total count of detailed findings generated in this report.")
    critical_indicators: List[str] = Field(
        default_factory=list,
        description="Key threat signals triggering elevated risk.",
    )


class ReportAuthenticationSection(BaseModel):
    """Structured email authentication results with verification scope clarification."""

    spf: str = Field(default="none", description="Header-reported SPF result.")
    dkim: str = Field(default="none", description="Header-reported DKIM result.")
    dmarc: str = Field(default="none", description="Header-reported DMARC result.")
    details: Optional[str] = Field(default=None, description="Authentication header raw details.")
    verification_scope_note: str = Field(
        default="Extracted from message headers; not an authoritative DNS or cryptographic validation.",
        description="Clarification regarding the verification authority scope.",
    )


class ReportHeaderForensicsSection(BaseModel):
    """Forensic breakdown of sender domains, routing hops, and mismatch anomalies."""

    from_domain: Optional[str] = Field(default=None, description="Sender domain parsed from From header.")
    reply_to_domain: Optional[str] = Field(default=None, description="Reply-to destination domain.")
    return_path_domain: Optional[str] = Field(default=None, description="Return-path bounce destination domain.")
    received_ips: List[str] = Field(default_factory=list, description="Transit relay IPs extracted from Received headers.")
    mismatch_indicators: List[str] = Field(default_factory=list, description="Discrepancies identified among headers.")


class ReportExtractedIndicators(BaseModel):
    """Aggregate collection of network indicators discovered across all email components."""

    urls: List[str] = Field(default_factory=list, description="Unique URLs extracted from email body.")
    domains: List[str] = Field(default_factory=list, description="Unique domains identified in headers and URLs.")
    ips: List[str] = Field(default_factory=list, description="Unique IP addresses identified in transit and URLs.")


class ReportThreatIntelligenceSection(BaseModel):
    """Summary of threat intelligence classifications."""

    total_ips_evaluated: int = Field(default=0, description="Count of evaluated IP addresses.")
    total_domains_evaluated: int = Field(default=0, description="Count of evaluated domains.")
    summary: str = Field(default="", description="Threat intelligence summary narrative.")
    external_feeds_queried: bool = Field(
        default=False,
        description="True if external threat reputation feeds were queried; False for deterministic local evaluation.",
    )


class ReportAIAnalysisSection(BaseModel):
    """Summary of AI content analysis findings."""

    status: str = Field(default="not_checked", description="Execution status of AI analysis.")
    overall_threat_level: Optional[str] = Field(default=None, description="AI-assessed content threat level.")
    summary: Optional[str] = Field(default=None, description="AI-generated content summary.")
    impersonation_detected: bool = Field(default=False, description="Whether brand or executive impersonation was detected.")
    credential_harvesting_detected: bool = Field(default=False, description="Whether credential harvesting was detected.")
    urgency_detected: bool = Field(default=False, description="Whether urgency or coercion tactics were detected.")
    financial_requests_detected: bool = Field(default=False, description="Whether financial/payment requests were detected.")
    provider: Optional[str] = Field(default=None, description="AI provider used (or None if skipped).")


class ReportGraphSummary(BaseModel):
    """Summary of the correlated entity investigation graph."""

    total_nodes: int = Field(default=0, description="Total entity nodes in graph.")
    total_edges: int = Field(default=0, description="Total relationship links in graph.")
    summary: str = Field(default="", description="High-level narrative graph correlation summary.")
    key_linkages: List[str] = Field(default_factory=list, description="Notable relationship links highlighted in report.")


class ForensicReport(BaseModel):
    """Complete, structured, and explainable forensic investigation report."""

    report_id: str = Field(..., description="Unique case / report identifier (e.g. 'REP-20260907-...').")
    generated_at: str = Field(..., description="ISO 8601 UTC timestamp of report generation.")
    email_metadata: EmailMetadata = Field(..., description="Extracted core email metadata.")
    executive_summary: ReportSummary = Field(..., description="High-level executive overview.")
    authentication: ReportAuthenticationSection = Field(..., description="Authentication evaluation results.")
    header_forensics: ReportHeaderForensicsSection = Field(..., description="Header forensics analysis.")
    extracted_indicators: ReportExtractedIndicators = Field(..., description="Extracted network indicators.")
    threat_intelligence: ReportThreatIntelligenceSection = Field(..., description="Threat intelligence evaluation.")
    ai_analysis: ReportAIAnalysisSection = Field(..., description="AI content analysis evaluation.")
    investigation_graph: ReportGraphSummary = Field(..., description="Correlated entity graph summary.")
    detailed_findings: List[ReportFinding] = Field(
        default_factory=list,
        description="Explainable forensic findings, each strictly linked to supporting evidence.",
    )
    evidence_list: List[ReportEvidence] = Field(
        default_factory=list,
        description="Complete list of factual, observable evidence items extracted from message.",
    )
    recommended_actions: List[RecommendedAction] = Field(
        default_factory=list,
        description="Prescriptive operational remediation steps.",
    )
    disclaimers: List[str] = Field(
        default_factory=list,
        description="Standard legal and technical forensic disclaimers.",
    )

"""Services package."""

from app.services.ai_analysis import (
    BaseAIContentAnalyzer,
    GroqContentAnalyzer,
    AIAnalysisService,
    get_ai_service,
)
from app.services.email_auth import (
    BaseEmailAuthenticator,
    HeaderBasedAuthenticator,
    get_authenticator,
)
from app.services.email_parser import extract_body, extract_urls, parse_raw_email
from app.services.forensic_report import ForensicReportService, get_forensic_report_service
from app.services.graph_correlation import GraphCorrelationService, get_graph_correlation_service
from app.services.header_forensics import (
    analyze_header_mismatches,
    extract_domain,
    extract_header_forensics,
    extract_ips_from_received,
)
from app.services.risk_scoring import RiskScoringService, get_risk_scoring_service
from app.services.threat_intel import (
    BaseThreatIntelProvider,
    LocalDeterministicProvider,
    ThreatIntelService,
    get_threat_intel_service,
)

__all__ = [
    "parse_raw_email",
    "extract_urls",
    "extract_body",
    "BaseEmailAuthenticator",
    "HeaderBasedAuthenticator",
    "get_authenticator",
    "extract_domain",
    "extract_ips_from_received",
    "analyze_header_mismatches",
    "extract_header_forensics",
    "BaseThreatIntelProvider",
    "LocalDeterministicProvider",
    "ThreatIntelService",
    "get_threat_intel_service",
    "BaseAIContentAnalyzer",
    "GroqContentAnalyzer",
    "AIAnalysisService",
    "get_ai_service",
    "RiskScoringService",
    "get_risk_scoring_service",
    "GraphCorrelationService",
    "get_graph_correlation_service",
    "ForensicReportService",
    "get_forensic_report_service",
]

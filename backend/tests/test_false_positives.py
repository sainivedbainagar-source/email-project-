"""Regression test suite verifying false-positive prevention and true-phishing preservation."""

import pytest

from app.models.ai_analysis import AIAnalysisStatus, AIContentAnalysis, ContentThreatLevel
from app.models.email_analysis import AuthenticationResult, HeaderForensics, HeaderMismatch
from app.models.risk_scoring import RiskScore, ThreatLevel
from app.models.threat_intel import (
    DomainThreatReport,
    IPClassification,
    IPThreatReport,
    IPType,
    ThreatIntelligenceReport,
    ThreatStatus,
)
from app.services.header_forensics import (
    analyze_header_mismatches,
    extract_header_forensics,
    get_registered_domain,
    is_same_organization,
)
from app.services.risk_scoring import RiskScoringService


# ---------------------------------------------------------------------------
# 1. Organizational Domain (eTLD+1) Extraction & Alignment Tests
# ---------------------------------------------------------------------------

def test_organizational_domain_extraction():
    """Verify that get_registered_domain correctly extracts eTLD+1."""
    assert get_registered_domain("google.com") == "google.com"
    assert get_registered_domain("scoutcamp.bounces.google.com") == "google.com"
    assert get_registered_domain("workspace.google.com") == "google.com"
    assert get_registered_domain("mail.paypal.com") == "paypal.com"
    assert get_registered_domain("support.service.co.uk") == "service.co.uk"
    assert get_registered_domain("evil-domain.xyz") == "evil-domain.xyz"
    assert get_registered_domain("paypa1-security.com") == "paypa1-security.com"


def test_is_same_organization():
    """Verify that subdomains of the same organization are matched correctly."""
    assert is_same_organization("google.com", "scoutcamp.bounces.google.com") is True
    assert is_same_organization("google.com", "workspace.google.com") is True
    assert is_same_organization("paypal.com", "mail.paypal.com") is True
    assert is_same_organization("paypal.com", "paypal.com") is True

    # Genuine cross-organization mismatches
    assert is_same_organization("paypal.com", "paypa1-security.com") is False
    assert is_same_organization("paypal.com", "evil-server.net") is False
    assert is_same_organization("google.com", "phish-google.com") is False


def test_header_mismatch_does_not_flag_legitimate_subdomains():
    """Verify that Return-Path subdomains under the same organization are not mismatches."""
    result = analyze_header_mismatches(
        from_domain="google.com",
        reply_to_domain="workspace.google.com",
        return_path_domain="scoutcamp.bounces.google.com",
    )

    assert result.from_reply_to_mismatch is False
    assert result.from_return_path_mismatch is False
    assert result.has_mismatch is False
    assert len(result.indicators) == 0


def test_header_mismatch_flags_genuine_third_party_infrastructure():
    """Verify that routing diverted to an external domain is flagged as a mismatch."""
    result = analyze_header_mismatches(
        from_domain="paypal.com",
        reply_to_domain="support@paypa1-security.com",
        return_path_domain="bounces@evil-server.net",
    )

    assert result.from_reply_to_mismatch is True
    assert result.from_return_path_mismatch is True
    assert result.has_mismatch is True
    assert len(result.indicators) >= 2


# ---------------------------------------------------------------------------
# 2. Legitimate Authenticated Email False-Positive Prevention Tests
# ---------------------------------------------------------------------------

def test_legitimate_authenticated_google_workspace_email_is_low_risk():
    """Verify that a legitimate authenticated email with subdomains and promotional text is classified as LOW risk."""
    service = RiskScoringService()

    # Fully passing authentication
    auth = AuthenticationResult(spf="pass", dkim="pass", dmarc="pass")

    # Header forensics with matching organizational domains
    forensics = extract_header_forensics(
        from_header="The Google Workspace Team <workspace-noreply@google.com>",
        reply_to_header=None,
        return_path_header="<scoutcamp.bounces.google.com>",
        received_headers=["from mail-sor.google.com ([209.85.220.69]) by mx.google.com"],
        auth_result=auth,
    )

    threat_intel = ThreatIntelligenceReport()

    # Marketing content: promotional discount, no credential theft, first-party Google communication
    ai = AIContentAnalysis(
        status=AIAnalysisStatus.COMPLETED,
        overall_threat_level=ContentThreatLevel.LOW,
        phishing_indicators=[],
        urgency_pressure_tactics=[],  # Promotional discount is not coercive panic
        impersonation_detected=False,  # Email is from Google itself
        credential_harvesting_detected=False,
        financial_requests_detected=False,
        summary="Legitimate promotional marketing from Google Workspace.",
    )

    urls = [
        "https://workspace.google.com/pricing",
        "https://myaccount.google.com/communication-preferences",
        "https://c.gle/ACT4xYwHnsElpe",
    ]

    result: RiskScore = service.calculate_risk(auth, forensics, threat_intel, ai, urls)

    # Must be safely classified as LOW (0 - 24)
    assert result.score < 25
    assert result.threat_level == ThreatLevel.LOW
    assert "FROM_RETURN_PATH_MISMATCH" not in [f.factor for f in result.factors]
    assert "AI_IMPERSONATION_DETECTED" not in [f.factor for f in result.factors]


# ---------------------------------------------------------------------------
# 3. True Phishing Preservation Regression Tests
# ---------------------------------------------------------------------------

def test_genuine_paypal_phishing_remains_critical():
    """Verify that a genuine PayPal phishing lure with auth failures and credential harvesting produces CRITICAL risk."""
    service = RiskScoringService()

    auth = AuthenticationResult(spf="fail", dkim="fail", dmarc="fail")

    forensics = extract_header_forensics(
        from_header="PayPal Support <service@paypal.com>",
        reply_to_header="support@paypa1-security.com",
        return_path_header="bounces@evil-server.net",
        received_headers=["from evil-server.net ([203.0.113.111]) by mx.victim.com"],
        auth_result=auth,
    )

    threat_intel = ThreatIntelligenceReport(
        domains=[
            DomainThreatReport(
                domain="paypa1-security.com",
                raw_domain="paypa1-security.com",
                threat_status=ThreatStatus.MALICIOUS,
            )
        ]
    )

    ai = AIContentAnalysis(
        status=AIAnalysisStatus.COMPLETED,
        overall_threat_level=ContentThreatLevel.CRITICAL,
        phishing_indicators=["Account restriction threat", "Deceptive verification portal"],
        urgency_pressure_tactics=["Account will be terminated in 24 hours"],
        impersonation_detected=True,
        impersonated_entities=["PayPal"],
        credential_harvesting_detected=True,
        financial_requests_detected=False,
        summary="Critical phishing attack attempting PayPal credential theft.",
    )

    urls = ["https://paypa1-security.com/restore-login"]

    result: RiskScore = service.calculate_risk(auth, forensics, threat_intel, ai, urls)

    assert result.score >= 75
    assert result.threat_level == ThreatLevel.CRITICAL
    factor_names = [f.factor for f in result.factors]
    assert "FROM_REPLY_TO_MISMATCH" in factor_names
    assert "FROM_RETURN_PATH_MISMATCH" in factor_names
    assert "SPF_AUTHENTICATION_FAILED" in factor_names
    assert "DMARC_POLICY_FAILED" in factor_names
    assert "AI_CREDENTIAL_HARVESTING" in factor_names
    assert "COMPOUND_CREDENTIAL_PHISHING_LURE" in factor_names


def test_credential_harvesting_on_attacker_authenticated_domain():
    """Verify that an attacker who configures SPF/DKIM on their own domain still scores HIGH/CRITICAL if harvesting credentials."""
    service = RiskScoringService()

    # Attacker owns bad-actor.com and passes SPF/DKIM on their own domain
    auth = AuthenticationResult(spf="pass", dkim="pass", dmarc="pass")

    forensics = extract_header_forensics(
        from_header="PayPal Security <security@bad-actor.com>",
        reply_to_header="security@bad-actor.com",
        return_path_header="bounces@bad-actor.com",
        received_headers=[],
        auth_result=auth,
    )

    threat_intel = ThreatIntelligenceReport()

    # But active credential harvesting and brand impersonation are present
    ai = AIContentAnalysis(
        status=AIAnalysisStatus.COMPLETED,
        overall_threat_level=ContentThreatLevel.CRITICAL,
        phishing_indicators=["Fake login page"],
        urgency_pressure_tactics=["Immediate action required"],
        impersonation_detected=True,
        impersonated_entities=["PayPal"],
        credential_harvesting_detected=True,
        financial_requests_detected=False,
    )

    urls = ["https://login-verify.bad-actor.com/signin"]

    result: RiskScore = service.calculate_risk(auth, forensics, threat_intel, ai, urls)

    # Auth passing does NOT make credential harvesting safe: must still score at least HIGH
    assert result.score >= 50
    assert result.threat_level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL)
    assert "AI_CREDENTIAL_HARVESTING" in [f.factor for f in result.factors]

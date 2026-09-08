"""Automated unit and integration tests for the deterministic Risk Scoring Engine."""

import json
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models.ai_analysis import AIAnalysisStatus, AIContentAnalysis, ContentThreatLevel
from app.models.email_analysis import AuthenticationResult, HeaderForensics, HeaderMismatch
from app.models.risk_scoring import RiskScore, ThreatLevel
from app.models.threat_intel import DomainThreatReport, IPClassification, IPThreatReport, IPType, ThreatIntelligenceReport, ThreatStatus
from app.services.risk_scoring import RiskScoringService

client = TestClient(app)
ENDPOINT = "/api/v1/analyze-email"


# ---------------------------------------------------------------------------
# Unit Tests: Direct Evaluation via RiskScoringService
# ---------------------------------------------------------------------------

def test_risk_scoring_benign_clean_email():
    """Verify that a legitimate, fully aligned email scores 0 points (low risk)."""
    service = RiskScoringService()

    auth = AuthenticationResult(spf="pass", dkim="pass", dmarc="pass")
    forensics = HeaderForensics(
        from_domain="trustedcorp.com",
        reply_to_domain="trustedcorp.com",
        return_path_domain="trustedcorp.com",
        received_ips=["192.0.2.1"],
        mismatches=HeaderMismatch(has_mismatch=False),
    )
    threat_intel = ThreatIntelligenceReport(
        ips=[
            IPThreatReport(
                ip="192.0.2.1",
                ip_type=IPType.IPV4,
                classification=IPClassification.RESERVED,
                is_routable=False,
                threat_status=ThreatStatus.NOT_CHECKED,
            )
        ],
        domains=[
            DomainThreatReport(
                domain="trustedcorp.com",
                raw_domain="trustedcorp.com",
                tld="com",
                is_punycode=False,
                threat_status=ThreatStatus.NOT_CHECKED,
            )
        ],
    )
    ai = AIContentAnalysis(
        status=AIAnalysisStatus.COMPLETED,
        overall_threat_level=ContentThreatLevel.BENIGN,
    )
    urls = ["https://trustedcorp.com/portal"]

    result: RiskScore = service.calculate_risk(auth, forensics, threat_intel, ai, urls)

    assert result.score == 0
    assert result.threat_level == ThreatLevel.LOW
    assert len(result.factors) == 0
    assert "Clean email" in result.summary


def test_risk_scoring_medium_risk_header_mismatches_only():
    """Verify medium risk (25-49) when From domain mismatches Reply-To and Return-Path."""
    service = RiskScoringService()

    auth = AuthenticationResult(spf="pass", dkim="pass", dmarc="pass")
    forensics = HeaderForensics(
        from_domain="company.com",
        reply_to_domain="external-redirect.xyz",
        return_path_domain="bounce-tracker.net",
        mismatches=HeaderMismatch(
            has_mismatch=True,
            from_reply_to_mismatch=True,
            from_return_path_mismatch=True,
        ),
    )
    threat_intel = ThreatIntelligenceReport()
    ai = AIContentAnalysis(status=AIAnalysisStatus.NOT_CHECKED)

    # Expected: FROM_REPLY_TO_MISMATCH (+15) + FROM_RETURN_PATH_MISMATCH (+10) = 25
    result = service.calculate_risk(auth, forensics, threat_intel, ai, urls=[])

    assert result.score == 25
    assert result.threat_level == ThreatLevel.MEDIUM
    factor_names = [f.factor for f in result.factors]
    assert "FROM_REPLY_TO_MISMATCH" in factor_names
    assert "FROM_RETURN_PATH_MISMATCH" in factor_names


def test_risk_scoring_medium_risk_authentication_failures_only():
    """Verify medium risk from combined SPF fail (+15), DMARC fail (+15), and DKIM fail (+10) = 40 points."""
    service = RiskScoringService()

    auth = AuthenticationResult(spf="fail", dkim="fail", dmarc="fail")
    forensics = HeaderForensics(
        from_domain="bank.com",
        reply_to_domain="bank.com",
        return_path_domain="bank.com",
        mismatches=HeaderMismatch(has_mismatch=False),
    )
    threat_intel = ThreatIntelligenceReport()
    ai = AIContentAnalysis(status=AIAnalysisStatus.NOT_CHECKED)

    result = service.calculate_risk(auth, forensics, threat_intel, ai, urls=[])

    assert result.score == 40
    assert result.threat_level == ThreatLevel.MEDIUM
    factor_names = [f.factor for f in result.factors]
    assert "SPF_AUTHENTICATION_FAILED" in factor_names
    assert "DMARC_POLICY_FAILED" in factor_names
    assert "DKIM_SIGNATURE_FAILED" in factor_names


def test_risk_scoring_high_risk_composite():
    """Verify high risk (50-74) with combined auth failures and domain redirect."""
    service = RiskScoringService()

    # SPF fail (15) + DMARC fail (15) + From vs Reply-To mismatch (15) + External link (5) = 50
    auth = AuthenticationResult(spf="fail", dkim="pass", dmarc="fail")
    forensics = HeaderForensics(
        from_domain="security-alert.com",
        reply_to_domain="attacker-drop.com",
        mismatches=HeaderMismatch(has_mismatch=True, from_reply_to_mismatch=True),
    )
    threat_intel = ThreatIntelligenceReport()
    ai = AIContentAnalysis(status=AIAnalysisStatus.NOT_CHECKED)
    urls = ["https://phish-portal.example/login"]

    result = service.calculate_risk(auth, forensics, threat_intel, ai, urls)

    assert result.score == 50
    assert result.threat_level == ThreatLevel.HIGH


def test_risk_scoring_critical_paypal_phishing_scenario():
    """Verify critical threat level (75-100) on a comprehensive phishing scenario mimicking PayPal spoofing."""
    service = RiskScoringService()

    # Auth: SPF fail (15) + DMARC fail (15) + DKIM fail (10) = 40
    auth = AuthenticationResult(spf="fail", dkim="fail", dmarc="fail")

    # Forensics: From vs Reply-To (15) + From vs Return-Path (10) + Display name deception (10) = 35
    forensics = HeaderForensics(
        from_domain="paypal.com",
        reply_to_domain="evil-stealer.xyz",
        return_path_domain="bounces-phish.net",
        mismatches=HeaderMismatch(
            has_mismatch=True,
            from_reply_to_mismatch=True,
            from_return_path_mismatch=True,
            indicators=["Display name 'support@paypal.com' mimics domain 'paypal.com' but actual sender is 'evil-stealer.xyz'"],
        ),
    )

    # Threat Intel: External URL link domain mismatch (5)
    threat_intel = ThreatIntelligenceReport(
        domains=[
            DomainThreatReport(
                domain="evil-stealer.xyz",
                raw_domain="evil-stealer.xyz",
                tld="xyz",
            )
        ]
    )

    # AI: Credential harvesting (15) + Impersonation (10) + Urgency (5) = 30
    ai = AIContentAnalysis(
        status=AIAnalysisStatus.COMPLETED,
        overall_threat_level=ContentThreatLevel.CRITICAL,
        credential_harvesting_detected=True,
        impersonation_detected=True,
        impersonated_entities=["PayPal"],
        urgency_pressure_tactics=["24-hour account suspension deadline"],
    )

    urls = ["https://fake-paypal-verify.net/signin"]

    # Total calculated points: 40 + 35 + 5 + 30 + 65 (compound factors) = 175 points -> clamped to 100
    result = service.calculate_risk(auth, forensics, threat_intel, ai, urls)

    assert result.score == 100  # Capped at 100
    assert result.threat_level == ThreatLevel.CRITICAL
    assert len(result.factors) == 14
    factor_names = [f.factor for f in result.factors]
    assert "COMPOUND_CREDENTIAL_PHISHING_LURE" in factor_names
    assert "COMPOUND_COERCIVE_URGENCY_PRESSURE" in factor_names
    assert "COMPOUND_SPOOFED_BRAND_IMPERSONATION" in factor_names
    assert "COMPOUND_AUTHENTICATION_FAILURE_WITH_PHISHING" in factor_names


def test_risk_scoring_paypal_phishing_without_auth_headers_compound_factors():
    """Verify that a PayPal phishing lure without MTA auth headers (previously under-scored at 35 MEDIUM)
    correctly triggers compound factors (credential harvesting + impersonation + urgency + external link mismatch)
    to produce a HIGH threat level (score 70).
    """
    service = RiskScoringService()

    # No MTA authentication headers available (e.g. raw email paste or missing headers)
    auth = AuthenticationResult(spf="none", dkim="none", dmarc="none")

    # Header forensics: from PayPal, but no reply-to or return-path headers
    forensics = HeaderForensics(
        from_domain="paypal.com",
        mismatches=HeaderMismatch(has_mismatch=False),
    )

    threat_intel = ThreatIntelligenceReport()

    # AI content analysis confirms active phishing vector
    ai = AIContentAnalysis(
        status=AIAnalysisStatus.COMPLETED,
        overall_threat_level=ContentThreatLevel.HIGH,
        credential_harvesting_detected=True,
        impersonation_detected=True,
        impersonated_entities=["PayPal"],
        urgency_pressure_tactics=["24-hour account suspension deadline"],
    )

    # Deceptive off-domain credential portal link
    urls = ["https://paypa1-security.com/restore-login"]

    result = service.calculate_risk(auth, forensics, threat_intel, ai, urls)

    # Base points:
    #   EXTERNAL_LINK_DOMAIN_MISMATCH (5)
    #   AI_CREDENTIAL_HARVESTING (15)
    #   AI_IMPERSONATION_DETECTED (10)
    #   AI_URGENCY_PRESSURE_TACTICS (5)
    #   = 35
    # Compound synergy points:
    #   COMPOUND_CREDENTIAL_PHISHING_LURE (20)
    #   COMPOUND_COERCIVE_URGENCY_PRESSURE (15)
    #   = 35
    # Total = 70 points -> HIGH threat level (elevated from previous 35 MEDIUM)
    assert result.score == 70
    assert result.threat_level == ThreatLevel.HIGH
    factor_names = [f.factor for f in result.factors]
    assert "EXTERNAL_LINK_DOMAIN_MISMATCH" in factor_names
    assert "AI_CREDENTIAL_HARVESTING" in factor_names
    assert "AI_IMPERSONATION_DETECTED" in factor_names
    assert "AI_URGENCY_PRESSURE_TACTICS" in factor_names
    assert "COMPOUND_CREDENTIAL_PHISHING_LURE" in factor_names
    assert "COMPOUND_COERCIVE_URGENCY_PRESSURE" in factor_names
    assert len(result.factors) == 6


def test_risk_scoring_punycode_and_ip_url():
    """Verify points added for Punycode homograph domain and direct IP URL host."""
    service = RiskScoringService()

    auth = AuthenticationResult(spf="pass", dkim="pass", dmarc="pass")
    forensics = HeaderForensics(
        from_domain="company.com",
        reply_to_domain="company.com",
        return_path_domain="company.com",
        mismatches=HeaderMismatch(has_mismatch=False),
    )
    threat_intel = ThreatIntelligenceReport(
        domains=[
            DomainThreatReport(
                domain="xn--pple-43d.com",
                raw_domain="xn--pple-43d.com",
                is_punycode=True,
                unicode_domain="аpple.com",
            )
        ]
    )
    ai = AIContentAnalysis(status=AIAnalysisStatus.NOT_CHECKED)
    urls = ["http://198.51.100.42/malware.exe"]

    # Punycode (+15) + IP address URL host (+10) = 25 points
    result = service.calculate_risk(auth, forensics, threat_intel, ai, urls)

    assert result.score == 25
    assert result.threat_level == ThreatLevel.MEDIUM
    factor_names = [f.factor for f in result.factors]
    assert "PUNYCODE_HOMOGRAPH_DOMAIN" in factor_names
    assert "IP_ADDRESS_URL_HOST" in factor_names


def test_risk_scoring_missing_ai_does_not_penalize():
    """Verify that when AI service is unavailable or not_checked, scoring functions safely without failure."""
    service = RiskScoringService()

    auth = AuthenticationResult(spf="pass", dkim="pass", dmarc="pass")
    forensics = HeaderForensics(
        from_domain="example.com",
        reply_to_domain="example.com",
        return_path_domain="example.com",
        mismatches=HeaderMismatch(has_mismatch=False),
    )
    threat_intel = ThreatIntelligenceReport()
    ai = AIContentAnalysis(
        status=AIAnalysisStatus.UNAVAILABLE,
        overall_threat_level=ContentThreatLevel.UNKNOWN,
        error_message="Groq API connection timed out.",
    )

    result = service.calculate_risk(auth, forensics, threat_intel, ai, urls=[])

    assert result.score == 0
    assert result.threat_level == ThreatLevel.LOW


# ---------------------------------------------------------------------------
# Integration Tests: Risk Score via /api/v1/analyze-email Endpoint
# ---------------------------------------------------------------------------

def test_endpoint_risk_score_benign():
    """Test full endpoint integration returning risk score for a clean email."""
    raw_email = (
        "From: Alice <alice@example.com>\r\n"
        "To: Bob <bob@example.com>\r\n"
        "Subject: Team Lunch\r\n"
        "Received: from mail.example.com ([192.0.2.1]) by mx.example.com\r\n"
        "\r\n"
        "Let's grab lunch at noon.\r\n"
    )

    response = client.post(ENDPOINT, json={"raw_email": raw_email})
    assert response.status_code == 200

    data = response.json()
    assert "risk_score" in data
    rs = data["risk_score"]
    assert "score" in rs
    assert "threat_level" in rs
    assert rs["threat_level"] == "low"
    assert rs["score"] < 25


def test_endpoint_risk_score_suspicious_paypal_scenario():
    """Test full endpoint integration returning high/critical risk score for suspicious spoofing email."""
    raw_email = (
        "Authentication-Results: mx.victim.com;\r\n"
        " spf=fail (mx.victim.com: domain of phish@paypal.com does not designate 203.0.113.88);\r\n"
        " dkim=fail reason=\"bad signature\";\r\n"
        " dmarc=fail action=none header.from=paypal.com\r\n"
        "From: \"PayPal Security\" <security@paypal.com>\r\n"
        "To: victim@example.com\r\n"
        "Reply-To: attacker@phish-drop.net\r\n"
        "Return-Path: <bounce@fake-host.org>\r\n"
        "Subject: Urgent: Verify Account\r\n"
        "Received: from evil.org ([203.0.113.88]) by mx.victim.com\r\n"
        "\r\n"
        "Verify your account now at https://fake-paypal-login.xyz/auth\r\n"
    )

    response = client.post(ENDPOINT, json={"raw_email": raw_email})
    assert response.status_code == 200

    data = response.json()
    assert "risk_score" in data
    rs = data["risk_score"]

    # Header evidence triggers:
    # SPF fail (15) + DMARC fail (15) + DKIM fail (10) + From vs Reply-To (15) + From vs Return-Path (10) + External link (5) = 70
    assert rs["score"] >= 50
    assert rs["threat_level"] in ["high", "critical"]
    factor_names = [f["factor"] for f in rs["factors"]]
    assert "SPF_AUTHENTICATION_FAILED" in factor_names
    assert "DMARC_POLICY_FAILED" in factor_names
    assert "DKIM_SIGNATURE_FAILED" in factor_names
    assert "FROM_REPLY_TO_MISMATCH" in factor_names
    assert "FROM_RETURN_PATH_MISMATCH" in factor_names


def test_endpoint_risk_score_paypal_phishing_with_ai_compound_factors():
    """Verify endpoint risk scoring with mocked Groq AI produces HIGH via compound factors (score 70)."""
    raw_email = (
        "From: PayPal Service <service@paypal.com>\r\n"
        "To: victim@example.com\r\n"
        "Subject: Urgent: Verify Your PayPal Account\r\n"
        "\r\n"
        "Dear Customer, verify your credentials within 24 hours to prevent account suspension:\r\n"
        "https://paypa1-security.com/restore-login\r\n"
    )

    mock_llm_payload = {
        "overall_threat_level": "high",
        "phishing_indicators": ["Credential verification lure mimicking PayPal"],
        "urgency_pressure_tactics": ["24-hour suspension ultimatum"],
        "impersonation_detected": True,
        "impersonated_entities": ["PayPal"],
        "credential_harvesting_detected": True,
        "financial_requests_detected": False,
        "social_engineering_patterns": ["Urgency", "Brand impersonation"],
        "summary": "Credential harvesting attack spoofing PayPal.",
    }

    mock_http_response = MagicMock()
    mock_http_response.status_code = 200
    mock_http_response.json.return_value = {
        "choices": [{"message": {"content": json.dumps(mock_llm_payload)}}]
    }

    mock_ctx = MagicMock()
    mock_ctx.__enter__.return_value.post.return_value = mock_http_response

    with patch("app.services.ai_analysis.groq_analyzer.settings.GROQ_API_KEY", "mock-key"):
        with patch("app.services.ai_analysis.groq_analyzer.httpx.Client", return_value=mock_ctx):
            response = client.post(ENDPOINT, json={"raw_email": raw_email})
            assert response.status_code == 200

            data = response.json()
            rs = data["risk_score"]
            assert rs["score"] == 70
            assert rs["threat_level"] == "high"
            factor_names = [f["factor"] for f in rs["factors"]]
            assert "COMPOUND_CREDENTIAL_PHISHING_LURE" in factor_names
            assert "COMPOUND_COERCIVE_URGENCY_PRESSURE" in factor_names

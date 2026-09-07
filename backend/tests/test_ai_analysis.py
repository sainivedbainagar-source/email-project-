"""Automated tests for AI content analysis using mocked Groq API responses."""

import json
from unittest.mock import MagicMock, patch
import httpx
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models.ai_analysis import AIAnalysisStatus, ContentThreatLevel
from app.services.ai_analysis.groq_analyzer import GroqContentAnalyzer

client = TestClient(app)
ENDPOINT = "/api/v1/analyze-email"


# ---------------------------------------------------------------------------
# Test 1: Missing API Key Fallback
# ---------------------------------------------------------------------------

def test_ai_analysis_missing_api_key_graceful_fallback():
    """Verify that when GROQ_API_KEY is not configured, the endpoint returns status 'not_checked' without failing."""
    raw_email = (
        "From: boss@corp.com\r\n"
        "To: employee@corp.com\r\n"
        "Subject: Meeting Notes\r\n"
        "\r\n"
        "Here are the notes from today's sync.\r\n"
    )

    with patch("app.services.ai_analysis.groq_analyzer.settings.GROQ_API_KEY", None):
        response = client.post(ENDPOINT, json={"raw_email": raw_email})
        assert response.status_code == 200

        data = response.json()
        assert "ai_analysis" in data
        ai = data["ai_analysis"]
        assert ai["status"] == AIAnalysisStatus.NOT_CHECKED.value
        assert ai["overall_threat_level"] == ContentThreatLevel.NOT_CHECKED.value
        assert ai["provider"] == "groq"
        assert "not configured" in ai["summary"].lower()


# ---------------------------------------------------------------------------
# Test 2: Mocked Phishing Email Analysis
# ---------------------------------------------------------------------------

def test_ai_analysis_mocked_phishing_detection():
    """Verify detection of phishing, urgency, impersonation, and credential harvesting via mocked Groq response."""
    raw_email = (
        "From: security@paypal-alerts.com\r\n"
        "To: user@example.com\r\n"
        "Subject: URGENT: Account Access Suspended in 24 Hours\r\n"
        "\r\n"
        "Dear customer, your PayPal account has been locked. Verify your password now at https://fake-paypal.com/verify to restore access.\r\n"
    )

    mock_llm_payload = {
        "overall_threat_level": "critical",
        "phishing_indicators": [
            "Deceptive link masquerading as PayPal",
            "Pretext of locked account requiring re-authentication",
        ],
        "urgency_pressure_tactics": [
            "24-hour deadline ultimatum to create artificial panic"
        ],
        "impersonation_detected": True,
        "impersonated_entities": ["PayPal"],
        "credential_harvesting_detected": True,
        "financial_requests_detected": False,
        "social_engineering_patterns": [
            "Fear and panic induction",
            "Authority impersonation",
        ],
        "summary": "High-risk credential harvesting campaign spoofing PayPal with an artificial deadline.",
    }

    mock_http_response = MagicMock()
    mock_http_response.status_code = 200
    mock_http_response.json.return_value = {
        "choices": [
            {
                "message": {
                    "content": json.dumps(mock_llm_payload)
                }
            }
        ]
    }

    mock_ctx = MagicMock()
    mock_ctx.__enter__.return_value.post.return_value = mock_http_response

    with patch("app.services.ai_analysis.groq_analyzer.settings.GROQ_API_KEY", "mock-groq-key-12345"):
        with patch("app.services.ai_analysis.groq_analyzer.httpx.Client", return_value=mock_ctx):
            response = client.post(ENDPOINT, json={"raw_email": raw_email})
            assert response.status_code == 200

            data = response.json()
            assert "ai_analysis" in data
            ai = data["ai_analysis"]

            assert ai["status"] == AIAnalysisStatus.COMPLETED.value
            assert ai["overall_threat_level"] == ContentThreatLevel.CRITICAL.value
            assert len(ai["phishing_indicators"]) == 2
            assert "24-hour deadline" in ai["urgency_pressure_tactics"][0]
            assert ai["impersonation_detected"] is True
            assert "PayPal" in ai["impersonated_entities"]
            assert ai["credential_harvesting_detected"] is True
            assert ai["financial_requests_detected"] is False
            assert len(ai["social_engineering_patterns"]) == 2
            assert "credential harvesting" in ai["summary"].lower()


# ---------------------------------------------------------------------------
# Test 3: Mocked Benign Email Analysis
# ---------------------------------------------------------------------------

def test_ai_analysis_mocked_benign_email():
    """Verify benign email content produces clean non-threat classifications."""
    raw_email = (
        "From: coworker@company.com\r\n"
        "To: dev@company.com\r\n"
        "Subject: Project Architecture Review\r\n"
        "\r\n"
        "Hi team, let's meet at 2pm tomorrow in Room 4B to go over the sprint backlog.\r\n"
    )

    mock_llm_payload = {
        "overall_threat_level": "benign",
        "phishing_indicators": [],
        "urgency_pressure_tactics": [],
        "impersonation_detected": False,
        "impersonated_entities": [],
        "credential_harvesting_detected": False,
        "financial_requests_detected": False,
        "social_engineering_patterns": [],
        "summary": "Internal company meeting coordination with no threat indicators.",
    }

    mock_http_response = MagicMock()
    mock_http_response.status_code = 200
    mock_http_response.json.return_value = {
        "choices": [
            {
                "message": {
                    "content": json.dumps(mock_llm_payload)
                }
            }
        ]
    }

    mock_ctx = MagicMock()
    mock_ctx.__enter__.return_value.post.return_value = mock_http_response

    with patch("app.services.ai_analysis.groq_analyzer.settings.GROQ_API_KEY", "mock-groq-key-12345"):
        with patch("app.services.ai_analysis.groq_analyzer.httpx.Client", return_value=mock_ctx):
            response = client.post(ENDPOINT, json={"raw_email": raw_email})
            assert response.status_code == 200

            ai = response.json()["ai_analysis"]
            assert ai["status"] == AIAnalysisStatus.COMPLETED.value
            assert ai["overall_threat_level"] == ContentThreatLevel.BENIGN.value
            assert ai["impersonation_detected"] is False
            assert ai["credential_harvesting_detected"] is False
            assert ai["phishing_indicators"] == []


# ---------------------------------------------------------------------------
# Test 4: Mocked Financial Request / Wire Fraud Detection
# ---------------------------------------------------------------------------

def test_ai_analysis_mocked_financial_fraud():
    """Verify payment and gift card request detection."""
    raw_email = (
        "From: ceo@firm.com\r\n"
        "To: accountant@firm.com\r\n"
        "Subject: Urgent: Buy Apple Gift Cards\r\n"
        "\r\n"
        "I need you to buy 5x $100 Apple gift cards right now for our client conference and email the codes.\r\n"
    )

    mock_llm_payload = {
        "overall_threat_level": "high",
        "phishing_indicators": ["Gift card scam pretext"],
        "urgency_pressure_tactics": ["Immediate execution demand"],
        "impersonation_detected": True,
        "impersonated_entities": ["CEO"],
        "credential_harvesting_detected": False,
        "financial_requests_detected": True,
        "social_engineering_patterns": ["Executive authority pressure"],
        "summary": "CEO fraud attempting financial transfer via gift cards.",
    }

    mock_http_response = MagicMock()
    mock_http_response.status_code = 200
    mock_http_response.json.return_value = {
        "choices": [
            {
                "message": {
                    "content": json.dumps(mock_llm_payload)
                }
            }
        ]
    }

    mock_ctx = MagicMock()
    mock_ctx.__enter__.return_value.post.return_value = mock_http_response

    with patch("app.services.ai_analysis.groq_analyzer.settings.GROQ_API_KEY", "mock-groq-key-12345"):
        with patch("app.services.ai_analysis.groq_analyzer.httpx.Client", return_value=mock_ctx):
            response = client.post(ENDPOINT, json={"raw_email": raw_email})
            assert response.status_code == 200

            ai = response.json()["ai_analysis"]
            assert ai["financial_requests_detected"] is True
            assert ai["impersonation_detected"] is True
            assert ai["overall_threat_level"] == ContentThreatLevel.HIGH.value


# ---------------------------------------------------------------------------
# Test 5: Service Unavailable Scenarios (Timeout & HTTP Errors)
# ---------------------------------------------------------------------------

def test_ai_analysis_timeout_handling():
    """Verify that an httpx TimeoutException marks status as unavailable and does not break the endpoint."""
    raw_email = "From: a@b.com\r\nTo: c@d.com\r\nSubject: Test\r\n\r\nHello"

    mock_ctx = MagicMock()
    mock_ctx.__enter__.return_value.post.side_effect = httpx.TimeoutException("Read timed out")

    with patch("app.services.ai_analysis.groq_analyzer.settings.GROQ_API_KEY", "mock-groq-key-12345"):
        with patch("app.services.ai_analysis.groq_analyzer.httpx.Client", return_value=mock_ctx):
            response = client.post(ENDPOINT, json={"raw_email": raw_email})
            assert response.status_code == 200

            ai = response.json()["ai_analysis"]
            assert ai["status"] == AIAnalysisStatus.UNAVAILABLE.value
            assert ai["overall_threat_level"] == ContentThreatLevel.UNKNOWN.value
            assert "timed out" in ai["error_message"].lower()


def test_ai_analysis_http_error_handling():
    """Verify that HTTP error from Groq (e.g. 429 Rate Limit) is caught and handled cleanly."""
    raw_email = "From: a@b.com\r\nTo: c@d.com\r\nSubject: Test\r\n\r\nHello"

    mock_err_response = MagicMock()
    mock_err_response.status_code = 429
    mock_err_response.text = "Rate limit exceeded"

    mock_ctx = MagicMock()
    mock_ctx.__enter__.return_value.post.side_effect = httpx.HTTPStatusError(
        "Rate limit", request=MagicMock(), response=mock_err_response
    )

    with patch("app.services.ai_analysis.groq_analyzer.settings.GROQ_API_KEY", "mock-groq-key-12345"):
        with patch("app.services.ai_analysis.groq_analyzer.httpx.Client", return_value=mock_ctx):
            response = client.post(ENDPOINT, json={"raw_email": raw_email})
            assert response.status_code == 200

            ai = response.json()["ai_analysis"]
            assert ai["status"] == AIAnalysisStatus.UNAVAILABLE.value
            assert "429" in ai["error_message"]


# ---------------------------------------------------------------------------
# Test 6: Direct Analyzer Unit Test with Custom Key/Model
# ---------------------------------------------------------------------------

def test_groq_analyzer_direct_unit_test():
    """Direct unit test of GroqContentAnalyzer behavior."""
    analyzer = GroqContentAnalyzer(
        api_key="test-key",
        model="llama-3.3-70b-versatile",
        timeout_seconds=5.0,
    )
    assert analyzer.provider_name == "groq"

    # Test missing key fallback
    empty_analyzer = GroqContentAnalyzer(api_key="")
    res = empty_analyzer.analyze_content("Subject", "Body")
    assert res.status == AIAnalysisStatus.NOT_CHECKED
    assert res.overall_threat_level == ContentThreatLevel.NOT_CHECKED

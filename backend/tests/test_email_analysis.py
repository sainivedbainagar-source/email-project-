"""Automated tests for POST /api/v1/analyze-email endpoint."""

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

ENDPOINT = "/api/v1/analyze-email"


# ---------------------------------------------------------------------------
# Valid Email Tests
# ---------------------------------------------------------------------------

def test_analyze_email_valid_plain_text():
    """Test standard valid plain-text email with all headers and URLs."""
    raw_email = (
        "From: Alice Smith <alice@example.com>\r\n"
        "To: Bob Jones <bob@example.com>\r\n"
        "Subject: Urgent Account Security Verification\r\n"
        "Date: Mon, 07 Sep 2026 10:00:00 +0000\r\n"
        "Reply-To: support@security-service.example\r\n"
        "Return-Path: <bounces@security-service.example>\r\n"
        "Message-ID: <unique-12345@security-service.example>\r\n"
        "Received: from mail.external.com (mail.external.com [192.0.2.1]) by mx.example.com\r\n"
        "Received: from internal.host (internal.host [10.0.0.1]) by mail.external.com\r\n"
        "\r\n"
        "Hello Bob,\r\n\r\n"
        "Please confirm your credentials at https://secure-verify.example/login?id=8831.\r\n"
        "More info: http://docs.example.com/help and https://secure-verify.example/login?id=8831\r\n"
    )

    response = client.post(ENDPOINT, json={"raw_email": raw_email})
    assert response.status_code == 200

    data = response.json()
    assert data["from"] == "Alice Smith <alice@example.com>"
    assert data["to"] == "Bob Jones <bob@example.com>"
    assert data["subject"] == "Urgent Account Security Verification"
    assert data["date"] == "Mon, 07 Sep 2026 10:00:00 +0000"
    assert data["reply_to"] == "support@security-service.example"
    assert data["return_path"] == "<bounces@security-service.example>"
    assert data["message_id"] == "<unique-12345@security-service.example>"

    # Check received headers
    assert len(data["received"]) == 2
    assert "192.0.2.1" in data["received"][0]
    assert "10.0.0.1" in data["received"][1]

    # Check body and URLs
    assert "Please confirm your credentials" in data["body"]
    assert "https://secure-verify.example/login?id=8831" in data["urls"]
    assert "http://docs.example.com/help" in data["urls"]
    # URLs should be deduplicated
    assert len(data["urls"]) == 2


def test_analyze_email_multipart_with_html():
    """Test multipart email containing both plain text and HTML with hyperlinks."""
    raw_email = (
        "From: notification@service.com\r\n"
        "To: user@example.com\r\n"
        "Subject: Invoice #9921 Available\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: multipart/alternative; boundary=\"BOUNDARY_TAG\"\r\n"
        "\r\n"
        "--BOUNDARY_TAG\r\n"
        "Content-Type: text/plain; charset=\"utf-8\"\r\n"
        "\r\n"
        "View your invoice at https://service.com/invoices/9921\r\n"
        "--BOUNDARY_TAG\r\n"
        "Content-Type: text/html; charset=\"utf-8\"\r\n"
        "\r\n"
        "<p>Click <a href=\"https://billing.service.com/pay\">here</a> to pay.</p>\r\n"
        "--BOUNDARY_TAG--\r\n"
    )

    response = client.post(ENDPOINT, json={"raw_email": raw_email})
    assert response.status_code == 200

    data = response.json()
    assert data["from"] == "notification@service.com"
    assert data["to"] == "user@example.com"
    assert data["subject"] == "Invoice #9921 Available"
    assert "View your invoice" in data["body"]
    assert "Click" in data["body"]
    assert "https://service.com/invoices/9921" in data["urls"]
    assert "https://billing.service.com/pay" in data["urls"]


def test_analyze_email_encoded_rfc2047_headers():
    """Test headers encoded in RFC 2047 format are decoded properly."""
    raw_email = (
        "From: =?UTF-8?B?QWxleCBQcm9maWxl?= <alex@example.com>\r\n"
        "To: target@example.com\r\n"
        "Subject: =?UTF-8?B?8J+UkSBTZWN1cml0eSBBbGVydCE=?=\r\n"
        "\r\n"
        "Please review activity.\r\n"
    )

    response = client.post(ENDPOINT, json={"raw_email": raw_email})
    assert response.status_code == 200

    data = response.json()
    assert "Alex Profile" in data["from"]
    assert "Security Alert!" in data["subject"]
    assert data["urls"] == []


def test_analyze_email_skips_attachment_body():
    """Test that email attachments are not mixed into the body text."""
    raw_email = (
        "From: sender@example.com\r\n"
        "To: receiver@example.com\r\n"
        "Subject: File attached\r\n"
        "Content-Type: multipart/mixed; boundary=\"MIXED_BOUNDARY\"\r\n"
        "\r\n"
        "--MIXED_BOUNDARY\r\n"
        "Content-Type: text/plain; charset=\"utf-8\"\r\n"
        "\r\n"
        "Here is the text portion.\r\n"
        "--MIXED_BOUNDARY\r\n"
        "Content-Type: application/pdf; name=\"invoice.pdf\"\r\n"
        "Content-Disposition: attachment; filename=\"invoice.pdf\"\r\n"
        "Content-Transfer-Encoding: base64\r\n"
        "\r\n"
        "JVBERi0xLjQKJcTl8uXrp...\r\n"
        "--MIXED_BOUNDARY--\r\n"
    )

    response = client.post(ENDPOINT, json={"raw_email": raw_email})
    assert response.status_code == 200

    data = response.json()
    assert "Here is the text portion." in data["body"]
    assert "JVBERi0x" not in data["body"]


def test_analyze_email_minimal_no_optional_headers():
    """Test email with missing optional headers returns None or empty lists."""
    raw_email = (
        "From: simple@example.com\r\n"
        "To: simple2@example.com\r\n"
        "\r\n"
        "Just a simple message with no subject, date, or URLs.\r\n"
    )

    response = client.post(ENDPOINT, json={"raw_email": raw_email})
    assert response.status_code == 200

    data = response.json()
    assert data["from"] == "simple@example.com"
    assert data["to"] == "simple2@example.com"
    assert data["subject"] is None
    assert data["date"] is None
    assert data["reply_to"] is None
    assert data["return_path"] is None
    assert data["message_id"] is None
    assert data["received"] == []
    assert data["urls"] == []
    assert data["body"] == "Just a simple message with no subject, date, or URLs."


# ---------------------------------------------------------------------------
# Malformed & Edge Case Tests
# ---------------------------------------------------------------------------

def test_analyze_email_empty_string_rejected():
    """Test that an empty raw_email string returns HTTP 400."""
    response = client.post(ENDPOINT, json={"raw_email": ""})
    assert response.status_code == 400
    assert "cannot be empty" in response.json()["detail"].lower()


def test_analyze_email_whitespace_only_rejected():
    """Test that whitespace-only raw_email returns HTTP 400."""
    response = client.post(ENDPOINT, json={"raw_email": "   \n\t\r\n   "})
    assert response.status_code == 400
    assert "cannot be empty" in response.json()["detail"].lower()


def test_analyze_email_missing_raw_email_field():
    """Test that missing raw_email field in JSON returns HTTP 422 (Pydantic validation error)."""
    response = client.post(ENDPOINT, json={})
    assert response.status_code == 422


def test_analyze_email_malformed_headerless_text():
    """Test that raw text without standard email headers is handled gracefully without crashing."""
    raw_content = "This is simply unstructured raw text without RFC headers.\nVisit https://fallback.org"

    response = client.post(ENDPOINT, json={"raw_email": raw_content})
    assert response.status_code == 200

    data = response.json()
    assert data["from"] is None
    assert data["to"] is None
    assert data["subject"] is None
    assert "unstructured raw text" in data["body"]
    assert "https://fallback.org" in data["urls"]


def test_analyze_email_malformed_multipart_boundary():
    """Test email declaring multipart boundary but lacking proper terminating boundaries."""
    malformed_raw = (
        "From: attacker@bad.com\r\n"
        "Subject: Broken Boundary\r\n"
        "Content-Type: multipart/alternative; boundary=\"nonexistent_boundary\"\r\n"
        "\r\n"
        "Body content without proper delimiter https://malicious.link/payload\r\n"
    )

    response = client.post(ENDPOINT, json={"raw_email": malformed_raw})
    assert response.status_code == 200

    data = response.json()
    assert data["from"] == "attacker@bad.com"
    assert data["subject"] == "Broken Boundary"
    # Should not crash, body or URLs extracted where available
    assert "https://malicious.link/payload" in data["urls"] or "https://malicious.link/payload" in data["body"]

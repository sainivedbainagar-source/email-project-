"""Automated tests for email authentication (SPF, DKIM, DMARC) and header forensics."""

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)
ENDPOINT = "/api/v1/analyze-email"


# ---------------------------------------------------------------------------
# Normal / Legitimate Authentication & Forensics Scenarios
# ---------------------------------------------------------------------------

def test_normal_legitimate_email_authentication():
    """Test a fully authenticated legitimate email with aligned domains and passing SPF/DKIM/DMARC."""
    raw_email = (
        "Authentication-Results: mx.google.com;\r\n"
        " dkim=pass header.i=@trustedbank.com header.s=s2026;\r\n"
        " spf=pass (google.com: domain of notification@trustedbank.com designates 192.0.2.25 as permitted sender);\r\n"
        " dmarc=pass (p=REJECT sp=REJECT) header.from=trustedbank.com\r\n"
        "From: Trusted Bank <notification@trustedbank.com>\r\n"
        "To: customer@example.com\r\n"
        "Reply-To: Trusted Bank <notification@trustedbank.com>\r\n"
        "Return-Path: <bounces@trustedbank.com>\r\n"
        "Subject: Monthly Account Statement\r\n"
        "Date: Mon, 07 Sep 2026 09:30:00 +0000\r\n"
        "Received: from mail.trustedbank.com (mail.trustedbank.com [192.0.2.25]) by mx.google.com\r\n"
        "\r\n"
        "Your monthly statement is ready to view.\r\n"
    )

    response = client.post(ENDPOINT, json={"raw_email": raw_email})
    assert response.status_code == 200

    data = response.json()
    # Check top-level auth fields
    assert data["spf"] == "pass"
    assert data["dkim"] == "pass"
    assert data["dmarc"] == "pass"

    # Check nested auth model
    assert data["authentication"]["spf"] == "pass"
    assert data["authentication"]["dkim"] == "pass"
    assert data["authentication"]["dmarc"] == "pass"

    # Check domains
    assert data["from_domain"] == "trustedbank.com"
    assert data["reply_to_domain"] == "trustedbank.com"
    assert data["return_path_domain"] == "trustedbank.com"
    assert data["forensics"]["from_domain"] == "trustedbank.com"

    # Check received IPs
    assert data["received_ips"] == ["192.0.2.25"]
    assert data["forensics"]["received_ips"] == ["192.0.2.25"]

    # Check mismatches (none expected for legitimate aligned email)
    assert data["mismatch_indicators"] == []
    assert data["forensics"]["mismatches"]["has_mismatch"] is False
    assert data["forensics"]["mismatches"]["from_reply_to_mismatch"] is False
    assert data["forensics"]["mismatches"]["from_return_path_mismatch"] is False


# ---------------------------------------------------------------------------
# Suspicious Scenarios: Domain Mismatches & Redirection
# ---------------------------------------------------------------------------

def test_suspicious_reply_to_and_return_path_mismatch():
    """Test suspicious email where From domain, Reply-To domain, and Return-Path domain all differ."""
    raw_email = (
        "From: Executive Office <ceo@globalbank.com>\r\n"
        "To: victim@example.com\r\n"
        "Reply-To: Attacker Inbox <attacker@external-stealer.xyz>\r\n"
        "Return-Path: <bounce@compromised-host.net>\r\n"
        "Subject: Urgent Wire Transfer\r\n"
        "Received: from relay.bad.com (relay.bad.com [198.51.100.99]) by mx.victim.com\r\n"
        "\r\n"
        "Please reply directly to authorize this transaction.\r\n"
    )

    response = client.post(ENDPOINT, json={"raw_email": raw_email})
    assert response.status_code == 200

    data = response.json()
    assert data["from_domain"] == "globalbank.com"
    assert data["reply_to_domain"] == "external-stealer.xyz"
    assert data["return_path_domain"] == "compromised-host.net"

    assert data["forensics"]["mismatches"]["has_mismatch"] is True
    assert data["forensics"]["mismatches"]["from_reply_to_mismatch"] is True
    assert data["forensics"]["mismatches"]["from_return_path_mismatch"] is True

    # Check indicator messages
    indicators = data["mismatch_indicators"]
    assert any("globalbank.com" in ind and "external-stealer.xyz" in ind for ind in indicators)
    assert any("globalbank.com" in ind and "compromised-host.net" in ind for ind in indicators)


# ---------------------------------------------------------------------------
# Suspicious Scenarios: Authentication Failures
# ---------------------------------------------------------------------------

def test_suspicious_authentication_failures():
    """Test email with SPF, DKIM, and DMARC failures reported in Authentication-Results."""
    raw_email = (
        "Authentication-Results: mx.victim.com;\r\n"
        " spf=fail (mx.victim.com: domain of phish@paypal.com does not designate 203.0.113.88);\r\n"
        " dkim=fail reason=\"signature verification failed\";\r\n"
        " dmarc=fail action=none header.from=paypal.com\r\n"
        "From: PayPal Security <security@paypal.com>\r\n"
        "To: user@victim.com\r\n"
        "Subject: Security Warning\r\n"
        "Received: from evil.org (evil.org [203.0.113.88]) by mx.victim.com\r\n"
        "\r\n"
        "Please verify your account immediately.\r\n"
    )

    response = client.post(ENDPOINT, json={"raw_email": raw_email})
    assert response.status_code == 200

    data = response.json()
    assert data["spf"] == "fail"
    assert data["dkim"] == "fail"
    assert data["dmarc"] == "fail"

    # Indicators should note SPF, DKIM, and DMARC failures
    indicators = data["mismatch_indicators"]
    assert any("SPF authentication failed" in ind for ind in indicators)
    assert any("DKIM authentication failed" in ind for ind in indicators)
    assert any("DMARC authentication failed" in ind for ind in indicators)


# ---------------------------------------------------------------------------
# Suspicious Scenarios: Display Name Address Spoofing
# ---------------------------------------------------------------------------

def test_suspicious_display_name_spoofing():
    """Test email where From display name contains a deceptive domain differing from actual sender domain."""
    raw_email = (
        "From: \"support@apple.com\" <scammer123@suspicious-domain.co>\r\n"
        "To: victim@example.com\r\n"
        "Subject: Apple ID Locked\r\n"
        "\r\n"
        "Your Apple ID has been suspended.\r\n"
    )

    response = client.post(ENDPOINT, json={"raw_email": raw_email})
    assert response.status_code == 200

    data = response.json()
    assert data["from_domain"] == "suspicious-domain.co"
    indicators = data["mismatch_indicators"]
    assert any("mimics domain 'apple.com'" in ind for ind in indicators)


# ---------------------------------------------------------------------------
# Fallback Header Parsing (Received-SPF and DKIM-Signature)
# ---------------------------------------------------------------------------

def test_fallback_received_spf_and_dkim_signature():
    """Test SPF extracted from Received-SPF header and DKIM detected via DKIM-Signature when Authentication-Results is absent."""
    raw_email = (
        "Received-SPF: softfail (mail.receiver.com: domain of sender@example.com designates 192.0.2.1 as tentative sender)\r\n"
        "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=k1;\r\n"
        "From: sender@example.com\r\n"
        "To: receiver@example.com\r\n"
        "Subject: Notice\r\n"
        "\r\n"
        "Notice content.\r\n"
    )

    response = client.post(ENDPOINT, json={"raw_email": raw_email})
    assert response.status_code == 200

    data = response.json()
    assert data["spf"] == "softfail"
    assert data["dkim"] == "signed"
    assert data["dmarc"] == "none"
    assert any("softfail" in ind for ind in data["mismatch_indicators"])


# ---------------------------------------------------------------------------
# Multi-Hop Network IP Extraction (IPv4 and IPv6)
# ---------------------------------------------------------------------------

def test_multi_hop_ip_extraction_including_ipv6():
    """Test extracting multiple IPv4 and IPv6 addresses across transit hops in order."""
    raw_email = (
        "From: dev@tech.org\r\n"
        "To: user@target.org\r\n"
        "Received: from edge.receiver.com ([2001:db8:85a3::8a2e:370:7334]) by core.receiver.com\r\n"
        "Received: from relay.sender.com (relay.sender.com [198.51.100.10]) by edge.receiver.com\r\n"
        "Received: from internal.lan ([10.20.30.40]) by relay.sender.com\r\n"
        "\r\n"
        "Multi-hop message body.\r\n"
    )

    response = client.post(ENDPOINT, json={"raw_email": raw_email})
    assert response.status_code == 200

    data = response.json()
    assert "2001:db8:85a3::8a2e:370:7334" in data["received_ips"]
    assert "198.51.100.10" in data["received_ips"]
    assert "10.20.30.40" in data["received_ips"]
    assert len(data["received_ips"]) == 3

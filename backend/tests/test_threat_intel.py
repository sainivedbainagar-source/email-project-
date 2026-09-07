"""Automated tests for threat intelligence service and IP/domain classification."""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models.threat_intel import IPClassification, IPType, ThreatStatus
from app.services.threat_intel.local import LocalDeterministicProvider

client = TestClient(app)
ENDPOINT = "/api/v1/analyze-email"


# ---------------------------------------------------------------------------
# Unit Tests: LocalDeterministicProvider (IP Classification)
# ---------------------------------------------------------------------------

def test_ip_classification_public():
    """Verify public IPv4 and IPv6 addresses are properly classified as public and routable."""
    provider = LocalDeterministicProvider()

    # Public IPv4
    res_v4 = provider.lookup_ip("8.8.8.8")
    assert res_v4.ip == "8.8.8.8"
    assert res_v4.ip_type == IPType.IPV4
    assert res_v4.classification == IPClassification.PUBLIC
    assert res_v4.is_routable is True
    assert res_v4.threat_status == ThreatStatus.NOT_CHECKED
    assert res_v4.reputation_score is None

    # Public IPv6
    res_v6 = provider.lookup_ip("2607:f8b0:4005:805::200e")
    assert res_v6.ip_type == IPType.IPV6
    assert res_v6.classification == IPClassification.PUBLIC
    assert res_v6.is_routable is True
    assert res_v6.threat_status == ThreatStatus.NOT_CHECKED
    assert res_v6.reputation_score is None


def test_ip_classification_private():
    """Verify RFC 1918 and ULA addresses are classified as private and non-routable."""
    provider = LocalDeterministicProvider()

    for private_ip in ["10.0.1.15", "172.16.5.20", "192.168.1.100", "fd00::1"]:
        res = provider.lookup_ip(private_ip)
        assert res.classification == IPClassification.PRIVATE
        assert res.is_routable is False
        assert res.threat_status == ThreatStatus.NOT_CHECKED
        assert res.reputation_score is None


def test_ip_classification_reserved():
    """Verify testnets, benchmarking, and documentation IPs are classified as reserved."""
    provider = LocalDeterministicProvider()

    for reserved_ip in ["192.0.2.1", "198.51.100.23", "203.0.113.88", "240.0.0.1", "2001:db8::1"]:
        res = provider.lookup_ip(reserved_ip)
        assert res.classification == IPClassification.RESERVED
        assert res.is_routable is False
        assert res.threat_status == ThreatStatus.NOT_CHECKED
        assert res.reputation_score is None


def test_ip_classification_loopback_and_link_local():
    """Verify loopback and link-local addresses."""
    provider = LocalDeterministicProvider()

    assert provider.lookup_ip("127.0.0.1").classification == IPClassification.LOOPBACK
    assert provider.lookup_ip("::1").classification == IPClassification.LOOPBACK
    assert provider.lookup_ip("169.254.10.20").classification == IPClassification.LINK_LOCAL
    assert provider.lookup_ip("fe80::1").classification == IPClassification.LINK_LOCAL


# ---------------------------------------------------------------------------
# Unit Tests: LocalDeterministicProvider (Domain Normalization)
# ---------------------------------------------------------------------------

def test_domain_normalization_standard_and_fqdn():
    """Verify uppercase domains and trailing FQDN dots are normalized to clean lowercase."""
    provider = LocalDeterministicProvider()

    report = provider.lookup_domain("MAIL.EXAMPLE.COM.")
    assert report.domain == "mail.example.com"
    assert report.raw_domain == "MAIL.EXAMPLE.COM."
    assert report.tld == "com"
    assert report.is_punycode is False
    assert report.threat_status == ThreatStatus.NOT_CHECKED
    assert report.reputation_score is None


def test_domain_normalization_port_stripping():
    """Verify ports are stripped from domain strings."""
    provider = LocalDeterministicProvider()

    report = provider.lookup_domain("phishing-gateway.org:8443")
    assert report.domain == "phishing-gateway.org"
    assert report.tld == "org"


def test_domain_normalization_punycode_idn():
    """Verify Punycode IDN domains are identified and decoded."""
    provider = LocalDeterministicProvider()

    # IDN Punycode for Cyrillic 'a' + 'pple.com'
    report = provider.lookup_domain("xn--pple-43d.com")
    assert report.domain == "xn--pple-43d.com"
    assert report.is_punycode is True
    assert report.unicode_domain is not None
    assert report.tld == "com"


# ---------------------------------------------------------------------------
# Integration Tests: Threat Intelligence in /api/v1/analyze-email
# ---------------------------------------------------------------------------

def test_endpoint_threat_intelligence_comprehensive():
    """Test full endpoint integration returning structured threat intelligence for IPs and domains."""
    raw_email = (
        "From: alerts@paypal-verify.com\r\n"
        "To: target@victim.org\r\n"
        "Subject: Critical Security Notice\r\n"
        "Received: from mx.external.com ([8.8.8.8]) by mx.victim.org\r\n"
        "Received: from doc-server ([198.51.100.1]) by mx.external.com\r\n"
        "Received: from internal-lan ([10.0.0.5]) by doc-server\r\n"
        "\r\n"
        "Visit our secure portal at https://secure.bank-update.net/login to confirm details.\r\n"
    )

    response = client.post(ENDPOINT, json={"raw_email": raw_email})
    assert response.status_code == 200

    data = response.json()
    assert "threat_intelligence" in data
    ti = data["threat_intelligence"]

    # Check IPs classification in threat report
    ip_map = {item["ip"]: item for item in ti["ips"]}
    assert "8.8.8.8" in ip_map
    assert ip_map["8.8.8.8"]["classification"] == "public"
    assert ip_map["8.8.8.8"]["is_routable"] is True
    assert ip_map["8.8.8.8"]["threat_status"] == "not_checked"
    assert ip_map["8.8.8.8"]["reputation_score"] is None

    assert "198.51.100.1" in ip_map
    assert ip_map["198.51.100.1"]["classification"] == "reserved"
    assert ip_map["198.51.100.1"]["is_routable"] is False

    assert "10.0.0.5" in ip_map
    assert ip_map["10.0.0.5"]["classification"] == "private"
    assert ip_map["10.0.0.5"]["is_routable"] is False

    # Check domains in threat report (From domain & URL domain)
    domain_names = [item["domain"] for item in ti["domains"]]
    assert "paypal-verify.com" in domain_names
    assert "secure.bank-update.net" in domain_names

    for d in ti["domains"]:
        assert d["threat_status"] == "not_checked"
        assert d["reputation_score"] is None
        assert d["provider"] == "local_deterministic"
        assert d["tld"] in ["com", "net"]


def test_endpoint_threat_intelligence_empty_fallback():
    """Test threat intelligence section when an email has no headers or IPs."""
    raw_email = "Just plain body without headers or links."

    response = client.post(ENDPOINT, json={"raw_email": raw_email})
    assert response.status_code == 200

    data = response.json()
    assert "threat_intelligence" in data
    assert data["threat_intelligence"]["ips"] == []
    assert data["threat_intelligence"]["domains"] == []

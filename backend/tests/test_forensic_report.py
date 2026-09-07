"""Automated unit and integration tests for the Forensic Report Generation Service."""

from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models.ai_analysis import AIAnalysisStatus, AIContentAnalysis, ContentThreatLevel
from app.models.email_analysis import (
    AuthenticationResult,
    EmailAnalysisResponse,
    HeaderForensics,
    HeaderMismatch,
)
from app.models.forensic_report import (
    ActionPriority,
    EvidenceType,
    FindingCategory,
    FindingSeverity,
    ForensicReport,
)
from app.models.graph import (
    EdgeRelationship,
    GraphEdge,
    GraphNode,
    InvestigationGraph,
    NodeType,
)
from app.models.risk_scoring import RiskFactor, RiskScore, ThreatLevel
from app.models.threat_intel import (
    DomainThreatReport,
    IPClassification,
    IPThreatReport,
    IPType,
    ThreatIntelligenceReport,
    ThreatStatus,
)
from app.services.forensic_report import ForensicReportService

client = TestClient(app)
REPORT_ENDPOINT = "/api/v1/analyze-email/report"


# ---------------------------------------------------------------------------
# Unit Tests: ForensicReportService Direct Evaluation
# ---------------------------------------------------------------------------


def test_forensic_report_clean_email():
    """Verify report generation for a clean, legitimate email."""
    service = ForensicReportService()

    auth = AuthenticationResult(spf="pass", dkim="pass", dmarc="pass")
    forensics = HeaderForensics(
        from_domain="trustedcorp.com",
        reply_to_domain="trustedcorp.com",
        return_path_domain="trustedcorp.com",
        received_ips=["198.51.100.1"],
        mismatches=HeaderMismatch(has_mismatch=False),
    )
    risk_score = RiskScore(
        score=0,
        threat_level=ThreatLevel.LOW,
        factors=[],
        summary="Clean email with no elevated risk indicators.",
    )
    graph = InvestigationGraph(
        nodes=[
            GraphNode(id="email:msg-001@trustedcorp.com", type=NodeType.EMAIL, label="Statement"),
            GraphNode(id="domain:trustedcorp.com", type=NodeType.DOMAIN, label="trustedcorp.com"),
        ],
        edges=[
            GraphEdge(
                source="email:msg-001@trustedcorp.com",
                target="domain:trustedcorp.com",
                relationship=EdgeRelationship.FROM_DOMAIN,
                evidence="From header aligns with sender domain",
            )
        ],
        summary="Graph contains 2 node(s) and 1 edge(s).",
    )

    analysis = EmailAnalysisResponse(
        from_="billing@trustedcorp.com",
        to="user@client.com",
        subject="Monthly Statement",
        date="Mon, 01 Sep 2026 10:00:00 +0000",
        message_id="<msg-001@trustedcorp.com>",
        received=["from mail.trustedcorp.com ([198.51.100.1]) by mx.client.com"],
        body="Your statement is ready for review.",
        urls=["https://trustedcorp.com/billing"],
        authentication=auth,
        forensics=forensics,
        risk_score=risk_score,
        investigation_graph=graph,
    )

    report = service.generate_report(analysis, case_id="CASE-CLEAN-01")

    assert isinstance(report, ForensicReport)
    assert report.report_id == "CASE-CLEAN-01"
    assert report.executive_summary.threat_level == ThreatLevel.LOW
    assert report.executive_summary.risk_score == 0
    assert report.email_metadata.subject == "Monthly Statement"
    assert report.email_metadata.from_address == "billing@trustedcorp.com"

    # Verify actions contain normal delivery recommendation
    action_types = [a.action for a in report.recommended_actions]
    assert any("normal message delivery" in a.lower() for a in action_types)

    # Disclaimers present
    assert len(report.disclaimers) >= 3
    assert any("not constitute legal proof" in d.lower() for d in report.disclaimers)


def test_forensic_report_suspicious_email():
    """Verify report generation for a suspicious email with header mismatches and SPF failure."""
    service = ForensicReportService()

    auth = AuthenticationResult(spf="fail", dkim="none", dmarc="none")
    forensics = HeaderForensics(
        from_domain="security-alert.org",
        reply_to_domain="collect-data.net",
        return_path_domain="bounces.spammer.biz",
        received_ips=["203.0.113.88"],
        mismatches=HeaderMismatch(
            has_mismatch=True,
            from_reply_to_mismatch=True,
            from_return_path_mismatch=True,
            indicators=["From domain differs from Reply-To domain"],
        ),
    )
    risk_score = RiskScore(
        score=45,
        threat_level=ThreatLevel.MEDIUM,
        factors=[
            RiskFactor(factor="SPF_AUTHENTICATION_FAILED", points=15, reason="SPF failed"),
            RiskFactor(factor="FROM_REPLY_TO_MISMATCH", points=15, reason="Reply-to mismatch"),
            RiskFactor(factor="FROM_RETURN_PATH_MISMATCH", points=10, reason="Return-path mismatch"),
        ],
        summary="Medium risk detected",
    )

    analysis = EmailAnalysisResponse(
        from_="alerts@security-alert.org",
        to="victim@example.com",
        reply_to="reply@collect-data.net",
        return_path="bounce@bounces.spammer.biz",
        subject="Action Required: Review Security Alerts",
        received=["from relay.spammer.biz ([203.0.113.88]) by mx.example.com"],
        body="Please respond directly to this alert.",
        urls=[],
        authentication=auth,
        forensics=forensics,
        risk_score=risk_score,
    )

    report = service.generate_report(analysis)

    assert report.executive_summary.threat_level == ThreatLevel.MEDIUM
    assert report.executive_summary.risk_score == 45

    # Check for specific forensic findings
    finding_titles = [f.title for f in report.detailed_findings]
    assert any("SPF Verification Failed" in t for t in finding_titles)
    assert any("Sender and Reply-To Domain Discrepancy" in t for t in finding_titles)

    # Check recommended actions include quarantine/spam review
    actions = [a.action for a in report.recommended_actions]
    assert any("quarantine or spam" in a.lower() for a in actions)


def test_forensic_report_critical_risk_paypal_phishing():
    """Verify comprehensive report on a critical-severity PayPal phishing attack."""
    service = ForensicReportService()

    auth = AuthenticationResult(spf="fail", dkim="fail", dmarc="fail")
    forensics = HeaderForensics(
        from_domain="paypal.com",
        reply_to_domain="secure-paypal-login.xyz",
        return_path_domain="bounce-sender.ru",
        received_ips=["203.0.113.200"],
        mismatches=HeaderMismatch(
            has_mismatch=True,
            from_reply_to_mismatch=True,
            from_return_path_mismatch=True,
            indicators=["From domain differs from Reply-To domain"],
        ),
    )
    ai = AIContentAnalysis(
        status=AIAnalysisStatus.COMPLETED,
        overall_threat_level=ContentThreatLevel.HIGH,
        phishing_indicators=["Fake login portal lure"],
        urgency_pressure_tactics=["Account will be suspended within 24 hours"],
        impersonation_detected=True,
        impersonated_entities=["PayPal"],
        credential_harvesting_detected=True,
        financial_requests_detected=False,
        summary="Phishing attempt impersonating PayPal to harvest user credentials.",
        provider="groq",
    )
    risk_score = RiskScore(
        score=95,
        threat_level=ThreatLevel.CRITICAL,
        factors=[
            RiskFactor(factor="SPF_AUTHENTICATION_FAILED", points=15, reason="SPF failed"),
            RiskFactor(factor="FROM_REPLY_TO_MISMATCH", points=15, reason="Reply-to mismatch"),
            RiskFactor(factor="AI_CREDENTIAL_HARVESTING", points=15, reason="Credential harvesting"),
            RiskFactor(factor="AI_IMPERSONATION_DETECTED", points=10, reason="Impersonation detected"),
        ],
        summary="Threat Level: CRITICAL (Score: 95/100)",
    )

    urls = [
        "https://secure-paypal-login.xyz/signin",
        "http://198.51.100.33:8080/confirm",
    ]

    analysis = EmailAnalysisResponse(
        from_="PayPal Support <service@paypal.com>",
        to="victim@company.com",
        reply_to="support@secure-paypal-login.xyz",
        return_path="bounces@bounce-sender.ru",
        subject="Urgent: Your PayPal Account Has Been Suspended",
        message_id="<phish-999@paypal.com>",
        received=["from relay.attack.com ([203.0.113.200]) by mx.company.com"],
        body="Log in immediately to verify your account:\nhttps://secure-paypal-login.xyz/signin\nhttp://198.51.100.33:8080/confirm",
        urls=urls,
        authentication=auth,
        forensics=forensics,
        ai_analysis=ai,
        risk_score=risk_score,
    )

    report = service.generate_report(analysis)

    assert report.executive_summary.threat_level == ThreatLevel.CRITICAL
    assert report.executive_summary.risk_score == 95

    # Verify findings contain credential harvesting, impersonation, direct IP URL
    finding_titles = [f.title for f in report.detailed_findings]
    assert any("Credential Harvesting" in t for t in finding_titles)
    assert any("Brand Impersonation" in t for t in finding_titles)
    assert any("Direct IP-Based Hyperlink" in t for t in finding_titles)

    # Verify prioritized actions across audiences
    priorities = {a.priority for a in report.recommended_actions}
    assert ActionPriority.IMMEDIATE in priorities
    assert ActionPriority.HIGH in priorities

    audiences = {a.target_audience for a in report.recommended_actions}
    assert "Mail Administrator" in audiences
    assert "SOC Analyst" in audiences


def test_forensic_report_missing_ai_graceful_fallback():
    """Verify that report handles unavailable or missing AI without errors or distortion."""
    service = ForensicReportService()

    ai_unavailable = AIContentAnalysis(
        status=AIAnalysisStatus.NOT_CHECKED,
        overall_threat_level=ContentThreatLevel.UNKNOWN,
        summary="AI analysis skipped or API key not configured.",
    )

    analysis = EmailAnalysisResponse(
        from_="test@example.com",
        subject="System Maintenance",
        body="Regular system maintenance scheduled.",
        ai_analysis=ai_unavailable,
    )

    report = service.generate_report(analysis)

    assert report.ai_analysis.status == "not_checked"
    # Finding explaining AI was not checked
    finding_titles = [f.title for f in report.detailed_findings]
    assert any("AI Content Analysis Not Performed" in t for t in finding_titles)


def test_forensic_report_missing_threat_intel_fallback():
    """Verify graceful handling when threat intelligence has no records."""
    service = ForensicReportService()

    empty_ti = ThreatIntelligenceReport(ips=[], domains=[], summary="No external IOCs queried.")

    analysis = EmailAnalysisResponse(
        from_="local@internal.corp",
        subject="Internal Note",
        body="Internal notice.",
        threat_intelligence=empty_ti,
    )

    report = service.generate_report(analysis)

    assert report.threat_intelligence.total_ips_evaluated == 0
    assert report.threat_intelligence.total_domains_evaluated == 0
    assert report.threat_intelligence.external_feeds_queried is False


def test_forensic_report_minimal_optional_fields():
    """Verify report handles raw text with no headers, date, or message-id."""
    service = ForensicReportService()

    analysis = EmailAnalysisResponse(
        from_=None,
        to=None,
        subject=None,
        date=None,
        message_id=None,
        body="Plain headerless text only.",
        urls=[],
    )

    report = service.generate_report(analysis)

    assert report.email_metadata.subject is None
    assert report.email_metadata.from_address is None
    assert report.email_metadata.message_id is None
    assert len(report.detailed_findings) >= 1
    assert len(report.evidence_list) >= 1


def test_forensic_report_evidence_traceability():
    """CRITICAL TEST: Ensure EVERY finding's evidence_ids exist in evidence_list."""
    service = ForensicReportService()

    analysis = EmailAnalysisResponse(
        from_="service@paypal.com",
        reply_to="phish@evil-login.xyz",
        return_path="bounce@spamsender.biz",
        subject="Urgent Security Alert",
        received=["from attacker.net ([203.0.113.55]) by mx.victim.com"],
        body="Restore access: https://evil-login.xyz/login and http://198.51.100.99/auth",
        urls=["https://evil-login.xyz/login", "http://198.51.100.99/auth"],
        authentication=AuthenticationResult(spf="fail", dkim="fail", dmarc="fail"),
        forensics=HeaderForensics(
            from_domain="paypal.com",
            reply_to_domain="evil-login.xyz",
            return_path_domain="spamsender.biz",
            received_ips=["203.0.113.55"],
            mismatches=HeaderMismatch(
                has_mismatch=True,
                from_reply_to_mismatch=True,
                from_return_path_mismatch=True,
                indicators=["Reply-To domain mismatch"],
            ),
        ),
        ai_analysis=AIContentAnalysis(
            status=AIAnalysisStatus.COMPLETED,
            credential_harvesting_detected=True,
            impersonation_detected=True,
            impersonated_entities=["PayPal"],
            urgency_pressure_tactics=["24h limit"],
        ),
        risk_score=RiskScore(score=90, threat_level=ThreatLevel.CRITICAL, summary="Critical risk"),
    )

    report = service.generate_report(analysis)

    evidence_id_set = {ev.id for ev in report.evidence_list}
    assert len(evidence_id_set) > 0, "Report must collect evidence"

    for finding in report.detailed_findings:
        assert len(finding.evidence_ids) > 0, (
            f"Finding '{finding.title}' ({finding.id}) must have at least one supporting evidence ID"
        )
        for ev_id in finding.evidence_ids:
            assert ev_id in evidence_id_set, (
                f"Finding '{finding.title}' references non-existent evidence ID '{ev_id}'"
            )


def test_forensic_report_no_fabricated_findings():
    """Verify that all entities referenced in findings exist in the original email."""
    service = ForensicReportService()

    claimed_from = "legit.example.com"
    body_link = "https://safe-portal.com/doc"

    analysis = EmailAnalysisResponse(
        from_=f"admin@{claimed_from}",
        subject="Clean Document",
        body=f"Document available at {body_link}",
        urls=[body_link],
        forensics=HeaderForensics(from_domain=claimed_from),
    )

    report = service.generate_report(analysis)

    # Check that extracted indicators only contain the real entities
    assert report.extracted_indicators.urls == [body_link]
    assert claimed_from in report.extracted_indicators.domains
    # No phantom external domains or IPs fabricated
    assert len(report.extracted_indicators.ips) == 0


def test_forensic_report_investigation_graph_linkages():
    """Verify graph summary and notable linkages are accurately reflected in report."""
    service = ForensicReportService()

    graph = InvestigationGraph(
        nodes=[
            GraphNode(id="email:msg1", type=NodeType.EMAIL, label="Email"),
            GraphNode(id="domain:target.com", type=NodeType.DOMAIN, label="target.com"),
            GraphNode(id="url:https://target.com/page", type=NodeType.URL, label="url"),
        ],
        edges=[
            GraphEdge(
                source="email:msg1",
                target="domain:target.com",
                relationship=EdgeRelationship.FROM_DOMAIN,
                evidence="From header",
            ),
            GraphEdge(
                source="url:https://target.com/page",
                target="domain:target.com",
                relationship=EdgeRelationship.HOSTED_ON_DOMAIN,
                evidence="Host domain",
            ),
        ],
        summary="Investigation graph with 3 nodes and 2 edges.",
    )

    analysis = EmailAnalysisResponse(
        from_="notify@target.com",
        subject="Page Link",
        investigation_graph=graph,
    )

    report = service.generate_report(analysis)

    assert report.investigation_graph.total_nodes == 3
    assert report.investigation_graph.total_edges == 2
    assert len(report.investigation_graph.key_linkages) == 2


# ---------------------------------------------------------------------------
# Integration Tests: POST /api/v1/analyze-email/report Endpoint
# ---------------------------------------------------------------------------


def test_endpoint_report_benign_email():
    """Verify API endpoint returns a valid ForensicReport for clean email."""
    email_text = (
        "From: HR Department <hr@company.com>\n"
        "To: staff@company.com\n"
        "Subject: Holiday Schedule 2026\n"
        "Date: Mon, 01 Sep 2026 09:00:00 +0000\n"
        "Message-ID: <hr-sched-2026@company.com>\n"
        "Received: from mail.company.com ([198.51.100.10]) by mx.company.com; Mon, 01 Sep 2026 09:00:01 +0000\n"
        "Authentication-Results: mx.company.com; spf=pass; dkim=pass; dmarc=pass\n"
        "\n"
        "Dear Team,\n\n"
        "The holiday schedule is posted at https://company.com/holidays.\n"
    )

    response = client.post(REPORT_ENDPOINT, json={"raw_email": email_text})
    assert response.status_code == 200
    data = response.json()

    assert "report_id" in data
    assert "generated_at" in data
    assert "executive_summary" in data
    assert data["executive_summary"]["threat_level"] == "low"
    assert data["executive_summary"]["risk_score"] == 0
    assert "detailed_findings" in data
    assert "evidence_list" in data
    assert "recommended_actions" in data
    assert "disclaimers" in data


def test_endpoint_report_paypal_phishing_scenario():
    """Verify API endpoint returns full threat report for a PayPal phishing email."""
    phishing_email = (
        "From: PayPal Service <service@paypal.com>\n"
        "Reply-To: support@paypa1-security.com\n"
        "Return-Path: bounces@evil-server.net\n"
        "To: victim@example.com\n"
        "Subject: Urgent: Verify Your PayPal Account\n"
        "Date: Tue, 02 Sep 2026 12:00:00 +0000\n"
        "Message-ID: <phish-pay-123@paypal.com>\n"
        "Received: from evil-server.net ([203.0.113.111]) by mx.example.com; Tue, 02 Sep 2026 12:00:01 +0000\n"
        "Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail\n"
        "\n"
        "Dear Customer,\n\n"
        "Verify your account now to avoid suspension:\n"
        "https://paypa1-security.com/restore-login\n"
    )

    response = client.post(REPORT_ENDPOINT, json={"raw_email": phishing_email})
    assert response.status_code == 200
    data = response.json()

    assert data["executive_summary"]["threat_level"] in ["high", "critical"]
    assert data["executive_summary"]["risk_score"] >= 50

    # Verify detailed findings exist and have evidence_ids
    findings = data["detailed_findings"]
    evidence = data["evidence_list"]
    ev_ids = {e["id"] for e in evidence}

    for f in findings:
        assert len(f["evidence_ids"]) > 0
        for eid in f["evidence_ids"]:
            assert eid in ev_ids

    # Verify actions contain immediate quarantine or URL block
    actions = data["recommended_actions"]
    assert any("quarantine" in a["action"].lower() or "block" in a["action"].lower() for a in actions)


def test_endpoint_report_empty_raw_email_rejected():
    """Verify API endpoint rejects empty or whitespace-only raw_email."""
    response = client.post(REPORT_ENDPOINT, json={"raw_email": "   \n\t  "})
    assert response.status_code == 400
    assert "Raw email content cannot be empty" in response.json()["detail"]

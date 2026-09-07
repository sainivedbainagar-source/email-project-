"""Automated unit and integration tests for the deterministic Investigation Graph Correlation."""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models.graph import (
    EdgeRelationship,
    GraphEdge,
    GraphNode,
    InvestigationGraph,
    NodeType,
)
from app.models.risk_scoring import RiskScore, ThreatLevel
from app.models.threat_intel import (
    DomainThreatReport,
    IPClassification,
    IPThreatReport,
    IPType,
    ThreatIntelligenceReport,
    ThreatStatus,
)
from app.services.graph_correlation import GraphCorrelationService

client = TestClient(app)
ENDPOINT = "/api/v1/analyze-email"


# ---------------------------------------------------------------------------
# Unit Tests: Direct Evaluation via GraphCorrelationService
# ---------------------------------------------------------------------------


def test_graph_correlation_clean_email():
    """Verify graph creation for a clean email with aligned domain, URL, and transit IP."""
    service = GraphCorrelationService()

    graph = service.build_graph(
        subject="Monthly Account Statement",
        message_id="<msg-001@legitcorp.com>",
        date="Mon, 1 Sep 2026 10:00:00 +0000",
        from_domain="legitcorp.com",
        reply_to_domain="legitcorp.com",
        return_path_domain="legitcorp.com",
        received_headers=["from mail.legitcorp.com ([198.51.100.1]) by mx.google.com"],
        received_ips=["198.51.100.1"],
        urls=["https://legitcorp.com/statement"],
        risk_score=RiskScore(
            score=0,
            threat_level=ThreatLevel.LOW,
            factors=[],
            summary="Clean email",
        ),
    )

    assert isinstance(graph, InvestigationGraph)
    assert len(graph.nodes) >= 3  # email, domain:legitcorp.com, url, ip
    assert len(graph.edges) >= 3

    # Check root email node
    root_node = next((n for n in graph.nodes if n.type == NodeType.EMAIL), None)
    assert root_node is not None
    assert root_node.id == "email:msg-001@legitcorp.com"
    assert root_node.label == "Monthly Account Statement"
    assert root_node.metadata["risk_score"] == 0
    assert root_node.metadata["threat_level"] == "low"

    # Verify domain node deduplication (from, reply-to, return-path, and URL host all share domain:legitcorp.com)
    domain_nodes = [n for n in graph.nodes if n.type == NodeType.DOMAIN]
    assert len(domain_nodes) == 1
    assert domain_nodes[0].id == "domain:legitcorp.com"

    # Verify edge types present
    relationships = {e.relationship for e in graph.edges}
    assert EdgeRelationship.FROM_DOMAIN in relationships
    assert EdgeRelationship.CONTAINS_URL in relationships
    assert EdgeRelationship.HOSTED_ON_DOMAIN in relationships
    assert EdgeRelationship.TRANSIT_HOP_IP in relationships

    # Non-attribution disclaimer in summary
    assert "do not establish threat actor identity" in graph.summary.lower()


def test_graph_correlation_sender_reply_to_mismatch():
    """Verify distinct domain nodes and relationships when headers mismatch."""
    service = GraphCorrelationService()

    graph = service.build_graph(
        subject="Urgent: Account Suspended",
        message_id="<phish-999@attacker.net>",
        from_domain="service.paypal.com",
        reply_to_domain="support-paypal.attacker-hq.ru",
        return_path_domain="bounces.spamsender.biz",
        received_ips=["203.0.113.50"],
        urls=[],
    )

    node_ids = {n.id for n in graph.nodes}
    assert "domain:service.paypal.com" in node_ids
    assert "domain:support-paypal.attacker-hq.ru" in node_ids
    assert "domain:bounces.spamsender.biz" in node_ids

    # Check directed edges from email root to the three distinct domains
    from_edge = next((e for e in graph.edges if e.relationship == EdgeRelationship.FROM_DOMAIN), None)
    assert from_edge is not None
    assert from_edge.target == "domain:service.paypal.com"

    reply_edge = next((e for e in graph.edges if e.relationship == EdgeRelationship.REPLY_TO_DOMAIN), None)
    assert reply_edge is not None
    assert reply_edge.target == "domain:support-paypal.attacker-hq.ru"

    return_edge = next((e for e in graph.edges if e.relationship == EdgeRelationship.RETURN_PATH_DOMAIN), None)
    assert return_edge is not None
    assert return_edge.target == "domain:bounces.spamsender.biz"


def test_graph_correlation_suspicious_url_hosted_on_ip():
    """Verify direct IP addressing in URL creates HOSTED_ON_IP edge."""
    service = GraphCorrelationService()

    graph = service.build_graph(
        subject="Security Alert",
        message_id="<alert-123@sec.org>",
        from_domain="sec.org",
        urls=["http://198.51.100.25:8080/login.php"],
    )

    node_dict = {n.id: n for n in graph.nodes}
    assert "url:http://198.51.100.25:8080/login.php" in node_dict
    assert "ip:198.51.100.25" in node_dict

    ip_node = node_dict["ip:198.51.100.25"]
    assert ip_node.type == NodeType.IP_ADDRESS

    hosted_edge = next((e for e in graph.edges if e.relationship == EdgeRelationship.HOSTED_ON_IP), None)
    assert hosted_edge is not None
    assert hosted_edge.source == "url:http://198.51.100.25:8080/login.php"
    assert hosted_edge.target == "ip:198.51.100.25"


def test_graph_correlation_transit_hops_and_resolves_to_ip():
    """Verify Received header domain-to-IP binding creates RESOLVES_TO_IP edge."""
    service = GraphCorrelationService()

    threat_intel = ThreatIntelligenceReport(
        ips=[
            IPThreatReport(
                ip="203.0.113.195",
                ip_type=IPType.IPV4,
                classification=IPClassification.PUBLIC,
                is_routable=True,
                threat_status=ThreatStatus.NOT_CHECKED,
            )
        ],
        domains=[
            DomainThreatReport(
                domain="relay.attacker.com",
                raw_domain="relay.attacker.com",
                threat_status=ThreatStatus.NOT_CHECKED,
            )
        ],
    )

    graph = service.build_graph(
        subject="Delivery Notice",
        message_id="<deliv-55@relay.attacker.com>",
        from_domain="relay.attacker.com",
        received_headers=["from relay.attacker.com (relay.attacker.com [203.0.113.195]) by mx.corp.com"],
        received_ips=["203.0.113.195"],
        threat_intel=threat_intel,
    )

    # Check transit hop edge
    transit_edge = next((e for e in graph.edges if e.relationship == EdgeRelationship.TRANSIT_HOP_IP), None)
    assert transit_edge is not None
    assert transit_edge.target == "ip:203.0.113.195"

    # Check IP metadata enrichment from threat intelligence
    ip_node = next((n for n in graph.nodes if n.id == "ip:203.0.113.195"), None)
    assert ip_node is not None
    assert ip_node.metadata.get("classification") == "public"
    assert ip_node.metadata.get("is_routable") is True

    # Check explicit RESOLVES_TO_IP edge from Received header binding
    resolve_edge = next((e for e in graph.edges if e.relationship == EdgeRelationship.RESOLVES_TO_IP), None)
    assert resolve_edge is not None
    assert resolve_edge.source == "domain:relay.attacker.com"
    assert resolve_edge.target == "ip:203.0.113.195"


def test_graph_correlation_deduplication_integrity():
    """Verify that duplicate URLs, domains, and transit IPs are deduplicated."""
    service = GraphCorrelationService()

    # Pass duplicate URLs, same domains for all headers, duplicate received IPs
    graph = service.build_graph(
        subject="Duplicate Entity Stress Test",
        message_id="<dup-test@bank.com>",
        from_domain="bank.com",
        reply_to_domain="bank.com",
        return_path_domain="bank.com",
        received_ips=["192.0.2.1", "192.0.2.1", "192.0.2.1"],
        urls=[
            "https://bank.com/login",
            "https://bank.com/login",
            "https://bank.com/login",
        ],
    )

    # Count nodes by ID
    node_ids = [n.id for n in graph.nodes]
    assert len(node_ids) == len(set(node_ids)), "All node IDs in graph must be unique"

    # Exactly one domain node, one URL node, one IP node, one email root node
    assert node_ids.count("domain:bank.com") == 1
    assert node_ids.count("url:https://bank.com/login") == 1
    assert node_ids.count("ip:192.0.2.1") == 1

    # Count edges by (source, target, relationship)
    edge_keys = [(e.source, e.target, e.relationship.value) for e in graph.edges]
    assert len(edge_keys) == len(set(edge_keys)), "All edges must be deduplicated"


def test_graph_correlation_empty_and_minimal_fallback():
    """Verify that graph gracefully constructs a root node without errors when input is minimal."""
    service = GraphCorrelationService()

    graph = service.build_graph()

    assert isinstance(graph, InvestigationGraph)
    assert len(graph.nodes) == 1
    assert graph.nodes[0].id == "email:message_root"
    assert graph.nodes[0].label == "Email Message"
    assert len(graph.edges) == 0
    assert "0 relationship edge(s)" in graph.summary


# ---------------------------------------------------------------------------
# Integration Tests: POST /api/v1/analyze-email Endpoint
# ---------------------------------------------------------------------------


def test_endpoint_investigation_graph_benign_email():
    """Test that the endpoint returns a valid investigation_graph for a legitimate email."""
    email_text = (
        "From: Alice Smith <alice@example.com>\n"
        "To: Bob Jones <bob@example.com>\n"
        "Subject: Project Kickoff Meeting\n"
        "Date: Mon, 01 Sep 2026 09:00:00 +0000\n"
        "Message-ID: <proj-meeting-001@example.com>\n"
        "Received: from mail.example.com ([93.184.216.34]) by mx.example.com; Mon, 01 Sep 2026 09:00:01 +0000\n"
        "Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass\n"
        "\n"
        "Hi Bob,\n\n"
        "Please review the agenda at https://example.com/agenda.\n"
    )

    response = client.post(ENDPOINT, json={"raw_email": email_text})
    assert response.status_code == 200
    data = response.json()

    assert "investigation_graph" in data
    graph = data["investigation_graph"]
    assert "nodes" in graph
    assert "edges" in graph
    assert "summary" in graph

    nodes = {n["id"]: n for n in graph["nodes"]}
    assert "email:proj-meeting-001@example.com" in nodes
    assert "domain:example.com" in nodes
    assert "url:https://example.com/agenda" in nodes
    assert "ip:93.184.216.34" in nodes

    edge_types = [e["relationship"] for e in graph["edges"]]
    assert "FROM_DOMAIN" in edge_types
    assert "CONTAINS_URL" in edge_types
    assert "HOSTED_ON_DOMAIN" in edge_types
    assert "TRANSIT_HOP_IP" in edge_types


def test_endpoint_investigation_graph_paypal_phishing_scenario():
    """Verify graph correlation captures phishing attack vectors on a suspicious email."""
    phishing_email = (
        "From: PayPal Support <service@paypal.com>\n"
        "Reply-To: security-verify@suspicious-paypal-verify.com\n"
        "Return-Path: bounce@attacker-relay.net\n"
        "To: victim@example.com\n"
        "Subject: Urgent: Your PayPal Account Has Been Suspended\n"
        "Date: Tue, 02 Sep 2026 14:00:00 +0000\n"
        "Message-ID: <phish-sec-999@paypal.com>\n"
        "Received: from attacker-relay.net ([203.0.113.100]) by mx.victim.com; Tue, 02 Sep 2026 14:00:01 +0000\n"
        "Authentication-Results: mx.victim.com; spf=fail; dkim=fail; dmarc=fail\n"
        "\n"
        "Dear Customer,\n\n"
        "Your account is locked. Restore access immediately:\n"
        "https://suspicious-paypal-verify.com/login?id=9928\n"
        "http://198.51.100.42:8000/emergency-restore\n"
    )

    response = client.post(ENDPOINT, json={"raw_email": phishing_email})
    assert response.status_code == 200
    data = response.json()

    graph = data["investigation_graph"]
    node_ids = {n["id"] for n in graph["nodes"]}

    # Domains
    assert "domain:paypal.com" in node_ids
    assert "domain:suspicious-paypal-verify.com" in node_ids
    assert "domain:attacker-relay.net" in node_ids

    # URLs
    assert "url:https://suspicious-paypal-verify.com/login?id=9928" in node_ids
    assert "url:http://198.51.100.42:8000/emergency-restore" in node_ids

    # IPs
    assert "ip:203.0.113.100" in node_ids
    assert "ip:198.51.100.42" in node_ids

    # Edges
    edges_map = {(e["source"], e["target"]): e["relationship"] for e in graph["edges"]}
    root_id = "email:phish-sec-999@paypal.com"

    assert edges_map.get((root_id, "domain:paypal.com")) == "FROM_DOMAIN"
    assert edges_map.get((root_id, "domain:suspicious-paypal-verify.com")) == "REPLY_TO_DOMAIN"
    assert edges_map.get((root_id, "domain:attacker-relay.net")) == "RETURN_PATH_DOMAIN"
    assert edges_map.get((root_id, "ip:203.0.113.100")) == "TRANSIT_HOP_IP"

    # URL host linkages
    assert edges_map.get((
        "url:https://suspicious-paypal-verify.com/login?id=9928",
        "domain:suspicious-paypal-verify.com",
    )) == "HOSTED_ON_DOMAIN"
    assert edges_map.get((
        "url:http://198.51.100.42:8000/emergency-restore",
        "ip:198.51.100.42",
    )) == "HOSTED_ON_IP"

    # Risk score preserved and high/critical
    assert data["risk_score"]["threat_level"] in ["high", "critical"]
    assert data["risk_score"]["score"] >= 50

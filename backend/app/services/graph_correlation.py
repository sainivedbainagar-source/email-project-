"""Investigation graph correlation service.

Constructs an explainable, deterministic entity graph connecting the analyzed email,
sender/reply-to/return-path domains, body URLs, URL host domains/IPs, and transit hop IPs.
"""

import ipaddress
import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from app.models.graph import (
    EdgeRelationship,
    GraphEdge,
    GraphNode,
    InvestigationGraph,
    NodeType,
)
from app.models.risk_scoring import RiskScore
from app.models.threat_intel import ThreatIntelligenceReport

RECEIVED_DOMAIN_IP_BINDING = re.compile(
    r"from\s+([a-zA-Z0-9\.-]+)\s+.*\[(?:IPv6:)?([0-9a-fA-F:\.]+)\]",
    re.IGNORECASE,
)


class GraphCorrelationService:
    """Service that builds an explainable forensic relationship graph from email metadata."""

    def build_graph(
        self,
        subject: Optional[str] = None,
        message_id: Optional[str] = None,
        date: Optional[str] = None,
        from_domain: Optional[str] = None,
        reply_to_domain: Optional[str] = None,
        return_path_domain: Optional[str] = None,
        received_headers: Optional[List[str]] = None,
        received_ips: Optional[List[str]] = None,
        urls: Optional[List[str]] = None,
        threat_intel: Optional[ThreatIntelligenceReport] = None,
        risk_score: Optional[RiskScore] = None,
    ) -> InvestigationGraph:
        """Construct the complete investigation graph from extracted evidence."""
        nodes: Dict[str, GraphNode] = {}
        edges: List[GraphEdge] = []
        seen_edges: Set[Tuple[str, str, str]] = set()

        def add_node(
            node_id: str,
            node_type: NodeType,
            label: str,
            metadata: Optional[Dict] = None,
        ) -> GraphNode:
            if node_id in nodes:
                if metadata:
                    nodes[node_id].metadata.update(metadata)
                return nodes[node_id]
            node = GraphNode(
                id=node_id,
                type=node_type,
                label=label,
                metadata=dict(metadata or {}),
            )
            nodes[node_id] = node
            return node

        def add_edge(
            source: str,
            target: str,
            relationship: EdgeRelationship,
            evidence: str,
        ) -> None:
            # Prevent self-loops or duplicate edges
            if source == target:
                return
            key = (source, target, relationship.value)
            if key in seen_edges:
                return
            seen_edges.add(key)
            edges.append(
                GraphEdge(
                    source=source,
                    target=target,
                    relationship=relationship,
                    evidence=evidence,
                )
            )

        # -------------------------------------------------------------------
        # 1. Email Root Node
        # -------------------------------------------------------------------
        email_id = (
            f"email:{message_id.strip('<> ')}"
            if message_id and message_id.strip("<> ")
            else "email:message_root"
        )
        email_label = subject.strip() if subject and subject.strip() else "Email Message"
        email_meta = {
            "subject": subject,
            "message_id": message_id,
            "date": date,
            "threat_level": risk_score.threat_level.value if risk_score else "unknown",
            "risk_score": risk_score.score if risk_score else 0,
        }
        email_node = add_node(email_id, NodeType.EMAIL, email_label, email_meta)

        # -------------------------------------------------------------------
        # 2. Header Domains (From, Reply-To, Return-Path)
        # -------------------------------------------------------------------
        if from_domain and from_domain.strip():
            clean_from = from_domain.strip().lower()
            from_node = add_node(
                f"domain:{clean_from}",
                NodeType.DOMAIN,
                clean_from,
                {"role": "from_domain"},
            )
            add_edge(
                email_node.id,
                from_node.id,
                EdgeRelationship.FROM_DOMAIN,
                f"From header declares sender address under domain '{clean_from}'",
            )

        if reply_to_domain and reply_to_domain.strip():
            clean_reply = reply_to_domain.strip().lower()
            reply_node = add_node(
                f"domain:{clean_reply}",
                NodeType.DOMAIN,
                clean_reply,
                {"role": "reply_to_domain"},
            )
            add_edge(
                email_node.id,
                reply_node.id,
                EdgeRelationship.REPLY_TO_DOMAIN,
                f"Reply-To header routes recipient responses to '{clean_reply}'",
            )

        if return_path_domain and return_path_domain.strip():
            clean_return = return_path_domain.strip().lower()
            return_node = add_node(
                f"domain:{clean_return}",
                NodeType.DOMAIN,
                clean_return,
                {"role": "return_path_domain"},
            )
            add_edge(
                email_node.id,
                return_node.id,
                EdgeRelationship.RETURN_PATH_DOMAIN,
                f"Return-Path envelope header designates bounce destination domain '{clean_return}'",
            )

        # -------------------------------------------------------------------
        # 3. URLs and URL Hosts (Domains or Direct IPs)
        # -------------------------------------------------------------------
        for url_str in urls or []:
            clean_url = url_str.strip()
            if not clean_url:
                continue

            url_id = f"url:{clean_url}"
            url_label = clean_url if len(clean_url) <= 60 else clean_url[:57] + "..."
            url_node = add_node(
                url_id,
                NodeType.URL,
                url_label,
                {"full_url": clean_url},
            )
            add_edge(
                email_node.id,
                url_node.id,
                EdgeRelationship.CONTAINS_URL,
                "Hyperlink extracted from email body content",
            )

            try:
                parsed = urlparse(clean_url)
                host = parsed.hostname
                if host and host.strip():
                    clean_host = host.strip().lower()
                    try:
                        # Check if host is a direct IP address
                        ipaddress.ip_address(clean_host)
                        ip_node = add_node(
                            f"ip:{clean_host}",
                            NodeType.IP_ADDRESS,
                            clean_host,
                            {"source": "url_host"},
                        )
                        add_edge(
                            url_node.id,
                            ip_node.id,
                            EdgeRelationship.HOSTED_ON_IP,
                            f"URL directly addresses host via IP '{clean_host}'",
                        )
                    except ValueError:
                        # Host is a domain
                        dom_node = add_node(
                            f"domain:{clean_host}",
                            NodeType.DOMAIN,
                            clean_host,
                            {"role": "url_domain"},
                        )
                        add_edge(
                            url_node.id,
                            dom_node.id,
                            EdgeRelationship.HOSTED_ON_DOMAIN,
                            f"URL is hosted under domain '{clean_host}'",
                        )
            except Exception:
                pass

        # -------------------------------------------------------------------
        # 4. Transit Hop IPs (from Received headers)
        # -------------------------------------------------------------------
        threat_ip_map = {}
        if threat_intel and threat_intel.ips:
            threat_ip_map = {item.ip: item for item in threat_intel.ips}

        for ip_str in received_ips or []:
            clean_ip = ip_str.strip()
            if not clean_ip:
                continue

            ip_meta = {"source": "received_transit_hop"}
            if clean_ip in threat_ip_map:
                ti_entry = threat_ip_map[clean_ip]
                ip_meta["classification"] = ti_entry.classification.value
                ip_meta["is_routable"] = ti_entry.is_routable

            ip_node = add_node(
                f"ip:{clean_ip}",
                NodeType.IP_ADDRESS,
                clean_ip,
                ip_meta,
            )
            add_edge(
                email_node.id,
                ip_node.id,
                EdgeRelationship.TRANSIT_HOP_IP,
                f"Received header records message transit relay through IP {clean_ip}",
            )

        # -------------------------------------------------------------------
        # 5. Received Header Explicit Domain-to-IP Associations
        # -------------------------------------------------------------------
        for header in received_headers or []:
            match = RECEIVED_DOMAIN_IP_BINDING.search(header)
            if match:
                hop_domain = match.group(1).lower().rstrip(".").strip("<>[]()")
                hop_ip = match.group(2).strip()
                domain_key = f"domain:{hop_domain}"
                ip_key = f"ip:{hop_ip}"

                # Link if both the domain and the IP exist in our graph
                if domain_key in nodes and ip_key in nodes:
                    add_edge(
                        domain_key,
                        ip_key,
                        EdgeRelationship.RESOLVES_TO_IP,
                        f"Received transit header explicitly associates domain '{hop_domain}' with IP [{hop_ip}]",
                    )

        # -------------------------------------------------------------------
        # 6. Graph Summary
        # -------------------------------------------------------------------
        summary = (
            f"Investigation graph contains {len(nodes)} unique entity node(s) and "
            f"{len(edges)} relationship edge(s). Correlated technical linkages represent message "
            "structure and network transit; they do not establish threat actor identity or physical location."
        )

        return InvestigationGraph(
            nodes=list(nodes.values()),
            edges=edges,
            summary=summary,
        )


_default_graph_service = GraphCorrelationService()


def get_graph_correlation_service() -> GraphCorrelationService:
    """Factory function returning the singleton GraphCorrelationService instance."""
    return _default_graph_service

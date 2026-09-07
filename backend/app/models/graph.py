"""Pydantic schemas and models for the investigation graph correlation feature."""

from enum import Enum
from typing import Any, Dict, List
from pydantic import BaseModel, Field


class NodeType(str, Enum):
    """Categorization of entities represented as nodes within the investigation graph."""

    EMAIL = "email"
    DOMAIN = "domain"
    URL = "url"
    IP_ADDRESS = "ip_address"


class EdgeRelationship(str, Enum):
    """Categorization of directional forensic links between graph nodes."""

    FROM_DOMAIN = "FROM_DOMAIN"
    REPLY_TO_DOMAIN = "REPLY_TO_DOMAIN"
    RETURN_PATH_DOMAIN = "RETURN_PATH_DOMAIN"
    CONTAINS_URL = "CONTAINS_URL"
    HOSTED_ON_DOMAIN = "HOSTED_ON_DOMAIN"
    HOSTED_ON_IP = "HOSTED_ON_IP"
    TRANSIT_HOP_IP = "TRANSIT_HOP_IP"
    RESOLVES_TO_IP = "RESOLVES_TO_IP"


class GraphNode(BaseModel):
    """Individual entity vertex within the forensic investigation graph."""

    id: str = Field(
        ...,
        description="Globally unique node identifier (e.g. 'domain:example.com', 'ip:192.0.2.1').",
    )
    type: NodeType = Field(
        ...,
        description="Standardized entity category (email, domain, url, ip_address).",
    )
    label: str = Field(
        ...,
        description="Human-readable display label suitable for graph visualization.",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Contextual forensic attributes and properties associated with this entity.",
    )


class GraphEdge(BaseModel):
    """Directional relationship connecting two vertices in the investigation graph."""

    source: str = Field(
        ...,
        description="Unique identifier of the originating source node.",
    )
    target: str = Field(
        ...,
        description="Unique identifier of the destination target node.",
    )
    relationship: EdgeRelationship = Field(
        ...,
        description="Semantic relationship type between source and target.",
    )
    evidence: str = Field(
        ...,
        description="Explainable forensic evidence or header trace establishing this relationship.",
    )


class InvestigationGraph(BaseModel):
    """Consolidated forensic investigation graph connecting extracted email entities."""

    nodes: List[GraphNode] = Field(
        default_factory=list,
        description="Deduplicated list of entity vertices in the graph.",
    )
    edges: List[GraphEdge] = Field(
        default_factory=list,
        description="Deduplicated list of directional forensic relationships connecting nodes.",
    )
    summary: str = Field(
        ...,
        description=(
            "Summary of graph topology and entity counts. "
            "Note: Correlated nodes and edges represent technical message linkages and do not "
            "prove threat actor identity or physical location."
        ),
    )

"""Pydantic schemas and models for threat intelligence."""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class IPType(str, Enum):
    """Internet Protocol version type."""

    IPV4 = "IPv4"
    IPV6 = "IPv6"


class IPClassification(str, Enum):
    """Categorization of an IP address scope based on RFC standards."""

    PUBLIC = "public"
    PRIVATE = "private"
    RESERVED = "reserved"
    LOOPBACK = "loopback"
    LINK_LOCAL = "link_local"
    MULTICAST = "multicast"


class ThreatStatus(str, Enum):
    """Standardized threat evaluation status.

    Explicitly separates unexamined resources from verified benign/malicious verdicts.
    """

    NOT_CHECKED = "not_checked"
    UNKNOWN = "unknown"
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class IPThreatReport(BaseModel):
    """Threat intelligence report for an extracted IP address."""

    ip: str = Field(..., description="Target IP address string.")
    ip_type: IPType = Field(..., description="IP protocol version (IPv4 or IPv6).")
    classification: IPClassification = Field(
        ...,
        description="Scope classification (public, private, reserved, loopback, link_local, multicast).",
    )
    is_routable: bool = Field(
        ...,
        description="Indicates whether the address is globally routable on the public Internet.",
    )
    threat_status: ThreatStatus = Field(
        default=ThreatStatus.NOT_CHECKED,
        description="Current threat intelligence verdict. Set to 'not_checked' when external feeds are inactive.",
    )
    reputation_score: Optional[int] = Field(
        default=None,
        description="Normalized risk score from 0 (benign) to 100 (critical threat). None when not evaluated.",
    )
    provider: str = Field(
        default="local_deterministic",
        description="Name of the intelligence provider or analysis engine.",
    )
    details: Optional[str] = Field(
        default=None,
        description="Contextual forensic details or provider-specific diagnostic notes.",
    )


class DomainThreatReport(BaseModel):
    """Threat intelligence report for an extracted domain."""

    domain: str = Field(..., description="Normalized domain name (lowercase, stripped).")
    raw_domain: str = Field(..., description="Original domain string prior to normalization.")
    tld: Optional[str] = Field(
        default=None,
        description="Top-level domain component (e.g. 'com', 'org').",
    )
    is_punycode: bool = Field(
        default=False,
        description="True if the domain is encoded in Internationalized Domain Name (IDN) Punycode.",
    )
    unicode_domain: Optional[str] = Field(
        default=None,
        description="Decoded Unicode representation of Punycode domain.",
    )
    threat_status: ThreatStatus = Field(
        default=ThreatStatus.NOT_CHECKED,
        description="Current threat intelligence verdict. Set to 'not_checked' when external feeds are inactive.",
    )
    reputation_score: Optional[int] = Field(
        default=None,
        description="Normalized risk score from 0 (benign) to 100 (critical threat). None when not evaluated.",
    )
    provider: str = Field(
        default="local_deterministic",
        description="Name of the intelligence provider or analysis engine.",
    )
    details: Optional[str] = Field(
        default=None,
        description="Contextual forensic details or provider-specific diagnostic notes.",
    )


class ThreatIntelligenceReport(BaseModel):
    """Consolidated threat intelligence report for all targets discovered in an email."""

    ips: List[IPThreatReport] = Field(
        default_factory=list,
        description="Threat reports for all extracted IPv4 and IPv6 addresses.",
    )
    domains: List[DomainThreatReport] = Field(
        default_factory=list,
        description="Threat reports for all extracted domains from headers and body URLs.",
    )
    summary: str = Field(
        default="Deterministic local analysis completed. External threat feeds (e.g. AbuseIPDB, VirusTotal) not queried.",
        description="High-level operational summary of the threat intelligence evaluation.",
    )

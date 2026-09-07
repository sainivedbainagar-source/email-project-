"""Local deterministic threat intelligence provider.

Performs strict RFC-compliant IP address classification and domain normalization
without relying on external network requests or third-party APIs.
"""

import ipaddress
import re
from typing import Optional, Tuple
import idna

from app.models.threat_intel import (
    DomainThreatReport,
    IPClassification,
    IPThreatReport,
    IPType,
    ThreatStatus,
)
from app.services.threat_intel.base import BaseThreatIntelProvider


class LocalDeterministicProvider(BaseThreatIntelProvider):
    """Deterministic local provider analyzing IP classification and domain structure."""

    # Special documentation, benchmark, and reserved network blocks
    RESERVED_IPV4_NETWORKS = [
        ipaddress.IPv4Network("192.0.2.0/24"),      # TEST-NET-1 (RFC 5737)
        ipaddress.IPv4Network("198.51.100.0/24"),   # TEST-NET-2 (RFC 5737)
        ipaddress.IPv4Network("203.0.113.0/24"),    # TEST-NET-3 (RFC 5737)
        ipaddress.IPv4Network("240.0.0.0/4"),       # Reserved for future use (RFC 1112)
        ipaddress.IPv4Network("100.64.0.0/10"),     # Shared Address Space / CGNAT (RFC 6598)
        ipaddress.IPv4Network("198.18.0.0/15"),     # Benchmarking (RFC 2544)
    ]

    PRIVATE_IPV4_NETWORKS = [
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv4Network("172.16.0.0/12"),
        ipaddress.IPv4Network("192.168.0.0/16"),
    ]

    RESERVED_IPV6_NETWORKS = [
        ipaddress.IPv6Network("2001:db8::/32"),     # Documentation (RFC 3849)
        ipaddress.IPv6Network("100::/64"),          # Discard prefix (RFC 6666)
    ]

    PRIVATE_IPV6_NETWORKS = [
        ipaddress.IPv6Network("fc00::/7"),          # Unique Local Address (RFC 4193)
    ]

    @property
    def name(self) -> str:
        return "local_deterministic"

    def classify_ip(self, ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> IPClassification:
        """Deterministically classify an IP address into scope categories."""
        if ip_obj.is_loopback:
            return IPClassification.LOOPBACK
        if ip_obj.is_link_local:
            return IPClassification.LINK_LOCAL
        if ip_obj.is_multicast:
            return IPClassification.MULTICAST
        if ip_obj.is_reserved:
            return IPClassification.RESERVED

        if isinstance(ip_obj, ipaddress.IPv4Address):
            for network in self.RESERVED_IPV4_NETWORKS:
                if ip_obj in network:
                    return IPClassification.RESERVED
            for network in self.PRIVATE_IPV4_NETWORKS:
                if ip_obj in network:
                    return IPClassification.PRIVATE
        elif isinstance(ip_obj, ipaddress.IPv6Address):
            for network in self.RESERVED_IPV6_NETWORKS:
                if ip_obj in network:
                    return IPClassification.RESERVED
            for network in self.PRIVATE_IPV6_NETWORKS:
                if ip_obj in network:
                    return IPClassification.PRIVATE

        if ip_obj.is_private:
            return IPClassification.PRIVATE
        if ip_obj.is_global:
            return IPClassification.PUBLIC

        return IPClassification.RESERVED

    def lookup_ip(self, ip: str) -> IPThreatReport:
        """Parse and classify an IP address."""
        clean_ip = ip.strip()
        try:
            ip_obj = ipaddress.ip_address(clean_ip)
            ip_type = IPType.IPV4 if ip_obj.version == 4 else IPType.IPV6
            classification = self.classify_ip(ip_obj)
            is_routable = classification == IPClassification.PUBLIC
            details = (
                f"Classified as {classification.value} {ip_type.value}. "
                "External threat feeds (e.g. AbuseIPDB, VirusTotal) not queried."
            )
        except ValueError:
            # Malformed or unparseable IP fallback
            ip_type = IPType.IPV4
            classification = IPClassification.RESERVED
            is_routable = False
            details = "Invalid or unparseable IP address format."

        return IPThreatReport(
            ip=clean_ip,
            ip_type=ip_type,
            classification=classification,
            is_routable=is_routable,
            threat_status=ThreatStatus.NOT_CHECKED,
            reputation_score=None,
            provider=self.name,
            details=details,
        )

    def normalize_domain(self, domain: str) -> Tuple[str, Optional[str], bool, Optional[str]]:
        """Normalize a domain, handling ports, paths, and IDN Punycode encoding."""
        raw = domain.strip().lower()

        # Remove scheme or path if present
        if "://" in raw:
            raw = raw.split("://", 1)[1]
        if "/" in raw:
            raw = raw.split("/", 1)[0]

        # Remove port if present (avoiding IPv6 bracketed addresses)
        if ":" in raw and not raw.startswith("["):
            raw = raw.split(":", 1)[0]

        # Remove trailing FQDN dot and stray characters
        raw = raw.rstrip(".").strip("<>[]()'\" ")

        is_punycode = False
        unicode_domain: Optional[str] = None

        if "xn--" in raw:
            is_punycode = True
            try:
                unicode_domain = idna.decode(raw)
            except Exception:
                unicode_domain = raw
        else:
            try:
                # Check for internationalized non-ASCII characters
                raw.encode("ascii")
            except UnicodeEncodeError:
                unicode_domain = raw
                try:
                    raw = idna.encode(raw).decode("ascii")
                    is_punycode = True
                except Exception:
                    pass

        tld = raw.split(".")[-1] if "." in raw else None
        return raw, unicode_domain, is_punycode, tld

    def lookup_domain(self, domain: str) -> DomainThreatReport:
        """Normalize and analyze domain structure."""
        normalized, unicode_domain, is_punycode, tld = self.normalize_domain(domain)

        details = (
            f"Normalized domain '{normalized}' with TLD '{tld or 'unknown'}'. "
            "External threat feeds (e.g. VirusTotal) not queried."
        )

        return DomainThreatReport(
            domain=normalized,
            raw_domain=domain,
            tld=tld,
            is_punycode=is_punycode,
            unicode_domain=unicode_domain,
            threat_status=ThreatStatus.NOT_CHECKED,
            reputation_score=None,
            provider=self.name,
            details=details,
        )

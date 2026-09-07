"""Abstract base interface for threat intelligence providers."""

from abc import ABC, abstractmethod

from app.models.threat_intel import DomainThreatReport, IPThreatReport


class BaseThreatIntelProvider(ABC):
    """Abstract base class defining the provider interface for threat intelligence feeds.

    Concrete implementations can be deterministic local analyzers or external API adapters
    (e.g., AbuseIPDB, VirusTotal, IPinfo).
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the unique name of this threat intelligence provider."""
        raise NotImplementedError

    @abstractmethod
    def lookup_ip(self, ip: str) -> IPThreatReport:
        """Evaluate or lookup threat intelligence for a single IP address."""
        raise NotImplementedError

    @abstractmethod
    def lookup_domain(self, domain: str) -> DomainThreatReport:
        """Evaluate or lookup threat intelligence for a single domain name."""
        raise NotImplementedError

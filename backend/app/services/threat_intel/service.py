"""Threat intelligence service orchestrator."""

from typing import List, Optional

from app.models.threat_intel import DomainThreatReport, IPThreatReport, ThreatIntelligenceReport
from app.services.threat_intel.base import BaseThreatIntelProvider
from app.services.threat_intel.local import LocalDeterministicProvider


class ThreatIntelService:
    """Service orchestrating deterministic and external threat intelligence analysis."""

    def __init__(self, providers: Optional[List[BaseThreatIntelProvider]] = None):
        self._providers: List[BaseThreatIntelProvider] = (
            providers if providers is not None else [LocalDeterministicProvider()]
        )

    def register_provider(self, provider: BaseThreatIntelProvider) -> None:
        """Register an additional provider adapter (e.g. AbuseIPDB, VirusTotal)."""
        self._providers.append(provider)

    def analyze_ips(self, ips: List[str]) -> List[IPThreatReport]:
        """Analyze and classify a list of IP addresses."""
        reports: List[IPThreatReport] = []
        seen = set()

        for ip in ips:
            clean = ip.strip()
            if not clean or clean in seen:
                continue
            seen.add(clean)

            # Evaluate with primary provider (local deterministic)
            primary_provider = self._providers[0]
            report = primary_provider.lookup_ip(clean)
            reports.append(report)

        return reports

    def analyze_domains(self, domains: List[str]) -> List[DomainThreatReport]:
        """Analyze and normalize a list of domain names."""
        reports: List[DomainThreatReport] = []
        seen = set()

        for domain in domains:
            clean = domain.strip()
            if not clean or clean.lower() in seen:
                continue
            seen.add(clean.lower())

            # Evaluate with primary provider (local deterministic)
            primary_provider = self._providers[0]
            report = primary_provider.lookup_domain(clean)
            reports.append(report)

        return reports

    def generate_report(self, ips: List[str], domains: List[str]) -> ThreatIntelligenceReport:
        """Generate a unified ThreatIntelligenceReport for discovered email targets."""
        ip_reports = self.analyze_ips(ips)
        domain_reports = self.analyze_domains(domains)

        return ThreatIntelligenceReport(
            ips=ip_reports,
            domains=domain_reports,
            summary=(
                f"Evaluated {len(ip_reports)} IP address(es) and {len(domain_reports)} domain(s). "
                "Deterministic local classification completed. External threat feeds not queried."
            ),
        )


_default_service = ThreatIntelService()


def get_threat_intel_service() -> ThreatIntelService:
    """Factory function returning the singleton ThreatIntelService instance."""
    return _default_service

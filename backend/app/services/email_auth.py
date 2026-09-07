"""Email authentication service (SPF, DKIM, DMARC) with a modular architecture.

Provides deterministic header-based parsing that can be replaced or augmented
by DNS-based verification mechanisms in future iterations.
"""

from abc import ABC, abstractmethod
from email.message import EmailMessage
import re
from typing import Optional

from app.models.email_analysis import AuthenticationResult


class BaseEmailAuthenticator(ABC):
    """Abstract base interface for email authentication evaluators."""

    @abstractmethod
    def evaluate(self, msg: EmailMessage) -> AuthenticationResult:
        """Evaluate SPF, DKIM, and DMARC status for an email message."""
        raise NotImplementedError


class HeaderBasedAuthenticator(BaseEmailAuthenticator):
    """Deterministic authenticator that extracts SPF, DKIM, and DMARC results

    from standard email headers (Authentication-Results, Received-SPF, ARC-Authentication-Results).
    """

    SPF_REGEX = re.compile(r"\bspf\s*=\s*([a-zA-Z0-9_-]+)", re.IGNORECASE)
    DKIM_REGEX = re.compile(r"\bdkim\s*=\s*([a-zA-Z0-9_-]+)", re.IGNORECASE)
    DMARC_REGEX = re.compile(r"\bdmarc\s*=\s*([a-zA-Z0-9_-]+)", re.IGNORECASE)
    RECEIVED_SPF_REGEX = re.compile(r"^\s*([a-zA-Z0-9_-]+)", re.IGNORECASE)

    def evaluate(self, msg: EmailMessage) -> AuthenticationResult:
        spf_result: Optional[str] = None
        dkim_result: Optional[str] = None
        dmarc_result: Optional[str] = None
        details_list = []

        # 1. Inspect Authentication-Results and ARC-Authentication-Results headers
        auth_headers = msg.get_all("Authentication-Results", []) or []
        arc_headers = msg.get_all("ARC-Authentication-Results", []) or []
        all_auth_headers = [str(h) for h in (auth_headers + arc_headers)]

        for header_value in all_auth_headers:
            clean_header = " ".join(header_value.split())

            if not spf_result:
                spf_match = self.SPF_REGEX.search(clean_header)
                if spf_match:
                    spf_result = spf_match.group(1).lower()

            if not dkim_result:
                dkim_match = self.DKIM_REGEX.search(clean_header)
                if dkim_match:
                    dkim_result = dkim_match.group(1).lower()

            if not dmarc_result:
                dmarc_match = self.DMARC_REGEX.search(clean_header)
                if dmarc_match:
                    dmarc_result = dmarc_match.group(1).lower()

            details_list.append(clean_header)

        # 2. Fallback for SPF: inspect Received-SPF header
        if not spf_result:
            received_spf_headers = msg.get_all("Received-SPF", []) or []
            for rspf in received_spf_headers:
                clean_rspf = " ".join(str(rspf).split())
                match = self.RECEIVED_SPF_REGEX.match(clean_rspf)
                if match:
                    spf_result = match.group(1).lower()
                    details_list.append(f"Received-SPF: {clean_rspf}")
                    break

        # 3. Fallback for DKIM: check presence of DKIM-Signature header
        if not dkim_result:
            dkim_sig = msg.get("DKIM-Signature")
            if dkim_sig:
                # Signature exists but no receiving MTA verification header found
                dkim_result = "signed"
                details_list.append("DKIM-Signature present (unverified by MTA header)")

        # Default unset results to "none"
        spf = spf_result if spf_result else "none"
        dkim = dkim_result if dkim_result else "none"
        dmarc = dmarc_result if dmarc_result else "none"

        details = " | ".join(details_list) if details_list else None

        return AuthenticationResult(
            spf=spf,
            dkim=dkim,
            dmarc=dmarc,
            details=details,
        )


def get_authenticator() -> BaseEmailAuthenticator:
    """Factory function returning the configured email authenticator.

    Enables seamless plug-in replacement for DNS-based authentication in the future.
    """
    return HeaderBasedAuthenticator()

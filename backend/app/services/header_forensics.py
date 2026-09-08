"""Header forensics and deterministic anomaly detection service."""

from email.utils import parseaddr
import ipaddress
import re
from typing import List, Optional

from app.models.email_analysis import AuthenticationResult, HeaderForensics, HeaderMismatch

# IPv4 regex pattern
IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Bracketed IP pattern commonly found in Received headers (e.g. [192.0.2.1] or [IPv6:2001:db8::1])
BRACKETED_IP_PATTERN = re.compile(r"\[(?:IPv6:)?([0-9a-fA-F:\.]+)\]")

try:
    import tldextract
    _tld_extractor = tldextract.TLDExtract(cache_dir=None)
except ImportError:
    _tld_extractor = None


def get_registered_domain(domain_or_address: Optional[str]) -> Optional[str]:
    """Extract the organizational / registrable domain (eTLD+1) from a domain name or address.

    Examples:
    - 'google.com' -> 'google.com'
    - 'scoutcamp.bounces.google.com' -> 'google.com'
    - 'workspace.google.com' -> 'google.com'
    - 'mail.paypal.co.uk' -> 'paypal.co.uk'
    """
    if not domain_or_address or not str(domain_or_address).strip():
        return None

    cleaned = str(domain_or_address).strip().lower().strip(".,;:!?'\"")
    if "@" in cleaned:
        cleaned = cleaned.split("@")[-1].strip().strip("<>[]()\"' ")

    if _tld_extractor:
        try:
            ext = _tld_extractor(cleaned)
            if ext.domain and ext.suffix:
                return f"{ext.domain}.{ext.suffix}".lower()
            if ext.domain:
                return ext.domain.lower()
        except Exception:
            pass

    # Fallback if tldextract is unavailable
    parts = cleaned.split(".")
    if len(parts) >= 2:
        if len(parts) >= 3 and parts[-2] in ("co", "com", "gov", "org", "net", "edu", "ac") and len(parts[-1]) == 2:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
    return cleaned


def is_same_organization(domain1: Optional[str], domain2: Optional[str]) -> bool:
    """Return True if domain1 and domain2 belong to the same organizational domain (eTLD+1)."""
    if not domain1 or not domain2:
        return False
    d1 = domain1.strip().lower()
    d2 = domain2.strip().lower()
    if d1 == d2:
        return True
    reg1 = get_registered_domain(d1)
    reg2 = get_registered_domain(d2)
    return bool(reg1 and reg2 and reg1 == reg2)


def extract_domain(address_str: Optional[str]) -> Optional[str]:
    """Extract and normalize the domain name from an email address or header string."""
    if not address_str or not address_str.strip():
        return None

    # Use email.utils.parseaddr to separate display name and email address
    _, addr = parseaddr(address_str)

    # Fallback to direct string search if parseaddr returns empty
    if not addr or "@" not in addr:
        match = re.search(r"[\w\.-]+@([\w\.-]+\.[a-zA-Z]{2,})", address_str)
        if match:
            return match.group(1).lower().strip(".,;:!?'\"")
        return None

    domain = addr.split("@")[-1].strip().strip("<>[]()\"' ").lower()

    # Basic validity check: must contain at least one dot and valid characters
    if "." in domain and not domain.startswith(".") and not domain.endswith("."):
        return domain

    return None


def extract_ips_from_received(received_headers: List[str]) -> List[str]:
    """Extract and validate all IPv4 and IPv6 addresses from Received headers in hop order."""
    if not received_headers:
        return []

    discovered_ips: List[str] = []
    seen = set()

    for header in received_headers:
        # 1. Check bracketed IPs first (most reliable MTA indicators)
        for candidate in BRACKETED_IP_PATTERN.findall(header):
            candidate = candidate.strip()
            try:
                ip_obj = ipaddress.ip_address(candidate)
                ip_str = str(ip_obj)
                if ip_str not in seen:
                    seen.add(ip_str)
                    discovered_ips.append(ip_str)
            except ValueError:
                pass

        # 2. Check general IPv4 occurrences
        for candidate in IPV4_PATTERN.findall(header):
            candidate = candidate.strip()
            try:
                ip_obj = ipaddress.ip_address(candidate)
                ip_str = str(ip_obj)
                if ip_str not in seen:
                    seen.add(ip_str)
                    discovered_ips.append(ip_str)
            except ValueError:
                pass

    return discovered_ips


def analyze_header_mismatches(
    from_domain: Optional[str],
    reply_to_domain: Optional[str],
    return_path_domain: Optional[str],
    from_header: Optional[str] = None,
    auth_result: Optional[AuthenticationResult] = None,
) -> HeaderMismatch:
    """Analyze headers for discrepancies and potential spoofing/phishing indicators.

    Uses organizational / registrable domains (eTLD+1) rather than exact hostname equality
    to ensure subdomains belonging to the same organization are not treated as mismatches.
    """
    indicators: List[str] = []
    from_reply_to_mismatch = False
    from_return_path_mismatch = False

    # 1. Check From domain vs Reply-To domain (organizational level)
    if from_domain and reply_to_domain and not is_same_organization(from_domain, reply_to_domain):
        from_reply_to_mismatch = True
        indicators.append(
            f"From domain '{from_domain}' does not match Reply-To domain '{reply_to_domain}'. "
            "Replies will be routed to a different organizational domain."
        )

    # 2. Check From domain vs Return-Path domain (organizational level)
    if from_domain and return_path_domain and not is_same_organization(from_domain, return_path_domain):
        from_return_path_mismatch = True
        indicators.append(
            f"From domain '{from_domain}' does not match Return-Path domain '{return_path_domain}'. "
            "Envelope sender differs from header sender organization."
        )

    # 3. Check for Display Name spoofing in From header (e.g. "CEO <scammer@other.com>" or "support@paypal.com <bad@evil.com>")
    if from_header:
        display_name, addr = parseaddr(from_header)
        if display_name and ("@" in display_name or ".com" in display_name.lower()):
            disp_domain = extract_domain(display_name)
            if disp_domain and from_domain and not is_same_organization(disp_domain, from_domain):
                indicators.append(
                    f"Display name '{display_name}' mimics domain '{disp_domain}' but actual sender domain is '{from_domain}'."
                )

    # 4. Check Authentication failure indicators
    if auth_result:
        if auth_result.spf.lower() in ("fail", "softfail"):
            indicators.append(f"SPF authentication failed with result: '{auth_result.spf}'.")
        if auth_result.dkim.lower() == "fail":
            indicators.append("DKIM authentication failed.")
        if auth_result.dmarc.lower() == "fail":
            indicators.append("DMARC authentication failed.")

    has_mismatch = (
        from_reply_to_mismatch
        or from_return_path_mismatch
        or len(indicators) > 0
    )

    return HeaderMismatch(
        has_mismatch=has_mismatch,
        from_reply_to_mismatch=from_reply_to_mismatch,
        from_return_path_mismatch=from_return_path_mismatch,
        indicators=indicators,
    )


def extract_header_forensics(
    from_header: Optional[str],
    reply_to_header: Optional[str],
    return_path_header: Optional[str],
    received_headers: List[str],
    auth_result: Optional[AuthenticationResult] = None,
) -> HeaderForensics:
    """Extract domain forensics, IP addresses, and mismatch indicators."""
    from_domain = extract_domain(from_header)
    reply_to_domain = extract_domain(reply_to_header)
    return_path_domain = extract_domain(return_path_header)
    received_ips = extract_ips_from_received(received_headers)

    mismatches = analyze_header_mismatches(
        from_domain=from_domain,
        reply_to_domain=reply_to_domain,
        return_path_domain=return_path_domain,
        from_header=from_header,
        auth_result=auth_result,
    )

    return HeaderForensics(
        from_domain=from_domain,
        reply_to_domain=reply_to_domain,
        return_path_domain=return_path_domain,
        received_ips=received_ips,
        mismatches=mismatches,
    )

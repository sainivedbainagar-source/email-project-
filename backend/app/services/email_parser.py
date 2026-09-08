"""Email parsing and extraction service utilizing Python's standard email library."""

import email
from email import policy
from email.message import EmailMessage
import ipaddress
import re
from typing import List, Optional
from urllib.parse import urlparse

from app.models.email_analysis import EmailAnalysisResponse
from app.services.ai_analysis import get_ai_service
from app.services.email_auth import get_authenticator
from app.services.graph_correlation import get_graph_correlation_service
from app.services.header_forensics import extract_header_forensics
from app.services.risk_scoring import get_risk_scoring_service
from app.services.threat_intel import get_threat_intel_service

# Regular expressions for URL extraction
URL_PATTERN = re.compile(
    r"(?:https?|ftp)://[^\s<>\"\'\)]+",
    re.IGNORECASE,
)
HREF_PATTERN = re.compile(
    r"href\s*=\s*[\"'](https?://[^\"\'\>\s]+)[\"']",
    re.IGNORECASE,
)


def extract_urls(text: str) -> List[str]:
    """Extract and deduplicate all URLs found in the given text while preserving order."""
    if not text:
        return []

    urls: List[str] = []
    seen = set()

    # 1. Capture HTML href links
    for match in HREF_PATTERN.findall(text):
        cleaned = match.strip().rstrip(".,;:!?\"')>]")
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            urls.append(cleaned)

    # 2. Capture plain text URLs
    for match in URL_PATTERN.findall(text):
        cleaned = match.strip().rstrip(".,;:!?\"')>]")
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            urls.append(cleaned)

    return urls


def extract_body(msg: EmailMessage) -> str:
    """Extract plain text and/or HTML body content from an email message.

    Skips attachments and handles character set decoding safely.
    """
    body_parts: List[str] = []

    if msg.is_multipart():
        for part in msg.walk():
            if part.is_multipart():
                continue

            content_disposition = str(part.get("Content-Disposition", "")).lower()
            if "attachment" in content_disposition:
                continue

            content_type = part.get_content_type()
            if content_type in ("text/plain", "text/html"):
                decoded_payload = part.get_payload(decode=True)
                if decoded_payload:
                    charset = part.get_content_charset() or "utf-8"
                    try:
                        text = decoded_payload.decode(charset, errors="replace")
                    except (LookupError, UnicodeDecodeError):
                        text = decoded_payload.decode("utf-8", errors="replace")
                    if text.strip():
                        body_parts.append(text.strip())
                else:
                    raw = part.get_payload()
                    if isinstance(raw, str) and raw.strip():
                        body_parts.append(raw.strip())
    else:
        decoded_payload = msg.get_payload(decode=True)
        if decoded_payload:
            charset = msg.get_content_charset() or "utf-8"
            try:
                text = decoded_payload.decode(charset, errors="replace")
            except (LookupError, UnicodeDecodeError):
                text = decoded_payload.decode("utf-8", errors="replace")
            if text.strip():
                body_parts.append(text.strip())
        else:
            raw = msg.get_payload()
            if isinstance(raw, str) and raw.strip():
                body_parts.append(raw.strip())

    return "\n\n".join(body_parts).strip()


def parse_raw_email(raw_email: str) -> EmailAnalysisResponse:
    """Parse raw RFC 822/2822/5322 email string and extract headers, body, URLs, authentication, forensics, and threat intelligence."""
    msg = email.message_from_string(raw_email, policy=policy.default)

    # Extract single-value headers
    from_header = str(msg.get("from")) if msg.get("from") is not None else None
    to_header = str(msg.get("to")) if msg.get("to") is not None else None
    subject_header = str(msg.get("subject")) if msg.get("subject") is not None else None
    date_header = str(msg.get("date")) if msg.get("date") is not None else None
    reply_to_header = str(msg.get("reply-to")) if msg.get("reply-to") is not None else None
    return_path_header = str(msg.get("return-path")) if msg.get("return-path") is not None else None
    message_id_header = str(msg.get("message-id")) if msg.get("message-id") is not None else None

    # Extract Received headers (can have multiple occurrences)
    raw_received = msg.get_all("received") or []
    received_headers = [str(h).strip() for h in raw_received if str(h).strip()]

    # Extract email body
    body_content = extract_body(msg)

    # Extract URLs from body
    extracted_urls = extract_urls(body_content)

    # Deterministic Authentication evaluation (SPF, DKIM, DMARC)
    authenticator = get_authenticator()
    auth_result = authenticator.evaluate(msg)

    # Header Forensics & Anomaly Analysis (Domains, IPs, Mismatches)
    forensics = extract_header_forensics(
        from_header=from_header,
        reply_to_header=reply_to_header,
        return_path_header=return_path_header,
        received_headers=received_headers,
        auth_result=auth_result,
    )

    # Collect domains and IPs for threat intelligence
    target_domains: List[str] = []
    target_ips: List[str] = list(forensics.received_ips)

    for domain in [forensics.from_domain, forensics.reply_to_domain, forensics.return_path_domain]:
        if domain and domain not in target_domains:
            target_domains.append(domain)

    # Extract hostnames/IPs from URLs
    for url in extracted_urls:
        try:
            parsed = urlparse(url)
            host = parsed.hostname
            if host:
                host = host.strip().lower()
                try:
                    ipaddress.ip_address(host)
                    if host not in target_ips:
                        target_ips.append(host)
                except ValueError:
                    if host not in target_domains:
                        target_domains.append(host)
        except Exception:
            pass

    threat_service = get_threat_intel_service()
    threat_report = threat_service.generate_report(ips=target_ips, domains=target_domains)

    # AI Content Analysis (Phishing, Urgency, Impersonation, Social Engineering)
    ai_service = get_ai_service()
    auth_summary = f"SPF: {auth_result.spf}, DKIM: {auth_result.dkim}, DMARC: {auth_result.dmarc}"
    ai_report = ai_service.analyze(
        subject=subject_header,
        body=body_content,
        sender=from_header,
        from_domain=forensics.from_domain,
        auth_status=auth_summary,
    )

    # Deterministic Risk Scoring Engine
    risk_service = get_risk_scoring_service()
    risk_score = risk_service.calculate_risk(
        auth_result=auth_result,
        forensics=forensics,
        threat_intel=threat_report,
        ai_analysis=ai_report,
        urls=extracted_urls,
    )

    # Deterministic Investigation Graph Correlation
    graph_service = get_graph_correlation_service()
    investigation_graph = graph_service.build_graph(
        subject=subject_header,
        message_id=message_id_header,
        date=date_header,
        from_domain=forensics.from_domain,
        reply_to_domain=forensics.reply_to_domain,
        return_path_domain=forensics.return_path_domain,
        received_headers=received_headers,
        received_ips=forensics.received_ips,
        urls=extracted_urls,
        threat_intel=threat_report,
        risk_score=risk_score,
    )

    return EmailAnalysisResponse(
        from_=from_header,
        to=to_header,
        subject=subject_header,
        date=date_header,
        reply_to=reply_to_header,
        return_path=return_path_header,
        message_id=message_id_header,
        received=received_headers,
        body=body_content,
        urls=extracted_urls,
        # Flat convenience fields
        spf=auth_result.spf,
        dkim=auth_result.dkim,
        dmarc=auth_result.dmarc,
        from_domain=forensics.from_domain,
        reply_to_domain=forensics.reply_to_domain,
        return_path_domain=forensics.return_path_domain,
        received_ips=forensics.received_ips,
        mismatch_indicators=forensics.mismatches.indicators,
        # Structured nested models
        authentication=auth_result,
        forensics=forensics,
        threat_intelligence=threat_report,
        ai_analysis=ai_report,
        risk_score=risk_score,
        investigation_graph=investigation_graph,
    )

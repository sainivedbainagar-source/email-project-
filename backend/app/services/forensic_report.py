"""Forensic report generation service.

Synthesizes complete email analysis (parsing, header forensics, threat intelligence,
AI content analysis, risk scoring, and graph correlation) into an explainable,
traceable, and evidence-backed forensic report.
"""

from datetime import datetime, timezone
import uuid
from typing import Dict, List, Optional, Set

from app.models.ai_analysis import AIAnalysisStatus, ContentThreatLevel
from app.models.email_analysis import EmailAnalysisResponse
from app.models.forensic_report import (
    ActionPriority,
    EmailMetadata,
    EvidenceType,
    FindingCategory,
    FindingSeverity,
    ForensicReport,
    RecommendedAction,
    ReportAIAnalysisSection,
    ReportAuthenticationSection,
    ReportEvidence,
    ReportExtractedIndicators,
    ReportFinding,
    ReportGraphSummary,
    ReportHeaderForensicsSection,
    ReportSummary,
    ReportThreatIntelligenceSection,
)
from app.models.risk_scoring import ThreatLevel

STANDARD_DISCLAIMERS: List[str] = [
    (
        "Observed technical indicators and investigation graph linkages reflect message structure "
        "and network relay transit. They do not constitute legal proof of threat actor identity or physical location."
    ),
    (
        "Authentication outcomes (SPF, DKIM, DMARC) are extracted directly from message headers "
        "and reflect header-reported status rather than independent live DNS or cryptographic verification."
    ),
    (
        "The numerical risk score (0–100) and threat levels are deterministic anomaly heuristics, "
        "not a legal determination or absolute probability of malicious intent."
    ),
    (
        "AI content analysis evaluates semantic patterns (urgency, impersonation, credential harvesting) "
        "as assistive intelligence and should be considered alongside deterministic header forensics."
    ),
]


class ForensicReportService:
    """Service that compiles an explainable, traceable forensic report from email analysis."""

    def generate_report(
        self,
        analysis: EmailAnalysisResponse,
        case_id: Optional[str] = None,
    ) -> ForensicReport:
        """Compile a comprehensive ForensicReport from an EmailAnalysisResponse."""
        report_id = case_id or f"REP-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
        generated_at = datetime.now(timezone.utc).isoformat()

        # -------------------------------------------------------------------
        # 1. Email Metadata
        # -------------------------------------------------------------------
        email_metadata = EmailMetadata(
            message_id=analysis.message_id,
            date=analysis.date,
            subject=analysis.subject,
            from_address=analysis.from_,
            to_address=analysis.to,
            reply_to_address=analysis.reply_to,
            return_path_address=analysis.return_path,
        )

        # -------------------------------------------------------------------
        # 2. Extract Factual Evidence (Observed Evidence Collection)
        # -------------------------------------------------------------------
        evidence_list: List[ReportEvidence] = []
        ev_id_counter = 1

        def add_evidence(
            ev_type: EvidenceType,
            source: str,
            raw_value: str,
            description: str,
        ) -> ReportEvidence:
            nonlocal ev_id_counter
            ev_id = f"EVD-{ev_id_counter:03d}"
            ev_id_counter += 1
            item = ReportEvidence(
                id=ev_id,
                type=ev_type,
                source=source,
                raw_value=raw_value,
                description=description,
            )
            evidence_list.append(item)
            return item

        # Headers evidence
        ev_from = None
        if analysis.from_:
            ev_from = add_evidence(
                EvidenceType.HEADER,
                "Header: From",
                analysis.from_,
                f"RFC From header designating claimed sender: {analysis.from_}",
            )

        ev_reply_to = None
        if analysis.reply_to:
            ev_reply_to = add_evidence(
                EvidenceType.HEADER,
                "Header: Reply-To",
                analysis.reply_to,
                f"RFC Reply-To header designating response destination: {analysis.reply_to}",
            )

        ev_return_path = None
        if analysis.return_path:
            ev_return_path = add_evidence(
                EvidenceType.HEADER,
                "Header: Return-Path",
                analysis.return_path,
                f"RFC Return-Path envelope designating bounce destination: {analysis.return_path}",
            )

        ev_subject = None
        if analysis.subject:
            ev_subject = add_evidence(
                EvidenceType.HEADER,
                "Header: Subject",
                analysis.subject,
                f"Email subject header: '{analysis.subject}'",
            )

        ev_auth = add_evidence(
            EvidenceType.HEADER,
            "Header: Authentication-Results",
            f"SPF={analysis.authentication.spf}; DKIM={analysis.authentication.dkim}; DMARC={analysis.authentication.dmarc}",
            (
                f"Header-reported authentication status: SPF '{analysis.authentication.spf}', "
                f"DKIM '{analysis.authentication.dkim}', DMARC '{analysis.authentication.dmarc}'"
            ),
        )

        # Received headers evidence
        ev_received_list: List[ReportEvidence] = []
        for idx, rec in enumerate(analysis.received, start=1):
            rec_ev = add_evidence(
                EvidenceType.HEADER,
                f"Header: Received (#{idx})",
                rec,
                f"Transit MTA relay hop recorded in Received header #{idx}",
            )
            ev_received_list.append(rec_ev)

        # Extracted URLs evidence
        ev_url_list: List[ReportEvidence] = []
        for url in analysis.urls:
            url_ev = add_evidence(
                EvidenceType.URL,
                "Email Body Hyperlink",
                url,
                f"Hyperlink extracted from message body: {url}",
            )
            ev_url_list.append(url_ev)

        # Body snippet evidence
        ev_body = None
        if analysis.body:
            body_preview = analysis.body[:300] + ("..." if len(analysis.body) > 300 else "")
            ev_body = add_evidence(
                EvidenceType.BODY_CONTENT,
                "Email Body Content",
                body_preview,
                f"Extracted plain/decoded body text ({len(analysis.body)} characters total)",
            )

        # AI analysis evidence
        ev_ai = None
        if analysis.ai_analysis:
            ai_summary_val = (
                f"Status: {analysis.ai_analysis.status.value}; "
                f"Threat Level: {analysis.ai_analysis.overall_threat_level.value}; "
                f"Impersonation: {analysis.ai_analysis.impersonation_detected}; "
                f"Credential Harvesting: {analysis.ai_analysis.credential_harvesting_detected}; "
                f"Urgency: {bool(analysis.ai_analysis.urgency_pressure_tactics)}"
            )
            ev_ai = add_evidence(
                EvidenceType.AI_INFERENCE,
                "Groq LLM Content Analysis",
                ai_summary_val,
                f"AI evaluation summary: {analysis.ai_analysis.summary or 'Content analysis completed'}",
            )

        # -------------------------------------------------------------------
        # 3. Derive Explainable Findings (strictly linked to evidence)
        # -------------------------------------------------------------------
        findings: List[ReportFinding] = []
        finding_id_counter = 1

        def add_finding(
            title: str,
            category: FindingCategory,
            severity: FindingSeverity,
            description: str,
            evidence_ids: List[str],
            mitigation_hint: Optional[str] = None,
        ) -> ReportFinding:
            nonlocal finding_id_counter
            f_id = f"FND-{finding_id_counter:03d}"
            finding_id_counter += 1
            f = ReportFinding(
                id=f_id,
                title=title,
                category=category,
                severity=severity,
                description=description,
                evidence_ids=evidence_ids,
                mitigation_hint=mitigation_hint,
            )
            findings.append(f)
            return f

        # --- A. Authentication Findings ---
        auth = analysis.authentication
        has_auth_failure = False
        if auth.spf in ["fail", "softfail"]:
            has_auth_failure = True
            add_finding(
                title=f"SPF Verification Failed ({auth.spf})",
                category=FindingCategory.AUTHENTICATION,
                severity=FindingSeverity.HIGH if auth.spf == "fail" else FindingSeverity.MEDIUM,
                description=(
                    f"The sending MTA IP was not designated as authorized by the sender domain SPF record "
                    f"(reported status: {auth.spf}). Message may be spoofed."
                ),
                evidence_ids=[ev_auth.id] + ([ev_from.id] if ev_from else []),
                mitigation_hint="Verify whether the sending IP belongs to an authorized mail service provider.",
            )

        if auth.dkim == "fail":
            has_auth_failure = True
            add_finding(
                title="DKIM Cryptographic Signature Failed",
                category=FindingCategory.AUTHENTICATION,
                severity=FindingSeverity.MEDIUM,
                description=(
                    "Header-reported DKIM cryptographic verification failed. "
                    "The message body or signed headers may have been modified in transit."
                ),
                evidence_ids=[ev_auth.id],
                mitigation_hint="Inspect email headers for header tampering or transit gateway modifications.",
            )

        if auth.dmarc == "fail":
            has_auth_failure = True
            add_finding(
                title="DMARC Alignment Verification Failed",
                category=FindingCategory.AUTHENTICATION,
                severity=FindingSeverity.HIGH,
                description=(
                    "The message failed sender domain DMARC alignment check. "
                    "Neither SPF nor DKIM passed with domain alignment."
                ),
                evidence_ids=[ev_auth.id] + ([ev_from.id] if ev_from else []),
                mitigation_hint="Enforce strict DMARC quarantine or reject policy at the inbound mail gateway.",
            )

        if not has_auth_failure and auth.spf == "pass" and auth.dkim == "pass":
            add_finding(
                title="Email Authentication Verified",
                category=FindingCategory.AUTHENTICATION,
                severity=FindingSeverity.INFO,
                description="Message headers report passing SPF and DKIM authentication with domain alignment.",
                evidence_ids=[ev_auth.id],
                mitigation_hint="Legitimate authentication confirms sending server authorization, but does not guarantee benign content.",
            )

        # --- B. Header Forensics Discrepancies ---
        forensics = analysis.forensics
        mismatches = forensics.mismatches
        has_mismatch = False

        if mismatches.from_reply_to_mismatch and ev_from and ev_reply_to:
            has_mismatch = True
            add_finding(
                title="Sender and Reply-To Domain Discrepancy",
                category=FindingCategory.HEADER_FORENSICS,
                severity=FindingSeverity.HIGH,
                description=(
                    f"The From domain ('{forensics.from_domain}') differs from the Reply-To domain "
                    f"('{forensics.reply_to_domain}'). Replies will be routed to a different domain, "
                    "a common tactic in phishing and business email compromise (BEC) campaigns."
                ),
                evidence_ids=[ev_from.id, ev_reply_to.id],
                mitigation_hint="Block or flag emails where Reply-To directs communication away from claimed brand domains.",
            )

        if mismatches.from_return_path_mismatch and ev_from and ev_return_path:
            has_mismatch = True
            add_finding(
                title="Sender and Return-Path Domain Discrepancy",
                category=FindingCategory.HEADER_FORENSICS,
                severity=FindingSeverity.MEDIUM,
                description=(
                    f"The From domain ('{forensics.from_domain}') differs from the Return-Path envelope "
                    f"domain ('{forensics.return_path_domain}'). Bounces and delivery notifications will route to a separate infrastructure."
                ),
                evidence_ids=[ev_from.id, ev_return_path.id],
                mitigation_hint="Inspect whether Return-Path belongs to a legitimate third-party ESP (e.g. SendGrid, Mailchimp).",
            )

        for indicator in mismatches.indicators:
            if "display name" in indicator.lower() and ev_from:
                add_finding(
                    title="Display Name Spoofing Detected",
                    category=FindingCategory.HEADER_FORENSICS,
                    severity=FindingSeverity.MEDIUM,
                    description=f"Header anomaly detected: {indicator}",
                    evidence_ids=[ev_from.id],
                    mitigation_hint="Educate users not to rely solely on display names when verifying sender identity.",
                )

        if not has_mismatch and forensics.from_domain:
            add_finding(
                title="Header Domains Fully Aligned",
                category=FindingCategory.HEADER_FORENSICS,
                severity=FindingSeverity.INFO,
                description=(
                    f"Sender domain ('{forensics.from_domain}') is consistent across available "
                    "From, Reply-To, and Return-Path headers."
                ),
                evidence_ids=[ev_from.id] if ev_from else [ev_auth.id],
            )

        # --- C. Body Link Findings ---
        if analysis.urls:
            # Check for suspicious direct-IP URLs
            ip_urls = [u for u in analysis.urls if any(c.isdigit() for c in u.split("://")[1].split("/")[0].split(":")[0]) and not any(c.isalpha() for c in u.split("://")[1].split("/")[0].split(":")[0])]
            for u in ip_urls:
                u_ev = next((ev for ev in ev_url_list if ev.raw_value == u), None)
                if u_ev:
                    add_finding(
                        title="Direct IP-Based Hyperlink Discovered",
                        category=FindingCategory.INFRASTRUCTURE,
                        severity=FindingSeverity.HIGH,
                        description=(
                            f"Hyperlink '{u}' specifies a raw numerical IP address instead of a registered domain name. "
                            "Direct IP links frequently bypass domain-based reputation filters and indicate suspicious hosting."
                        ),
                        evidence_ids=[u_ev.id],
                        mitigation_hint="Block direct IP URLs at the web proxy and secure email gateway.",
                    )

            # External domain mismatch check
            if forensics.from_domain:
                foreign_urls = []
                for u in analysis.urls:
                    if forensics.from_domain not in u.lower():
                        foreign_urls.append(u)
                if foreign_urls and len(foreign_urls) == len(analysis.urls):
                    u_evs = [ev.id for ev in ev_url_list if ev.raw_value in foreign_urls]
                    add_finding(
                        title="Hyperlinks Direct Away From Sender Domain",
                        category=FindingCategory.CONTENT_ANALYSIS,
                        severity=FindingSeverity.LOW if analysis.risk_score.score < 50 else FindingSeverity.MEDIUM,
                        description=(
                            f"All embedded hyperlinks point to external domains rather than the sender's domain '{forensics.from_domain}'."
                        ),
                        evidence_ids=u_evs[:3] + ([ev_from.id] if ev_from else []),
                        mitigation_hint="Verify whether the external link destination represents a recognized affiliate or business partner.",
                    )

        # --- D. AI Content Analysis Findings ---
        ai = analysis.ai_analysis
        if ai and ai.status == AIAnalysisStatus.COMPLETED and ev_ai:
            if ai.credential_harvesting_detected:
                add_finding(
                    title="AI Detected Credential Harvesting Intent",
                    category=FindingCategory.CONTENT_ANALYSIS,
                    severity=FindingSeverity.CRITICAL,
                    description=(
                        "AI language model identified explicit cues prompting the recipient to submit passwords, "
                        "account credentials, or authentication tokens."
                    ),
                    evidence_ids=[ev_ai.id] + ([ev_body.id] if ev_body else []),
                    mitigation_hint="Immediately revoke active sessions and reset credentials if recipient interacted with links.",
                )

            if ai.impersonation_detected:
                entities_str = ", ".join(ai.impersonated_entities) if ai.impersonated_entities else "recognized organization"
                add_finding(
                    title=f"AI Detected Brand Impersonation ({entities_str})",
                    category=FindingCategory.CONTENT_ANALYSIS,
                    severity=FindingSeverity.HIGH,
                    description=(
                        f"AI language model identified deceptive impersonation targeting: {entities_str}. "
                        "Sender appears to mimic an established entity to gain unearned trust."
                    ),
                    evidence_ids=[ev_ai.id] + ([ev_from.id] if ev_from else []),
                    mitigation_hint="Report impersonation abuse to the brand's security operations team.",
                )

            if ai.urgency_pressure_tactics:
                add_finding(
                    title="AI Detected Coercive Urgency or Pressure Tactics",
                    category=FindingCategory.CONTENT_ANALYSIS,
                    severity=FindingSeverity.MEDIUM,
                    description=(
                        f"AI model identified psychological pressure tactics: {'; '.join(ai.urgency_pressure_tactics)}. "
                        "Urgency is commonly leveraged to compel hurried actions without verification."
                    ),
                    evidence_ids=[ev_ai.id] + ([ev_body.id] if ev_body else []),
                    mitigation_hint="Train users to identify artificial deadlines and verify urgent requests through out-of-band channels.",
                )

            if ai.financial_requests_detected:
                add_finding(
                    title="AI Detected Financial or Payment Request",
                    category=FindingCategory.CONTENT_ANALYSIS,
                    severity=FindingSeverity.HIGH,
                    description="AI model identified wire transfer, invoice settlement, or cryptocurrency payment solicitations.",
                    evidence_ids=[ev_ai.id] + ([ev_body.id] if ev_body else []),
                    mitigation_hint="Verify bank routing details out-of-band using previously established contact numbers.",
                )

            if ai.overall_threat_level == ContentThreatLevel.BENIGN and not ai.phishing_indicators:
                add_finding(
                    title="AI Content Analysis: Benign Semantic Profile",
                    category=FindingCategory.CONTENT_ANALYSIS,
                    severity=FindingSeverity.INFO,
                    description="AI evaluation did not detect phishing lures, social engineering, or coercive patterns in message text.",
                    evidence_ids=[ev_ai.id],
                )
        elif ai and ai.status in [AIAnalysisStatus.NOT_CHECKED, AIAnalysisStatus.UNAVAILABLE]:
            add_finding(
                title=f"AI Content Analysis Not Performed ({ai.status.value})",
                category=FindingCategory.CONTENT_ANALYSIS,
                severity=FindingSeverity.INFO,
                description=(
                    f"AI content analysis was not completed (status: {ai.status.value}). "
                    "Risk scoring and findings rely solely on deterministic header and network forensics."
                ),
                evidence_ids=[ev_auth.id],
            )

        # --- E. Threat Intelligence Findings ---
        ti = analysis.threat_intelligence
        if ti and ti.ips:
            private_ips = [item.ip for item in ti.ips if not item.is_routable]
            if private_ips:
                ev_matches = [ev.id for ev in ev_received_list if any(p in ev.raw_value for p in private_ips)]
                if not ev_matches:
                    ev_matches = [ev_auth.id]
                add_finding(
                    title="Private or Non-Routable IP in Message Transit",
                    category=FindingCategory.THREAT_INTELLIGENCE,
                    severity=FindingSeverity.INFO,
                    description=(
                        f"Received headers contain non-routable / private IP addresses ({', '.join(private_ips)}). "
                        "This typically represents internal mail relays, staging servers, or local proxy interfaces."
                    ),
                    evidence_ids=ev_matches,
                )

        # --- F. Investigation Graph Correlation Finding ---
        graph = analysis.investigation_graph
        if graph and graph.nodes:
            notable_links = [f"{e.source} -> [{e.relationship.value}] -> {e.target}" for e in graph.edges[:3]]
            add_finding(
                title="Investigation Graph Correlated Entities",
                category=FindingCategory.GRAPH_CORRELATION,
                severity=FindingSeverity.INFO,
                description=(
                    f"Correlated {len(graph.nodes)} entity nodes and {len(graph.edges)} directional relationships. "
                    f"Key topological links: {'; '.join(notable_links) if notable_links else 'Direct email-entity associations'}. "
                    "Correlations reflect message transit and structural links; they do not establish threat actor identity."
                ),
                evidence_ids=[ev_from.id if ev_from else ev_auth.id],
            )

        # Fallback finding if email is completely clean and had no findings generated
        if not findings:
            add_finding(
                title="No Anomalous Indicators Discovered",
                category=FindingCategory.HEADER_FORENSICS,
                severity=FindingSeverity.INFO,
                description="Deterministic analysis of email headers, content, and network artifacts revealed no threat signals.",
                evidence_ids=[ev_auth.id],
            )

        # -------------------------------------------------------------------
        # 4. Synthesize Recommended Actions
        # -------------------------------------------------------------------
        actions: List[RecommendedAction] = []
        action_counter = 1

        def add_action(
            priority: ActionPriority,
            action: str,
            rationale: str,
            target_audience: str,
        ) -> None:
            nonlocal action_counter
            act_id = f"ACT-{action_counter:03d}"
            action_counter += 1
            actions.append(
                RecommendedAction(
                    id=act_id,
                    priority=priority,
                    action=action,
                    rationale=rationale,
                    target_audience=target_audience,
                )
            )

        threat_lvl = analysis.risk_score.threat_level
        risk_val = analysis.risk_score.score

        if threat_lvl in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]:
            add_action(
                priority=ActionPriority.IMMEDIATE,
                action="Quarantine or purge email from recipient inboxes across the organization.",
                rationale=f"Email exhibits elevated threat indicators with a calculated risk score of {risk_val}/100.",
                target_audience="Mail Administrator",
            )

            # If URLs present
            if analysis.urls:
                add_action(
                    priority=ActionPriority.HIGH,
                    action=f"Block extracted URLs ({len(analysis.urls)} link(s)) on perimeter web proxies and DNS filters.",
                    rationale="Prevent user endpoints from establishing outbound connections to potentially malicious hosting infrastructure.",
                    target_audience="SOC Analyst",
                )

            # If sender domain mismatch or credential theft
            if (ai and ai.credential_harvesting_detected) or (mismatches and mismatches.from_reply_to_mismatch):
                add_action(
                    priority=ActionPriority.HIGH,
                    action="Identify any users who opened or replied to this message and enforce immediate credential resets.",
                    rationale="Credential harvesting indicators or reply redirection tactics present high risk of account compromise.",
                    target_audience="SOC Analyst",
                )

            add_action(
                priority=ActionPriority.MEDIUM,
                action="Distribute an internal phishing alert advising users not to interact with similar unsolicited notices.",
                rationale="Threat campaign may be actively targeting other employees using identical lure themes.",
                target_audience="End User",
            )

        elif threat_lvl == ThreatLevel.MEDIUM:
            add_action(
                priority=ActionPriority.MEDIUM,
                action="Move message to user Quarantine or Spam folder pending secondary manual review.",
                rationale=f"Moderate risk signals detected (score {risk_val}/100). Message should not be directly trusted.",
                target_audience="Mail Administrator",
            )
            add_action(
                priority=ActionPriority.MEDIUM,
                action="Verify sender authenticity via known out-of-band communication channel before executing any requested actions.",
                rationale="Header discrepancies or authentication anomalies suggest possible sender impersonation.",
                target_audience="End User",
            )
            add_action(
                priority=ActionPriority.LOW,
                action="Audit sender domain SPF, DKIM, and DMARC configurations if sender is a recognized vendor or business partner.",
                rationale="Legitimate senders with misconfigured DNS records can trigger false-positive authentication alerts.",
                target_audience="SOC Analyst",
            )

        else:  # LOW / CLEAN
            add_action(
                priority=ActionPriority.INFORMATIONAL,
                action="Permit normal message delivery to recipient inbox.",
                rationale="Email exhibits no elevated risk factors and aligns with standard authentication policies.",
                target_audience="Mail Administrator",
            )
            add_action(
                priority=ActionPriority.LOW,
                action="Maintain standard operational vigilance and report unexpected behavioral anomalies.",
                rationale="Zero-day campaigns or newly compromised legitimate accounts can initially appear clean.",
                target_audience="End User",
            )

        # -------------------------------------------------------------------
        # 5. Executive Summary
        # -------------------------------------------------------------------
        critical_indicators = [
            f.title for f in findings if f.severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH]
        ]
        if not critical_indicators and analysis.risk_score.factors:
            critical_indicators = [factor.factor for factor in analysis.risk_score.factors]

        summary_narrative = (
            f"Forensic evaluation classified this message as {threat_lvl.value.upper()} threat "
            f"(Deterministic Risk Score: {risk_val}/100) based on {len(findings)} explainable finding(s). "
        )
        if critical_indicators:
            summary_narrative += f"Primary risk drivers: {'; '.join(critical_indicators[:3])}. "
        else:
            summary_narrative += "No suspicious header discrepancies, authentication failures, or social engineering cues observed. "
        summary_narrative += (
            f"{len(actions)} operational action(s) recommended for SOC and Mail Administration."
        )

        executive_summary = ReportSummary(
            threat_level=threat_lvl,
            risk_score=risk_val,
            summary_text=summary_narrative,
            key_findings_count=len(findings),
            critical_indicators=critical_indicators,
        )

        # -------------------------------------------------------------------
        # 6. Structured Sections
        # -------------------------------------------------------------------
        auth_section = ReportAuthenticationSection(
            spf=analysis.authentication.spf,
            dkim=analysis.authentication.dkim,
            dmarc=analysis.authentication.dmarc,
            details=analysis.authentication.details,
            verification_scope_note="Extracted from message headers; not an authoritative DNS or cryptographic validation.",
        )

        header_forensics_section = ReportHeaderForensicsSection(
            from_domain=analysis.forensics.from_domain,
            reply_to_domain=analysis.forensics.reply_to_domain,
            return_path_domain=analysis.forensics.return_path_domain,
            received_ips=analysis.forensics.received_ips,
            mismatch_indicators=analysis.forensics.mismatches.indicators,
        )

        all_domains: Set[str] = set()
        for d in [analysis.forensics.from_domain, analysis.forensics.reply_to_domain, analysis.forensics.return_path_domain]:
            if d:
                all_domains.add(d)
        if analysis.threat_intelligence and analysis.threat_intelligence.domains:
            for d_rep in analysis.threat_intelligence.domains:
                all_domains.add(d_rep.domain)

        all_ips: Set[str] = set(analysis.forensics.received_ips)
        if analysis.threat_intelligence and analysis.threat_intelligence.ips:
            for ip_rep in analysis.threat_intelligence.ips:
                all_ips.add(ip_rep.ip)

        indicators_section = ReportExtractedIndicators(
            urls=list(analysis.urls),
            domains=sorted(list(all_domains)),
            ips=sorted(list(all_ips)),
        )

        ti_section = ReportThreatIntelligenceSection(
            total_ips_evaluated=len(analysis.threat_intelligence.ips) if analysis.threat_intelligence else 0,
            total_domains_evaluated=len(analysis.threat_intelligence.domains) if analysis.threat_intelligence else 0,
            summary=analysis.threat_intelligence.summary if analysis.threat_intelligence else "Threat intelligence evaluation completed.",
            external_feeds_queried=False,
        )

        ai_section = ReportAIAnalysisSection(
            status=analysis.ai_analysis.status.value if analysis.ai_analysis else "not_checked",
            overall_threat_level=analysis.ai_analysis.overall_threat_level.value if analysis.ai_analysis else None,
            summary=analysis.ai_analysis.summary if analysis.ai_analysis else None,
            impersonation_detected=analysis.ai_analysis.impersonation_detected if analysis.ai_analysis else False,
            credential_harvesting_detected=analysis.ai_analysis.credential_harvesting_detected if analysis.ai_analysis else False,
            urgency_detected=bool(analysis.ai_analysis.urgency_pressure_tactics) if analysis.ai_analysis else False,
            financial_requests_detected=analysis.ai_analysis.financial_requests_detected if analysis.ai_analysis else False,
            provider=analysis.ai_analysis.provider if analysis.ai_analysis else None,
        )

        key_graph_links: List[str] = []
        if analysis.investigation_graph and analysis.investigation_graph.edges:
            for edge in analysis.investigation_graph.edges[:5]:
                key_graph_links.append(f"{edge.source} -> [{edge.relationship.value}] -> {edge.target}")

        graph_section = ReportGraphSummary(
            total_nodes=len(analysis.investigation_graph.nodes) if analysis.investigation_graph else 0,
            total_edges=len(analysis.investigation_graph.edges) if analysis.investigation_graph else 0,
            summary=analysis.investigation_graph.summary if analysis.investigation_graph else "Investigation graph empty.",
            key_linkages=key_graph_links,
        )

        # -------------------------------------------------------------------
        # 7. Compile Complete Report
        # -------------------------------------------------------------------
        return ForensicReport(
            report_id=report_id,
            generated_at=generated_at,
            email_metadata=email_metadata,
            executive_summary=executive_summary,
            authentication=auth_section,
            header_forensics=header_forensics_section,
            extracted_indicators=indicators_section,
            threat_intelligence=ti_section,
            ai_analysis=ai_section,
            investigation_graph=graph_section,
            detailed_findings=findings,
            evidence_list=evidence_list,
            recommended_actions=actions,
            disclaimers=STANDARD_DISCLAIMERS,
        )


_default_forensic_report_service = ForensicReportService()


def get_forensic_report_service() -> ForensicReportService:
    """Singleton factory returning the ForensicReportService instance."""
    return _default_forensic_report_service

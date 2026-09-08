"""Deterministic risk scoring engine for email security and forensic intelligence.

Combines structured evidence from header forensics, authentication results (SPF/DKIM/DMARC),
domain/IP threat intelligence, and AI content analysis into an explainable 0-100 risk score.
"""

import ipaddress
from typing import List, Optional
from urllib.parse import urlparse

from app.models.ai_analysis import AIAnalysisStatus, AIContentAnalysis
from app.models.email_analysis import AuthenticationResult, HeaderForensics
from app.models.risk_scoring import RiskFactor, RiskScore, ThreatLevel
from app.models.threat_intel import ThreatIntelligenceReport, ThreatStatus
from app.services.header_forensics import get_registered_domain, is_same_organization


class RiskScoringService:
    """Service that computes a deterministic, explainable composite risk score from 0 to 100."""

    @staticmethod
    def map_threat_level(score: int) -> ThreatLevel:
        """Map numerical score (0-100) into standardized threat levels."""
        if score < 25:
            return ThreatLevel.LOW
        elif score < 50:
            return ThreatLevel.MEDIUM
        elif score < 75:
            return ThreatLevel.HIGH
        else:
            return ThreatLevel.CRITICAL

    def calculate_risk(
        self,
        auth_result: AuthenticationResult,
        forensics: HeaderForensics,
        threat_intel: ThreatIntelligenceReport,
        ai_analysis: AIContentAnalysis,
        urls: List[str],
    ) -> RiskScore:
        """Evaluate evidence across all analytical modules and return an itemized RiskScore."""
        factors: List[RiskFactor] = []
        from_dom = (forensics.from_domain or "").lower()

        # -------------------------------------------------------------------
        # 1. Authentication Integrity (Header-reported SPF, DKIM, DMARC)
        # Note: These reflect MTA header evaluations, not direct DNS cryptographic proofs.
        # -------------------------------------------------------------------
        spf = (auth_result.spf or "none").strip().lower()
        if spf in ("fail", "permerror"):
            factors.append(
                RiskFactor(
                    factor="SPF_AUTHENTICATION_FAILED",
                    points=15,
                    reason=(
                        f"Header-reported SPF check failed with status '{spf}'. "
                        "The sending MTA IP was not designated as authorized by domain policy."
                    ),
                )
            )
        elif spf == "softfail":
            factors.append(
                RiskFactor(
                    factor="SPF_AUTHENTICATION_SOFTFAIL",
                    points=8,
                    reason=(
                        "Header-reported SPF check returned softfail. "
                        "Domain policy marks the sending IP as questionable/unconfirmed."
                    ),
                )
            )

        dmarc = (auth_result.dmarc or "none").strip().lower()
        if dmarc == "fail":
            factors.append(
                RiskFactor(
                    factor="DMARC_POLICY_FAILED",
                    points=15,
                    reason=(
                        "Header-reported DMARC alignment check failed. "
                        "Message violates sender domain published DMARC policy."
                    ),
                )
            )

        dkim = (auth_result.dkim or "none").strip().lower()
        if dkim in ("fail", "permerror"):
            factors.append(
                RiskFactor(
                    factor="DKIM_SIGNATURE_FAILED",
                    points=10,
                    reason=(
                        f"Header-reported DKIM cryptographic check failed ('{dkim}'). "
                        "Message contents or headers may have been modified in transit."
                    ),
                )
            )

        # -------------------------------------------------------------------
        # 2. Header Forensics & Identity Mismatch Indicators
        # -------------------------------------------------------------------
        mismatches = forensics.mismatches
        if mismatches.from_reply_to_mismatch:
            factors.append(
                RiskFactor(
                    factor="FROM_REPLY_TO_MISMATCH",
                    points=15,
                    reason=(
                        f"Sender From domain ('{forensics.from_domain}') differs from "
                        f"Reply-To domain ('{forensics.reply_to_domain}'). "
                        "Common indicator of reply redirection or credential theft."
                    ),
                )
            )

        if mismatches.from_return_path_mismatch:
            factors.append(
                RiskFactor(
                    factor="FROM_RETURN_PATH_MISMATCH",
                    points=10,
                    reason=(
                        f"Sender From domain ('{forensics.from_domain}') differs from "
                        f"Return-Path envelope domain ('{forensics.return_path_domain}'). "
                        "Envelope sender discrepancy suggests potential sender spoofing."
                    ),
                )
            )

        # Display name spoofing (e.g. "support@brand.com" <attacker@evil.com>)
        display_name_spoofed = any(
            "mimics domain" in ind.lower() or "display name" in ind.lower()
            for ind in mismatches.indicators
        )
        if display_name_spoofed:
            factors.append(
                RiskFactor(
                    factor="DISPLAY_NAME_DECEPTION",
                    points=10,
                    reason=(
                        "From header display name mimics a brand or email address "
                        "that conflicts with the actual sender domain."
                    ),
                )
            )

        # -------------------------------------------------------------------
        # 3. URL & Domain Forensics
        # -------------------------------------------------------------------
        # Check for Punycode / IDN homograph domains
        punycode_domains = [d.domain for d in threat_intel.domains if d.is_punycode]
        if punycode_domains:
            factors.append(
                RiskFactor(
                    factor="PUNYCODE_HOMOGRAPH_DOMAIN",
                    points=15,
                    reason=(
                        f"Internationalized Punycode domain detected ({', '.join(punycode_domains)}). "
                        "Punycode is frequently employed in deceptive homograph attacks."
                    ),
                )
            )

        # Check for direct IP address hosts in URLs
        ip_urls = []
        url_domains = []
        for u in urls:
            try:
                host = urlparse(u).hostname
                if host:
                    host = host.strip()
                    try:
                        ipaddress.ip_address(host)
                        if host not in ip_urls:
                            ip_urls.append(host)
                    except ValueError:
                        if host.lower() not in url_domains:
                            url_domains.append(host.lower())
            except Exception:
                pass

        if ip_urls:
            factors.append(
                RiskFactor(
                    factor="IP_ADDRESS_URL_HOST",
                    points=10,
                    reason=(
                        f"Body URL uses a raw IP address ({', '.join(ip_urls)}) rather than a domain name, "
                        "bypassing standard DNS-based reputation controls."
                    ),
                )
            )

        # External Link Domain Mismatch:
        # Evaluate whether URLs align with the sender's organizational domain (eTLD+1).
        # External links and URL shorteners are treated as weak evidence unless stronger malicious indicators exist.
        has_external_link_mismatch = False
        if forensics.from_domain and url_domains:
            from_dom = forensics.from_domain.lower()
            aligned = any(
                is_same_organization(d, from_dom) or d == from_dom or d.endswith("." + from_dom)
                for d in url_domains
            )
            if not aligned and len(url_domains) > 0:
                has_external_link_mismatch = True
                has_auth_pass = (spf == "pass" and dkim == "pass" and dmarc == "pass")
                has_other_risks = (
                    bool(mismatches.from_reply_to_mismatch)
                    or bool(mismatches.from_return_path_mismatch)
                    or display_name_spoofed
                    or bool(ip_urls)
                    or bool(punycode_domains)
                    or (spf in ("fail", "permerror", "softfail"))
                    or (dmarc == "fail")
                    or (dkim in ("fail", "permerror"))
                    or (threat_intel and any(d.threat_status == ThreatStatus.MALICIOUS for d in threat_intel.domains))
                    or (
                        ai_analysis.status == AIAnalysisStatus.COMPLETED
                        and (
                            ai_analysis.credential_harvesting_detected
                            or ai_analysis.impersonation_detected
                            or ai_analysis.financial_requests_detected
                        )
                    )
                )

                # Weak evidence: only penalize external links if other risk indicators exist or auth didn't pass
                if has_other_risks or not has_auth_pass:
                    factors.append(
                        RiskFactor(
                            factor="EXTERNAL_LINK_DOMAIN_MISMATCH",
                            points=5,
                            reason=(
                                f"Hyperlinks point exclusively to third-party domains ({', '.join(url_domains[:3])}) "
                                f"unaffiliated with sender domain '{from_dom}'."
                            ),
                        )
                    )

        # -------------------------------------------------------------------
        # 4. AI Content Analysis (Evaluated ONLY if AI service completed)
        # Note: If AI is not_checked or unavailable, 0 points are added.
        # -------------------------------------------------------------------
        if ai_analysis.status == AIAnalysisStatus.COMPLETED:
            if ai_analysis.credential_harvesting_detected:
                factors.append(
                    RiskFactor(
                        factor="AI_CREDENTIAL_HARVESTING",
                        points=15,
                        reason=(
                            "AI content analysis detected explicit login credential, "
                            "password, or account verification harvesting intent."
                        ),
                    )
                )

            if ai_analysis.impersonation_detected:
                entities = ", ".join(ai_analysis.impersonated_entities) or "an authority"
                factors.append(
                    RiskFactor(
                        factor="AI_IMPERSONATION_DETECTED",
                        points=10,
                        reason=f"AI content analysis detected brand or executive impersonation ({entities}).",
                    )
                )

            if ai_analysis.financial_requests_detected:
                factors.append(
                    RiskFactor(
                        factor="AI_FINANCIAL_FRAUD_REQUEST",
                        points=10,
                        reason=(
                            "AI content analysis identified fraudulent payment, wire transfer, "
                            "invoice, or gift card solicitation."
                        ),
                    )
                )

            if ai_analysis.urgency_pressure_tactics:
                factors.append(
                    RiskFactor(
                        factor="AI_URGENCY_PRESSURE_TACTICS",
                        points=5,
                        reason=(
                            f"AI content analysis identified coercive urgency cues: "
                            f"{', '.join(ai_analysis.urgency_pressure_tactics[:2])}."
                        ),
                    )
                )

        # -------------------------------------------------------------------
        # 5. Evidence-Based Compound Threat Factors (Cross-Module Combinations)
        # Identifies compounding multi-vector risk synergies while keeping
        # scoring deterministic, transparent, and capped at 100.
        # -------------------------------------------------------------------
        has_ip_url = bool(ip_urls)
        has_off_domain_link = has_external_link_mismatch or has_ip_url
        has_auth_failure = (
            spf in ("fail", "permerror")
            or dmarc == "fail"
            or dkim in ("fail", "permerror")
        )
        has_routing_mismatch = (
            mismatches.from_reply_to_mismatch
            or mismatches.from_return_path_mismatch
            or display_name_spoofed
        )

        if ai_analysis.status == AIAnalysisStatus.COMPLETED:
            # Compound 1: Targeted Credential Phishing Lure
            # Convergence of brand impersonation, credential harvesting, and off-domain destination links or off-brand sender
            is_off_brand = (
                any(
                    not is_same_organization(ent.lower(), from_dom)
                    for ent in ai_analysis.impersonated_entities
                )
                if ai_analysis.impersonated_entities
                else False
            )
            if (
                ai_analysis.credential_harvesting_detected
                and ai_analysis.impersonation_detected
                and (has_off_domain_link or is_off_brand or not from_dom)
            ):
                impersonated = ", ".join(ai_analysis.impersonated_entities) or "trusted brand"
                dest = ", ".join(url_domains[:2]) if url_domains else (", ".join(ip_urls[:2]) if ip_urls else "external host")
                factors.append(
                    RiskFactor(
                        factor="COMPOUND_CREDENTIAL_PHISHING_LURE",
                        points=20,
                        reason=(
                            f"High-confidence phishing lure: brand impersonation ('{impersonated}') "
                            f"converges with deceptive destination links ('{dest}') "
                            "and credential harvesting directives."
                        ),
                    )
                )

            # Compound 2: Coercive Psychological Pressure in Phishing
            # Artificial urgency pressure cues deployed alongside credential harvesting or impersonation
            if ai_analysis.urgency_pressure_tactics and (
                ai_analysis.credential_harvesting_detected
                or ai_analysis.impersonation_detected
                or ai_analysis.financial_requests_detected
            ):
                urgency_cues = ", ".join(ai_analysis.urgency_pressure_tactics[:2])
                factors.append(
                    RiskFactor(
                        factor="COMPOUND_COERCIVE_URGENCY_PRESSURE",
                        points=15,
                        reason=(
                            f"Coercive psychological manipulation: artificial urgency pressure cues "
                            f"({urgency_cues}) deployed alongside deceptive exploitation indicators "
                            "to induce impulsive compliance."
                        ),
                    )
                )

            # Compound 3: Spoofed Identity Misdirection
            # Brand impersonation coincides with sender header routing discrepancies (Reply-To or Return-Path diversion)
            if ai_analysis.impersonation_detected and has_routing_mismatch:
                factors.append(
                    RiskFactor(
                        factor="COMPOUND_SPOOFED_BRAND_IMPERSONATION",
                        points=15,
                        reason=(
                            "Identity deception synergy: brand impersonation coincides with sender header "
                            "routing discrepancies (Reply-To or Return-Path diverted to third-party infrastructure)."
                        ),
                    )
                )

            # Compound 4: Cryptographic / Policy Authentication Failure with Phishing Content
            # Header-reported auth failures directly coinciding with active deceptive phishing content
            if has_auth_failure and (
                ai_analysis.credential_harvesting_detected
                or ai_analysis.impersonation_detected
            ):
                factors.append(
                    RiskFactor(
                        factor="COMPOUND_AUTHENTICATION_FAILURE_WITH_PHISHING",
                        points=15,
                        reason=(
                            "Authentication policy failure (SPF/DKIM/DMARC) directly coincides with "
                            "active deceptive phishing content (credential harvesting or brand impersonation)."
                        ),
                    )
                )

            # Compound 5: Financial Fraud & Brand/Executive Impersonation (BEC)
            if ai_analysis.financial_requests_detected and ai_analysis.impersonation_detected:
                factors.append(
                    RiskFactor(
                        factor="COMPOUND_FINANCIAL_IMPERSONATION_FRAUD",
                        points=15,
                        reason=(
                            "Business Email Compromise (BEC) pattern: brand or executive impersonation "
                            "directly combined with payment, invoice, or wire transfer solicitation."
                        ),
                    )
                )

        # -------------------------------------------------------------------
        # Aggregate Score Computation & Threat Level Mapping
        # -------------------------------------------------------------------
        raw_score = sum(f.points for f in factors)
        score = min(100, max(0, raw_score))
        threat_level = self.map_threat_level(score)

        if score == 0:
            summary = "Clean email with no elevated risk indicators or security anomalies detected."
        else:
            summary = (
                f"Threat Level: {threat_level.value.upper()} (Score: {score}/100) based on "
                f"{len(factors)} triggered risk factor(s): {', '.join(f.factor for f in factors)}."
            )

        return RiskScore(
            score=score,
            threat_level=threat_level,
            factors=factors,
            summary=summary,
        )


_default_risk_service = RiskScoringService()


def get_risk_scoring_service() -> RiskScoringService:
    """Factory function returning the singleton RiskScoringService instance."""
    return _default_risk_service

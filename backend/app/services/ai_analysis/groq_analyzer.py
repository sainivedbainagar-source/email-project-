"""Groq API content analysis implementation for email security forensics."""

import json
from typing import Any, Dict, List, Optional
import httpx

from app.core.config import settings
from app.models.ai_analysis import AIAnalysisStatus, AIContentAnalysis, ContentThreatLevel
from app.services.ai_analysis.base import BaseAIContentAnalyzer

SYSTEM_PROMPT = """You are a senior email cybersecurity and forensic intelligence analyst.
Evaluate the provided email content for cyber threats, social engineering, credential harvesting, and fraud.

CRITICAL EVALUATION GUIDELINES (FALSE-POSITIVE PREVENTION):
1. DISTINGUISH COMMERCIAL MARKETING FROM COERCIVE PHISHING:
   - Legitimate commercial marketing, newsletters, product promotions, SaaS onboarding, and promotional discounts often use promotional calls-to-action, links, and marketing deadlines (e.g. 'limited time offer', 'save 50%', 'finish setting up your account', 'offer valid until tomorrow').
   - DO NOT classify legitimate promotional discounts, incentives, or onboarding notifications as malicious phishing or coercive urgency.
   - ONLY flag 'urgency_pressure_tactics' when there is coercive, manipulative panic or severe threats (e.g., immediate account suspension, administrative lock-out within 24h, law enforcement threat, unauthorized access alert).

2. FIRST-PARTY BRAND COMMUNICATION vs. IMPERSONATION:
   - If an email originates from the legitimate domain of an organization (e.g., Google sending emails about Google Workspace from google.com, or PayPal sending from paypal.com), this is legitimate first-party communication and NOT impersonation.
   - ONLY flag 'impersonation_detected' when an attacker is pretending to be a third-party brand from unrelated or spoofed infrastructure.

3. CREDENTIAL HARVESTING:
   - ONLY flag 'credential_harvesting_detected' when the email explicitly directs the recipient to enter passwords, login credentials, PINs, or sensitive account recovery secrets on suspicious or external forms.

You MUST respond strictly with a valid JSON object matching this schema:
{
  "overall_threat_level": "benign" | "low" | "medium" | "high" | "critical",
  "phishing_indicators": ["list of detected phishing tactics, deceptive claims, or lure details"],
  "urgency_pressure_tactics": ["list of identified coercive urgency cues, deadlines, or panic-inducing phrasing"],
  "impersonation_detected": true or false,
  "impersonated_entities": ["list of entities, brands, or roles being impersonated"],
  "credential_harvesting_detected": true or false,
  "financial_requests_detected": true or false,
  "social_engineering_patterns": ["list of psychological triggers, pretexting, or manipulation techniques"],
  "summary": "concise rationale and threat assessment"
}
"""


class GroqContentAnalyzer(BaseAIContentAnalyzer):
    """AI analyzer using Groq's low-latency inference endpoint."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        api_url: Optional[str] = None,
        timeout_seconds: Optional[float] = None,
    ):
        self._api_key = api_key
        self._model = model
        self._api_url = api_url
        self._timeout_seconds = timeout_seconds

    @property
    def api_key(self) -> Optional[str]:
        return self._api_key if self._api_key is not None else settings.GROQ_API_KEY

    @property
    def model(self) -> str:
        return self._model if self._model is not None else settings.GROQ_MODEL

    @property
    def api_url(self) -> str:
        return self._api_url if self._api_url is not None else settings.GROQ_API_URL

    @property
    def timeout_seconds(self) -> float:
        return (
            self._timeout_seconds
            if self._timeout_seconds is not None
            else settings.GROQ_TIMEOUT_SECONDS
        )

    @property
    def provider_name(self) -> str:
        return "groq"

    def _normalize_threat_level(self, val: Any) -> ContentThreatLevel:
        if not val or not isinstance(val, str):
            return ContentThreatLevel.UNKNOWN
        clean = val.strip().lower()
        level_map = {
            "benign": ContentThreatLevel.BENIGN,
            "low": ContentThreatLevel.LOW,
            "medium": ContentThreatLevel.MEDIUM,
            "high": ContentThreatLevel.HIGH,
            "critical": ContentThreatLevel.CRITICAL,
        }
        return level_map.get(clean, ContentThreatLevel.UNKNOWN)

    def analyze_content(
        self,
        subject: Optional[str],
        body: str,
        sender: Optional[str] = None,
        from_domain: Optional[str] = None,
        auth_status: Optional[str] = None,
    ) -> AIContentAnalysis:
        """Analyze subject and body using Groq API with sender context."""
        # Check if API key is configured
        if not self.api_key or not self.api_key.strip():
            return AIContentAnalysis(
                status=AIAnalysisStatus.NOT_CHECKED,
                overall_threat_level=ContentThreatLevel.NOT_CHECKED,
                provider=self.provider_name,
                model=self.model,
                summary="GROQ_API_KEY is not configured in environment. AI content analysis skipped.",
            )

        # Truncate content reasonably to avoid extreme context token overflows
        safe_subject = (subject or "").strip()[:500]
        safe_body = (body or "").strip()[:8000]

        meta_parts = []
        if sender:
            meta_parts.append(f"From (Sender Header): {sender.strip()[:200]}")
        if from_domain:
            meta_parts.append(f"Sender Domain: {from_domain.strip()[:100]}")
        if auth_status:
            meta_parts.append(f"Authentication Results: {auth_status.strip()[:200]}")

        meta_header = "\n".join(meta_parts) + "\n\n" if meta_parts else ""
        user_content = f"{meta_header}Subject: {safe_subject}\n\nEmail Body:\n{safe_body}"

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_content},
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.1,
        }

        headers = {
            "Authorization": f"Bearer {self.api_key.strip()}",
            "Content-Type": "application/json",
        }

        try:
            with httpx.Client(timeout=self.timeout_seconds) as client:
                response = client.post(self.api_url, json=payload, headers=headers)
                response.raise_for_status()
                data = response.json()

            # Parse JSON content inside choice
            choices = data.get("choices", [])
            if not choices:
                raise ValueError("No completion choices returned by Groq API.")

            raw_message_content = choices[0].get("message", {}).get("content", "{}")
            parsed_result: Dict[str, Any] = json.loads(raw_message_content)

            return AIContentAnalysis(
                status=AIAnalysisStatus.COMPLETED,
                overall_threat_level=self._normalize_threat_level(
                    parsed_result.get("overall_threat_level")
                ),
                phishing_indicators=list(parsed_result.get("phishing_indicators") or []),
                urgency_pressure_tactics=list(parsed_result.get("urgency_pressure_tactics") or []),
                impersonation_detected=bool(parsed_result.get("impersonation_detected", False)),
                impersonated_entities=list(parsed_result.get("impersonated_entities") or []),
                credential_harvesting_detected=bool(
                    parsed_result.get("credential_harvesting_detected", False)
                ),
                financial_requests_detected=bool(
                    parsed_result.get("financial_requests_detected", False)
                ),
                social_engineering_patterns=list(
                    parsed_result.get("social_engineering_patterns") or []
                ),
                summary=parsed_result.get("summary"),
                provider=self.provider_name,
                model=self.model,
                error_message=None,
            )

        except httpx.TimeoutException as exc:
            return AIContentAnalysis(
                status=AIAnalysisStatus.UNAVAILABLE,
                overall_threat_level=ContentThreatLevel.UNKNOWN,
                provider=self.provider_name,
                model=self.model,
                error_message=f"Groq API connection timed out ({self.timeout_seconds}s).",
            )
        except httpx.HTTPStatusError as exc:
            return AIContentAnalysis(
                status=AIAnalysisStatus.UNAVAILABLE,
                overall_threat_level=ContentThreatLevel.UNKNOWN,
                provider=self.provider_name,
                model=self.model,
                error_message=f"Groq API returned HTTP error {exc.response.status_code}.",
            )
        except httpx.RequestError as exc:
            return AIContentAnalysis(
                status=AIAnalysisStatus.UNAVAILABLE,
                overall_threat_level=ContentThreatLevel.UNKNOWN,
                provider=self.provider_name,
                model=self.model,
                error_message=f"Network error communicating with Groq API: {str(exc)}",
            )
        except Exception as exc:
            return AIContentAnalysis(
                status=AIAnalysisStatus.UNAVAILABLE,
                overall_threat_level=ContentThreatLevel.UNKNOWN,
                provider=self.provider_name,
                model=self.model,
                error_message=f"AI content evaluation failed: {str(exc)}",
            )

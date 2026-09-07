"""Groq API content analysis implementation for email security forensics."""

import json
from typing import Any, Dict, List, Optional
import httpx

from app.core.config import settings
from app.models.ai_analysis import AIAnalysisStatus, AIContentAnalysis, ContentThreatLevel
from app.services.ai_analysis.base import BaseAIContentAnalyzer

SYSTEM_PROMPT = """You are a senior email cybersecurity and forensic intelligence analyst.
Evaluate the provided email subject and body content for cyber threats, social engineering, and fraud.

You MUST respond strictly with a valid JSON object matching this schema:
{
  "overall_threat_level": "benign" | "low" | "medium" | "high" | "critical",
  "phishing_indicators": ["list of detected phishing tactics, deceptive claims, or lure details"],
  "urgency_pressure_tactics": ["list of identified urgency cues, deadlines, or panic-inducing phrasing"],
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

    def analyze_content(self, subject: Optional[str], body: str) -> AIContentAnalysis:
        """Analyze subject and body using Groq API."""
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

        user_content = f"Subject: {safe_subject}\n\nEmail Body:\n{safe_body}"

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

"""Abstract base interface for AI email content analyzers."""

from abc import ABC, abstractmethod
from typing import Optional

from app.models.ai_analysis import AIContentAnalysis


class BaseAIContentAnalyzer(ABC):
    """Interface for AI/LLM providers analyzing email subject and body content."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return the unique identifier of the AI provider."""
        raise NotImplementedError

    @abstractmethod
    def analyze_content(
        self,
        subject: Optional[str],
        body: str,
        sender: Optional[str] = None,
        from_domain: Optional[str] = None,
        auth_status: Optional[str] = None,
    ) -> AIContentAnalysis:
        """Analyze subject and body for phishing, urgency, impersonation, and social engineering."""
        raise NotImplementedError

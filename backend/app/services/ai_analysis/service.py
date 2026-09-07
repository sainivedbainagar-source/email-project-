"""AI content analysis service orchestrator."""

from typing import Optional

from app.models.ai_analysis import AIContentAnalysis
from app.services.ai_analysis.base import BaseAIContentAnalyzer
from app.services.ai_analysis.groq_analyzer import GroqContentAnalyzer


class AIAnalysisService:
    """Service managing AI email content analysis with pluggable provider adapters."""

    def __init__(self, analyzer: Optional[BaseAIContentAnalyzer] = None):
        self._analyzer: BaseAIContentAnalyzer = (
            analyzer if analyzer is not None else GroqContentAnalyzer()
        )

    def set_analyzer(self, analyzer: BaseAIContentAnalyzer) -> None:
        """Replace the active AI analyzer (useful for testing or alternative providers)."""
        self._analyzer = analyzer

    def analyze(self, subject: Optional[str], body: str) -> AIContentAnalysis:
        """Evaluate email subject and body for security threats."""
        return self._analyzer.analyze_content(subject=subject, body=body)


_default_ai_service = AIAnalysisService()


def get_ai_service() -> AIAnalysisService:
    """Factory function returning the configured AIAnalysisService instance."""
    return _default_ai_service

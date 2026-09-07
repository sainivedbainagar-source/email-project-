"""Email analysis API endpoints."""

from fastapi import APIRouter, HTTPException, status

from app.models.email_analysis import EmailAnalysisRequest, EmailAnalysisResponse
from app.models.forensic_report import ForensicReport
from app.services.email_parser import parse_raw_email
from app.services.forensic_report import get_forensic_report_service

router = APIRouter()


@router.post(
    "/analyze-email",
    response_model=EmailAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze and parse raw email",
    description="Accepts a raw RFC 822/2822/5322 email string, parses headers, extracts body content, and discovers URLs.",
)
async def analyze_email(payload: EmailAnalysisRequest) -> EmailAnalysisResponse:
    """Analyze raw email text and extract structured forensic metadata."""
    if not payload.raw_email or not payload.raw_email.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Raw email content cannot be empty or only whitespace.",
        )

    try:
        result = parse_raw_email(payload.raw_email)
        return result
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to parse email message: {str(exc)}",
        ) from exc


@router.post(
    "/analyze-email/report",
    response_model=ForensicReport,
    status_code=status.HTTP_200_OK,
    summary="Generate comprehensive forensic investigation report",
    description=(
        "Executes the full email analysis pipeline (parsing, authentication, forensics, "
        "threat intelligence, AI analysis, risk scoring, graph correlation) and compiles a "
        "structured, explainable forensic report with traceable findings and recommended actions."
    ),
)
async def generate_email_forensic_report(payload: EmailAnalysisRequest) -> ForensicReport:
    """Generate an explainable and evidence-backed forensic report for a raw email."""
    if not payload.raw_email or not payload.raw_email.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Raw email content cannot be empty or only whitespace.",
        )

    try:
        analysis = parse_raw_email(payload.raw_email)
        report_service = get_forensic_report_service()
        report = report_service.generate_report(analysis)
        return report
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to generate forensic report: {str(exc)}",
        ) from exc

"""V1 API Router aggregator."""

from fastapi import APIRouter

from app.api.v1.endpoints.email import router as email_router
from app.api.v1.endpoints.gmail import router as gmail_router

api_router = APIRouter()

api_router.include_router(email_router, tags=["Email Analysis"])
api_router.include_router(gmail_router, tags=["Gmail"])
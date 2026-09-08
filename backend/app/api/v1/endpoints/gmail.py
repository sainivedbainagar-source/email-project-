import os
from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
from googleapiclient.discovery import build
import base64

from app.services.gmail_service import (
    create_google_flow,
    load_gmail_credentials,
    save_gmail_credentials,
)
from app.services.email_parser import parse_raw_email

router = APIRouter()

gmail_credentials = load_gmail_credentials()


@router.get("/gmail/auth")
def gmail_auth(request: Request):
    redirect_uri = None
    if os.getenv("GOOGLE_REDIRECT_URI"):
        redirect_uri = os.getenv("GOOGLE_REDIRECT_URI")
    else:
        proto = request.headers.get("x-forwarded-proto") or request.url.scheme
        host = request.headers.get("x-forwarded-host") or request.headers.get("host")
        if host and host not in ("localhost:8001", "127.0.0.1:8001"):
            redirect_uri = f"{proto}://{host}/api/v1/gmail/oauth/callback"

    flow = create_google_flow(redirect_uri=redirect_uri)

    authorization_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
    )

    return RedirectResponse(authorization_url)


@router.get("/gmail/oauth/callback")
def gmail_callback(code: str, request: Request):
    global gmail_credentials

    redirect_uri = None
    if os.getenv("GOOGLE_REDIRECT_URI"):
        redirect_uri = os.getenv("GOOGLE_REDIRECT_URI")
    else:
        proto = request.headers.get("x-forwarded-proto") or request.url.scheme
        host = request.headers.get("x-forwarded-host") or request.headers.get("host")
        if host and host not in ("localhost:8001", "127.0.0.1:8001"):
            redirect_uri = f"{proto}://{host}/api/v1/gmail/oauth/callback"

    flow = create_google_flow(redirect_uri=redirect_uri)
    flow.fetch_token(code=code)

    gmail_credentials = flow.credentials
    save_gmail_credentials(gmail_credentials)

    return RedirectResponse(url="/frontend/t8.html")


@router.get("/gmail/emails")
def get_gmail_emails():
    if gmail_credentials is None:
        return {
            "status": "error",
            "message": "Gmail is not connected. Open /api/v1/gmail/auth first."
        }

    gmail = build(
        "gmail",
        "v1",
        credentials=gmail_credentials
    )

    results = gmail.users().messages().list(
        userId="me",
        maxResults=5
    ).execute()

    messages = results.get("messages", [])

    emails = []

    for message in messages:
        email_data = gmail.users().messages().get(
            userId="me",
            id=message["id"],
            format="full"
        ).execute()

        headers = email_data["payload"].get("headers", [])

        subject = next(
            (
                h["value"]
                for h in headers
                if h["name"].lower() == "subject"
            ),
            ""
        )

        sender = next(
            (
                h["value"]
                for h in headers
                if h["name"].lower() == "from"
            ),
            ""
        )

        emails.append({
            "id": message["id"],
            "thread_id": email_data.get("threadId"),
            "from": sender,
            "subject": subject,
            "snippet": email_data.get("snippet", "")
        })

    return {
        "status": "success",
        "count": len(emails),
        "emails": emails
    }


@router.get("/gmail/emails/{message_id}")
def get_gmail_email(message_id: str):
    if gmail_credentials is None:
        return {
            "status": "error",
            "message": "Gmail is not connected. Open /api/v1/gmail/auth first."
        }

    gmail = build(
        "gmail",
        "v1",
        credentials=gmail_credentials
    )

    email_data = gmail.users().messages().get(
        userId="me",
        id=message_id,
        format="raw"
    ).execute()

    raw_email = base64.urlsafe_b64decode(
        email_data["raw"] + "==="
    ).decode("utf-8", errors="replace")

    return {
        "status": "success",
        "id": message_id,
        "raw_email": raw_email
    }


@router.post("/gmail/emails/{message_id}/analyze")
def analyze_gmail_email(message_id: str):
    if gmail_credentials is None:
        return {
            "status": "error",
            "message": "Gmail is not connected."
        }

    gmail = build(
        "gmail",
        "v1",
        credentials=gmail_credentials
    )

    email_data = gmail.users().messages().get(
        userId="me",
        id=message_id,
        format="raw"
    ).execute()

    raw_email = base64.urlsafe_b64decode(
        email_data["raw"] + "==="
    ).decode("utf-8", errors="replace")

    # Send the real Gmail email into the existing ThreatMail AI pipeline
    analysis = parse_raw_email(raw_email)

    return analysis
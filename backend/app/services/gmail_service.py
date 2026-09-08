import os
from pathlib import Path

from dotenv import load_dotenv
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import Flow

load_dotenv()

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8001/api/v1/gmail/oauth/callback")

TOKEN_FILE = Path(__file__).resolve().parents[2] / "token.json"


def create_google_flow(redirect_uri: str = None):
    chosen_uri = redirect_uri or os.getenv("GOOGLE_REDIRECT_URI") or REDIRECT_URI
    allowed_uris = list(dict.fromkeys([chosen_uri, REDIRECT_URI, "http://localhost:8001/api/v1/gmail/oauth/callback"]))

    client_config = {
        "web": {
            "client_id": os.getenv("GOOGLE_CLIENT_ID"),
            "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": allowed_uris,
        }
    }

    return Flow.from_client_config(
        client_config,
        scopes=SCOPES,
        redirect_uri=chosen_uri,
        autogenerate_code_verifier=False,
    )


def load_gmail_credentials():
    if not TOKEN_FILE.exists():
        return None

    try:
        credentials = Credentials.from_authorized_user_file(
            str(TOKEN_FILE),
            SCOPES
        )

        if credentials.expired and credentials.refresh_token:
            credentials.refresh(Request())
            save_gmail_credentials(credentials)

        return credentials

    except Exception:
        return None


def save_gmail_credentials(credentials):
    TOKEN_FILE.write_text(
        credentials.to_json(),
        encoding="utf-8"
    )
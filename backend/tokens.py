"""
tokens.py
Module to generate and verify expiring, secure download tokens for PDF reports.
"""

from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from fastapi import HTTPException

SECRET_KEY = "super-secret-key"  # TODO: Use environment variable in production
serializer = URLSafeTimedSerializer(SECRET_KEY)

def create_download_token(report_id: str, expires_sec: int = 3600) -> str:
    """
    Create a signed token for secure PDF download, valid for expires_sec seconds.
    """
    return serializer.dumps({"report_id": report_id})

def verify_download_token(token: str, max_age: int = 3600) -> str:
    """
    Verify a signed download token and return the report_id if valid.
    Raises HTTPException if invalid or expired.
    """
    try:
        data = serializer.loads(token, max_age=max_age)
        return data["report_id"]
    except SignatureExpired:
        raise HTTPException(status_code=401, detail="Token expired")
    except BadSignature:
        raise HTTPException(status_code=401, detail="Invalid token")
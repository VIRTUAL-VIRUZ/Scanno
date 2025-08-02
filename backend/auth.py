"""
auth.py
Module to handle authentication using Firebase Auth.
"""

import firebase_admin
from firebase_admin import auth, credentials
from fastapi import HTTPException
from typing import Dict

# Initialize Firebase Admin SDK (should be called once at startup)
cred = credentials.Certificate("/path/to/firebase-service-account.json")  # TODO: Set correct path
if not firebase_admin._apps:
    firebase_admin.initialize_app(cred)

def verify_firebase_token(id_token: str) -> Dict:
    """
    Verify a Firebase ID token and return user info.
    Raises HTTPException if invalid.
    """
    try:
        decoded_token = auth.verify_id_token(id_token)
        return decoded_token
    except Exception as e:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
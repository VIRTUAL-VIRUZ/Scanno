"""
web_routes.py
Main API routes for SCANNO backend.
"""

from fastapi import APIRouter, Depends, Request
from .scanner import scan_url
from .pdf_generator import generate_pdf_report
from .auth import verify_firebase_token
from .tokens import create_download_token, verify_download_token

router = APIRouter()

@router.post("/scan")
def start_scan(request: Request):
    # TODO: Parse request, verify auth, check plan limits, start scan
    return {"status": "scan started"}

@router.get("/report/{report_id}")
def download_report(report_id: str, token: str):
    # TODO: Verify token, serve PDF file
    return {"status": "report download"}

@router.post("/verify-domain")
def verify_domain(request: Request):
    # TODO: Implement domain verification logic
    return {"status": "domain verification started"}

@router.get("/scan-history")
def scan_history(request: Request):
    # TODO: Return user's scan history
    return {"history": []}
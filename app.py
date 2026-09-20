"""
app.py — FastAPI entry point for MailGuard AI.

Start with:
    python -m uvicorn app:app --host 127.0.0.1 --port 8000 --reload

Then open: http://127.0.0.1:8000
"""

from __future__ import annotations
import os
import uuid
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
try:
    from fastapi.staticfiles import StaticFiles
except ImportError:
    StaticFiles = None

import db
from detector import ThreatDetector
from geo import get_geolocation
from models import (
    AnalyzeRequest, AnalyzeResponse, BreakdownModel, CheckItem,
    DashboardStats, EmailSummary, ForensicsInfo, GeoInfo,
    HealthResponse, PillarScore, StatusUpdate,
)

# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)s  %(message)s")
log = logging.getLogger("mailguard")

from contextlib import asynccontextmanager

# ---------------------------------------------------------------------------
# Lifespan: init DB + seed demo emails
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        db.init_db()
        log.info("Database initialised at %s", db.DB_PATH)
        if db.count_emails() == 0:
            _seed_demo_emails()
            log.info("Demo emails seeded.")
    except Exception as e:
        log.warning("Lifespan init warning (non-fatal): %s", e)
    yield

app = FastAPI(
    title="MailGuard AI",
    description="AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=lifespan,
)

# CORS — only needed if you later separate frontend/backend.
# With the single-origin setup this is a no-op safety net.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_detector = ThreatDetector()

# ---------------------------------------------------------------------------
# Global exception handler — never expose Python tracebacks to the browser
# ---------------------------------------------------------------------------
@app.exception_handler(Exception)
async def _global_exc(request: Request, exc: Exception):
    log.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "detail": str(exc)},
    )


# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/health", response_model=HealthResponse, tags=["System"])
def health():
    """Liveness probe — verifies backend and database are running."""
    try:
        db.count_emails()
        db_status = "connected"
    except Exception:
        db_status = "error"
    return {
        "status":   "ok",
        "service":  "MailGuard AI",
        "database": db_status,
        "detector": "ready",
    }


@app.post("/api/analyze", tags=["Analysis"])
def analyze(req: AnalyzeRequest):
    """
    Analyse an email and return a complete threat assessment.
    All fields are optional — at minimum provide the body or headers.
    """
    # Run detection
    result = _detector.analyse(
        subject      = req.subject      or "",
        from_address = req.from_address or "",
        reply_to     = req.reply_to     or "",
        sender_ip    = req.sender_ip    or "",
        headers      = req.headers      or "",
        body         = req.body         or "",
    )

    # Geolocation
    geo = get_geolocation(req.sender_ip or "")

    # Build DB record
    email_id  = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()

    record = {
        "id":                 email_id,
        "timestamp":          timestamp,
        "subject":            req.subject      or "",
        "from_address":       req.from_address or "",
        "reply_to":           req.reply_to     or "",
        "sender_ip":          req.sender_ip    or "",
        "headers":            req.headers      or "",
        "body":               (req.body or "")[:50_000],  # trim for storage
        "score":              result["score"],
        "verdict":            result["verdict"],
        "category":           result["category"],
        "confidence":         result["confidence"],
        "reasons":            result["reasons"],
        "breakdown":          result["breakdown"],
        "checks":             result["checks"],
        "geo":                geo,
        "forensics":          result["forensics"],
        "recommended_action": result["recommended_action"],
        "status":             "new",
    }
    db.insert_email(record)

    return record


@app.get("/api/emails", tags=["Emails"])
def list_emails(limit: int = 100, offset: int = 0):
    """Return a paginated list of analysed emails (newest first)."""
    emails = db.list_emails(limit=limit, offset=offset)
    # Return lightweight summary fields only
    return [
        {
            "id":           e["id"],
            "timestamp":    e["timestamp"],
            "subject":      e["subject"],
            "from_address": e["from_address"],
            "score":        e["score"],
            "verdict":      e["verdict"],
            "category":     e["category"],
            "confidence":   e["confidence"],
            "status":       e["status"],
        }
        for e in emails
    ]


@app.get("/api/emails/{email_id}", tags=["Emails"])
def get_email(email_id: str):
    """Return the full analysis record for one email."""
    record = db.get_email(email_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Email {email_id!r} not found")
    return record


@app.patch("/api/emails/{email_id}/status", tags=["Emails"])
def update_status(email_id: str, body: StatusUpdate):
    """Update the analyst status of an email (new / reviewed / quarantined / cleared)."""
    updated = db.update_status(email_id, body.status)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Email {email_id!r} not found")
    return {"id": email_id, "status": body.status}


@app.get("/api/dashboard", tags=["Dashboard"])
def dashboard():
    """Aggregate statistics for the SOC dashboard."""
    return db.dashboard_stats()


@app.get("/api/reports", tags=["Reports"])
def reports(limit: int = 50, offset: int = 0):
    """Return all emails for the reports list view (full records)."""
    return db.list_emails(limit=limit, offset=offset)


# ---------------------------------------------------------------------------
# Static file serving — Frontend SPA
# On Vercel, static files are served by @vercel/static (see vercel.json).
# Locally, we mount them via FastAPI StaticFiles.
# ---------------------------------------------------------------------------
_STATIC = Path(__file__).parent / "static"
_IS_VERCEL = bool(os.getenv("VERCEL") or os.getenv("VERCEL_ENV"))

if not _IS_VERCEL and StaticFiles is not None and _STATIC.exists():
    app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static_assets")

# Root — serve index.html
@app.get("/", include_in_schema=False)
def root():
    index = _STATIC / "index.html"
    if index.exists():
        return FileResponse(str(index))
    return JSONResponse(status_code=200, content={"service": "MailGuard AI", "status": "ok"})

# Catch-all: serve index.html for SPA routing (non-API, non-static paths)
@app.get("/{full_path:path}", include_in_schema=False)
def spa_fallback(full_path: str):
    # Don't intercept static asset requests
    if full_path.startswith("static/") or full_path.startswith("api/"):
        return JSONResponse(status_code=404, content={"error": "Not found"})
    index = _STATIC / "index.html"
    if index.exists():
        return FileResponse(str(index))
    return JSONResponse(status_code=503, content={"error": "Frontend not found"})


# ---------------------------------------------------------------------------
# Demo seed data
# ---------------------------------------------------------------------------
def _seed_email(subject, from_address, reply_to, sender_ip, headers, body, is_demo=True):
    """Analyse and persist a demo email."""
    result = _detector.analyse(
        subject=subject, from_address=from_address,
        reply_to=reply_to, sender_ip=sender_ip,
        headers=headers, body=body,
    )
    geo = get_geolocation(sender_ip)
    email_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()
    record = {
        "id":                 email_id,
        "timestamp":          timestamp,
        "subject":            subject,
        "from_address":       from_address,
        "reply_to":           reply_to,
        "sender_ip":          sender_ip,
        "headers":            headers,
        "body":               body,
        "score":              result["score"],
        "verdict":            result["verdict"],
        "category":           result["category"],
        "confidence":         result["confidence"],
        "reasons":            result["reasons"],
        "breakdown":          result["breakdown"],
        "checks":             result["checks"],
        "geo":                geo,
        "forensics":          result["forensics"],
        "recommended_action": result["recommended_action"],
        "status":             "new",
    }
    db.insert_email(record)


def _seed_demo_emails():
    """Insert six realistic demo emails covering the full threat spectrum."""

    # 1. SAFE — Internal memo
    _seed_email(
        subject      = "Q3 2026 Team Lunch — Friday 12pm",
        from_address = "Alice Johnson <alice.johnson@acme-corp.com>",
        reply_to     = "alice.johnson@acme-corp.com",
        sender_ip    = "",
        headers      = (
            "Received: from mail.acme-corp.com ([10.0.0.5]) by mx.acme-corp.com\n"
            "Authentication-Results: mx.acme-corp.com; spf=pass; dkim=pass; dmarc=pass\n"
            "DKIM-Signature: v=1; a=rsa-sha256; d=acme-corp.com\n"
            "To: team@acme-corp.com\n"
        ),
        body = (
            "Hi team,\n\n"
            "Just a reminder that we have our Q3 team lunch this Friday at 12pm in the "
            "main conference room. Please RSVP to this email by Thursday EOD.\n\n"
            "Menu options will be available on the intranet portal. The company will cover costs.\n\n"
            "Looking forward to seeing everyone!\n\n"
            "Best,\nAlice Johnson\nSenior Project Manager, Acme Corp"
        ),
    )

    # 2. CRITICAL — Classic phishing (PayPal spoof)
    _seed_email(
        subject      = "Your PayPal account has been SUSPENDED - Verify Immediately",
        from_address = "PayPal Security <security@paypa1-secure.tk>",
        reply_to     = "noreply@paypal-helpdesk.ml",
        sender_ip    = "185.220.101.45",
        headers      = (
            "Received: from unknown-host-185.220.101.45 ([185.220.101.45]) by mx1.victim.com\n"
            "Authentication-Results: mx1.victim.com; spf=fail; dkim=fail; dmarc=fail\n"
            "To: valued.customer@victim.com\n"
        ),
        body = (
            "Dear Customer,\n\n"
            "URGENT: Your PayPal account has been suspended due to suspicious activity. "
            "You must verify your identity immediately to restore access.\n\n"
            "Failure to respond within 24 hours will result in permanent account termination.\n\n"
            "Click here to verify your account and enter your username and password: "
            "http://185.220.101.45/paypal/verify\n\n"
            "If you do not verify, we will be forced to take legal action and report "
            "your account to relevant authorities.\n\n"
            "PayPal Security Team"
        ),
    )

    # 3. CRITICAL — Business Email Compromise (CFO fraud)
    _seed_email(
        subject      = "Confidential — Urgent Wire Transfer Required",
        from_address = "\"Robert Chen - CEO\" <robert.chen.ceo@acme-corp-hq.xyz>",
        reply_to     = "rchen.payments@gmail.com",
        sender_ip    = "91.108.4.1",
        headers      = (
            "Received: from smtp.gmail.com ([91.108.4.1]) by mx.victim.com\n"
            "Authentication-Results: mx.victim.com; spf=softfail; dkim=pass; dmarc=fail\n"
            "To: finance@victim.com\n"
        ),
        body = (
            "Hi Sarah,\n\n"
            "I need you to process a confidential wire transfer today as part of an urgent "
            "acquisition deal. This is time sensitive and must be completed before close of business.\n\n"
            "Please transfer $87,500 to our new partner's bank account:\n"
            "Bank: First National Trust\n"
            "Routing Number: 021000021\n"
            "Account Number: 7829301847\n"
            "Reference: ACQ-2026-Q3\n\n"
            "Please keep this confidential — do not discuss this with anyone else in the office. "
            "I am currently in a board meeting and cannot be reached by phone.\n\n"
            "Please confirm once completed.\n\n"
            "Robert Chen\nChief Executive Officer"
        ),
    )

    # 4. HIGH_RISK — Credential theft (Microsoft 365 spoof)
    _seed_email(
        subject      = "Action Required: Your Microsoft 365 Password Expires Today",
        from_address = "Microsoft IT Support <support@micros0ft-365.top>",
        reply_to     = "support@micros0ft-365.top",
        sender_ip    = "103.224.182.9",
        headers      = (
            "Received: from smtp.micros0ft-365.top ([103.224.182.9])\n"
            "Authentication-Results: spf=fail; dkim=fail\n"
            "To: employee@victim.com\n"
        ),
        body = (
            "Dear User,\n\n"
            "Your Microsoft 365 account password expires today. "
            "To continue using your account without interruption, you must update your "
            "password immediately.\n\n"
            "Click the link below to sign in and update your credentials:\n"
            "https://micros0ft-365.top/m365/login?redirect=portal\n\n"
            "If you do not update your password within 24 hours, your account will be "
            "disabled and you will lose access to all Microsoft services.\n\n"
            "Microsoft Support Team\nDo not reply to this email."
        ),
    )

    # 5. SUSPICIOUS — Suspicious password reset (unknown source)
    _seed_email(
        subject      = "Password Reset Request for Your Account",
        from_address = "noreply@accounts-reset-portal.download",
        reply_to     = "noreply@accounts-reset-portal.download",
        sender_ip    = "78.46.113.7",
        headers      = (
            "Received: from mail.accounts-reset-portal.download ([78.46.113.7])\n"
            "Authentication-Results: spf=softfail; dkim=fail\n"
        ),
        body = (
            "Hello,\n\n"
            "We received a request to reset your account password.\n\n"
            "Click the link below to reset your password:\n"
            "http://bit.ly/3xR9pQZ\n\n"
            "If you did not request this, please ignore this email. "
            "Your account will remain secure.\n\n"
            "Account Security Team"
        ),
    )

    # 6. CRITICAL — Executive impersonation + social engineering
    _seed_email(
        subject      = "Personal Request — Need Your Help Urgently",
        from_address = "\"Dr. Meena Sharma - Managing Director\" <md@globaltech-inc.cf>",
        reply_to     = "meena.sharma.md2026@gmail.com",
        sender_ip    = "162.158.102.10",
        headers      = (
            "Received: from smtp.outbound.cf ([162.158.102.10])\n"
            "Authentication-Results: spf=fail; dkim=fail; dmarc=fail\n"
        ),
        body = (
            "Hi,\n\n"
            "I need your immediate and confidential assistance. I am currently in a board "
            "meeting and cannot discuss this on the phone. Please keep this strictly between us.\n\n"
            "I need you to purchase 10 Amazon gift cards worth INR 5,000 each for an urgent "
            "corporate gift requirement. Once purchased, please share the redemption codes "
            "with me via this email as soon as possible.\n\n"
            "I will reimburse you from petty cash when I am back in the office. "
            "Do not mention this to anyone — including HR or Finance — as this is a "
            "confidential executive matter. Failure to act promptly will affect the deal.\n\n"
            "Regards,\n"
            "Dr. Meena Sharma\nManaging Director"
        ),
    )

    log.info("Six demo emails seeded successfully.")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)

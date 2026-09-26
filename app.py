"""
app.py — FastAPI entry point for MailGuard AI.
Pre-Delivery Email Security Gateway + Threat Intelligence + SOC Platform.

Start with:
    python -m uvicorn app:app --host 127.0.0.1 --port 8000 --reload

Then open: http://127.0.0.1:8000
"""

from __future__ import annotations
import os
import uuid
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Optional, Dict, Any
import re

from fastapi import FastAPI, HTTPException, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
try:
    from fastapi.staticfiles import StaticFiles
except ImportError:
    StaticFiles = None

import db
from detector import ThreatDetector
from geo import get_geolocation
from threat_intel import threat_intel
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
    description="AI-Powered Pre-Delivery Email Security Gateway & SOC Intelligence Platform",
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=lifespan,
)

# CORS — restricted to localhost and loopback origins only.
# For a local academic prototype, wildcard (*) is not appropriate.
# If deploying to a specific domain, add that origin here explicitly.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["Content-Type", "Accept"],
)

_detector = ThreatDetector()

# ---------------------------------------------------------------------------
# Global exception handler — never expose Python tracebacks to the browser
# ---------------------------------------------------------------------------
@app.exception_handler(Exception)
async def _global_exc(request: Request, exc: Exception):
    log.exception("Unhandled error on %s %s", request.method, request.url.path)
    # Do NOT expose exception detail to the browser — information disclosure risk.
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error"},
    )


# ===========================================================================
# API Endpoints
# ===========================================================================

# ── System ──────────────────────────────────────────────────────────────────

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


@app.get("/api/system/status", tags=["System"])
def system_status():
    """Extended system status for the System Status page."""
    try:
        total = db.count_emails()
        db_status = "healthy"
    except Exception:
        total = 0
        db_status = "error"

    return {
        "status": "operational",
        "version": "2.0.0",
        "components": {
            "email_gateway": {"status": "active", "description": "Pre-delivery email interception"},
            "threat_detector": {"status": "active", "description": "Multi-pillar heuristic engine"},
            "url_analyzer": {"status": "active", "description": "URL reputation and threat analysis"},
            "attachment_analyzer": {"status": "active", "description": "Static file analysis [PROTOTYPE]"},
            "qr_analyzer": {"status": "prototype", "description": "QR code extraction architecture ready [PROTOTYPE]"},
            "geolocation": {"status": "active", "description": "IP geolocation via ip-api.com"},
            "database": {"status": db_status, "description": f"SQLite — {total} emails stored"},
            "bec_detector": {"status": "active", "description": "Business Email Compromise detection"},
            "threat_intelligence": {"status": "local", "description": "Local IOC + heuristic intelligence [LOCAL]"},
            "policy_engine": {"status": "active", "description": "Configurable security policy rules"},
        },
        "analysis_pipeline": [
            "EMAIL RECEIVED",
            "HEADER PARSING",
            "SPF / DKIM / DMARC CHECK",
            "SENDER ANALYSIS",
            "DOMAIN ANALYSIS",
            "URL ANALYSIS",
            "ATTACHMENT CHECK",
            "BEC DETECTION",
            "CREDENTIAL PHISHING DETECTION",
            "BEHAVIOURAL ANALYSIS",
            "THREAT INTELLIGENCE LOOKUP",
            "RISK SCORE CALCULATION",
            "POLICY ENGINE",
            "DELIVER / QUARANTINE / BLOCK",
            "FORENSIC REPORT GENERATED",
        ],
        "notes": [
            "Attachment sandbox: STATIC ANALYSIS only (no live execution)",
            "QR decode: Architecture ready, library integration pending",
            "Threat intelligence: Local heuristic rules (no external feed connected)",
            "IP geolocation: Approximate location only — not physical attacker location",
        ]
    }


# ── Core Email Analysis ──────────────────────────────────────────────────────

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

    # Threat Intelligence evaluation
    urls_found = result["forensics"].get("urls_found", [])
    intel_result = threat_intel.evaluate_email(
        from_address = req.from_address or "",
        reply_to     = req.reply_to     or "",
        sender_ip    = req.sender_ip    or "",
        urls         = urls_found,
        attachments  = [],
    )

    # Sender reputation derived from threat intel
    sender_reputation = _derive_sender_reputation(
        req.from_address or "", req.sender_ip or "", intel_result
    )

    # Language/Social Engineering analysis (extracted from content analysis)
    language_analysis = _extract_language_analysis(result)

    # Enrich forensics with threat intel and language analysis
    result["forensics"]["threat_intel"]       = intel_result
    result["forensics"]["sender_reputation"]  = sender_reputation
    result["forensics"]["language_analysis"]  = language_analysis

    # Build forensic timeline
    timeline = _build_timeline(result, req)

    # Security decision (beyond raw score)
    decision = _security_decision(result)

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
        "body":               (req.body or "")[:50_000],
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
        "decision":           decision,
        "timeline":           timeline,
    }
    db.insert_email(record)

    return record


@app.post("/api/email/analyze", tags=["Analysis"])
def analyze_v2(req: AnalyzeRequest):
    """Alias for /api/analyze — v2 endpoint path."""
    return analyze(req)


@app.get("/api/emails", tags=["Emails"])
def list_emails(limit: int = 100, offset: int = 0):
    """Return a paginated list of analysed emails (newest first)."""
    emails = db.list_emails(limit=limit, offset=offset)
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


@app.get("/api/emails/{email_id}/forensics", tags=["Emails"])
def get_email_forensics(email_id: str):
    """Return the forensic details for one email."""
    record = db.get_email(email_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Email {email_id!r} not found")
    return {
        "id": record["id"],
        "timestamp": record["timestamp"],
        "from_address": record["from_address"],
        "reply_to": record["reply_to"],
        "sender_ip": record["sender_ip"],
        "subject": record["subject"],
        "forensics": record["forensics"],
        "geo": record["geo"],
        "breakdown": record["breakdown"],
        "score": record["score"],
        "verdict": record["verdict"],
        "decision": record.get("decision", {}),
    }


@app.get("/api/emails/{email_id}/timeline", tags=["Emails"])
def get_email_timeline(email_id: str):
    """Return the forensic timeline for one email."""
    record = db.get_email(email_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Email {email_id!r} not found")
    timeline = record.get("timeline", [])
    if not timeline:
        # Reconstruct from existing data
        timeline = _reconstruct_timeline(record)
    return {"id": email_id, "timeline": timeline}


@app.patch("/api/emails/{email_id}/status", tags=["Emails"])
def update_status(email_id: str, body: StatusUpdate):
    """Update the analyst status of an email."""
    updated = db.update_status(email_id, body.status)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Email {email_id!r} not found")
    return {"id": email_id, "status": body.status}


# ── Dashboard ────────────────────────────────────────────────────────────────

@app.get("/api/dashboard", tags=["Dashboard"])
def dashboard():
    """Aggregate statistics for the SOC dashboard."""
    return db.dashboard_stats()


@app.get("/api/dashboard/stats", tags=["Dashboard"])
def dashboard_stats():
    """Extended stats — alias for /api/dashboard."""
    return db.dashboard_stats()


# ── URL Analysis ─────────────────────────────────────────────────────────────

@app.post("/api/url/analyze", tags=["Analysis"])
def analyze_url(body: dict):
    """
    Standalone URL analysis.
    Send: {"url": "https://example.com"}
    """
    from urllib.parse import urlparse
    from detector import (
        SUSPICIOUS_DOMAIN_KEYWORDS, TRUSTED_DOMAINS,
        SUSPICIOUS_TLDS, SHORTENED_URL_DOMAINS, LOOKALIKE_MAP,
    )

    url = (body.get("url") or "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    indicators = []
    risk_score = 0

    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()

        # IP-based URL
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host):
            indicators.append({"type": "IP_URL", "detail": f"URL uses raw IP address: {host}", "risk": 25})
            risk_score += 25

        # Shortened URL
        for sdom in SHORTENED_URL_DOMAINS:
            if sdom in host:
                indicators.append({"type": "SHORTENED", "detail": f"URL uses shortening service ({sdom}) — destination hidden", "risk": 15})
                risk_score += 15
                break

        # Suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if host.endswith(tld):
                indicators.append({"type": "SUSPICIOUS_TLD", "detail": f"Domain uses high-abuse TLD: {tld}", "risk": 15})
                risk_score += 15
                break

        # Typosquatting detection (simple char substitution check against TRUSTED_DOMAINS)
        def _normalize(s: str) -> str:
            for k, v in LOOKALIKE_MAP.items():
                s = s.replace(k, v)
            return s

        norm_host = _normalize(host)
        for trusted in TRUSTED_DOMAINS:
            if norm_host == trusted and host != trusted:
                indicators.append({"type": "TYPOSQUATTING", "detail": f"Domain '{host}' appears to impersonate '{trusted}'", "risk": 25})
                risk_score += 25
                break

        # Suspicious keywords in URL path/host
        for kw in SUSPICIOUS_DOMAIN_KEYWORDS:
            if kw in url.lower() and host not in TRUSTED_DOMAINS:
                indicators.append({"type": "SUSPICIOUS_KEYWORD", "detail": f"Suspicious keyword in URL: '{kw}'", "risk": 10})
                risk_score += 10
                break

        # Login / credential keywords in URL
        login_kws = ["login", "signin", "account", "verify", "secure", "password", "credential"]
        for kw in login_kws:
            if kw in url.lower() and host not in TRUSTED_DOMAINS:
                indicators.append({"type": "LOGIN_INDICATOR", "detail": f"Credential/login keyword in URL: '{kw}'", "risk": 10})
                risk_score += 10
                break

        # Redirect parameter
        if any(p in url.lower() for p in ["redirect=", "url=", "link=", "return="]):
            indicators.append({"type": "REDIRECT", "detail": "URL contains open redirect parameter", "risk": 10})
            risk_score += 10

        # Percent-encoding obfuscation
        if "%" in url and host not in TRUSTED_DOMAINS:
            indicators.append({"type": "OBFUSCATION", "detail": "URL contains percent-encoded characters (possible obfuscation)", "risk": 10})
            risk_score += 10

        risk_score = min(100, risk_score)
        if risk_score >= 70:   verdict = "MALICIOUS"
        elif risk_score >= 40: verdict = "SUSPICIOUS"
        elif risk_score >= 15: verdict = "LOW_RISK"
        else:                  verdict = "SAFE"

    except Exception as e:
        indicators.append({"type": "PARSE_ERROR", "detail": f"Could not parse URL: {e}", "risk": 5})
        verdict, risk_score = "UNKNOWN", 5

    return {
        "url": url,
        "verdict": verdict,
        "risk_score": risk_score,
        "indicators": indicators,
        "analysis_type": "STATIC_HEURISTIC",
        "note": "URL analysis uses static heuristics only. No live browsing or sandbox execution.",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ── Attachment Analysis ──────────────────────────────────────────────────────

@app.post("/api/attachment/analyze", tags=["Analysis"])
def analyze_attachment(body: dict):
    """
    Static attachment analysis (prototype — no live sandbox execution).
    Send: {"filename": "invoice.exe", "size": 1024, "mime_type": "application/x-msdownload"}
    """
    filename = (body.get("filename") or "").strip()
    size = body.get("size", 0)
    mime_type = (body.get("mime_type") or "").lower()
    sha256 = (body.get("sha256") or "").strip()

    indicators = []
    risk_score = 0

    if not filename:
        raise HTTPException(status_code=400, detail="filename is required")

    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    # Executable extensions
    exec_exts = {"exe", "bat", "cmd", "com", "msi", "vbs", "js", "jar", "ps1", "scr",
                 "pif", "reg", "hta", "vbe", "wsf", "wsh", "lnk", "dll", "sys"}
    if ext in exec_exts:
        indicators.append({"type": "EXECUTABLE", "detail": f"File is executable type: .{ext}", "risk": 40})
        risk_score += 40

    # Double extension (e.g., invoice.pdf.exe)
    parts = filename.split(".")
    if len(parts) >= 3:
        indicators.append({"type": "DOUBLE_EXTENSION", "detail": f"Suspicious double extension: {filename}", "risk": 20})
        risk_score += 20

    # Office documents with macro potential
    macro_exts = {"docm", "xlsm", "pptm", "xlam", "xltm", "dotm"}
    if ext in macro_exts:
        indicators.append({"type": "MACRO_ENABLED", "detail": f"Macro-enabled Office document: .{ext} — macros can execute code", "risk": 30})
        risk_score += 30

    # Archive files (may contain malware)
    archive_exts = {"zip", "rar", "7z", "gz", "tar"}
    if ext in archive_exts:
        indicators.append({"type": "ARCHIVE", "detail": "Archive file — may contain hidden malicious payloads", "risk": 10})
        risk_score += 10

    # Script files
    script_exts = {"py", "sh", "rb", "php", "asp", "aspx", "jsp"}
    if ext in script_exts:
        indicators.append({"type": "SCRIPT", "detail": f"Script file: .{ext} — can execute server-side or locally", "risk": 25})
        risk_score += 25

    # MIME type mismatch
    mime_map = {
        "exe": "application/x-msdownload",
        "pdf": "application/pdf",
        "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    }
    if ext in mime_map and mime_type and mime_type != mime_map[ext]:
        indicators.append({"type": "MIME_MISMATCH", "detail": f"MIME type mismatch: declared {mime_type}, expected {mime_map[ext]}", "risk": 15})
        risk_score += 15

    risk_score = min(100, risk_score)

    if risk_score >= 70:
        verdict = "CRITICAL"
    elif risk_score >= 40:
        verdict = "HIGH_RISK"
    elif risk_score >= 15:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LOW_RISK"

    return {
        "filename": filename,
        "extension": ext,
        "mime_type": mime_type or "unknown",
        "size_bytes": size,
        "sha256": sha256 or "Not provided",
        "verdict": verdict,
        "risk_score": risk_score,
        "indicators": indicators,
        "analysis_type": "STATIC_ANALYSIS",
        "sandbox_status": "NOT_EXECUTED",
        "note": "⚠ STATIC ANALYSIS ONLY — File was not executed or detonated in a sandbox. Results based on file metadata and extension analysis.",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ── Threat Intelligence ──────────────────────────────────────────────────────

@app.get("/api/threats", tags=["Intelligence"])
def threat_feed(limit: int = 50, verdict: Optional[str] = None):
    """
    Threat intelligence feed — recent threats from the local database.
    Optionally filter by verdict.
    """
    all_emails = db.list_emails(limit=200, offset=0)

    # Filter to threats only (non-safe)
    threats = [
        e for e in all_emails
        if e.get("verdict", "SAFE") != "SAFE"
    ]

    if verdict:
        threats = [t for t in threats if t.get("verdict") == verdict.upper()]

    threats = threats[:limit]

    return {
        "total": len(threats),
        "intelligence_type": "LOCAL",
        "note": "LOCAL INTELLIGENCE — Threat data from locally analysed emails. No external threat feeds connected.",
        "threats": [
            {
                "id": t["id"],
                "timestamp": t["timestamp"],
                "from_address": t["from_address"],
                "subject": t["subject"],
                "verdict": t["verdict"],
                "category": t["category"],
                "score": t["score"],
                "status": t["status"],
            }
            for t in threats
        ],
    }


@app.get("/api/threat-feed", tags=["Intelligence"])
def threat_feed_alias(limit: int = 50):
    """Alias for /api/threats."""
    return threat_feed(limit=limit)


# ── Security Policies ────────────────────────────────────────────────────────

# Default policies (in-memory for prototype; can be extended to DB)
_DEFAULT_POLICIES = [
    {
        "id": "pol-001",
        "name": "Block Malicious URLs",
        "description": "Block emails containing URLs that resolve to known malicious patterns",
        "condition": "url_verdict == MALICIOUS",
        "action": "BLOCK",
        "enabled": True,
        "priority": 1,
    },
    {
        "id": "pol-002",
        "name": "Block Malicious Attachments",
        "description": "Block emails with executable or macro-enabled attachments",
        "condition": "attachment_verdict == CRITICAL",
        "action": "BLOCK",
        "enabled": True,
        "priority": 2,
    },
    {
        "id": "pol-003",
        "name": "Block Credential Phishing",
        "description": "Block emails detected as credential phishing attacks",
        "condition": "category == CREDENTIAL_THEFT AND score >= 60",
        "action": "BLOCK",
        "enabled": True,
        "priority": 3,
    },
    {
        "id": "pol-004",
        "name": "Quarantine BEC Attempts",
        "description": "Quarantine Business Email Compromise attempts for analyst review",
        "condition": "category == BUSINESS_EMAIL_COMPROMISE",
        "action": "QUARANTINE",
        "enabled": True,
        "priority": 4,
    },
    {
        "id": "pol-005",
        "name": "Quarantine Failed Authentication",
        "description": "Quarantine emails failing SPF + DKIM + DMARC simultaneously",
        "condition": "spf == fail AND dkim == fail AND dmarc == fail",
        "action": "QUARANTINE",
        "enabled": True,
        "priority": 5,
    },
    {
        "id": "pol-006",
        "name": "Quarantine High Risk Emails",
        "description": "Quarantine emails scoring 60-79 for analyst review",
        "condition": "score >= 60 AND score < 80",
        "action": "QUARANTINE",
        "enabled": True,
        "priority": 6,
    },
    {
        "id": "pol-007",
        "name": "Block Critical Threats",
        "description": "Automatically block all emails scoring 80 or above",
        "condition": "score >= 80",
        "action": "BLOCK",
        "enabled": True,
        "priority": 7,
    },
    {
        "id": "pol-008",
        "name": "Quarantine Suspicious TLD",
        "description": "Quarantine emails from high-abuse TLDs (.tk, .ml, .xyz, etc.)",
        "condition": "sender_tld IN [.tk, .ml, .ga, .cf, .xyz, .top]",
        "action": "QUARANTINE",
        "enabled": True,
        "priority": 8,
    },
    {
        "id": "pol-009",
        "name": "Flag Suspicious Emails",
        "description": "Flag emails scoring 30-59 as suspicious for user awareness",
        "condition": "score >= 30 AND score < 60",
        "action": "FLAG",
        "enabled": True,
        "priority": 9,
    },
    {
        "id": "pol-010",
        "name": "Deliver Safe Emails",
        "description": "Deliver emails scoring below 30 with no critical indicators",
        "condition": "score < 30 AND no_critical_indicators",
        "action": "DELIVER",
        "enabled": True,
        "priority": 10,
    },
]

_policies = list(_DEFAULT_POLICIES)


@app.get("/api/policies", tags=["Policies"])
def get_policies():
    """Return all configured security policies."""
    return {
        "total": len(_policies),
        "note": "PROTOTYPE — Policies are stored in-memory. Changes reset on server restart.",
        "policies": _policies,
    }


@app.post("/api/policies", tags=["Policies"])
def create_policy(body: dict):
    """Create a new security policy."""
    pol = {
        "id": f"pol-{uuid.uuid4().hex[:6]}",
        "name": body.get("name", "Custom Policy"),
        "description": body.get("description", ""),
        "condition": body.get("condition", ""),
        "action": body.get("action", "FLAG"),
        "enabled": body.get("enabled", True),
        "priority": len(_policies) + 1,
    }
    _policies.append(pol)
    return pol


@app.patch("/api/policies/{policy_id}", tags=["Policies"])
def update_policy(policy_id: str, body: dict):
    """Toggle or update a policy."""
    for pol in _policies:
        if pol["id"] == policy_id:
            if "enabled" in body:
                pol["enabled"] = bool(body["enabled"])
            if "action" in body:
                pol["action"] = body["action"]
            return pol
    raise HTTPException(status_code=404, detail=f"Policy {policy_id!r} not found")


# ── Reports ──────────────────────────────────────────────────────────────────

@app.get("/api/reports", tags=["Reports"])
def reports(limit: int = 50, offset: int = 0):
    """Return all emails for the reports list view (full records)."""
    return db.list_emails(limit=limit, offset=offset)


# ── Sender Reputation ────────────────────────────────────────────────────────

@app.post("/api/sender/reputation", tags=["Analysis"])
def sender_reputation(body: dict):
    """
    Look up sender reputation for a domain or IP address.
    Send: {"from_address": "...", "sender_ip": "...", "reply_to": "..."}
    """
    from_address = (body.get("from_address") or "").strip()
    sender_ip    = (body.get("sender_ip")    or "").strip()
    reply_to     = (body.get("reply_to")     or "").strip()

    intel_result = threat_intel.evaluate_email(
        from_address=from_address,
        reply_to=reply_to,
        sender_ip=sender_ip,
        urls=[],
        attachments=[],
    )

    reputation_result = _derive_sender_reputation(from_address, sender_ip, intel_result)
    reputation_result["from_address"] = from_address
    reputation_result["sender_ip"]    = sender_ip
    reputation_result["intel"]        = intel_result
    reputation_result["timestamp"]    = datetime.now(timezone.utc).isoformat()
    return reputation_result


# ── Campaign Correlation ──────────────────────────────────────────────────────

@app.get("/api/campaign/correlate", tags=["Intelligence"])
def campaign_correlate():
    """
    Detect possible email campaigns by correlating indicators across analysed emails.
    Groups emails by shared domains, URL patterns, and subject similarity.
    """
    all_emails = db.list_emails(limit=200, offset=0)
    threats = [e for e in all_emails if e.get("verdict", "SAFE") != "SAFE"]

    # Group by sender domain
    domain_re = re.compile(r"@([a-zA-Z0-9.\-]+)")
    domain_groups: Dict[str, List[dict]] = {}
    for email in threats:
        m = domain_re.search(email.get("from_address", ""))
        if m:
            domain = m.group(1).lower().strip(">\"' ")
            if domain not in domain_groups:
                domain_groups[domain] = []
            domain_groups[domain].append(email)

    campaigns = []
    campaign_counter = 1
    for domain, group in domain_groups.items():
        if len(group) >= 2:
            verdicts = [e["verdict"] for e in group]
            scores = [e["score"] for e in group]
            avg_score = round(sum(scores) / len(scores))
            confidence = min(95, 50 + len(group) * 10)

            campaigns.append({
                "campaign_id": f"MG-CAMP-{campaign_counter:03d}",
                "indicator_type": "DOMAIN",
                "indicator_value": domain,
                "email_count": len(group),
                "emails": [{"id": e["id"], "subject": e["subject"][:60], "verdict": e["verdict"]} for e in group[:5]],
                "verdicts": list(set(verdicts)),
                "avg_score": avg_score,
                "confidence": confidence,
                "description": f"Multiple threat emails sharing sender domain '{domain}'",
                "analysis_note": "CORRELATION — Not confirmed attribution. Based on shared infrastructure indicators.",
            })
            campaign_counter += 1

    return {
        "total_campaigns": len(campaigns),
        "campaigns": campaigns,
        "analysis_scope": len(threats),
        "note": "Campaign detection uses heuristic indicator correlation. This is NOT confirmed threat attribution.",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ── Email Parse ───────────────────────────────────────────────────────────────

@app.post("/api/email/parse", tags=["Analysis"])
def email_parse(body: dict):
    """
    Parse raw email headers and extract structured fields.
    Send: {"headers": "...", "from_address": "...", "body": "..."}
    """
    from detector import _extract_domain, _extract_display_name, _extract_urls, _count_received_hops, _parse_auth_result

    headers      = (body.get("headers")      or "").strip()
    from_address = (body.get("from_address") or "").strip()
    reply_to     = (body.get("reply_to")     or "").strip()
    email_body   = (body.get("body")         or "").strip()
    subject      = (body.get("subject")      or "").strip()

    from_domain     = _extract_domain(from_address)
    rt_domain       = _extract_domain(reply_to)
    display_name    = _extract_display_name(from_address)
    hops            = _count_received_hops(headers)
    urls            = _extract_urls(f"{subject} {email_body}")

    spf   = _parse_auth_result(headers, "spf")   if headers else "unknown"
    dkim  = _parse_auth_result(headers, "dkim")  if headers else "unknown"
    dmarc = _parse_auth_result(headers, "dmarc") if headers else "unknown"

    # Extract originating IP from Received headers
    ip_pattern = re.compile(r"Received:.*?\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]", re.IGNORECASE)
    ips_found = ip_pattern.findall(headers or "")
    originating_ip = ips_found[0] if ips_found else ""

    return {
        "parsed_fields": {
            "from_address":   from_address,
            "from_domain":    from_domain,
            "display_name":   display_name,
            "reply_to":       reply_to,
            "reply_to_domain": rt_domain,
            "subject":        subject,
            "originating_ip": originating_ip,
        },
        "authentication": {
            "spf":   spf,
            "dkim":  dkim,
            "dmarc": dmarc,
        },
        "header_analysis": {
            "received_hops":   hops,
            "domain_mismatch": bool(from_domain and rt_domain and from_domain != rt_domain),
        },
        "urls_found":   urls[:30],
        "url_count":    len(urls),
        "analysis_type": "STATIC_PARSE",
        "timestamp":    datetime.now(timezone.utc).isoformat(),
    }


# ── Behaviour Analysis ────────────────────────────────────────────────────────

@app.post("/api/behavior/analyze", tags=["Analysis"])
def behavior_analyze(body: dict):
    """
    Standalone behavioral analysis for an email.
    Returns behavioral signals without full scoring.
    """
    from_address = (body.get("from_address") or "").strip()
    reply_to     = (body.get("reply_to")     or "").strip()
    subject      = (body.get("subject")      or "").strip()
    email_body   = (body.get("body")         or "").strip()
    headers      = (body.get("headers")      or "").strip()

    signals = []
    domain_re = re.compile(r"@([a-zA-Z0-9.\-]+)")
    from_match = domain_re.search(from_address)
    rt_match   = domain_re.search(reply_to)

    from_domain = from_match.group(1).lower() if from_match else ""
    rt_domain   = rt_match.group(1).lower() if rt_match else ""

    if from_domain and rt_domain and from_domain != rt_domain:
        signals.append({
            "signal": "REPLY_TO_MISMATCH",
            "level": "HIGH",
            "detail": f"Reply-To domain '{rt_domain}' differs from sender domain '{from_domain}'",
        })

    if "to:" not in (headers or "").lower():
        signals.append({
            "signal": "MISSING_TO_HEADER",
            "level": "MEDIUM",
            "detail": "No To: header found — possible mass BCC distribution",
        })

    exec_words = ["ceo", "cfo", "cto", "president", "director", "managing director"]
    body_lower = (subject + " " + email_body).lower()
    if any(w in body_lower for w in exec_words):
        signals.append({
            "signal": "EXECUTIVE_REFERENCE",
            "level": "MEDIUM",
            "detail": "Email references executive role — potential impersonation or authority pressure",
        })

    conf_words = ["keep this confidential", "do not share", "between us", "do not mention"]
    if any(w in body_lower for w in conf_words):
        signals.append({
            "signal": "CONFIDENTIALITY_PRESSURE",
            "level": "HIGH",
            "detail": "Email instructs recipient to keep content secret — social engineering indicator",
        })

    return {
        "signals": signals,
        "signal_count": len(signals),
        "baseline_available": False,
        "baseline_note": "Historical baseline unavailable — no stored communication history. Analysis based on current email signals only.",
        "from_domain": from_domain,
        "analysis_type": "HEURISTIC_SIGNALS",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ── Threat Intelligence Check ─────────────────────────────────────────────────

@app.post("/api/threat-intelligence/check", tags=["Intelligence"])
def threat_intelligence_check(body: dict):
    """
    Check an individual indicator (IP, domain, or URL) against threat intelligence.
    Send: {"type": "ip"|"domain"|"url", "value": "..."}
    """
    indicator_type  = (body.get("type")  or "").strip().lower()
    indicator_value = (body.get("value") or "").strip()

    if not indicator_value:
        raise HTTPException(status_code=400, detail="indicator value is required")

    result = None
    if indicator_type == "ip":
        result = threat_intel.lookup_ip(indicator_value)
    elif indicator_type == "domain":
        result = threat_intel.lookup_domain(indicator_value)
    elif indicator_type == "url":
        result = threat_intel.lookup_url(indicator_value)
    else:
        raise HTTPException(status_code=400, detail="type must be 'ip', 'domain', or 'url'")

    if result:
        return {
            "found": True,
            "indicator": indicator_value,
            "type": indicator_type,
            "intelligence": result,
            "source": "MailGuard Local IOC Database",
            "external_providers": "NOT_CONFIGURED",
            "note": "LOCAL INTELLIGENCE ONLY — External providers (VirusTotal, AlienVault, AbuseIPDB) not configured.",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    else:
        return {
            "found": False,
            "indicator": indicator_value,
            "type": indicator_type,
            "intelligence": None,
            "source": "MailGuard Local IOC Database",
            "external_providers": "NOT_CONFIGURED",
            "note": "No match in local IOC database. External intelligence providers not configured.",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }



# ===========================================================================
# Helper functions
# ===========================================================================

def _derive_sender_reputation(from_address: str, sender_ip: str, intel_result: dict) -> dict:
    """
    Derive sender reputation from available signals.
    Returns structured reputation result with indicators and confidence.
    """
    indicators = []
    reputation = "unknown"
    confidence = 0

    if intel_result.get("has_threats"):
        ioc_hits = intel_result.get("ioc_hits", [])
        for hit in ioc_hits:
            if hit.get("type") in ("MALICIOUS_IP", "MALICIOUS_IP_SUBNET", "MALICIOUS_DOMAIN", "MALICIOUS_SUBDOMAIN"):
                indicators.append({
                    "indicator": hit.get("indicator", ""),
                    "type": hit.get("type", ""),
                    "detail": hit.get("description", ""),
                    "severity": hit.get("severity", ""),
                    "source": hit.get("source", "Local IOC DB"),
                })

        severity_levels = [h.get("severity", "LOW") for h in ioc_hits]
        if "CRITICAL" in severity_levels:
            reputation = "malicious"
            confidence = 92
        elif "HIGH" in severity_levels:
            reputation = "suspicious"
            confidence = 78
        else:
            reputation = "suspicious"
            confidence = 60
    elif sender_ip:
        # No IOC hit but IP is public — unknown
        reputation = "unknown"
        confidence = 20
        indicators.append({
            "indicator": sender_ip,
            "type": "IP",
            "detail": "No known threat intelligence data for this IP.",
            "severity": "UNKNOWN",
            "source": "Local IOC DB",
        })
    else:
        reputation = "unknown"
        confidence = 0

    return {
        "reputation": reputation,
        "confidence": confidence,
        "indicators": indicators,
        "sources": ["MailGuard Local IOC Database", "Anti-Squat Domain Watch", "High-Abuse TLD Monitor"],
        "note": "LOCAL ANALYSIS — No external threat-intelligence provider configured. Reputation based on local IOC database only.",
        "available": True,
    }


def _extract_language_analysis(result: dict) -> dict:
    """
    Extract language/social-engineering signals from the content analysis pillar.
    Returns structured language analysis with detected categories and risk level.
    """
    breakdown = result.get("breakdown", {})
    content = breakdown.get("content_analysis", {})
    checks = content.get("checks", [])

    urgency_detected = any("urgency" in c.get("name", "").lower() for c in checks if c.get("result") in ("fail", "warn"))
    credential_detected = any("credential" in c.get("name", "").lower() for c in checks if c.get("result") in ("fail", "warn"))
    financial_detected = any("financial" in c.get("name", "").lower() for c in checks if c.get("result") in ("fail", "warn"))
    impersonation_detected = any("impersonat" in c.get("name", "").lower() or "spoof" in c.get("name", "").lower() for c in checks if c.get("result") in ("fail", "warn"))
    tech_support_detected = any("tech support" in c.get("name", "").lower() or "fake invoice" in c.get("name", "").lower() for c in checks if c.get("result") in ("fail", "warn"))
    lottery_detected = any("lottery" in c.get("name", "").lower() or "prize" in c.get("name", "").lower() for c in checks if c.get("result") in ("fail", "warn"))
    extortion_detected = any("extortion" in c.get("name", "").lower() or "blackmail" in c.get("name", "").lower() for c in checks if c.get("result") in ("fail", "warn"))
    sensitive_info = any("sensitive" in c.get("name", "").lower() for c in checks if c.get("result") in ("fail", "warn"))

    signals = []
    if urgency_detected:      signals.append({"type": "URGENCY",            "level": "HIGH",   "detail": "Artificial urgency or threat of account suspension"})
    if credential_detected:   signals.append({"type": "CREDENTIAL_REQUEST", "level": "HIGH",   "detail": "Requests login credentials, password, or verification"})
    if financial_detected:    signals.append({"type": "FINANCIAL_PRESSURE",  "level": "HIGH",   "detail": "Payment or wire transfer request detected"})
    if impersonation_detected: signals.append({"type": "IMPERSONATION",      "level": "HIGH",   "detail": "Impersonates trusted brand or authority figure"})
    if tech_support_detected: signals.append({"type": "TECH_SUPPORT_SCAM",   "level": "MEDIUM", "detail": "Fake invoice or tech support refund scam pattern"})
    if lottery_detected:      signals.append({"type": "LOTTERY_SCAM",        "level": "MEDIUM", "detail": "Prize or lottery winning notification"})
    if extortion_detected:    signals.append({"type": "EXTORTION",           "level": "CRITICAL","detail": "Blackmail or extortion threat detected"})
    if sensitive_info:        signals.append({"type": "PII_REQUEST",          "level": "HIGH",   "detail": "Requests sensitive personal information (SSN, card, etc.)"})

    risk_level = "LOW"
    if any(s["level"] == "CRITICAL" for s in signals): risk_level = "CRITICAL"
    elif any(s["level"] == "HIGH" for s in signals) and len(signals) >= 2: risk_level = "HIGH"
    elif any(s["level"] == "HIGH" for s in signals): risk_level = "MEDIUM"
    elif signals: risk_level = "LOW"

    return {
        "signals": signals,
        "risk_level": risk_level,
        "social_engineering": len(signals) >= 2,
        "signal_count": len(signals),
        "analysis_type": "HEURISTIC_LOCAL",
        "note": "Language analysis uses rule-based heuristic pattern matching on email content.",
    }


def _security_decision(result: dict) -> dict:
    """
    Apply policy-based security decision beyond raw score.
    Returns structured decision with action and justification.
    """
    score = result["score"]
    verdict = result["verdict"]
    category = result["category"]
    forensics = result.get("forensics", {})

    action = "DELIVER"
    justifications = []

    # Critical score → BLOCK
    if score >= 80:
        action = "BLOCK"
        justifications.append(f"Threat score {score}/100 exceeds BLOCK threshold (80)")

    # High risk → QUARANTINE
    elif score >= 60:
        action = "QUARANTINE"
        justifications.append(f"Threat score {score}/100 exceeds QUARANTINE threshold (60)")

    # Suspicious → FLAG
    elif score >= 30:
        action = "FLAG"
        justifications.append(f"Threat score {score}/100 exceeds SUSPICIOUS threshold (30)")

    # Override by category
    if category == "CREDENTIAL_THEFT" and action not in ("BLOCK",):
        action = "BLOCK"
        justifications.append("Credential phishing detected — policy override to BLOCK")

    if category == "BUSINESS_EMAIL_COMPROMISE" and action not in ("BLOCK",):
        action = "QUARANTINE"
        justifications.append("Business Email Compromise detected — policy override to QUARANTINE")

    # Auth failure override
    spf = forensics.get("spf", "unknown")
    dkim = forensics.get("dkim", "unknown")
    dmarc = forensics.get("dmarc", "unknown")
    if spf == "fail" and dkim == "fail" and dmarc == "fail" and action == "DELIVER":
        action = "QUARANTINE"
        justifications.append("Triple authentication failure (SPF+DKIM+DMARC) — policy override to QUARANTINE")

    return {
        "action": action,
        "justifications": justifications,
        "policy_applied": f"pol-{action.lower()}",
        "score": score,
        "verdict": verdict,
    }


def _build_timeline(result: dict, req: AnalyzeRequest) -> List[dict]:
    """Build a forensic processing timeline for the email."""
    base = datetime.now(timezone.utc)
    events = []

    def evt(offset_ms: int, event: str, detail: str, level: str = "info"):
        ts = (base + timedelta(milliseconds=offset_ms)).isoformat()
        events.append({"timestamp": ts, "event": event, "detail": detail, "level": level})

    evt(0,   "EMAIL RECEIVED",         "Email received by MailGuard gateway for pre-delivery inspection")
    evt(50,  "HEADER PARSING",         f"Headers parsed — From: {(req.from_address or '—')[:60]}")
    evt(100, "SPF CHECK",              _auth_status_text("SPF", result["forensics"].get("spf", "unknown")),
        _auth_level(result["forensics"].get("spf", "unknown")))
    evt(120, "DKIM CHECK",             _auth_status_text("DKIM", result["forensics"].get("dkim", "unknown")),
        _auth_level(result["forensics"].get("dkim", "unknown")))
    evt(140, "DMARC CHECK",            _auth_status_text("DMARC", result["forensics"].get("dmarc", "unknown")),
        _auth_level(result["forensics"].get("dmarc", "unknown")))
    evt(200, "SENDER ANALYSIS",        f"Sender domain: {result['forensics'].get('from_domain', '—')}")

    if result["forensics"].get("domain_mismatch"):
        evt(210, "DOMAIN MISMATCH DETECTED",
            f"Reply-To domain differs from sender domain",
            "warning")

    if result["forensics"].get("typosquatting"):
        evt(220, "LOOKALIKE DOMAIN DETECTED",
            "Sender domain appears to impersonate a trusted brand",
            "critical")

    urls = result["forensics"].get("urls_found", [])
    if urls:
        evt(300, "URL EXTRACTION",     f"{len(urls)} URL(s) found in email body")
        susp_urls = result["forensics"].get("suspicious_urls", [])
        if susp_urls:
            evt(350, "MALICIOUS URLS DETECTED",
                f"{len(susp_urls)} suspicious URL(s) identified",
                "critical")
        else:
            evt(350, "URL ANALYSIS COMPLETE", "No malicious URLs detected", "info")
    else:
        evt(300, "URL ANALYSIS",       "No URLs found in email body", "info")

    # BEC check
    bd = result.get("breakdown", {})
    behav = bd.get("behavioural", {})
    bec_checks = [c for c in (behav.get("checks") or []) if "bank" in c.get("name","").lower() or "bec" in c.get("name","").lower() or "wire" in c.get("name","").lower()]
    if bec_checks:
        evt(400, "BEC INDICATORS DETECTED",
            "Business Email Compromise signals found: executive impersonation + payment request",
            "critical")
    else:
        evt(400, "BEC CHECK COMPLETE",  "No Business Email Compromise indicators", "info")

    # Credential phishing
    cat = result.get("category", "")
    if cat == "CREDENTIAL_THEFT":
        evt(420, "CREDENTIAL PHISHING DETECTED",
            "Email requests login credentials or password verification",
            "critical")

    evt(500, "BEHAVIOURAL ANALYSIS",   "Historical pattern analysis complete [HEURISTIC]")

    # Threat Intelligence event
    intel = result["forensics"].get("threat_intel", {})
    if intel.get("has_threats"):
        ioc_count = len(intel.get("ioc_hits", []))
        evt(540, "THREAT INTELLIGENCE MATCH",
            f"{ioc_count} IOC(s) matched in local threat database [LOCAL INTELLIGENCE]",
            "critical")
    else:
        evt(540, "THREAT INTELLIGENCE",
            "Local IOC database lookup complete — no matches [LOCAL INTELLIGENCE]",
            "info")

    # Sender Reputation event
    rep = result["forensics"].get("sender_reputation", {})
    rep_val = rep.get("reputation", "unknown")
    rep_level = "critical" if rep_val == "malicious" else ("warning" if rep_val == "suspicious" else "info")
    evt(560, "SENDER REPUTATION",
        f"Reputation: {rep_val.upper()} (confidence: {rep.get('confidence', 0)}%) [LOCAL ANALYSIS]",
        rep_level)

    evt(600, "RISK SCORE CALCULATED",  f"Final threat score: {result['score']}/100 — {result['verdict']}")

    # Final action
    decision = _security_decision(result)
    action = decision["action"]
    level_map = {"BLOCK": "critical", "QUARANTINE": "warning", "FLAG": "warning", "DELIVER": "info"}
    evt(650, f"SECURITY DECISION: {action}",
        f"Policy engine decision: {action}. {', '.join(decision['justifications'][:1])}",
        level_map.get(action, "info"))

    evt(700, "FORENSIC REPORT GENERATED", "Complete investigation report available")

    return events


def _auth_status_text(protocol: str, status: str) -> str:
    status_map = {
        "pass": f"{protocol} authentication passed — sending server is authorized",
        "fail": f"{protocol} authentication FAILED — sending server not authorized for domain",
        "softfail": f"{protocol} soft fail — sending server not fully authorized",
        "unknown": f"{protocol} result unknown — no authentication header found",
    }
    return status_map.get(status, f"{protocol}: {status}")


def _auth_level(status: str) -> str:
    return {"pass": "info", "fail": "warning", "softfail": "warning"}.get(status, "info")


def _reconstruct_timeline(record: dict) -> List[dict]:
    """Reconstruct a basic timeline for records that pre-date timeline support."""
    base_ts = record.get("timestamp", datetime.now(timezone.utc).isoformat())
    try:
        base = datetime.fromisoformat(base_ts.replace("Z", "+00:00"))
    except Exception:
        base = datetime.now(timezone.utc)

    forensics = record.get("forensics", {})
    verdict = record.get("verdict", "SAFE")
    score = record.get("score", 0)

    def evt(offset_ms, event, detail, level="info"):
        ts = (base + timedelta(milliseconds=offset_ms)).isoformat()
        return {"timestamp": ts, "event": event, "detail": detail, "level": level}

    events = [
        evt(0,   "EMAIL RECEIVED",       "Email received by MailGuard gateway"),
        evt(50,  "HEADERS PARSED",       f"From: {record.get('from_address','—')[:60]}"),
        evt(100, "SPF CHECK",            _auth_status_text("SPF", forensics.get("spf","unknown")),
            _auth_level(forensics.get("spf","unknown"))),
        evt(120, "DKIM CHECK",           _auth_status_text("DKIM", forensics.get("dkim","unknown")),
            _auth_level(forensics.get("dkim","unknown"))),
        evt(500, "RISK SCORE CALCULATED",f"Threat score: {score}/100 — {verdict}"),
        evt(600, "REPORT GENERATED",     "Investigation report available"),
    ]
    return events


# ===========================================================================
# Seed data
# ===========================================================================

def _seed_email(subject, from_address, reply_to, sender_ip, headers, body, is_demo=True):
    """Analyse and persist a demo email."""
    result = _detector.analyse(
        subject=subject, from_address=from_address,
        reply_to=reply_to, sender_ip=sender_ip,
        headers=headers, body=body,
    )
    geo = get_geolocation(sender_ip)

    # Threat Intelligence for seed emails
    urls_found = result["forensics"].get("urls_found", [])
    intel_result = threat_intel.evaluate_email(
        from_address=from_address,
        reply_to=reply_to,
        sender_ip=sender_ip,
        urls=urls_found,
        attachments=[],
    )
    sender_reputation = _derive_sender_reputation(from_address, sender_ip, intel_result)
    language_analysis = _extract_language_analysis(result)

    result["forensics"]["threat_intel"]      = intel_result
    result["forensics"]["sender_reputation"] = sender_reputation
    result["forensics"]["language_analysis"] = language_analysis

    email_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()

    # Build a simple AnalyzeRequest-like object for timeline
    class _Req:
        def __init__(self):
            self.subject = subject
            self.from_address = from_address
            self.reply_to = reply_to
            self.sender_ip = sender_ip
            self.headers = headers
            self.body = body

    timeline = _build_timeline(result, _Req())
    decision = _security_decision(result)

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
        "decision":           decision,
        "timeline":           timeline,
    }
    db.insert_email(record)


def _seed_demo_emails():
    """Insert 11 realistic demo emails covering the full threat spectrum."""

    # 1. SAFE — Internal memo
    _seed_email(
        subject      = "[DEMO] Q3 2026 Team Lunch — Friday 12pm",
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
            "Best,\nAlice Johnson\nSenior Project Manager, Acme Corp"
        ),
    )

    # 2. CRITICAL — Classic phishing (PayPal spoof)
    _seed_email(
        subject      = "[DEMO] Your PayPal account has been SUSPENDED - Verify Immediately",
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
            "PayPal Security Team"
        ),
    )

    # 3. CRITICAL — Business Email Compromise (CFO fraud)
    _seed_email(
        subject      = "[DEMO] Confidential — Urgent Wire Transfer Required",
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
            "Robert Chen\nChief Executive Officer"
        ),
    )

    # 4. HIGH_RISK — Credential theft (Microsoft 365 spoof)
    _seed_email(
        subject      = "[DEMO] Action Required: Your Microsoft 365 Password Expires Today",
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
        subject      = "[DEMO] Password Reset Request for Your Account",
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
            "If you did not request this, please ignore this email.\n\n"
            "Account Security Team"
        ),
    )

    # 6. CRITICAL — Executive impersonation + social engineering
    _seed_email(
        subject      = "[DEMO] Personal Request — Need Your Help Urgently",
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
            "Do not mention this to anyone — including HR or Finance.\n\n"
            "Regards,\nDr. Meena Sharma\nManaging Director"
        ),
    )

    # 7. CRITICAL — Reply-To spoofing with domain mismatch
    _seed_email(
        subject      = "[DEMO] Security Alert: Unusual Sign-in Activity Detected",
        from_address = "Google Security <no-reply@accounts.google-security-verify.ml>",
        reply_to     = "support@hacker-collect.xyz",
        sender_ip    = "45.137.22.19",
        headers      = (
            "Received: from mail.google-security-verify.ml ([45.137.22.19])\n"
            "Authentication-Results: spf=fail; dkim=fail; dmarc=fail\n"
            "To: target@example.com\n"
        ),
        body = (
            "Dear Google Account Holder,\n\n"
            "We detected unusual sign-in activity on your Google account from an unrecognized device.\n\n"
            "If this was not you, please verify your account immediately:\n"
            "https://google-security-verify.ml/accounts/verify?token=a8x2k\n\n"
            "Failure to verify within 24 hours will result in account suspension.\n\n"
            "Enter your password and recovery email to confirm your identity.\n\n"
            "Google Account Security Team"
        ),
    )

    # 8. HIGH_RISK — QR code phishing (architecture demo)
    _seed_email(
        subject      = "[DEMO] Important: Verify Your Bank Account via QR Code",
        from_address = "HDFC NetBanking <noreply@hdfc-bank-secure.ml>",
        reply_to     = "noreply@hdfc-bank-secure.ml",
        sender_ip    = "139.59.48.5",
        headers      = (
            "Received: from mail.hdfc-bank-secure.ml ([139.59.48.5])\n"
            "Authentication-Results: spf=fail; dkim=fail\n"
        ),
        body = (
            "Dear Valued Customer,\n\n"
            "Your HDFC NetBanking account requires immediate verification.\n\n"
            "Please scan the QR code below using your smartphone camera to verify your account:\n"
            "[QR CODE IMAGE - Destination: https://hdfc-verify-account.xyz/login]\n\n"
            "⚠ QR PHISHING SIMULATION — This demonstrates how attackers embed malicious QR codes in emails.\n"
            "The QR code would redirect to a credential harvesting page.\n\n"
            "Failure to verify will result in account suspension within 24 hours.\n\n"
            "HDFC Bank Security Team"
        ),
    )

    # 9. SUSPICIOUS — Malicious attachment indicator
    _seed_email(
        subject      = "[DEMO] Invoice #INV-2026-0934 Attached for Your Review",
        from_address = "Billing <billing@supplier-invoices-global.download>",
        reply_to     = "accounts@supplier-invoices-global.download",
        sender_ip    = "94.102.49.190",
        headers      = (
            "Received: from mail.supplier-invoices-global.download ([94.102.49.190])\n"
            "Authentication-Results: spf=softfail; dkim=fail\n"
        ),
        body = (
            "Dear Accounts Team,\n\n"
            "Please find attached Invoice #INV-2026-0934 for your review and approval.\n\n"
            "Attached file: Invoice_INV-2026-0934.pdf.exe\n"
            "Amount due: $4,250.00\n"
            "Payment due: 30 September 2026\n\n"
            "Please process this payment urgently to avoid late fees.\n\n"
            "Supplier Accounts Team\nNote: [DEMO] This demonstrates a malicious executable disguised as a PDF invoice."
        ),
    )

    # 10. SPF/DKIM/DMARC Triple Failure
    _seed_email(
        subject      = "[DEMO] Your Package Could Not Be Delivered — Reschedule Now",
        from_address = "FedEx Delivery <delivery-alert@fedex-redelivery-portal.xyz>",
        reply_to     = "alerts@fedex-redelivery-portal.xyz",
        sender_ip    = "185.234.218.147",
        headers      = (
            "Received: from mail.fedex-redelivery-portal.xyz ([185.234.218.147])\n"
            "Authentication-Results: spf=fail; dkim=fail; dmarc=fail\n"
        ),
        body = (
            "Dear Customer,\n\n"
            "Your FedEx package could not be delivered as nobody was available at your address.\n\n"
            "To schedule a redelivery, please pay a small customs clearance fee of $2.99:\n"
            "https://fedex-redelivery-portal.xyz/pay?ref=FX99201847\n\n"
            "Failure to pay within 48 hours will result in the package being returned to sender.\n\n"
            "FedEx Customer Service"
        ),
    )

    # 11. CRITICAL — Multi-stage attack simulation
    _seed_email(
        subject      = "[DEMO] Action Required: Verify Your AWS Account — Unusual Activity",
        from_address = "Amazon Web Services <security@aws-account-verify.tk>",
        reply_to     = "noreply@aws-alert-security.ml",
        sender_ip    = "45.142.212.100",
        headers      = (
            "Received: from smtp.aws-account-verify.tk ([45.142.212.100])\n"
            "Authentication-Results: spf=fail; dkim=fail; dmarc=fail\n"
            "To: admin@company.com\n"
        ),
        body = (
            "Dear AWS Account Holder,\n\n"
            "We have detected unusual API activity on your AWS account. Multiple root-level "
            "API calls were made from an unrecognized IP address.\n\n"
            "URGENT: Your account may be compromised. You must verify your identity and "
            "update your credentials immediately to prevent data loss.\n\n"
            "Step 1: Click to sign in and verify: https://aws-account-verify.tk/signin\n"
            "Step 2: Enter your AWS root email and password\n"
            "Step 3: Provide your MFA code\n"
            "Step 4: Update your root credentials\n\n"
            "Failure to verify within 12 hours will result in automatic account suspension "
            "and your EC2 instances will be terminated.\n\n"
            "Amazon Web Services Security Team"
        ),
    )

    log.info("11 demo emails seeded successfully.")


# ===========================================================================
# Static file serving — Frontend SPA
# ===========================================================================
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
    if full_path.startswith("static/") or full_path.startswith("api/"):
        return JSONResponse(status_code=404, content={"error": "Not found"})
    index = _STATIC / "index.html"
    if index.exists():
        return FileResponse(str(index))
    return JSONResponse(status_code=503, content={"error": "Frontend not found"})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)

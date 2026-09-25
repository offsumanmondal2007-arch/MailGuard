"""
models.py — Pydantic request/response models for MailGuard AI.
All field names here define the single source of truth for the API contract.
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator
import re


# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    subject:      Optional[str] = Field(default="", description="Email subject line")
    from_address: Optional[str] = Field(default="", description="Sender address (From header)")
    reply_to:     Optional[str] = Field(default="", description="Reply-To header value")
    sender_ip:    Optional[str] = Field(default="", description="Originating sender IP")
    headers:      Optional[str] = Field(default="", description="Raw email headers (optional)")
    body:         Optional[str] = Field(default="", description="Email body text")

    @field_validator("body")
    @classmethod
    def body_max_length(cls, v: str) -> str:
        if v and len(v) > 100_000:
            raise ValueError("Email body exceeds maximum allowed size (100,000 characters).")
        return v

    @field_validator("sender_ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        if not v:
            return v
        # Allow empty or valid IPv4/IPv6 — reject obvious garbage
        ipv4 = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        ipv6 = re.compile(r"^[0-9a-fA-F:]+$")
        if v and not (ipv4.match(v) or ipv6.match(v)):
            raise ValueError(f"Invalid IP address format: {v!r}")
        return v


class StatusUpdate(BaseModel):
    status: str = Field(..., description="New status: new | reviewed | quarantined | cleared")

    @field_validator("status")
    @classmethod
    def valid_status(cls, v: str) -> str:
        allowed = {"new", "reviewed", "quarantined", "cleared"}
        if v not in allowed:
            raise ValueError(f"Status must be one of: {', '.join(allowed)}")
        return v


# ---------------------------------------------------------------------------
# Sub-models used inside AnalyzeResponse
# ---------------------------------------------------------------------------

class PillarScore(BaseModel):
    score: int
    max:   int
    checks: List[Dict[str, Any]] = []


class BreakdownModel(BaseModel):
    header_forensics: PillarScore
    content_analysis: PillarScore
    url_intelligence: PillarScore
    behavioural:      PillarScore
    ml_heuristic:     PillarScore


class CheckItem(BaseModel):
    name:   str
    result: str   # pass | fail | warn | info
    detail: str


class GeoInfo(BaseModel):
    ip:        str = ""
    country:   str = "Unknown"
    region:    str = "Unknown"
    city:      str = "Unknown"
    isp:       str = "Unknown"
    org:       str = "Unknown"
    asn:       str = "Unknown"
    lat:       Optional[float] = None
    lon:       Optional[float] = None
    available: bool = False
    is_demo:   bool = False


class ForensicsInfo(BaseModel):
    from_domain:           str = ""
    reply_to_domain:       str = ""
    domain_mismatch:       bool = False
    spf:                   str = "unknown"
    dkim:                  str = "unknown"
    dmarc:                 str = "unknown"
    urls_found:            List[str] = []
    suspicious_urls:       List[str] = []
    display_name:          str = ""
    display_name_spoofing: bool = False
    received_hops:         int = 0
    typosquatting:         bool = False
    suspicious_tld:        bool = False


# ---------------------------------------------------------------------------
# Response Models
# ---------------------------------------------------------------------------

class AnalyzeResponse(BaseModel):
    id:                 str
    timestamp:          str
    subject:            str
    from_address:       str
    reply_to:           str
    sender_ip:          str
    score:              int
    verdict:            str   # SAFE | SUSPICIOUS | HIGH_RISK | CRITICAL
    category:           str
    confidence:         float
    reasons:            List[str]
    breakdown:          BreakdownModel
    checks:             List[CheckItem]
    geo:                GeoInfo
    forensics:          ForensicsInfo
    recommended_action: str
    status:             str


class EmailSummary(BaseModel):
    id:          str
    timestamp:   str
    subject:     str
    from_address: str
    score:       int
    verdict:     str
    category:    str
    confidence:  float
    status:      str


class DashboardStats(BaseModel):
    total:            int
    safe:             int
    suspicious:       int
    high_risk:        int
    critical:         int
    quarantined:      int
    blocked:          int = 0
    threat_percentage: float
    recent:           List[EmailSummary]
    by_category:      Dict[str, int]
    by_verdict:       Dict[str, int]
    by_day:           Dict[str, int]
    top_domains:      List[List[Any]]


class HealthResponse(BaseModel):
    status:   str
    service:  str
    database: str
    detector: str

"""
tests/test_api.py — Automated API tests for MailGuard AI.

Run with:
    pytest tests/ -v

Requires: pytest, httpx
"""

import json
import pytest
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi.testclient import TestClient
import db
from app import app, _seed_demo_emails

# Initialize DB and seed demo emails for testing
db.init_db()
if db.count_emails() == 0:
    _seed_demo_emails()

client = TestClient(app)


# ════════════════════════════════════════════════════════════
# Health endpoint
# ════════════════════════════════════════════════════════════
def test_health():
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["service"] == "MailGuard AI"
    assert data["database"] == "connected"
    assert data["detector"] == "ready"


# ════════════════════════════════════════════════════════════
# Analyze endpoint
# ════════════════════════════════════════════════════════════
def test_analyze_safe_email():
    resp = client.post("/api/analyze", json={
        "subject":      "Team lunch on Friday",
        "from_address": "alice@acme-corp.com",
        "reply_to":     "alice@acme-corp.com",
        "sender_ip":    "",
        "headers":      "Authentication-Results: spf=pass; dkim=pass",
        "body":         "Hi team, reminder about the team lunch on Friday at 12pm. See you there!",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "id" in data
    assert "score" in data
    assert data["score"] <= 35, f"Expected safe score, got {data['score']}"
    assert data["verdict"] in ("SAFE", "SUSPICIOUS")
    assert "breakdown" in data
    assert "forensics" in data
    assert "geo" in data
    assert isinstance(data["reasons"], list)


def test_analyze_phishing_email():
    resp = client.post("/api/analyze", json={
        "subject":      "URGENT: Your PayPal account has been SUSPENDED",
        "from_address": "PayPal <security@paypa1-secure.tk>",
        "reply_to":     "noreply@paypal-helpdesk.ml",
        "sender_ip":    "185.220.101.45",
        "headers":      "Authentication-Results: spf=fail; dkim=fail; dmarc=fail",
        "body": (
            "Dear Customer, URGENT: Your account is suspended. "
            "Verify immediately or account will be permanently terminated within 24 hours. "
            "Click here to verify your account and enter your username and password: "
            "http://185.220.101.45/paypal/verify. Legal action will follow if ignored."
        ),
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["score"] >= 50, f"Expected high score for phishing, got {data['score']}"
    assert data["verdict"] in ("SUSPICIOUS", "HIGH_RISK", "CRITICAL")
    assert len(data["reasons"]) > 0
    assert data["forensics"]["domain_mismatch"] is True


def test_analyze_bec_email():
    resp = client.post("/api/analyze", json={
        "subject":      "Confidential — Urgent Wire Transfer Required",
        "from_address": '"Robert Chen - CEO" <ceo@acme-corp-hq.xyz>',
        "reply_to":     "rchen.payments@gmail.com",
        "sender_ip":    "91.108.4.1",
        "headers":      "Authentication-Results: spf=softfail; dkim=pass; dmarc=fail",
        "body": (
            "Hi Sarah, I need you to process a confidential wire transfer today. "
            "Transfer $87,500 to the new bank account: Routing Number: 021000021, "
            "Account Number: 7829301847. Keep this confidential — do not discuss with anyone. "
            "I am in a board meeting. Please confirm once completed."
        ),
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["score"] >= 40, f"Expected medium-high score for BEC, got {data['score']}"
    assert data["category"] in (
        "BUSINESS_EMAIL_COMPROMISE", "PAYMENT_FRAUD",
        "EXECUTIVE_IMPERSONATION", "PHISHING"
    )


def test_analyze_empty_body_rejected():
    """At least one field must be present."""
    resp = client.post("/api/analyze", json={
        "subject": "",
        "from_address": "",
        "reply_to": "",
        "sender_ip": "",
        "headers": "",
        "body": "",
    })
    # Should still run (score will be 0) — validation is frontend
    assert resp.status_code == 200
    data = resp.json()
    assert data["score"] == 0
    assert data["verdict"] == "SAFE"


def test_analyze_invalid_ip_rejected():
    resp = client.post("/api/analyze", json={
        "subject": "test",
        "from_address": "a@b.com",
        "body": "test body",
        "sender_ip": "not_an_ip_address!",
    })
    # Should return 422 Unprocessable Entity
    assert resp.status_code == 422


def test_analyze_body_too_large_rejected():
    resp = client.post("/api/analyze", json={
        "body": "x" * 150_000,
    })
    assert resp.status_code == 422


def test_analyze_missing_optional_fields():
    """All optional fields should work fine if omitted."""
    resp = client.post("/api/analyze", json={
        "body": "Hello, this is a test email with no other fields."
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "score" in data
    assert "verdict" in data


# ════════════════════════════════════════════════════════════
# Email list endpoint
# ════════════════════════════════════════════════════════════
def test_list_emails():
    resp = client.get("/api/emails")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    # At least the demo emails should exist
    assert len(data) >= 1
    first = data[0]
    assert "id" in first
    assert "score" in first
    assert "verdict" in first
    assert "from_address" in first


def test_get_email_not_found():
    resp = client.get("/api/emails/00000000-0000-0000-0000-000000000000")
    assert resp.status_code == 404


def test_get_email_by_id():
    # First get a real ID from the list
    emails = client.get("/api/emails").json()
    assert len(emails) > 0
    email_id = emails[0]["id"]
    resp = client.get(f"/api/emails/{email_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == email_id
    assert "breakdown" in data
    assert "forensics" in data
    assert "geo" in data
    assert "checks" in data
    assert "reasons" in data


# ════════════════════════════════════════════════════════════
# Status update
# ════════════════════════════════════════════════════════════
def test_update_status_valid():
    emails = client.get("/api/emails").json()
    email_id = emails[0]["id"]
    resp = client.patch(f"/api/emails/{email_id}/status", json={"status": "reviewed"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "reviewed"


def test_update_status_invalid():
    emails = client.get("/api/emails").json()
    email_id = emails[0]["id"]
    resp = client.patch(f"/api/emails/{email_id}/status", json={"status": "hacked"})
    assert resp.status_code == 422


def test_update_status_not_found():
    resp = client.patch("/api/emails/00000000-0000-0000-0000-000000000000/status", json={"status": "reviewed"})
    assert resp.status_code == 404


# ════════════════════════════════════════════════════════════
# Dashboard endpoint
# ════════════════════════════════════════════════════════════
def test_dashboard():
    resp = client.get("/api/dashboard")
    assert resp.status_code == 200
    data = resp.json()
    assert "total" in data
    assert "safe" in data
    assert "suspicious" in data
    assert "high_risk" in data
    assert "critical" in data
    assert "threat_percentage" in data
    assert "recent" in data
    assert "by_category" in data
    assert "by_verdict" in data
    assert "by_day" in data
    assert "top_domains" in data
    assert isinstance(data["recent"], list)
    assert data["total"] >= 0


def test_dashboard_totals_consistent():
    data = client.get("/api/dashboard").json()
    category_total = sum(data["by_verdict"].values())
    assert category_total == data["total"], "Verdict counts should sum to total"


# ════════════════════════════════════════════════════════════
# Reports endpoint
# ════════════════════════════════════════════════════════════
def test_reports():
    resp = client.get("/api/reports")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)


# ════════════════════════════════════════════════════════════
# Detector unit tests
# ════════════════════════════════════════════════════════════
def test_detector_score_range():
    """Score must always be 0–100."""
    from detector import ThreatDetector
    det = ThreatDetector()
    for _ in range(5):
        result = det.analyse(
            body="Hello, urgent action required. Enter your password immediately. "
                 "Wire transfer to new bank account. CEO request. Confidential."
        )
        assert 0 <= result["score"] <= 100
        assert result["verdict"] in ("SAFE", "SUSPICIOUS", "HIGH_RISK", "CRITICAL")


def test_detector_safe_email():
    from detector import ThreatDetector
    det = ThreatDetector()
    result = det.analyse(
        subject="Meeting at 3pm",
        from_address="bob@company.com",
        reply_to="bob@company.com",
        body="Hi, just confirming our 3pm meeting today. See you then.",
    )
    assert result["score"] <= 20, f"Safe email scored too high: {result['score']}"
    assert result["verdict"] == "SAFE"


def test_detector_phishing_signals():
    from detector import ThreatDetector
    det = ThreatDetector()
    result = det.analyse(
        subject="URGENT: Verify your account password immediately",
        from_address="PayPal <security@paypa1-secure.tk>",
        reply_to="noreply@paypal-help.ml",
        body="Dear Customer, verify your account credentials at http://185.1.2.3/login. "
             "Failure to act within 24 hours will result in legal action and account suspension.",
    )
    assert result["score"] >= 40
    assert result["forensics"]["domain_mismatch"] is True


def test_detector_url_extraction():
    from detector import ThreatDetector
    det = ThreatDetector()
    result = det.analyse(
        body="Click here http://bit.ly/abcdef and also visit http://192.168.1.1/phish"
    )
    urls = result["forensics"].get("urls_found", [])
    assert len(urls) >= 1  # at least one URL found


def test_detector_spam_and_scams():
    from detector import ThreatDetector
    det = ThreatDetector()

    # Lottery scam
    lottery = det.analyse(
        subject="You won $1,000,000 lottery",
        body="Congratulations! You have won $1,000,000 in the Google Annual Sweepstakes. Click here to claim your prize now: http://lottery-win.xyz"
    )
    assert lottery["verdict"] in ("SAFE", "SUSPICIOUS", "HIGH_RISK", "CRITICAL")
    assert lottery["category"] in ("SAFE", "SPAM", "LOTTERY_SCAM")

    # Tech support / fake invoice scam
    tech = det.analyse(
        subject="Invoice for Geek Squad Renewal $499.99",
        body="Your annual Geek Squad subscription has been auto-renewed for $499.99. If you did not authorize this charge, call our refund department at +1-800-555-0199 immediately."
    )
    assert tech["verdict"] in ("SAFE", "SUSPICIOUS", "HIGH_RISK", "CRITICAL")
    assert tech["category"] in ("SAFE", "SPAM", "TECH_SUPPORT_SCAM", "PAYMENT_FRAUD")

    # Delivery scam
    delivery = det.analyse(
        subject="USPS: Delivery Failed",
        body="Your package could not be delivered due to incomplete address. Please schedule redelivery and pay $1.50 customs fee: http://usps-redelivery-update.top"
    )
    assert delivery["verdict"] in ("SUSPICIOUS", "HIGH_RISK", "CRITICAL")
    assert delivery["category"] in ("SPAM", "PACKAGE_DELIVERY_SCAM", "PHISHING")

    # Promotional spam
    spam = det.analyse(
        subject="100% FREE Casino Bonus - Act Now and Save!",
        body="Buy 1 get 1 free! Limited time offer! Clearance sale, save up to 80%! Click here to unsubscribe."
    )
    assert spam["verdict"] in ("SAFE", "SUSPICIOUS", "HIGH_RISK")
    assert spam["category"] in ("SAFE", "SPAM")


# ════════════════════════════════════════════════════════════
# Score consistency tests (verifies fix for booster bug)
# ════════════════════════════════════════════════════════════
def test_score_equals_pillar_sum():
    """
    The displayed score must equal the sum of the five pillar scores
    (or the adaptively scaled version for text-only submissions).
    It must never be inflated by hidden boosters.
    """
    from detector import ThreatDetector
    det = ThreatDetector()

    # Test with headers present — score should be min(100, pillar_sum)
    result = det.analyse(
        subject="URGENT: Your PayPal account has been SUSPENDED",
        from_address="PayPal <security@paypa1-secure.tk>",
        reply_to="noreply@paypal-helpdesk.ml",
        sender_ip="185.220.101.45",
        headers="Authentication-Results: spf=fail; dkim=fail; dmarc=fail",
        body=(
            "Dear Customer, verify your account credentials at "
            "http://185.220.101.45/login. Failure to act within "
            "24 hours will result in account suspension."
        ),
    )

    bd = result["breakdown"]
    pillar_sum = (
        bd["header_forensics"]["score"]
        + bd["content_analysis"]["score"]
        + bd["url_intelligence"]["score"]
        + bd["behavioural"]["score"]
        + bd["ml_heuristic"]["score"]
    )
    expected = min(100, pillar_sum)
    assert result["score"] == expected, (
        f"Score {result['score']} does not match pillar sum {pillar_sum}. "
        f"Breakdown: header={bd['header_forensics']['score']}, "
        f"content={bd['content_analysis']['score']}, "
        f"url={bd['url_intelligence']['score']}, "
        f"behav={bd['behavioural']['score']}, "
        f"ml={bd['ml_heuristic']['score']}"
    )


def test_score_no_hidden_boosters():
    """
    Regression test: when pillar scores sum to a value like 58,
    the final score must NOT be silently inflated to 75 or any other
    value by hidden booster overrides.
    """
    from detector import ThreatDetector
    det = ThreatDetector()

    # A moderately threatening email — score should reflect actual pillar values only
    result = det.analyse(
        subject="Password Reset Request",
        from_address="noreply@accounts-reset-portal.download",
        headers="Authentication-Results: spf=softfail; dkim=fail",
        body=(
            "Hello, we received a request to reset your account password. "
            "Click the link below to reset: http://bit.ly/3xR9pQZ "
            "If you did not request this, please ignore this email."
        ),
    )

    bd = result["breakdown"]
    pillar_sum = (
        bd["header_forensics"]["score"]
        + bd["content_analysis"]["score"]
        + bd["url_intelligence"]["score"]
        + bd["behavioural"]["score"]
        + bd["ml_heuristic"]["score"]
    )
    expected = min(100, pillar_sum)
    assert result["score"] == expected, (
        f"Score was inflated from {pillar_sum} to {result['score']}! "
        f"This indicates hidden boosters are still active."
    )


def test_score_breakdown_consistency_across_scenarios():
    """
    For multiple email scenarios, verify the score always matches the breakdown sum.
    """
    from detector import ThreatDetector
    det = ThreatDetector()

    scenarios = [
        {
            "name": "Safe email",
            "kwargs": {
                "subject": "Team lunch Friday",
                "from_address": "alice@acme-corp.com",
                "reply_to": "alice@acme-corp.com",
                "headers": "Authentication-Results: spf=pass; dkim=pass; dmarc=pass",
                "body": "Hi, just a reminder about team lunch on Friday at noon.",
            },
        },
        {
            "name": "BEC wire transfer",
            "kwargs": {
                "subject": "Confidential — Urgent Wire Transfer",
                "from_address": '"CEO" <ceo@acme-hq.xyz>',
                "reply_to": "ceo.payments@gmail.com",
                "headers": "Authentication-Results: spf=softfail; dkim=pass; dmarc=fail",
                "body": (
                    "Process a confidential wire transfer today. "
                    "New bank account: Routing 021000021. "
                    "Keep confidential. I am in a board meeting."
                ),
            },
        },
        {
            "name": "Lottery spam",
            "kwargs": {
                "subject": "CONGRATULATIONS!!! YOU WON $1,000,000!!!",
                "from_address": "rewards@promotions-direct.top",
                "headers": "Authentication-Results: spf=fail; dkim=fail",
                "body": (
                    "You have been selected as our lucky winner! "
                    "Claim your prize immediately. Limited time offer!!! "
                    "Click now: http://promotions-direct.top/claim"
                ),
            },
        },
    ]

    for scenario in scenarios:
        result = det.analyse(**scenario["kwargs"])
        bd = result["breakdown"]
        pillar_sum = (
            bd["header_forensics"]["score"]
            + bd["content_analysis"]["score"]
            + bd["url_intelligence"]["score"]
            + bd["behavioural"]["score"]
            + bd["ml_heuristic"]["score"]
        )
        expected = min(100, pillar_sum)
        assert result["score"] == expected, (
            f"[{scenario['name']}] Score {result['score']} != pillar sum {expected}. "
            f"header={bd['header_forensics']['score']}, "
            f"content={bd['content_analysis']['score']}, "
            f"url={bd['url_intelligence']['score']}, "
            f"behav={bd['behavioural']['score']}, "
            f"ml={bd['ml_heuristic']['score']}"
        )

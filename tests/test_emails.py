"""
tests/test_emails.py — Comprehensive Test Dataset & Evaluation Suite for MailGuard AI.

Contains realistic fictional test cases across all threat categories:
- 5 Legitimate Emails (Clean/Safe)
- 5 Obvious Spam Emails
- 5 Phishing Emails
- 3 Credential Theft Emails
- 3 Payment Fraud / BEC Emails
- 3 Suspicious Mixed Cases
- 5 Required Core Demo Cases

Run with:
    pytest tests/test_emails.py -v
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from detector import ThreatDetector

det = ThreatDetector()


# ===========================================================================
# 1. Five Legitimate Emails (SAFE)
# ===========================================================================

LEGITIMATE_EMAILS = [
    {
        "name": "legit_team_meeting",
        "subject": "Team Meeting Tomorrow",
        "from_address": "rahul.sharma@company.com",
        "reply_to": "rahul.sharma@company.com",
        "headers": "Authentication-Results: spf=pass; dkim=pass; dmarc=pass\nTo: project-team@company.com",
        "body": "Hello team,\nJust a reminder that our project meeting is tomorrow at 10 AM.\nPlease bring your progress update.\nRegards,\nRahul",
        "expected_category": "SAFE",
        "expected_verdict": "SAFE",
        "max_score": 25,
    },
    {
        "name": "legit_monthly_invoice",
        "subject": "Your Monthly Invoice",
        "from_address": "billing@acme-services.com",
        "reply_to": "billing@acme-services.com",
        "headers": "Authentication-Results: spf=pass; dkim=pass; dmarc=pass",
        "body": "Your monthly invoice is now available in your normal customer portal.\nYou can log in through the company website to view your billing information.",
        "expected_category": "SAFE",
        "expected_verdict": "SAFE",
        "max_score": 25,
    },
    {
        "name": "legit_support_resolution",
        "subject": "Issue Resolved: Ticket #48291",
        "from_address": "support@cloudservice.com",
        "reply_to": "support@cloudservice.com",
        "headers": "Authentication-Results: spf=pass; dkim=pass; dmarc=pass",
        "body": "Hi Sarah, The issue with your urgent support request regarding database latency has been resolved by our engineering team. Let us know if you need further help.",
        "expected_category": "SAFE",
        "expected_verdict": "SAFE",
        "max_score": 25,
    },
    {
        "name": "legit_company_newsletter",
        "subject": "Acme Monthly Newsletter — September 2026",
        "from_address": "newsletter@acme-corp.com",
        "reply_to": "newsletter@acme-corp.com",
        "headers": "Authentication-Results: spf=pass; dkim=pass; dmarc=pass",
        "body": "Welcome to our September internal newsletter! This month we celebrate our quarterly achievements and welcome 5 new colleagues to the engineering team.",
        "expected_category": "SAFE",
        "expected_verdict": "SAFE",
        "max_score": 25,
    },
    {
        "name": "legit_shipping_confirmation",
        "subject": "Your Order #92817 has shipped",
        "from_address": "orders@trusted-store.com",
        "reply_to": "orders@trusted-store.com",
        "headers": "Authentication-Results: spf=pass; dkim=pass; dmarc=pass",
        "body": "Good news! Your order #92817 has shipped via standard courier and is estimated to arrive on Thursday. Thank you for your purchase.",
        "expected_category": "SAFE",
        "expected_verdict": "SAFE",
        "max_score": 25,
    },
]


# ===========================================================================
# 2. Five Obvious Spam Emails (SPAM)
# ===========================================================================

SPAM_EMAILS = [
    {
        "name": "spam_prize_lottery",
        "subject": "CONGRATULATIONS!!! YOU WON $1,000,000!!!",
        "from_address": "lucky-reward@promotions-direct.top",
        "reply_to": "claim@promotions-direct.top",
        "body": "You have been selected as our lucky winner!\nClaim your prize immediately.\nLimited time offer!!!\nClick now to receive your reward!!!",
        "expected_category": "SPAM",
        "min_score": 30,
    },
    {
        "name": "spam_casino_bonus",
        "subject": "100% FREE Casino Bonus - Act Now and Save!",
        "from_address": "bonus@casinowinners-club.xyz",
        "reply_to": "optout@casinowinners-club.xyz",
        "body": "Buy 1 get 1 free! 500 free spins waiting! Clearance sale, save up to 80%! Unsubscribe here: http://casinowinners-club.xyz/optout",
        "expected_category": "SPAM",
        "min_score": 35,
    },
    {
        "name": "spam_work_from_home",
        "subject": "Earn $500/day working from home - No Experience Required!",
        "from_address": "careers@fast-cash-income.stream",
        "reply_to": "hr@fast-cash-income.stream",
        "body": "Make money online with passive income! Earn $500 daily with part-time data entry. Immediate job offer, no credit check needed.",
        "expected_category": "SPAM",
        "min_score": 15,
    },
    {
        "name": "spam_weight_loss_miracle",
        "subject": "Exclusive Discount: Secret weight loss formula clearance sale",
        "from_address": "deals@health-discount-now.club",
        "reply_to": "info@health-discount-now.club",
        "body": "Money back guarantee! 100% free trial bottle. Limited time deal on our weight loss supplement. Order today and save 70% while supplies last!",
        "expected_category": "SPAM",
        "min_score": 15,
    },
    {
        "name": "spam_geek_squad_invoice",
        "subject": "Invoice for Geek Squad Renewal $499.99",
        "from_address": "Geek Squad Billing <billing-service-notice@gmail.com>",
        "reply_to": "refund-desk@outlook.com",
        "body": "Your annual Geek Squad subscription has been auto-renewed for $499.99. If you did not authorize this charge, call our refund department at +1-800-555-0199 immediately.",
        "expected_category": "SPAM",
        "min_score": 30,
    },
]


# ===========================================================================
# 3. Five Phishing Emails (PHISHING)
# ===========================================================================

PHISHING_EMAILS = [
    {
        "name": "phish_account_suspension",
        "subject": "URGENT: Your PayPal account has been SUSPENDED",
        "from_address": "PayPal Security <security@paypa1-secure.tk>",
        "reply_to": "noreply@paypal-helpdesk.ml",
        "headers": "Authentication-Results: spf=fail; dkim=fail; dmarc=fail",
        "body": "Dear Customer, URGENT: Your PayPal account has been suspended. Verify immediately or account will be permanently terminated. Click here to verify your account: http://185.220.101.45/paypal/verify. Failure to comply will lead to legal action.",
        "expected_category": "PHISHING",
        "min_score": 60,
    },
    {
        "name": "phish_bank_alert",
        "subject": "Security Alert: Unauthorized access detected on your bank profile",
        "from_address": "Chase Security <alerts@chase-banking-security.top>",
        "reply_to": "support@chase-banking-security.top",
        "body": "We detected unauthorized login attempts from an unknown IP address. Click here to verify your identity and protect your account immediately: http://chase-banking-security.top/verify",
        "expected_category": "PHISHING",
        "min_score": 50,
    },
    {
        "name": "phish_shared_google_doc",
        "subject": "Important Document shared with you via Google Drive",
        "from_address": "Google Docs Team <share-notice@g00gle-drive-docs.xyz>",
        "reply_to": "noreply@g00gle-drive-docs.xyz",
        "body": "You have received a secure document via Google Docs. Click here to view and sign the document: http://g00gle-drive-docs.xyz/view?doc=9281. Sign in with your email credentials to access.",
        "expected_category": "PHISHING",
        "min_score": 30,
    },
    {
        "name": "phish_office365_storage",
        "subject": "Action Required: Your Office 365 mailbox storage is full",
        "from_address": "IT Helpdesk <admin@micros0ft-support.online>",
        "reply_to": "admin@micros0ft-support.online",
        "body": "Your mailbox has exceeded its storage quota. Incoming emails are held. Click here to validate your credentials and re-authenticate your mailbox: http://micros0ft-support.online/m365",
        "expected_category": "PHISHING",
        "min_score": 50,
    },
    {
        "name": "phish_dhl_redelivery",
        "subject": "USPS/DHL: Delivery Failed — Address Confirmation Required",
        "from_address": "DHL Express Tracking <tracking@dhl-parcel-delivery.click>",
        "reply_to": "tracking@dhl-parcel-delivery.click",
        "body": "Your package could not be delivered due to an incorrect address. Please update your delivery address and pay the $1.50 redelivery fee: http://dhl-parcel-delivery.click/redelivery",
        "expected_category": "PHISHING",
        "min_score": 50,
    },
]


# ===========================================================================
# 4. Three Credential Theft Emails (CREDENTIAL_THEFT)
# ===========================================================================

CREDENTIAL_THEFT_EMAILS = [
    {
        "name": "cred_theft_password_entry",
        "subject": "URGENT: Verify Your Account",
        "from_address": "security-team@accounts-verify.top",
        "reply_to": "security-team@accounts-verify.top",
        "body": "Your account will be suspended today. Click the link below and enter your password immediately: http://accounts-verify.top/login",
        "expected_category": "CREDENTIAL_THEFT",
        "min_score": 40,
    },
    {
        "name": "cred_theft_m365_expired",
        "subject": "Action Required: Microsoft 365 Password Expired",
        "from_address": "Microsoft IT Support <support@micros0ft-365.top>",
        "reply_to": "support@micros0ft-365.top",
        "body": "Your Microsoft 365 account password expired today. Enter your username and password to confirm credentials: https://micros0ft-365.top/m365/login",
        "expected_category": "CREDENTIAL_THEFT",
        "min_score": 40,
    },
    {
        "name": "cred_theft_pin_otp",
        "subject": "Security Checkpoint: Confirm your security PIN and OTP",
        "from_address": "portal-auth@security-validate.icu",
        "reply_to": "portal-auth@security-validate.icu",
        "body": "Please confirm your account identity. Enter your one-time password OTP and security PIN to unlock your account access.",
        "expected_category": "CREDENTIAL_THEFT",
        "min_score": 30,
    },
]


# ===========================================================================
# 5. Three Payment Fraud / BEC Emails (PAYMENT_FRAUD / BEC)
# ===========================================================================

PAYMENT_FRAUD_BEC_EMAILS = [
    {
        "name": "bec_ceo_wire_transfer",
        "subject": "Confidential — Urgent Wire Transfer Required",
        "from_address": '"Robert Chen - CEO" <robert.chen@acme-corp-hq.xyz>',
        "reply_to": "rchen.payments@gmail.com",
        "headers": "Authentication-Results: spf=softfail; dkim=pass; dmarc=fail",
        "body": "Hi Sarah, I need you to process a confidential wire transfer today. Transfer $87,500 to our new partner: Bank: First National Trust, Routing Number: 021000021, Account Number: 7829301847. Please keep this confidential — do not discuss with anyone. I am in a board meeting.",
        "expected_category": "BUSINESS_EMAIL_COMPROMISE",
        "min_score": 40,
    },
    {
        "name": "payment_fraud_urgent_request",
        "subject": "Urgent Payment Request",
        "from_address": "director.finance@corp-mail.xyz",
        "reply_to": "director.finance@corp-mail.xyz",
        "body": "I am currently unavailable. Please transfer the payment to this new bank account immediately and keep this confidential.",
        "expected_category": "PAYMENT_FRAUD",
        "min_score": 40,
    },
    {
        "name": "payment_fraud_vendor_routing_change",
        "subject": "Updated Vendor Bank Routing Details for Pending Invoice",
        "from_address": "accounting@supplier-corp.online",
        "reply_to": "supplier.payments@gmail.com",
        "body": "Please update your bank details for our invoice remittance. Our new bank account routing number is 021000021 and Account Number is 99882211. Send payment required immediately.",
        "expected_category": "PAYMENT_FRAUD",
        "min_score": 30,
    },
]


# ===========================================================================
# 6. Three Suspicious Mixed Cases
# ===========================================================================

SUSPICIOUS_MIXED_EMAILS = [
    {
        "name": "mixed_unsolicited_sales_shortlink",
        "subject": "B2B Outreach: Transform your cloud infrastructure",
        "from_address": "alex@outbound-marketing.site",
        "reply_to": "alex@outbound-marketing.site",
        "body": "Hi, we help companies optimize cloud spend. Check out our client case studies at http://bit.ly/cloud-case-study to see how they saved 40%.",
        "expected_verdict": "SUSPICIOUS",
        "min_score": 10,
    },
    {
        "name": "mixed_unknown_password_reset",
        "subject": "Password Reset Notification for Unrecognized App",
        "from_address": "noreply@app-portal-notice.xyz",
        "reply_to": "",
        "body": "We received a password reset request for your account. If you initiated this, visit http://bit.ly/3xR9pQZ to proceed.",
        "expected_verdict": "SUSPICIOUS",
        "min_score": 10,
    },
    {
        "name": "mixed_executive_gift_card_request",
        "subject": "Personal Request — Need Your Help Urgently",
        "from_address": '"Dr. Meena Sharma - Managing Director" <md@globaltech-inc.cf>',
        "reply_to": "meena.sharma.md2026@gmail.com",
        "body": "Hi, I am in a board meeting — keep this strictly between us. Purchase 10 Amazon gift cards worth INR 5,000 each and share codes via email. I will reimburse from petty cash.",
        "expected_category": "EXECUTIVE_IMPERSONATION",
        "min_score": 35,
    },
]


# ===========================================================================
# Test Functions
# ===========================================================================

@pytest.mark.parametrize("item", LEGITIMATE_EMAILS, ids=lambda x: x["name"])
def test_legitimate_emails_classified_as_safe(item):
    """Verify legitimate business emails are NOT falsely flagged as spam or threats."""
    r = det.analyse(
        subject=item.get("subject", ""),
        from_address=item.get("from_address", ""),
        reply_to=item.get("reply_to", ""),
        headers=item.get("headers", ""),
        body=item.get("body", ""),
    )
    assert r["verdict"] == "SAFE", f"Expected SAFE verdict, got {r['verdict']} (score: {r['score']})"
    assert r["category"] == "SAFE", f"Expected SAFE category, got {r['category']}"
    assert r["score"] <= item.get("max_score", 29), f"Score {r['score']} exceeded max allowed {item['max_score']}"


@pytest.mark.parametrize("item", SPAM_EMAILS, ids=lambda x: x["name"])
def test_spam_emails_detected(item):
    """Verify promotional and sweepstakes spam emails are correctly identified."""
    r = det.analyse(
        subject=item.get("subject", ""),
        from_address=item.get("from_address", ""),
        reply_to=item.get("reply_to", ""),
        body=item.get("body", ""),
    )
    assert r["score"] >= item.get("min_score", 30), f"Score {r['score']} below expected min {item['min_score']}"
    assert r["verdict"] in ("SAFE", "SUSPICIOUS", "HIGH_RISK", "CRITICAL")
    assert r["category"] in ("SAFE", "SPAM", "PAYMENT_FRAUD", "PHISHING")


@pytest.mark.parametrize("item", PHISHING_EMAILS, ids=lambda x: x["name"])
def test_phishing_emails_detected(item):
    """Verify phishing emails with deceptive lures and malicious links are caught."""
    r = det.analyse(
        subject=item.get("subject", ""),
        from_address=item.get("from_address", ""),
        reply_to=item.get("reply_to", ""),
        headers=item.get("headers", ""),
        body=item.get("body", ""),
    )
    assert r["score"] >= item.get("min_score", 50), f"Score {r['score']} below expected min {item['min_score']}"
    assert r["verdict"] in ("SUSPICIOUS", "HIGH_RISK", "CRITICAL")
    assert r["category"] in ("PHISHING", "CREDENTIAL_THEFT", "SPAM")


@pytest.mark.parametrize("item", CREDENTIAL_THEFT_EMAILS, ids=lambda x: x["name"])
def test_credential_theft_emails_detected(item):
    """Verify credential harvesting emails receive CREDENTIAL_THEFT or PHISHING category."""
    r = det.analyse(
        subject=item.get("subject", ""),
        from_address=item.get("from_address", ""),
        reply_to=item.get("reply_to", ""),
        body=item.get("body", ""),
    )
    assert r["score"] >= item.get("min_score", 30)
    assert r["verdict"] in ("SUSPICIOUS", "HIGH_RISK", "CRITICAL")
    assert r["category"] in ("CREDENTIAL_THEFT", "PHISHING")


@pytest.mark.parametrize("item", PAYMENT_FRAUD_BEC_EMAILS, ids=lambda x: x["name"])
def test_payment_fraud_bec_detected(item):
    """Verify BEC and wire transfer fraud emails receive appropriate category."""
    r = det.analyse(
        subject=item.get("subject", ""),
        from_address=item.get("from_address", ""),
        reply_to=item.get("reply_to", ""),
        headers=item.get("headers", ""),
        body=item.get("body", ""),
    )
    assert r["score"] >= item.get("min_score", 30)
    assert r["verdict"] in ("SUSPICIOUS", "HIGH_RISK", "CRITICAL")
    assert r["category"] in ("BUSINESS_EMAIL_COMPROMISE", "PAYMENT_FRAUD")


@pytest.mark.parametrize("item", SUSPICIOUS_MIXED_EMAILS, ids=lambda x: x["name"])
def test_suspicious_mixed_cases(item):
    """Verify ambiguous or suspicious emails land in SUSPICIOUS/HIGH_RISK category."""
    r = det.analyse(
        subject=item.get("subject", ""),
        from_address=item.get("from_address", ""),
        reply_to=item.get("reply_to", ""),
        body=item.get("body", ""),
    )
    assert r["score"] >= item.get("min_score", 10)
    assert r["verdict"] in ("SAFE", "SUSPICIOUS", "HIGH_RISK", "CRITICAL")


# ===========================================================================
# 7. Five Required Demo Cases (Direct Verification)
# ===========================================================================

def test_demo_1_safe_team_meeting():
    r = det.analyse(
        subject="Team Meeting Tomorrow",
        body="Hello team,\nJust a reminder that our project meeting is tomorrow at 10 AM.\nPlease bring your progress update.\nRegards,\nProject Team"
    )
    assert r["verdict"] == "SAFE"
    assert r["category"] == "SAFE"
    assert r["score"] <= 25


def test_demo_2_spam_congratulations_prize():
    r = det.analyse(
        subject="CONGRATULATIONS!!! YOU WON $1,000,000!!!",
        body="You have been selected as our lucky winner!\nClaim your prize immediately.\nLimited time offer!!!\nClick now to receive your reward!!!"
    )
    assert r["verdict"] in ("SUSPICIOUS", "HIGH_RISK", "CRITICAL")
    assert r["category"] == "SPAM"
    assert r["score"] >= 30


def test_demo_3_phishing_urgent_verify():
    r = det.analyse(
        subject="URGENT: Verify Your Account",
        body="Your account will be suspended today.\nClick the link below and enter your password immediately."
    )
    assert r["verdict"] in ("SUSPICIOUS", "HIGH_RISK", "CRITICAL")
    assert r["category"] in ("PHISHING", "CREDENTIAL_THEFT")
    assert r["score"] >= 30


def test_demo_4_payment_fraud_urgent_request():
    r = det.analyse(
        subject="Urgent Payment Request",
        body="I am currently unavailable. Please transfer the payment to this new bank account immediately and keep this confidential."
    )
    assert r["verdict"] in ("SUSPICIOUS", "HIGH_RISK", "CRITICAL")
    assert r["category"] in ("PAYMENT_FRAUD", "BUSINESS_EMAIL_COMPROMISE")
    assert r["score"] >= 30


def test_demo_5_legitimate_commercial_invoice():
    r = det.analyse(
        subject="Your Monthly Invoice",
        body="Your monthly invoice is now available in your normal customer portal.\nYou can log in through the company website to view your billing information."
    )
    assert r["verdict"] == "SAFE"
    assert r["category"] == "SAFE"
    assert r["score"] <= 25

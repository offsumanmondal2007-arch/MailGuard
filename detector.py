"""
detector.py — Explainable multi-signal heuristic threat and spam detection engine for MailGuard AI.

Scoring pillars (total 100 pts):
  1. Header Forensics      max 25
  2. Content Analysis      max 25
  3. URL Intelligence      max 20
  4. Behavioural Signals   max 15
  5. Heuristic ML layer    max 15

Verdict Thresholds:
  0–29   SAFE
  30–59  SUSPICIOUS
  60–79  HIGH_RISK
  80–100 CRITICAL

Categories:
  - SAFE
  - SPAM
  - PHISHING
  - CREDENTIAL_THEFT
  - PAYMENT_FRAUD
  - BUSINESS_EMAIL_COMPROMISE
  - EXECUTIVE_IMPERSONATION
  - SOCIAL_ENGINEERING

Transparency & Explainability Notice:
  This engine uses explainable rule-based heuristics, contextual signal analysis, and pattern matching.
  Every score contribution is accompanied by an explicit check name, result status, and evidence explanation.
  Adaptive normalization ensures accurate threat detection for full RFC 822 emails as well as text-only submissions.
"""

from __future__ import annotations
import re
import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse


# ===========================================================================
# Pattern Banks (Contextual & Multi-Signal)
# ===========================================================================

# Coercive urgency patterns (threat of lockout, penalties, tight deadlines)
URGENCY_PATTERNS = [
    r"\burgent(ly)?\b", r"\bimmediately\b", r"\bact now\b", r"\baction required\b",
    r"\bimmediate action\b", r"\bwithin 24 hours?\b", r"\bwithin 48 hours?\b",
    r"\bwithin 12 hours?\b", r"\bwithin \d+ hours?\b",
    r"\bdeadline\b", r"\btime.?sensitive\b", r"\basap\b", r"\bdo not delay\b",
    r"\bfinal (notice|warning|reminder|call)\b", r"\blast chance\b",
    r"\byour account (will be|has been) (suspended|terminated|disabled|deleted|restricted|locked|blocked)\b",
    r"\baccount (suspension|termination|restriction|locked|disabled)\b",
    r"\bfailure to (respond|comply|act|verify|update)\b",
    r"\bimmediate response\b", r"\bexpires (today|soon|within)\b",
    r"\baccount closure\b", r"\bunauthorized access detected\b",
]

# Credential solicitation patterns (soliciting passwords, credentials, login verification)
CREDENTIAL_PATTERNS = [
    r"\bverify your (account|identity|email|password|credentials|profile|wallet)\b",
    r"\bconfirm your (account|identity|email|password|credentials|pin)\b",
    r"\benter your (password|username|credentials|login|passcode|pin)\b",
    r"\bupdate your (password|credentials|login|account|security settings)\b",
    r"\bclick (here|the link below|below) to (log\s?in|sign\s?in|verify|confirm|activate|unlock|re.?authenticate|enter)\b",
    r"\byour (password|credential).{0,30}(expire|invalid|incorrect|reset|compromised)\b",
    r"\bsign\s?in to (verify|confirm|secure|protect|unlock|continue)\b",
    r"\bvalidate your (identity|account|credentials|email)\b",
    r"\bauthenticate\b.{0,30}(account|identity|email|device)\b",
    r"\breactivate your (account|membership|access)\b",
    r"\bunlock your account\b", r"\bsecurity checkpoint\b",
]

# Financial / wire redirection patterns
FINANCIAL_PATTERNS = [
    r"\bwire transfer\b", r"\bbank (account|details|transfer|routing)\b",
    r"\brouting number\b", r"\baccount number\b",
    r"\bpayment (required|needed|pending|processing|overdue|failed)\b",
    r"\bprocess (the )?payment\b", r"\btransfer the payment\b",
    r"\bpurchase order\b", r"\bremittance\b", r"\bfunds? transfer\b",
    r"\bnew (bank|payment|wire) (account|details|information)\b",
    r"\bchange (of )?bank (account|details)\b",
    r"\bupdated (bank|payment|wire) (account|details)\b",
    r"\bswift code\b", r"\biban\b", r"\btax refund\b",
]

# Unsolicited bulk promotional & advertising spam
SPAM_PROMOTIONAL_PATTERNS = [
    r"\bbuy 1 get 1\b", r"\bbuy one get one\b", r"\b100% free\b", r"\brisk.?free\b",
    r"\bmoney back guarantee\b", r"\blimited time (offer|deal|discount)\b",
    r"\bspecial (promotion|offer|discount)\b", r"\bexclusive (deal|invitation|access|discount)\b",
    r"\blowest price\b", r"\blowest rate\b", r"\bact now and save\b",
    r"\border today and (get|save)\b", r"\bearn extra (cash|income|money)\b",
    r"\bwork from home\b", r"\bmake money online\b", r"\bpassive income\b",
    r"\bno credit check\b", r"\bpre.?approved (loan|credit card|offer)\b",
    r"\bunclaimed (funds|money|reward)\b", r"\bcheap (meds|pills|viagra|cialis)\b",
    r"\bweight loss (supplement|formula|secret)\b", r"\bcasino (bonus|spins)\b",
    r"\bfree spins\b", r"\bopt.?out\b", r"\bunsubscribe (here|now)?\b",
    r"\bclick (here )?to (unsubscribe|opt out)\b", r"\bclearance sale\b",
    r"\bgiveaway entry\b", r"\bclaim your discount\b", r"\bsave up to \d+%\b",
    r"\bwhile supplies last\b", r"\bcall now\b", r"\btoll.?free number\b",
    r"\bclick now to receive\b", r"\bclaim your reward\b",
]

# Lottery, prize, and reward lures
LOTTERY_PRIZE_PATTERNS = [
    r"\byou (have )?won\b", r"\bcongratulations.?(you|winner|selected|chosen)\b",
    r"\blucky winner\b", r"\bsweepstakes (winner|entry|result)\b",
    r"\bclaim your (prize|reward|gift|winnings|payout)\b",
    r"\bcash prize\b", r"\blottery (ticket|jackpot|draw|winnings)\b",
    r"\bannual lottery\b", r"\bwinning notification\b",
    r"\bselected as the (lucky )?winner\b", r"\bselected recipient\b",
    r"\bwon \$?[\d,]+(,\d+)?\b", r"\bwon (one|two|five|ten) million\b",
    r"\bamazon gift card\b", r"\bwalmart (gift card|voucher)\b",
    r"\bapple gift card\b", r"\bclaim reward\b", r"\breward confirmation\b",
    r"\bfree gift card\b", r"\bexclusive winner\b",
]

# Tech support, auto-renewal, and refund scams
TECH_SUPPORT_REFUND_PATTERNS = [
    r"\bgeek squad\b", r"\bmcafee( total protection)?\b", r"\bnorton( 360)?\b",
    r"\bbest buy( support)?\b", r"\bwindows defender security\b",
    r"\bsubscription (auto.?)?renew(ed|al)?\b", r"\bcharged your (account|card|bank)\b",
    r"\bauto.debit(ed)?\b", r"\brefund department\b",
    r"\bif you did not (authorize|order|make|request) this\b",
    r"\bto cancel (this|the) (charge|subscription|order|service)\b",
    r"\bcall (us|our|customer support|helpline|desk|toll.?free) (at|on)?\b",
    r"\bremote access\b", r"\banydesk\b", r"\bteamviewer\b", r"\bultraviewer\b",
    r"\binfected with (virus|trojan|malware|spyware)\b",
    r"\bpc (compromised|infected|blocked)\b",
]

# Fake courier and package delivery scams
DELIVERY_SCAM_PATTERNS = [
    r"\busps\b", r"\bfedex\b", r"\bups (delivery|express|tracking)\b",
    r"\bdhl (express|delivery|tracking)\b", r"\broyal mail\b", r"\bpostal service\b",
    r"\bdelivery (failed|attempt|pending|exception|suspended|delayed)\b",
    r"\bmissed (delivery|parcel|package)\b", r"\bparcel (tracking|held|delivery|shipment)\b",
    r"\bcustoms (fee|duty|clearance|charge)\b",
    r"\bredelivery (fee|charge|request|schedule)\b",
    r"\bschedule (a )?redelivery\b", r"\bupdate (your )?(delivery )?address\b",
    r"\bpackage (held|pending|undelivered|at warehouse)\b",
]

# Crypto, airdrop, and wallet scams
CRYPTO_SCAM_PATTERNS = [
    r"\bbitcoin\b", r"\bethereum\b", r"\busdt\b", r"\bbtc wallet\b",
    r"\bblockchain wallet\b", r"\bmetamask\b", r"\btrust wallet\b",
    r"\bbinance\b", r"\bcoinbase\b", r"\bairdrop\b", r"\bclaim (your )?tokens?\b",
    r"\bseed phrase\b", r"\bprivate key\b", r"\bcrypto doubling\b",
    r"\bsend btc to receive\b", r"\binvest( in)? (cryptocurrency|crypto|bitcoin)\b",
    r"\bguaranteed (crypto |daily )?return\b", r"\bconnect your wallet\b",
]

# Advance fee 419, inheritance, and diplomat scams
ADVANCE_FEE_419_PATTERNS = [
    r"\bnext of kin\b", r"\bdeceased (client|customer|relative|father|husband)\b",
    r"\bdormant account\b", r"\bforeign beneficiary\b", r"\bconsignment box\b",
    r"\bdiplomatic (courier|delivery|agent)\b", r"\bbarrister\b", r"\battorney general\b",
    r"\bcompensation fund\b", r"\bunited nations compensation\b", r"\bworld bank (fund|grant)\b",
    r"\btransfer of \$?[\d,]+(,\d+)?\b", r"\bsum of \$?[\d,]+(,\d+)?\b",
    r"\bconfidential (business )?proposal\b", r"\blate (husband|father|mother|benefactor)\b",
]

# Extortion, blackmail, and sextortion
EXTORTION_SEXTORTION_PATTERNS = [
    r"\brecorded you\b", r"\bwebcam video\b", r"\bwatching you through\b",
    r"\bhacked your (device|operating system|computer|phone|camera)\b",
    r"\binstalled (a )?(trojan|malware|pegasus|spyware)\b",
    r"\bdirty secrets\b", r"\bsend (bitcoin|btc) to (this|the) (address|wallet)\b",
    r"\brelease (this |the video )?to (all )?your contacts\b",
    r"\bpay in bitcoin\b", r"\badult (websites|content|videos)\b",
]

# Job & check fraud scams
JOB_SCAM_PATTERNS = [
    r"\bwork from home job\b", r"\bearn \$?\d+[\-\s]?\$?\d* (daily|per day|hourly|weekly)\b",
    r"\bpart.?time data entry\b", r"\bno experience (needed|required|necessary)\b",
    r"\bpayment processing (agent|assistant|manager)\b", r"\bmystery shopper\b",
    r"\bwe will send you a check\b", r"\bdeposit the check\b",
]

# Social engineering confidentiality / secrecy pressure
SOCIAL_ENGINEERING_PATTERNS = [
    r"\bkeep this (confidential|secret|between us)\b",
    r"\bdo not (share|forward|disclose|mention) this\b",
    r"\bconfidential(ly)?\b.{0,40}(request|matter|information)\b",
    r"\bthis email is (strictly )?confidential\b",
    r"\bdo not discuss\b",
    r"\bplease keep (this )?(private|between us|confidential)\b",
    r"\btreat this with (utmost|high) urgency\b",
    r"\bi am in a (board )?meeting\b",
]

# Executive authority impersonation
EXECUTIVE_IMPERSONATION_PATTERNS = [
    r"\b(ceo|cfo|coo|cto|president|vice.?president|vp|managing director|md|board|director)\b",
    r"\b(chief (executive|financial|operating|technology) officer)\b",
    r"\b(executive|senior) (management|leadership|team)\b",
]

# Sensitive PII solicitation
SENSITIVE_INFO_PATTERNS = [
    r"\bsocial security (number|no\.?)\b", r"\bssn\b",
    r"\bcredit card (number|no\.?|details|cvv|cvc)\b",
    r"\bdate of birth\b", r"\bdob\b",
    r"\bpassport (number|no\.?)\b",
    r"\bdriver.?s? licen[sc]e\b",
    r"\btax (id|identification|number)\b",
    r"\bone.?time password\b", r"\botp\b", r"\bsecurity pin\b",
]

# High-risk TLDs
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",
    ".xyz", ".top", ".click", ".download",
    ".loan", ".work", ".date", ".review", ".stream",
    ".accountant", ".faith", ".racing", ".win",
    ".online", ".site", ".space", ".monster", ".icu",
    ".buzz", ".cam", ".live", ".shop", ".vip", ".bid",
    ".club", ".surf", ".rest", ".fit", ".bar",
}

SHORTENED_URL_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "shorte.st", "clck.ru",
    "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "linktr.ee",
}

TRUSTED_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "paypal.com", "facebook.com", "twitter.com", "linkedin.com",
    "github.com", "outlook.com", "gmail.com", "yahoo.com",
    "dropbox.com", "salesforce.com", "adobe.com", "zoom.us",
    "netflix.com", "ebay.com", "chase.com", "bankofamerica.com",
    "wellsfargo.com", "usps.com", "fedex.com", "ups.com", "dhl.com",
}

FREE_WEBMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "aol.com", "protonmail.com", "proton.me", "yandex.com",
    "mail.com", "gmx.com", "zoho.com", "icloud.com",
}

SUSPICIOUS_DOMAIN_KEYWORDS = [
    "secure", "login", "verify", "account", "update", "banking",
    "paypal", "apple", "microsoft", "google", "amazon", "support",
    "helpdesk", "admin", "webmail", "portal", "signin", "validate",
    "redelivery", "tracking", "package", "invoice", "refund", "claim",
    "wallet", "reward", "winner",
]

LOOKALIKE_MAP = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
    "@": "a", "!": "i", "rn": "m", "vv": "w",
}

VERDICT_THRESHOLDS = [
    (80, "CRITICAL"),
    (60, "HIGH_RISK"),
    (30, "SUSPICIOUS"),
    (0,  "SAFE"),
]

RECOMMENDED_ACTIONS = {
    "CRITICAL": (
        "⚠ CRITICAL THREAT — Quarantine immediately. "
        "Block sender and sending domain. "
        "Reset any potentially compromised credentials. "
        "Investigate related emails in the thread. "
        "Report to your security team / SOC."
    ),
    "HIGH_RISK": (
        "🔴 HIGH RISK — Do NOT interact with links, attachments, or phone numbers. "
        "Mark as phishing/spam and report to IT Security. "
        "Block sender domain in email gateway. "
        "Warn affected users."
    ),
    "SUSPICIOUS": (
        "🟡 SUSPICIOUS — Exercise caution before responding or opening links. "
        "Verify sender identity through an independent channel. "
        "Do not provide sensitive data or credentials. "
        "Flag for analyst review."
    ),
    "SAFE": (
        "✅ SAFE — No significant threat or spam indicators detected. "
        "Standard email hygiene applies. "
        "Remain vigilant and report anything unusual."
    ),
}


# ===========================================================================
# Data Structures
# ===========================================================================

@dataclass
class CheckResult:
    name:   str
    result: str   # pass | fail | warn | info
    detail: str
    points: int = 0


@dataclass
class PillarResult:
    score: int
    max:   int
    checks: List[CheckResult] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score":  self.score,
            "max":    self.max,
            "checks": [
                {"name": c.name, "result": c.result, "detail": c.detail}
                for c in self.checks
            ],
        }


# ===========================================================================
# Helper Functions
# ===========================================================================

def _extract_domain(address: str) -> str:
    """Extract domain from an email address or return empty string."""
    address = (address or "").strip().lower()
    m = re.search(r"<([^>]+)>", address)
    if m:
        address = m.group(1)
    if "@" in address:
        return address.split("@", 1)[1].strip()
    return ""


def _extract_display_name(address: str) -> str:
    """Extract display name from 'Name <email>' or return empty string."""
    address = (address or "").strip()
    m = re.match(r'^"?([^"<]+)"?\s*<', address)
    if m:
        return m.group(1).strip()
    return ""


def _extract_urls(text: str) -> List[str]:
    """Extract all URLs from text."""
    url_re = re.compile(
        r"https?://[^\s\"'<>)\]]+|"
        r"www\.[^\s\"'<>)\]]+"
    )
    return url_re.findall(text or "")


def _is_ip_url(url: str) -> bool:
    try:
        host = urlparse(url).hostname or ""
        return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host))
    except Exception:
        return False


def _is_shortened(url: str) -> bool:
    try:
        host = urlparse(url).hostname or ""
        host = host.lower().lstrip("www.")
        return host in SHORTENED_URL_DOMAINS
    except Exception:
        return False


def _has_suspicious_tld(url: str) -> bool:
    try:
        host = urlparse(url).hostname or ""
        for tld in SUSPICIOUS_TLDS:
            if host.endswith(tld):
                return True
    except Exception:
        pass
    return False


def _normalise_domain(domain: str) -> str:
    d = domain.lower()
    for fake, real in LOOKALIKE_MAP.items():
        d = d.replace(fake, real)
    return d


def _is_typosquatting(domain: str) -> Optional[str]:
    norm = _normalise_domain(domain)
    for trusted in TRUSTED_DOMAINS:
        t_base = trusted.rsplit(".", 1)[0]
        if t_base in norm and domain not in TRUSTED_DOMAINS:
            return trusted
    return None


def _match_patterns(text: str, patterns: List[str]) -> List[str]:
    text = (text or "").lower()
    matched = []
    for p in patterns:
        if re.search(p, text, re.IGNORECASE):
            matched.append(p)
    return matched


def _count_matches(text: str, patterns: List[str]) -> int:
    return len(_match_patterns(text, patterns))


def _parse_auth_result(header_text: str, keyword: str) -> str:
    pattern = rf"{keyword}[=:\s]+(\w+)"
    m = re.search(pattern, header_text, re.IGNORECASE)
    if m:
        result = m.group(1).lower()
        if result in ("pass",):
            return "pass"
        if result in ("fail", "failure", "hardfail"):
            return "fail"
        if result in ("softfail", "neutral", "none"):
            return "softfail"
    return "unknown"


def _count_received_hops(header_text: str) -> int:
    return len(re.findall(r"^Received:", header_text or "", re.MULTILINE))


def _cap(value: int, maximum: int) -> int:
    return min(value, maximum)


# ===========================================================================
# Five Scoring Pillars
# ===========================================================================

def _header_forensics(
    from_addr: str,
    reply_to: str,
    headers: str,
    sender_ip: str,
) -> Tuple[PillarResult, Dict[str, Any]]:
    """
    Pillar 1 — Header Forensics (max 25 pts).
    """
    MAX = 25
    score = 0
    checks: List[CheckResult] = []

    from_domain = _extract_domain(from_addr)
    rt_domain   = _extract_domain(reply_to)
    display_name = _extract_display_name(from_addr)

    forensics: Dict[str, Any] = {
        "from_domain":           from_domain,
        "reply_to_domain":       rt_domain,
        "domain_mismatch":       False,
        "spf":                   "unknown",
        "dkim":                  "unknown",
        "dmarc":                 "unknown",
        "display_name":          display_name,
        "display_name_spoofing": False,
        "received_hops":         0,
        "typosquatting":         False,
        "suspicious_tld":        False,
        "urls_found":            [],
        "suspicious_urls":       [],
    }

    # 1. Reply-To domain mismatch
    if from_domain and rt_domain and from_domain != rt_domain:
        pts = 9
        score += pts
        checks.append(CheckResult(
            "Reply-To Domain Mismatch",
            "fail",
            f"From domain [{from_domain}] differs from Reply-To domain [{rt_domain}]. "
            "Tactique to redirect replies to attacker inbox.",
            pts,
        ))
        forensics["domain_mismatch"] = True
    elif rt_domain:
        checks.append(CheckResult("Reply-To Domain Mismatch", "pass", f"Reply-To matches From domain [{from_domain}].", 0))

    # 2. Display-name spoofing & Free webmail impersonation
    if display_name and from_domain:
        dn_lower = display_name.lower()
        brand_keywords = [t.rsplit(".", 1)[0] for t in TRUSTED_DOMAINS] + [
            "geek squad", "mcafee", "norton", "security team", "it support",
            "customer support", "accounting", "ceo", "director", "helpdesk",
        ]
        is_spoofing = False
        for brand in brand_keywords:
            if brand in dn_lower and brand not in from_domain:
                pts = 8
                score += pts
                checks.append(CheckResult(
                    "Display-Name Spoofing",
                    "fail",
                    f"Display name '{display_name}' impersonates brand/entity '{brand}', "
                    f"but sending domain is '{from_domain}'.",
                    pts,
                ))
                forensics["display_name_spoofing"] = True
                is_spoofing = True
                break

        if not is_spoofing and from_domain in FREE_WEBMAIL_DOMAINS:
            if any(k in dn_lower for k in ["support", "service", "team", "security", "official", "billing", "desk"]):
                pts = 6
                score += pts
                checks.append(CheckResult(
                    "Free Webmail Impersonation",
                    "fail",
                    f"Commercial entity '{display_name}' sent from free webmail '{from_domain}'.",
                    pts,
                ))
                is_spoofing = True

        if not is_spoofing:
            checks.append(CheckResult("Display-Name Spoofing", "pass", "Display name does not impersonate a known brand.", 0))

    # 3. Suspicious sender TLD
    if from_domain:
        for tld in SUSPICIOUS_TLDS:
            if from_domain.endswith(tld):
                pts = 5
                score += pts
                checks.append(CheckResult(
                    "Suspicious Sender TLD",
                    "warn",
                    f"Sender domain '{from_domain}' uses high-abuse TLD '{tld}'.",
                    pts,
                ))
                forensics["suspicious_tld"] = True
                break
        else:
            checks.append(CheckResult("Suspicious Sender TLD", "pass", "Sender TLD appears normal.", 0))

    # 4. Typosquatting / Lookalike domain
    if from_domain:
        impersonated = _is_typosquatting(from_domain)
        if impersonated:
            pts = 6
            score += pts
            checks.append(CheckResult(
                "Typosquatting / Lookalike Domain",
                "fail",
                f"Sender domain '{from_domain}' appears to be a lookalike of '{impersonated}'.",
                pts,
            ))
            forensics["typosquatting"] = True
        else:
            checks.append(CheckResult("Typosquatting / Lookalike Domain", "pass", "Domain is not a known lookalike.", 0))

    # 5. SPF / DKIM / DMARC authentication
    if headers:
        spf   = _parse_auth_result(headers, "spf")
        dkim  = _parse_auth_result(headers, "dkim")
        dmarc = _parse_auth_result(headers, "dmarc")

        forensics["spf"]   = spf
        forensics["dkim"]  = dkim
        forensics["dmarc"] = dmarc

        if spf in ("fail", "softfail"):
            pts = 4
            score += pts
            checks.append(CheckResult(
                "SPF Authentication",
                "fail" if spf == "fail" else "warn",
                f"SPF result is '{spf}'. Sending server is unauthenticated for domain.",
                pts,
            ))
        elif spf == "pass":
            checks.append(CheckResult("SPF Authentication", "pass", "SPF check passed.", 0))

        if dkim in ("fail",):
            pts = 3
            score += pts
            checks.append(CheckResult(
                "DKIM Signature",
                "fail",
                "DKIM signature verification failed. Message may have been altered.",
                pts,
            ))
        elif dkim == "pass":
            checks.append(CheckResult("DKIM Signature", "pass", "DKIM signature verified.", 0))

        if dmarc in ("fail",):
            pts = 3
            score += pts
            checks.append(CheckResult(
                "DMARC Policy",
                "fail",
                "DMARC policy check failed. Domain alignment not satisfied.",
                pts,
            ))
        elif dmarc == "pass":
            checks.append(CheckResult("DMARC Policy", "pass", "DMARC policy satisfied.", 0))

        hops = _count_received_hops(headers)
        forensics["received_hops"] = hops
        checks.append(CheckResult("Mail Relay Hops", "info", f"{hops} 'Received:' header(s) found.", 0))

    score = _cap(score, MAX)
    return PillarResult(score, MAX, checks), forensics


def _content_analysis(subject: str, body: str) -> Tuple[PillarResult, List[str]]:
    """
    Pillar 2 — Content Analysis (max 25 pts).
    Contextual, explainable threat and spam signal evaluation.
    """
    MAX = 25
    score = 0
    checks: List[CheckResult] = []
    reasons: List[str] = []
    full_text = f"{subject or ''} {body or ''}".strip()

    if not full_text:
        checks.append(CheckResult("Content Analysis", "info", "No text content provided.", 0))
        return PillarResult(0, MAX, checks), reasons

    # 1. Prize / Sweepstakes / Lottery scam
    lottery_hits = _count_matches(full_text, LOTTERY_PRIZE_PATTERNS)
    if lottery_hits >= 2:
        pts = 10
        score += pts
        checks.append(CheckResult("Lottery / Prize Scam", "fail", f"Lottery/Prize scam indicators detected ({lottery_hits} matches).", pts))
        reasons.append("Lottery/Prize scam lure — informs recipient they won money or rewards without entering")
    elif lottery_hits == 1:
        pts = 6
        score += pts
        checks.append(CheckResult("Lottery / Prize Scam", "warn", "Prize/reward solicitation pattern detected.", pts))
        reasons.append("Prize or reward winning pattern detected")

    # 2. Tech support / fake subscription invoice refund scam
    tech_hits = _count_matches(full_text, TECH_SUPPORT_REFUND_PATTERNS)
    if tech_hits >= 2:
        pts = 10
        score += pts
        checks.append(CheckResult("Tech Support / Fake Invoice Scam", "fail", f"Tech support refund/auto-renewal scam patterns detected ({tech_hits} matches).", pts))
        reasons.append("Fake invoice / Tech support refund scam — uses fake charge notice to induce phone contact")
    elif tech_hits == 1:
        pts = 6
        score += pts
        checks.append(CheckResult("Tech Support / Fake Invoice Scam", "warn", "Subscription auto-renewal or refund pattern detected.", pts))
        reasons.append("Subscription charge / refund solicitation detected")

    # 3. Credential harvesting solicitation
    cred_hits = _count_matches(full_text, CREDENTIAL_PATTERNS)
    if cred_hits >= 2:
        pts = 10
        score += pts
        checks.append(CheckResult("Credential Solicitation", "fail", f"Multiple credential harvesting patterns ({cred_hits} matches).", pts))
        reasons.append("Email solicits account login, password, or security credentials")
    elif cred_hits == 1:
        pts = 7
        score += pts
        checks.append(CheckResult("Credential Solicitation", "fail", "Direct request to enter credentials or verify password.", pts))
        reasons.append("Credential-related verification or password entry request detected")

    # 4. Package delivery phishing
    deliv_hits = _count_matches(full_text, DELIVERY_SCAM_PATTERNS)
    if deliv_hits >= 2:
        pts = 9
        score += pts
        checks.append(CheckResult("Package Delivery Scam", "fail", f"Delivery/courier phishing patterns detected ({deliv_hits} matches).", pts))
        reasons.append("Package delivery phishing — fake courier notification requesting redelivery fee/action")
    elif deliv_hits == 1:
        pts = 5
        score += pts
        checks.append(CheckResult("Package Delivery Scam", "warn", "Postal/delivery notice pattern detected.", pts))

    # 5. Cryptocurrency scam
    crypto_hits = _count_matches(full_text, CRYPTO_SCAM_PATTERNS)
    if crypto_hits >= 2:
        pts = 9
        score += pts
        checks.append(CheckResult("Cryptocurrency Scam", "fail", f"Crypto scam/wallet solicitation patterns detected ({crypto_hits} matches).", pts))
        reasons.append("Cryptocurrency / Wallet phishing solicitation detected")
    elif crypto_hits == 1:
        pts = 5
        score += pts
        checks.append(CheckResult("Cryptocurrency Scam", "warn", "Cryptocurrency transaction patterns detected.", pts))

    # 6. Advance-fee 419 / Inheritance fraud
    aff_hits = _count_matches(full_text, ADVANCE_FEE_419_PATTERNS)
    if aff_hits >= 2:
        pts = 10
        score += pts
        checks.append(CheckResult("Advance-Fee 419 Scam", "fail", f"Advance-fee/Inheritance fraud indicators detected ({aff_hits} matches).", pts))
        reasons.append("Advance-Fee Fraud / Inheritance scam — promise of large payout in exchange for fees/contact")
    elif aff_hits == 1:
        pts = 6
        score += pts
        checks.append(CheckResult("Advance-Fee 419 Scam", "warn", "Inheritance/beneficiary transfer pattern detected.", pts))

    # 7. Extortion / Blackmail
    extort_hits = _count_matches(full_text, EXTORTION_SEXTORTION_PATTERNS)
    if extort_hits >= 1:
        pts = 10
        score += pts
        checks.append(CheckResult("Extortion / Blackmail", "fail", f"Extortion/Blackmail threat detected ({extort_hits} matches).", pts))
        reasons.append("Extortion / Blackmail attempt detected — demands ransom/bitcoin")

    # 8. Promotional / Bulk marketing spam
    spam_hits = _count_matches(full_text, SPAM_PROMOTIONAL_PATTERNS)
    if spam_hits >= 3:
        pts = 8
        score += pts
        checks.append(CheckResult("Promotional Spam Patterns", "fail", f"High volume of promotional spam terms ({spam_hits} matches).", pts))
        reasons.append("Unsolicited bulk marketing / promotional spam keywords detected")
    elif spam_hits >= 1:
        pts = 4
        score += pts
        checks.append(CheckResult("Promotional Spam Patterns", "warn", f"Promotional keywords detected ({spam_hits} match(es)).", pts))
        reasons.append("Marketing/promotional language detected")

    # 9. Coercive Urgency & Account Threat
    urgency_hits = _count_matches(full_text, URGENCY_PATTERNS)
    if urgency_hits >= 2:
        pts = 7
        score += pts
        checks.append(CheckResult("Urgency Pressure", "fail", f"High urgency / coercive deadlines ({urgency_hits} patterns).", pts))
        reasons.append("Artificial urgency pressure detected (tight deadlines / threat of termination)")
    elif urgency_hits == 1:
        pts = 4
        score += pts
        checks.append(CheckResult("Urgency Pressure", "warn", "Urgency language detected.", pts))
        reasons.append("Urgency language detected in email content")

    # 10. Financial / Payment content
    fin_hits = _count_matches(full_text, FINANCIAL_PATTERNS)
    if fin_hits >= 2:
        pts = 6
        score += pts
        checks.append(CheckResult("Financial Content", "fail", f"Multiple payment/financial patterns ({fin_hits} matches).", pts))
        reasons.append("Financial transaction / payment transfer details detected")
    elif fin_hits == 1:
        pts = 3
        score += pts
        checks.append(CheckResult("Financial Content", "warn", "Financial/payment language detected.", pts))

    # 11. Sensitive PII request
    sens_hits = _count_matches(full_text, SENSITIVE_INFO_PATTERNS)
    if sens_hits >= 1:
        pts = 7
        score += pts
        checks.append(CheckResult("Sensitive Info Request", "fail", "Solicitation of sensitive PII (SSN, credit card, PIN, etc.).", pts))
        reasons.append("Requests sensitive personal identifiable information (SSN, banking info, card numbers)")

    # 12. Stylistic formatting signals (ALL CAPS and excessive punctuation)
    words = full_text.split()
    if len(words) >= 4:
        caps_words = [w for w in words if w.isupper() and len(w) > 1 and w.isalpha()]
        caps_ratio = len(caps_words) / len(words)
        if caps_ratio > 0.35:
            pts = 4
            score += pts
            checks.append(CheckResult("Excessive ALL CAPS", "warn", f"Excessive capitalization ({caps_ratio:.0%} of words are ALL CAPS).", pts))
            reasons.append("Excessive uppercase lettering — common in aggressive spam/phishing campaigns")

    excl_count = full_text.count("!") + full_text.count("?") + full_text.count("$$$")
    if excl_count >= 4:
        pts = 3
        score += pts
        checks.append(CheckResult("Aggressive Punctuation", "warn", f"Spammy punctuation detected ({excl_count} excessive symbols).", pts))

    score = _cap(score, MAX)
    return PillarResult(score, MAX, checks), reasons


def _url_intelligence(body: str, subject: str) -> Tuple[PillarResult, List[str], List[str]]:
    """
    Pillar 3 — URL Intelligence (max 20 pts).
    """
    MAX = 20
    score = 0
    checks: List[CheckResult] = []
    full_text = f"{subject or ''} {body or ''}"
    urls = _extract_urls(full_text)
    suspicious_urls: List[str] = []

    if not urls:
        checks.append(CheckResult("URL Presence", "info", "No URLs found in the email.", 0))
        return PillarResult(0, MAX, checks), urls, suspicious_urls

    checks.append(CheckResult("URL Presence", "info", f"{len(urls)} URL(s) found in email.", 0))

    ip_urls    = [u for u in urls if _is_ip_url(u)]
    short_urls = [u for u in urls if _is_shortened(u)]
    bad_tld    = [u for u in urls if _has_suspicious_tld(u)]

    if ip_urls:
        pts = 7
        score += pts
        suspicious_urls.extend(ip_urls)
        checks.append(CheckResult("IP-Based URLs", "fail", f"{len(ip_urls)} URL(s) use raw IP addresses: {', '.join(ip_urls[:3])}", pts))

    if short_urls:
        pts = 4
        score += pts
        suspicious_urls.extend(short_urls)
        checks.append(CheckResult("Shortened URLs", "warn", f"{len(short_urls)} shortened URL(s) detected: {', '.join(short_urls[:3])}", pts))

    if bad_tld:
        pts = 5
        score += pts
        suspicious_urls.extend(bad_tld)
        checks.append(CheckResult("Suspicious URL TLD", "fail", f"{len(bad_tld)} URL(s) use high-risk TLDs: {', '.join(bad_tld[:3])}", pts))

    typo_urls = []
    for u in urls:
        try:
            host = urlparse(u).hostname or ""
            impersonated = _is_typosquatting(host)
            if impersonated:
                typo_urls.append((u, impersonated))
        except Exception:
            pass

    if typo_urls:
        pts = 7
        score += pts
        suspicious_urls.extend([t[0] for t in typo_urls])
        checks.append(CheckResult("Lookalike / Typosquatting URLs", "fail", f"{len(typo_urls)} URL(s) impersonate trusted domains: {typo_urls[0][0]} -> {typo_urls[0][1]}", pts))

    kw_abuse_urls = []
    for u in urls:
        u_lower = u.lower()
        if any(k in u_lower for k in SUSPICIOUS_DOMAIN_KEYWORDS):
            try:
                host = urlparse(u).hostname or ""
                if host not in TRUSTED_DOMAINS:
                    kw_abuse_urls.append(u)
            except Exception:
                pass

    if kw_abuse_urls:
        pts = 5
        score += pts
        suspicious_urls.extend(kw_abuse_urls)
        checks.append(CheckResult("Suspicious URL Keywords", "warn", f"{len(kw_abuse_urls)} URL(s) contain security/login/reward keywords on untrusted hosts.", pts))

    obf_urls = [u for u in urls if "%" in u or "redirect" in u.lower() or "url=" in u.lower() or "link=" in u.lower()]
    if obf_urls:
        pts = 4
        score += pts
        suspicious_urls.extend(obf_urls)
        checks.append(CheckResult("URL Obfuscation / Redirect", "warn", f"{len(obf_urls)} URL(s) use redirect parameters or percent-encoding.", pts))

    if not suspicious_urls:
        checks.append(CheckResult("URL Safety", "pass", "No obviously malicious URLs detected.", 0))

    score = _cap(score, MAX)
    seen = set()
    deduped = []
    for u in suspicious_urls:
        if u not in seen:
            seen.add(u)
            deduped.append(u)

    return PillarResult(score, MAX, checks), list(dict.fromkeys(urls)), deduped


def _behavioural_signals(
    from_addr: str,
    reply_to: str,
    subject: str,
    body: str,
    headers: str,
) -> Tuple[PillarResult, List[str]]:
    """
    Pillar 4 — Behavioural Signals (max 15 pts).
    """
    MAX = 15
    score = 0
    checks: List[CheckResult] = []
    reasons: List[str] = []
    full_text = f"{subject or ''} {body or ''} {from_addr or ''}"

    # 1. New bank account request (BEC)
    new_bank = _count_matches(body or "", [
        r"\bnew (bank|payment|wire) (account|details|information)\b",
        r"\bchange (of )?bank (account|details)\b",
        r"\bupdated (bank|payment|wire) (account|details)\b",
        r"\bplease (use|transfer (to )?)(the )?new (account|bank|wire)\b",
        r"\btransfer the payment to this new bank account\b",
    ])
    if new_bank:
        pts = 7
        score += pts
        checks.append(CheckResult(
            "New Bank Account Request",
            "fail",
            "Email requests redirection of payment to a new or changed bank account (primary BEC indicator).",
            pts,
        ))
        reasons.append("Request to redirect payment to new/changed bank account — BEC fraud indicator")

    # 2. Executive impersonation / Whaling
    exec_hits = _count_matches(full_text, EXECUTIVE_IMPERSONATION_PATTERNS)
    if exec_hits:
        pts = 5
        score += pts
        checks.append(CheckResult(
            "Executive Impersonation",
            "warn",
            "Email references executive authority (CEO/MD/President) to demand compliance.",
            pts,
        ))
        reasons.append("Executive role referenced — potential whaling or executive impersonation")

    # 3. Confidentiality / Secrecy pressure
    conf_hits = _count_matches(full_text, SOCIAL_ENGINEERING_PATTERNS)
    if conf_hits:
        pts = 5
        score += pts
        checks.append(CheckResult(
            "Confidentiality Pressure",
            "warn",
            "Email instructs recipient not to discuss or disclose this request.",
            pts,
        ))
        reasons.append("Social engineering secrecy pressure — recipient instructed to keep matter confidential")

    # 4. Missing To: header
    if headers and "To:" not in headers and "to:" not in headers.lower():
        pts = 3
        score += pts
        checks.append(CheckResult("Missing To: Header", "warn", "No 'To:' header found in headers (possible mass BCC distribution).", pts))
        reasons.append("Missing To: header — mass distribution indicator")

    score = _cap(score, MAX)
    return PillarResult(score, MAX, checks), reasons


def _ml_heuristic_layer(
    p1: PillarResult,
    p2: PillarResult,
    p3: PillarResult,
    p4: PillarResult,
    has_headers: bool = True,
) -> PillarResult:
    """
    Pillar 5 — Heuristic ML-equivalent layer (max 15 pts).
    Adaptive weighted normalization across active signals.
    """
    MAX = 15
    checks: List[CheckResult] = []

    n1 = p1.score / p1.max if p1.max else 0
    n2 = p2.score / p2.max if p2.max else 0
    n3 = p3.score / p3.max if p3.max else 0
    n4 = p4.score / p4.max if p4.max else 0

    if has_headers:
        weights = [0.30, 0.30, 0.25, 0.15]
        weighted_avg = sum(w * n for w, n in zip(weights, [n1, n2, n3, n4]))
    else:
        weights = [0.55, 0.30, 0.15]
        weighted_avg = sum(w * n for w, n in zip(weights, [n2, n3, n4]))

    # Multi-signal corroboration boost
    active_highs = sum(1 for n in [n2, n3, n4] if n > 0.4)
    if active_highs >= 2:
        weighted_avg = min(1.0, weighted_avg * 1.35)
    elif max(n2, n3, n4) > 0.6:
        weighted_avg = min(1.0, weighted_avg * 1.20)

    raw_score = round(weighted_avg * MAX)

    checks.append(CheckResult(
        "Heuristic Signal Analysis",
        "fail" if raw_score >= 10 else ("warn" if raw_score >= 5 else "pass"),
        (
            f"Multi-pillar corroborated signal analysis: "
            f"Header={n1:.0%}, Content={n2:.0%}, URL={n3:.0%}, Behaviour={n4:.0%}. "
            f"Corroborated heuristic score: {raw_score}/{MAX}."
        ),
        raw_score,
    ))

    return PillarResult(raw_score, MAX, checks)


# ===========================================================================
# Category Determination
# ===========================================================================

def _determine_category(
    p1: PillarResult,
    p2: PillarResult,
    p3: PillarResult,
    p4: PillarResult,
    full_text: str,
    total_score: int,
) -> str:
    """
    Determine the primary threat or communication category.
    Priority hierarchy ensures clear separation between spam, phishing, and BEC.
    """
    if total_score < 30:
        return "SAFE"

    text = full_text.lower()

    has_extort      = _count_matches(text, EXTORTION_SEXTORTION_PATTERNS) >= 1
    has_tech_supp   = _count_matches(text, TECH_SUPPORT_REFUND_PATTERNS) >= 1
    has_lottery     = _count_matches(text, LOTTERY_PRIZE_PATTERNS) >= 1
    has_deliv       = _count_matches(text, DELIVERY_SCAM_PATTERNS) >= 1
    has_crypto      = _count_matches(text, CRYPTO_SCAM_PATTERNS) >= 1
    has_419         = _count_matches(text, ADVANCE_FEE_419_PATTERNS) >= 1
    has_job         = _count_matches(text, JOB_SCAM_PATTERNS) >= 1
    has_spam        = _count_matches(text, SPAM_PROMOTIONAL_PATTERNS) >= 1
    has_credential  = _count_matches(text, CREDENTIAL_PATTERNS) >= 1
    has_financial   = _count_matches(text, FINANCIAL_PATTERNS) >= 1 or "transfer" in text or "payment" in text
    has_executive   = _count_matches(text, EXECUTIVE_IMPERSONATION_PATTERNS) >= 1
    has_new_bank    = _count_matches(text, [r"\bnew (bank|account|payment|wire)\b", r"\bchange (of )?bank\b"]) >= 1
    has_sensitive   = _count_matches(text, SENSITIVE_INFO_PATTERNS) >= 1
    has_conf        = _count_matches(text, SOCIAL_ENGINEERING_PATTERNS) >= 1
    has_urgency     = _count_matches(text, URGENCY_PATTERNS) >= 1

    # Count how many lottery/prize and spam signals matched.
    lottery_count   = _count_matches(text, LOTTERY_PRIZE_PATTERNS)
    spam_prom_count = _count_matches(text, SPAM_PROMOTIONAL_PATTERNS)

    # An email is "clearly spam" if it has multiple lottery/prize hits OR combined
    # lottery + promotional signals. These should NOT be classified as PHISHING
    # just because they also happen to contain urgency language and a suspicious URL.
    is_clearly_spam = (
        lottery_count >= 2
        or spam_prom_count >= 3
        or (has_lottery and has_spam)
        or (has_lottery and spam_prom_count >= 1)
    )

    # 1. Business Email Compromise (Executive + Payment/New bank/Confidentiality)
    if (has_new_bank and has_executive) or (has_financial and has_executive and has_conf):
        return "BUSINESS_EMAIL_COMPROMISE"

    # 2. Payment Fraud / Bank redirection
    if has_new_bank or (
        has_financial and (has_conf or has_urgency)
        and not has_credential
        and not is_clearly_spam
    ):
        return "PAYMENT_FRAUD"

    # 3. Credential Theft (Explicit password/login/credentials solicitation)
    if has_credential and (
        has_sensitive
        or "enter your password" in text
        or "credentials" in text
        or "enter your" in text
    ):
        return "CREDENTIAL_THEFT"

    # 4. Spam & Scams — checked BEFORE generic phishing to prevent misclassification.
    #    Lottery/prize/promotional/tech-support/delivery/crypto/419 scams are SPAM,
    #    not PHISHING, unless they ALSO actively solicit login credentials.
    if is_clearly_spam and not has_credential:
        return "SPAM"
    if (
        has_lottery or has_spam or has_tech_supp
        or has_deliv or has_crypto or has_419 or has_job
    ) and not has_credential:
        return "SPAM"

    # 5. Phishing — requires credential solicitation OR account-threat language.
    #    Plain urgency + suspicious URL is NOT enough if the email is clearly promotional.
    phishing_account_threat = (
        "account" in text
        and ("suspend" in text or "disabled" in text or "verify" in text
             or "terminated" in text or "locked" in text)
    )
    phishing_cred_and_url = has_credential and p3.score >= 5
    if has_credential or phishing_account_threat or phishing_cred_and_url:
        return "PHISHING"

    # 6. Executive Impersonation (Authority figure without financial request)
    if has_executive and (has_conf or p1.score >= 5):
        return "EXECUTIVE_IMPERSONATION"

    # 7. Social Engineering / Extortion
    if has_extort or (has_conf and not has_financial):
        return "SOCIAL_ENGINEERING"

    # 8. Remaining spam/scam (single-hit, below combined threshold)
    if has_lottery or has_spam or has_tech_supp or has_deliv or has_crypto or has_419 or has_job:
        return "SPAM"

    # Default fallbacks based on score
    if total_score >= 60:
        return "PHISHING"
    if total_score >= 30:
        return "SPAM"
    return "SAFE"


# ===========================================================================
# Main Threat Detector Class
# ===========================================================================

class ThreatDetector:
    """
    Explainable Multi-pillar Threat and Spam Detection Engine.
    """

    def analyse(
        self,
        subject:      str = "",
        from_address: str = "",
        reply_to:     str = "",
        sender_ip:    str = "",
        headers:      str = "",
        body:         str = "",
    ) -> Dict[str, Any]:
        """
        Run multi-pillar analysis and return explainable assessment.
        """
        has_headers = bool(headers or sender_ip)
        full_text = f"{subject or ''} {body or ''} {from_address or ''}".strip()

        # 1. Execute all 5 pillars
        p1, forensics = _header_forensics(from_address, reply_to, headers, sender_ip)
        p2, content_reasons = _content_analysis(subject, body)
        p3, all_urls, suspicious_urls = _url_intelligence(body, subject)
        p4, behav_reasons = _behavioural_signals(from_address, reply_to, subject, body, headers)
        p5 = _ml_heuristic_layer(p1, p2, p3, p4, has_headers=has_headers)

        forensics["urls_found"]      = all_urls[:20]
        forensics["suspicious_urls"] = suspicious_urls[:10]

        # 2. Raw total
        raw_total = p1.score + p2.score + p3.score + p4.score + p5.score

        # 3. Adaptive scaling for text-only submissions (when headers are not provided)
        # Total available without headers is 75 (content 25 + url 20 + behav 15 + ml 15)
        # Plus any header points derived from From/Reply-To (p1.score)
        if not has_headers:
            non_header_total = p2.score + p3.score + p4.score + p5.score
            if non_header_total > 0 or p1.score > 0:
                adapted_total = round((non_header_total / 75.0) * 100) + p1.score
                score = max(raw_total, min(100, adapted_total))
            else:
                score = raw_total
        else:
            score = min(100, raw_total)

        # 5. Verdict determination (0–29 SAFE, 30–59 SUSPICIOUS, 60–79 HIGH_RISK, 80–100 CRITICAL)
        verdict = "SAFE"
        for threshold, label in VERDICT_THRESHOLDS:
            if score >= threshold:
                verdict = label
                break

        # 6. Category determination
        category = _determine_category(p1, p2, p3, p4, full_text, score)
        if verdict == "SAFE":
            category = "SAFE"

        # 7. Confidence calculation
        if verdict == "CRITICAL":
            conf = 0.85 + (score - 80) / 100
        elif verdict == "HIGH_RISK":
            conf = 0.65 + (score - 60) / 100
        elif verdict == "SUSPICIOUS":
            conf = 0.45 + (score - 30) / 100
        else:
            conf = max(0.50, 1.0 - score / 30)
        confidence = round(min(0.99, conf), 2)

        # 8. Reasons compilation & deduplication
        reasons: List[str] = []
        for pillar in [p1, p2, p3, p4, p5]:
            for chk in pillar.checks:
                if chk.result in ("fail", "warn") and chk.points > 0:
                    reasons.append(chk.detail.split(".")[0] + ".")
        reasons.extend(content_reasons)
        reasons.extend(behav_reasons)

        seen_r: set = set()
        unique_reasons: List[str] = []
        for r in reasons:
            if r not in seen_r:
                seen_r.add(r)
                unique_reasons.append(r)

        all_checks = []
        for chk in (p1.checks + p2.checks + p3.checks + p4.checks + p5.checks):
            all_checks.append({"name": chk.name, "result": chk.result, "detail": chk.detail})

        breakdown = {
            "header_forensics": p1.to_dict(),
            "content_analysis": p2.to_dict(),
            "url_intelligence": p3.to_dict(),
            "behavioural":      p4.to_dict(),
            "ml_heuristic":     p5.to_dict(),
        }

        recommended = RECOMMENDED_ACTIONS.get(verdict, RECOMMENDED_ACTIONS["SAFE"])

        return {
            "score":              score,
            "verdict":            verdict,
            "category":           category,
            "confidence":         confidence,
            "reasons":            unique_reasons,
            "breakdown":          breakdown,
            "checks":             all_checks,
            "forensics":          forensics,
            "recommended_action": recommended,
        }

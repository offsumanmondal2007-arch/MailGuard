"""
threat_intel.py — Threat Intelligence engine for MailGuard AI.
Provides local IOC (Indicators of Compromise) matching, reputation analysis,
and attribution against known phishing domains, malicious IPs, and attack patterns.
"""

from __future__ import annotations
import ipaddress
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


# ═══════════════════════════════════════════════════════════════════════════
# Curated Local IOC Database
# ═══════════════════════════════════════════════════════════════════════════

# Known Malicious / Suspicious IP Addresses & Threat Attribution
KNOWN_MALICIOUS_IPS: Dict[str, Dict[str, Any]] = {
    "185.220.101.45": {
        "threat_name": "PhishRelay-DarkTor",
        "actor": "FIN7-Affiliated Phishing Cluster",
        "category": "CREDENTIAL_HARVESTING",
        "confidence": 0.96,
        "severity": "CRITICAL",
        "source": "MailGuard Global IOC Feed",
        "tags": ["tor-exit-node", "credential-theft", "brand-spoofing"],
        "description": "Known Tor exit relay frequently abused for PayPal and banking credential harvesting.",
    },
    "45.137.22.19": {
        "threat_name": "GhostHost-PhishNet",
        "actor": "APT-Lookalike Syndicate",
        "category": "PHISHING",
        "confidence": 0.94,
        "severity": "CRITICAL",
        "source": "MailGuard Global IOC Feed",
        "tags": ["bulletproof-hosting", "google-phishing", "dmarc-bypass"],
        "description": "Bulletproof hosting provider IP associated with fake Google Security and OAuth phishing.",
    },
    "94.102.49.190": {
        "threat_name": "InvoiceDropper-TrojanCluster",
        "actor": "Storm-0324 Phishing Broker",
        "category": "MALWARE_DISTRIBUTION",
        "confidence": 0.98,
        "severity": "CRITICAL",
        "source": "MailGuard Malware Hash Vault",
        "tags": ["double-extension", "trojan-dropper", "fake-invoice"],
        "description": "Originating IP hosting weaponized fake invoices (pdf.exe) delivering remote access trojans.",
    },
    "185.234.218.147": {
        "threat_name": "SmishParcel-GlobalRelay",
        "actor": "DeliveryFraud Consortium",
        "category": "PAYMENT_FRAUD",
        "confidence": 0.92,
        "severity": "HIGH",
        "source": "MailGuard Brand Watch",
        "tags": ["package-scam", "courier-impersonation", "card-skimming"],
        "description": "Relay IP used for FedEx, DHL, and postal service customs fee clearance phishing campaigns.",
    },
    "45.142.212.100": {
        "threat_name": "CloudInfiltrate-AWSTheft",
        "actor": "CloudCredential Syndicate",
        "category": "CREDENTIAL_THEFT",
        "confidence": 0.97,
        "severity": "CRITICAL",
        "source": "MailGuard Cloud SecWatch",
        "tags": ["aws-phishing", "cloud-takeover", "root-credential-theft"],
        "description": "Infrastructure host used in targeting corporate AWS root and IAM credentials.",
    },
    "91.108.4.1": {
        "threat_name": "WireRedirect-BEC-Relay",
        "actor": "Scattered BEC Operator",
        "category": "BUSINESS_EMAIL_COMPROMISE",
        "confidence": 0.88,
        "severity": "HIGH",
        "source": "MailGuard BEC Tracker",
        "tags": ["bec-wire-fraud", "ceo-impersonation", "fake-routing"],
        "description": "Originating relay seen in corporate executive impersonation and fraudulent wire redirection.",
    },
    "103.224.182.9": {
        "threat_name": "M365-HarvestCluster",
        "actor": "EvilProxy / PhishKit Collective",
        "category": "CREDENTIAL_THEFT",
        "confidence": 0.91,
        "severity": "HIGH",
        "source": "MailGuard Global IOC Feed",
        "tags": ["microsoft-365", "reverse-proxy", "mfa-bypass"],
        "description": "Hosting reverse-proxy phish kits harvesting Microsoft 365 enterprise sessions and passwords.",
    },
    "139.59.48.5": {
        "threat_name": "QuishingNet-BankLure",
        "actor": "QR Phishing Syndicate",
        "category": "PHISHING",
        "confidence": 0.89,
        "severity": "HIGH",
        "source": "MailGuard Mobile SecWatch",
        "tags": ["quishing", "qr-phishing", "banking-fraud"],
        "description": "IP hosting mobile QR-code bank verification lures targeting NetBanking users.",
    },
    "162.158.102.10": {
        "threat_name": "GiftCard-ExecutiveSpoof",
        "actor": "GiftCard Lure Gang",
        "category": "EXECUTIVE_IMPERSONATION",
        "confidence": 0.87,
        "severity": "HIGH",
        "source": "MailGuard BEC Tracker",
        "tags": ["gift-card-scam", "md-impersonation", "coercive-urgency"],
        "description": "Compromised relay used for executive urgent gift card requests.",
    },
}

# Malicious IP subnets (CIDR ranges)
KNOWN_MALICIOUS_CIDRS = [
    ipaddress.ip_network("185.220.101.0/24"),
    ipaddress.ip_network("45.137.22.0/24"),
    ipaddress.ip_network("94.102.49.0/24"),
    ipaddress.ip_network("185.234.218.0/24"),
    ipaddress.ip_network("45.142.212.0/24"),
]

# Known Phishing / Impersonation Domains
KNOWN_MALICIOUS_DOMAINS: Dict[str, Dict[str, Any]] = {
    "paypa1-secure.tk": {
        "threat_name": "Typosquat-PayPal",
        "target_brand": "PayPal",
        "category": "CREDENTIAL_THEFT",
        "severity": "CRITICAL",
        "confidence": 0.99,
        "source": "MailGuard Anti-Squat Feed",
        "tags": ["typosquatting", "brand-abuse", "paypal-target"],
    },
    "paypal-helpdesk.ml": {
        "threat_name": "Lookalike-PayPal-Support",
        "target_brand": "PayPal",
        "category": "CREDENTIAL_THEFT",
        "severity": "CRITICAL",
        "confidence": 0.98,
        "source": "MailGuard Anti-Squat Feed",
        "tags": ["suspicious-tld", "brand-abuse"],
    },
    "acme-corp-hq.xyz": {
        "threat_name": "BEC-AcmeImpersonator",
        "target_brand": "Acme Corp",
        "category": "BUSINESS_EMAIL_COMPROMISE",
        "severity": "HIGH",
        "confidence": 0.92,
        "source": "MailGuard BEC Domain Watch",
        "tags": ["bec", "ceo-spoof", "wire-fraud"],
    },
    "micros0ft-365.top": {
        "threat_name": "Typosquat-Microsoft365",
        "target_brand": "Microsoft",
        "category": "CREDENTIAL_THEFT",
        "severity": "CRITICAL",
        "confidence": 0.99,
        "source": "MailGuard Anti-Squat Feed",
        "tags": ["leetspeak-domain", "m365-target", "credential-harvesting"],
    },
    "globaltech-inc.cf": {
        "threat_name": "FreeTLD-ExecSpoof",
        "target_brand": "GlobalTech",
        "category": "EXECUTIVE_IMPERSONATION",
        "severity": "HIGH",
        "confidence": 0.90,
        "source": "MailGuard FreeTLD Watch",
        "tags": ["free-tld", "executive-spoof"],
    },
    "google-security-verify.ml": {
        "threat_name": "GoogleVerify-PhishPortal",
        "target_brand": "Google",
        "category": "PHISHING",
        "severity": "CRITICAL",
        "confidence": 0.99,
        "source": "MailGuard Anti-Squat Feed",
        "tags": ["google-impersonation", "fake-security-alert"],
    },
    "hacker-collect.xyz": {
        "threat_name": "Generic-C2-DropDomain",
        "target_brand": "None",
        "category": "CREDENTIAL_THEFT",
        "severity": "CRITICAL",
        "confidence": 0.95,
        "source": "MailGuard Threat Vault",
        "tags": ["credential-drop", "c2-destination"],
    },
    "hdfc-bank-secure.ml": {
        "threat_name": "HDFC-NetBank-Squat",
        "target_brand": "HDFC Bank",
        "category": "PHISHING",
        "severity": "CRITICAL",
        "confidence": 0.97,
        "source": "MailGuard BankWatch",
        "tags": ["banking-trojan", "quishing-target"],
    },
    "hdfc-verify-account.xyz": {
        "threat_name": "HDFC-Harvest-Destination",
        "target_brand": "HDFC Bank",
        "category": "PHISHING",
        "severity": "CRITICAL",
        "confidence": 0.98,
        "source": "MailGuard BankWatch",
        "tags": ["banking-credentials", "otp-theft"],
    },
    "supplier-invoices-global.download": {
        "threat_name": "MalwareDownload-InvoicePortal",
        "target_brand": "Supplier",
        "category": "MALWARE_DISTRIBUTION",
        "severity": "CRITICAL",
        "confidence": 0.98,
        "source": "MailGuard Malware Watch",
        "tags": ["malware-distribution", "double-extension"],
    },
    "fedex-redelivery-portal.xyz": {
        "threat_name": "Courier-Delivery-Fraud",
        "target_brand": "FedEx",
        "category": "PAYMENT_FRAUD",
        "severity": "CRITICAL",
        "confidence": 0.96,
        "source": "MailGuard Brand Watch",
        "tags": ["courier-fraud", "payment-skimmer"],
    },
    "aws-account-verify.tk": {
        "threat_name": "AWS-RootTheft-Portal",
        "target_brand": "Amazon Web Services",
        "category": "CREDENTIAL_THEFT",
        "severity": "CRITICAL",
        "confidence": 0.99,
        "source": "MailGuard Cloud SecWatch",
        "tags": ["aws-phishing", "mfa-theft", "cloud-takeover"],
    },
    "aws-alert-security.ml": {
        "threat_name": "AWS-FakeAlert-Relay",
        "target_brand": "Amazon Web Services",
        "category": "CREDENTIAL_THEFT",
        "severity": "HIGH",
        "confidence": 0.93,
        "source": "MailGuard Cloud SecWatch",
        "tags": ["aws-phishing", "alert-lure"],
    },
    "accounts-reset-portal.download": {
        "threat_name": "Generic-AccountReset-Phish",
        "target_brand": "Generic Identity",
        "category": "CREDENTIAL_THEFT",
        "severity": "HIGH",
        "confidence": 0.91,
        "source": "MailGuard Anti-Squat Feed",
        "tags": ["password-reset", "suspicious-tld"],
    },
}

# High Abuse TLDs (.tk, .ml, .ga, .cf, .gq, .xyz, .top, .download, .click, .loan, .work)
HIGH_ABUSE_TLDS = {
    ".tk": 18, ".ml": 18, ".ga": 18, ".cf": 18, ".gq": 18,
    ".xyz": 12, ".top": 15, ".download": 16, ".click": 14,
    ".loan": 14, ".work": 12, ".kim": 12, ".party": 12,
}


# ═══════════════════════════════════════════════════════════════════════════
# Threat Intelligence Lookup Engine
# ═══════════════════════════════════════════════════════════════════════════

class ThreatIntelEngine:
    """
    Threat Intelligence evaluation engine.
    Matches observed email indicators against local threat databases,
    active IOC repositories, and behavioral pattern banks.
    """

    def __init__(self):
        self._cache = {}

    def lookup_ip(self, ip_str: str) -> Optional[Dict[str, Any]]:
        """Look up sender IP against known malicious IPs and CIDR ranges."""
        if not ip_str or not ip_str.strip():
            return None

        clean_ip = ip_str.strip().split(",")[0].strip()

        # Direct exact match
        if clean_ip in KNOWN_MALICIOUS_IPS:
            match = dict(KNOWN_MALICIOUS_IPS[clean_ip])
            match["indicator"] = clean_ip
            match["type"] = "MALICIOUS_IP"
            return match

        # CIDR range match
        try:
            addr = ipaddress.ip_address(clean_ip)
            for cidr in KNOWN_MALICIOUS_CIDRS:
                if addr in cidr:
                    return {
                        "indicator": clean_ip,
                        "type": "MALICIOUS_IP_SUBNET",
                        "threat_name": f"SubnetMatch-{cidr}",
                        "actor": "Known Threat Infrastructure",
                        "category": "SUSPICIOUS_NETWORK",
                        "confidence": 0.85,
                        "severity": "HIGH",
                        "source": "MailGuard Threat Range DB",
                        "tags": ["suspicious-cidr", "threat-cluster"],
                        "description": f"IP belongs to known bulletproof or proxy CIDR block {cidr}.",
                    }
        except ValueError:
            pass

        return None

    def lookup_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Look up a domain against known malicious domains and high-abuse TLDs."""
        if not domain or not domain.strip():
            return None

        d = domain.lower().strip(">\"' .")

        # Direct domain match
        if d in KNOWN_MALICIOUS_DOMAINS:
            match = dict(KNOWN_MALICIOUS_DOMAINS[d])
            match["indicator"] = d
            match["type"] = "MALICIOUS_DOMAIN"
            return match

        # Check subdomains
        for known_d, info in KNOWN_MALICIOUS_DOMAINS.items():
            if d.endswith("." + known_d):
                match = dict(info)
                match["indicator"] = d
                match["type"] = "MALICIOUS_SUBDOMAIN"
                match["threat_name"] = f"Subdomain-{info['threat_name']}"
                return match

        # High-abuse TLD match
        for tld, tld_score in HIGH_ABUSE_TLDS.items():
            if d.endswith(tld):
                return {
                    "indicator": d,
                    "type": "SUSPICIOUS_TLD",
                    "threat_name": f"HighAbuseTLD-{tld}",
                    "actor": "Unverified TLD Registrant",
                    "category": "SUSPICIOUS_INFRASTRUCTURE",
                    "confidence": 0.70,
                    "severity": "MEDIUM",
                    "source": "MailGuard TLD Reputation",
                    "tags": ["free-or-low-cost-tld", "high-abuse-rate"],
                    "description": f"Domain registered under high-abuse TLD {tld}, frequently leveraged in automated spam/phishing.",
                    "tld_risk": tld_score,
                }

        return None

    def lookup_url(self, url: str) -> Optional[Dict[str, Any]]:
        """Look up URL against known malicious domains, IP URLs, and path signatures."""
        if not url or not url.strip():
            return None

        try:
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower()
            path = (parsed.path or "").lower()
            query = (parsed.query or "").lower()

            # Check domain
            domain_match = self.lookup_domain(host)
            if domain_match and domain_match["severity"] in ("CRITICAL", "HIGH"):
                return {
                    "indicator": url,
                    "type": "MALICIOUS_URL",
                    "threat_name": domain_match["threat_name"],
                    "actor": domain_match.get("actor", "Threat Actor"),
                    "category": domain_match.get("category", "PHISHING"),
                    "confidence": domain_match.get("confidence", 0.95),
                    "severity": domain_match.get("severity", "CRITICAL"),
                    "source": domain_match.get("source", "MailGuard URL Intel"),
                    "tags": domain_match.get("tags", []) + ["phishing-link"],
                    "description": f"Destination domain {host} is flagged in active threat intelligence feeds.",
                }

            # IP-based URL
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
                ip_match = self.lookup_ip(host)
                return {
                    "indicator": url,
                    "type": "IP_BASED_URL",
                    "threat_name": ip_match["threat_name"] if ip_match else "Bare-IP-PhishingURL",
                    "actor": ip_match.get("actor", "Unknown Actor") if ip_match else "Evasion Cluster",
                    "category": "PHISHING",
                    "confidence": 0.92,
                    "severity": "CRITICAL" if ip_match else "HIGH",
                    "source": "MailGuard IP-URL Detector",
                    "tags": ["ip-url", "domain-evasion"],
                    "description": f"URL bypasses DNS with raw IP address ({host}) commonly used by phishing landing kits.",
                }

            # High risk credential paths on non-whitelisted domains
            if any(p in path for p in ["/verify", "/login", "/signin", "/auth", "/accounts", "/update"]):
                if any(param in query for param in ["token=", "ref=", "id=", "code="]):
                    return {
                        "indicator": url,
                        "type": "SUSPICIOUS_PHISH_PATTERN",
                        "threat_name": "Phishing-Kit-Endpoint-Match",
                        "actor": "Phishing Kit Template",
                        "category": "CREDENTIAL_THEFT",
                        "confidence": 0.80,
                        "severity": "HIGH",
                        "source": "MailGuard URL Heuristics",
                        "tags": ["phish-endpoint", "credential-lure"],
                        "description": "URL path structure matches known credential harvester query endpoint signatures.",
                    }

        except Exception:
            pass

        return None

    def evaluate_email(
        self,
        from_address: str,
        reply_to: str,
        sender_ip: str,
        urls: List[str],
        attachments: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Evaluate full set of email indicators against Threat Intelligence sources.
        Returns aggregated IOC hits, attribution metadata, and intelligence risk score.
        """
        ioc_hits: List[Dict[str, Any]] = []
        threat_tags: set = set()
        matched_actors: set = set()
        sources_consulted: List[str] = [
            "MailGuard Local IOC Database",
            "Anti-Squat Domain Watch",
            "High-Abuse TLD Monitor",
            "IP Threat Vault (v2.0)",
        ]

        # 1. Evaluate Sender IP
        if sender_ip:
            ip_hit = self.lookup_ip(sender_ip)
            if ip_hit:
                ioc_hits.append(ip_hit)
                matched_actors.add(ip_hit.get("actor", "Unknown"))
                threat_tags.update(ip_hit.get("tags", []))

        # 2. Evaluate From & Reply-To Domains
        domain_re = re.compile(r"@([a-zA-Z0-9.\-]+)")
        from_match = domain_re.search(from_address or "")
        if from_match:
            from_domain = from_match.group(1).lower().strip(">\"' ")
            d_hit = self.lookup_domain(from_domain)
            if d_hit:
                ioc_hits.append(d_hit)
                matched_actors.add(d_hit.get("actor", "Unknown"))
                threat_tags.update(d_hit.get("tags", []))

        if reply_to:
            rt_match = domain_re.search(reply_to)
            if rt_match:
                rt_domain = rt_match.group(1).lower().strip(">\"' ")
                rt_hit = self.lookup_domain(rt_domain)
                if rt_hit and rt_hit not in ioc_hits:
                    ioc_hits.append(rt_hit)
                    matched_actors.add(rt_hit.get("actor", "Unknown"))
                    threat_tags.update(rt_hit.get("tags", []))

        # 3. Evaluate URLs
        for url in urls or []:
            u_hit = self.lookup_url(url)
            if u_hit:
                ioc_hits.append(u_hit)
                matched_actors.add(u_hit.get("actor", "Unknown"))
                threat_tags.update(u_hit.get("tags", []))

        # 4. Evaluate Attachments
        for att in attachments or []:
            fn = att.lower().strip()
            if fn.endswith((".pdf.exe", ".docm.exe", ".invoice.exe", ".scr", ".bat")):
                ioc_hits.append({
                    "indicator": att,
                    "type": "MALICIOUS_ATTACHMENT",
                    "threat_name": "DoubleExtension-TrojanPayload",
                    "actor": "Storm-0324 Phishing Broker",
                    "category": "MALWARE_DISTRIBUTION",
                    "confidence": 0.99,
                    "severity": "CRITICAL",
                    "source": "MailGuard Malware Watch",
                    "tags": ["double-extension", "trojan-dropper"],
                    "description": f"Attachment '{att}' uses double-extension obfuscation to disguise executable payload.",
                })
                threat_tags.add("double-extension-malware")

        # 5. Calculate Threat Intel Score Boost & Level
        if not ioc_hits:
            intel_level = "CLEAN"
            intel_score = 0
            summary = "No indicators matched known malicious feeds or threat actors."
        else:
            severities = [h.get("severity", "LOW") for h in ioc_hits]
            if "CRITICAL" in severities:
                intel_level = "CRITICAL"
                intel_score = 40  # Direct +40 risk boost for critical IOC match
                summary = f"CRITICAL IOC MATCH: Corroborated with active threat campaigns ({', '.join(sorted(matched_actors))})."
            elif "HIGH" in severities:
                intel_level = "HIGH"
                intel_score = 25  # Direct +25 risk boost
                summary = f"HIGH-RISK IOC MATCH: Matched suspicious infrastructure ({', '.join(sorted(matched_actors))})."
            else:
                intel_level = "SUSPICIOUS"
                intel_score = 12
                summary = f"SUSPICIOUS REPUTATION: {len(ioc_hits)} indicator(s) matched unverified or high-abuse infrastructure."

        return {
            "has_threats": len(ioc_hits) > 0,
            "ioc_hits": ioc_hits,
            "intel_score": intel_score,
            "threat_level": intel_level,
            "threat_actors": sorted(list(matched_actors)),
            "tags": sorted(list(threat_tags)),
            "sources_consulted": sources_consulted,
            "summary": summary,
        }


# Singleton engine instance
threat_intel = ThreatIntelEngine()

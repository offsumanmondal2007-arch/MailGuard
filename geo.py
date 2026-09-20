"""
geo.py — IP geolocation with graceful fallback for MailGuard AI.

Primary source: ip-api.com (free, no API key required, 45 req/min limit).
On any error (network, rate-limit, invalid IP), returns an 'unavailable' stub
so the rest of the analysis pipeline is never blocked.
"""

from __future__ import annotations
import re
from typing import Dict, Any

import requests

_TIMEOUT = 5  # seconds — increased for Vercel cold-start latency


def _is_private_ip(ip: str) -> bool:
    """Return True for RFC-1918 / loopback addresses that cannot be geolocated."""
    private_prefixes = (
        "10.", "192.168.", "127.", "::1", "fc", "fd",
    )
    for prefix in private_prefixes:
        if ip.startswith(prefix):
            return True
    # 172.16.0.0 – 172.31.255.255
    try:
        parts = ip.split(".")
        if len(parts) == 4 and parts[0] == "172":
            second = int(parts[1])
            if 16 <= second <= 31:
                return True
    except ValueError:
        pass
    return False


def _empty_geo(ip: str, reason: str = "") -> Dict[str, Any]:
    return {
        "ip":        ip,
        "country":   "Unknown",
        "region":    "Unknown",
        "city":      "Unknown",
        "isp":       "Unknown",
        "org":       "Unknown",
        "asn":       "Unknown",
        "lat":       None,
        "lon":       None,
        "available": False,
        "note":      reason,
        "is_demo":   False,
    }


def get_geolocation(ip: str) -> Dict[str, Any]:
    """
    Look up geolocation for *ip*.

    Returns a dict matching the GeoInfo schema.
    Never raises — always returns a valid (possibly empty) dict.
    """
    ip = (ip or "").strip()

    if not ip:
        return _empty_geo("", "No IP provided")

    # Validate basic IPv4 format
    ipv4_re = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    ipv6_re = re.compile(r"^[0-9a-fA-F:]+$")
    if not (ipv4_re.match(ip) or ipv6_re.match(ip)):
        return _empty_geo(ip, "Invalid IP format")

    if _is_private_ip(ip):
        return _empty_geo(ip, "Private/internal IP — geolocation not applicable")

    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as,lat,lon,query"
        resp = requests.get(url, timeout=_TIMEOUT)
        data = resp.json()

        if data.get("status") == "success":
            return {
                "ip":        data.get("query", ip),
                "country":   data.get("country",    "Unknown"),
                "region":    data.get("regionName", "Unknown"),
                "city":      data.get("city",        "Unknown"),
                "isp":       data.get("isp",         "Unknown"),
                "org":       data.get("org",         "Unknown"),
                "asn":       data.get("as",          "Unknown"),
                "lat":       data.get("lat"),
                "lon":       data.get("lon"),
                "available": True,
                "note":      "",
                "is_demo":   False,
            }
        else:
            return _empty_geo(ip, data.get("message", "Lookup failed"))

    except requests.exceptions.Timeout:
        return _empty_geo(ip, "Geolocation service timed out")
    except requests.exceptions.ConnectionError:
        return _empty_geo(ip, "Cannot reach geolocation service (offline?)")
    except Exception as exc:  # noqa: BLE001
        return _empty_geo(ip, f"Geolocation error: {type(exc).__name__}")

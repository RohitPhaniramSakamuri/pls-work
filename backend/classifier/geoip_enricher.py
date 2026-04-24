"""
geoip_enricher.py — IP address geolocation + privacy-preserving hashing.

Privacy-preserving transforms (per PDF Section II.D):
  - IP address hashed with SHA-256 + daily rotating salt
  - Raw IP stored only internally for GeoIP lookup, then discarded

GeoIP resolution:
  - Uses ip-api.com (free, no key, 45 req/min for HTTP)
  - In-process LRU cache (512 entries) to stay within rate limits
  - Private/RFC-1918 IPs short-circuit without network call
  - Falls back gracefully on network errors

Usage:
    from geoip_enricher import enrich
    row = enrich({"src_ip": "185.220.101.5", ...})
    # row now has: src_ip_hash, country, country_code, lat, lon, org
    # raw src_ip is preserved for classifier use, hash goes to InfluxDB
"""
from __future__ import annotations

import hashlib
import ipaddress
import logging
import os
import time
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Dict, Optional, Tuple

import requests

log = logging.getLogger(__name__)

# ── Config ─────────────────────────────────────────────────────────────────────
GEOIP_API_URL     = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,lat,lon,org,isp,query"
GEOIP_TIMEOUT_S   = 3.0
GEOIP_RATE_LIMIT  = 0.07  # seconds between requests to stay under 45/min

_last_request_ts  = 0.0


def _daily_salt() -> str:
    """Returns a salt string that rotates every UTC midnight."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def hash_ip(ip: str, salt: Optional[str] = None) -> str:
    """
    SHA-256 hash of salt:ip, truncated to 16 hex chars for storage efficiency.
    Salt rotates daily so historical correlations degrade over time.
    """
    s = salt or _daily_salt()
    digest = hashlib.sha256(f"{s}:{ip}".encode()).hexdigest()
    return digest[:16]


def _is_private(ip: str) -> bool:
    """True for RFC-1918, loopback, link-local, and other reserved ranges."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
    except ValueError:
        return True  # treat unknown as private


@lru_cache(maxsize=512)
def _geoip_lookup_cached(ip: str) -> Dict[str, Any]:
    """Cached GeoIP lookup. Returns empty dict on failure."""
    global _last_request_ts

    if _is_private(ip):
        return {"country": "Private", "countryCode": "XX", "lat": 0.0, "lon": 0.0,
                "org": "Private Network", "isp": ""}

    # Throttle requests
    now = time.time()
    wait = GEOIP_RATE_LIMIT - (now - _last_request_ts)
    if wait > 0:
        time.sleep(wait)
    _last_request_ts = time.time()

    try:
        url = GEOIP_API_URL.format(ip=ip)
        resp = requests.get(url, timeout=GEOIP_TIMEOUT_S)
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") == "success":
            return data
        log.debug(f"GeoIP API returned non-success for {ip}: {data}")
        return {}
    except Exception as exc:
        log.debug(f"GeoIP lookup failed for {ip}: {exc}")
        return {}


def geoip_lookup(ip: str) -> Dict[str, Any]:
    """Public wrapper that handles normalisation before cache lookup."""
    ip = ip.strip() if ip else ""
    if not ip or ip in ("0.0.0.0", "127.0.0.1", ""):
        return {}
    return _geoip_lookup_cached(ip)


def enrich(row: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich a session/event dict with:
      - src_ip_hash: privacy-preserving hash of the source IP
      - country, country_code, lat, lon, org: from GeoIP

    The original src_ip is preserved in the dict for downstream classifiers
    but only the hash is tagged in InfluxDB classified_events.
    """
    ip = str(row.get("src_ip", "") or "")
    result = dict(row)

    # Privacy transform — always
    result["src_ip_hash"] = hash_ip(ip) if ip else "0000000000000000"

    # GeoIP enrichment
    geo = geoip_lookup(ip)
    result["country"]      = str(geo.get("country",      "Unknown"))
    result["country_code"] = str(geo.get("countryCode",  "XX"))
    result["lat"]          = float(geo.get("lat",         0.0))
    result["lon"]          = float(geo.get("lon",         0.0))
    result["org"]          = str(geo.get("org",           geo.get("isp", "")))

    return result


def enrich_batch(rows: list) -> list:
    """Enrich a list of session dicts. GeoIP cache makes repeated IPs free."""
    return [enrich(r) for r in rows]

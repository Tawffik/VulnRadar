"""EPSS enrichment for target-matched CVEs.

EPSS (FIRST.org) estimates the probability that a CVE will be exploited in
the wild in the next 30 days. It is a prioritisation signal, not proof of
exploitability, and it never changes a name/vendor match into a finding.

The full EPSS feed is large; this module fetches only the CVEs that already
matched a configured target (capped by max_entries), so a daily run stays
bounded and respectful of the public API.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from pipeline.collectors.http_utils import request_with_retry  # noqa: E402

EPSS_URL = "https://api.first.org/data/v1/epss"
USER_AGENT = "VulnRadar/1.0 (+https://github.com/Tawffik/VulnRadar)"
DEFAULT_MAX = 50


def fetch_epss(cve: str, _request=None) -> dict | None:
    """Return {'epss', 'epss_percentile', 'epss_date'} for one CVE or None."""
    if not cve:
        return None
    url = f"{EPSS_URL}?{urllib.parse.urlencode({'cve': cve})}"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    fetcher = _request or request_with_retry
    try:
        raw = fetcher(req, timeout=15)
        payload = json.loads(raw)
        rows = payload.get("data") or []
        if not rows:
            return None
        row = rows[0]
        if row.get("cve") and row.get("cve") != cve:
            return None
        return {
            "epss": float(row.get("epss", 0.0)),
            "epss_percentile": float(row.get("percentile", 0.0)),
            "epss_date": row.get("date", ""),
        }
    except Exception:
        return None


def enrich_entries(entries: list, *, fetch=None, max_entries: int = DEFAULT_MAX) -> tuple[list, int]:
    """Add EPSS fields to target-matched entries. Never raises."""
    fetch = fetch or fetch_epss
    enriched = 0
    for entry in entries:
        if enriched >= max_entries:
            break
        if not entry.get("matched_targets"):
            continue
        if entry.get("epss") is not None:
            continue
        try:
            data = fetch(entry.get("cve", ""))
        except Exception:
            continue
        if not data:
            continue
        entry.update(data)
        enriched += 1
    return entries, enriched

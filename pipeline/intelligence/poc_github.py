"""Public PoC existence check via nomi-sec/PoC-in-GitHub.

A public exploit repository is a strong "this is practically exploitable"
signal, but it is still a LEAD: the PoC may target a different version or
fail against the deployed target. This module checks only target-matched
CVEs and caps lookups per run.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from pipeline.collectors.http_utils import request_with_retry  # noqa: E402

BASE = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master"
USER_AGENT = "VulnRadar/1.0 (+https://github.com/Tawffik/VulnRadar)"
DEFAULT_MAX = 50


def fetch_pocs(cve: str, _request=None) -> dict | None:
    if not cve or cve.count("-") < 2:
        return None
    year = cve.split("-")[1]
    url = f"{BASE}/{year}/{cve}.json"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    fetcher = _request or request_with_retry
    try:
        raw = fetcher(req, timeout=15)
        rows = json.loads(raw)
        if not isinstance(rows, list) or not rows:
            return None
        return {
            "poc_count": len(rows),
            "poc_repos": [r.get("html_url", "") for r in rows[:3] if r.get("html_url")],
        }
    except Exception:
        return None


def enrich_entries(entries: list, *, fetch=None, max_entries: int = DEFAULT_MAX) -> tuple[list, int]:
    fetch = fetch or fetch_pocs
    enriched = 0
    for entry in entries:
        if enriched >= max_entries:
            break
        if not entry.get("matched_targets") or entry.get("poc_count") is not None:
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

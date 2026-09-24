#!/usr/bin/env python3
"""
pipeline/collectors/nvd.py

Collects from the National Vulnerability Database's official API 2.0
(https://services.nvd.nist.gov/rest/json/cves/2.0). Polls for recently
MODIFIED CVEs (not just published) using the lastModStartDate/
lastModEndDate window, since NVD's own analysis (CVSS scoring, CPE
matching) is often added or corrected after a CVE's initial CVE.org
publication.

The one thing NVD provides that neither cisa_kev.py nor cve_org.py
reliably do: structured CPE version-range data
(versionStartIncluding/versionEndExcluding etc.), which is exactly what
docs/ROADMAP.md's Priority 1 "Version Intelligence" item needs. This
collector CAPTURES that data (see cpe_version_range in each normalized
entry) but does not yet USE it for filtering — technology_matcher.py
still only does name-based matching for V1. Wiring version-range
comparison into the matcher is the next real step, not done here.

HONESTY NOTE — different from cisa_kev.py and cve_org.py: this
collector's normalization logic was written against NVD's officially
documented API 2.0 JSON schema (stable, versioned, well-established —
this is not a guess), but could NOT be verified against a live fetch
during development: services.nvd.nist.gov is not reachable from the
sandbox this was built in (unlike api.github.com and
raw.githubusercontent.com, which cisa_kev.py and cve_org.py WERE
tested against live). This means, unlike those two, there is a real
chance the live response has a subtle shape difference from what's
coded here that won't surface until the first real CI run. Verify the
first real run's output before trusting this collector the way the
other two are trusted.

An NVD API key is optional but strongly recommended: unauthenticated
requests are limited to 5 requests per 30 seconds, which is workable
for a 15-minute polling interval but leaves no margin for retries.
Set NVD_API_KEY as an environment variable or GitHub Actions secret.
Request one free at https://nvd.nist.gov/developers/request-an-api-key
"""
import json
import os
import urllib.parse
import urllib.request
import urllib.error

from pipeline.collectors import http_utils
from datetime import datetime, timedelta, timezone

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _extract_cpe_vendor_product(criteria: str):
    """cpe:2.3:a:vendor:product:version:update:edition:language:sw_edition:
    target_sw:target_hw:other -> (vendor, product). Returns (None, None)
    if the string doesn't look like a well-formed CPE 2.3 URI."""
    parts = criteria.split(":")
    if len(parts) < 5 or parts[0] != "cpe" or parts[1] != "2.3":
        return None, None
    return parts[3], parts[4]


def _normalize_cve(raw_cve: dict) -> list:
    cve_id = raw_cve.get("id", "")
    if not cve_id:
        return []

    descriptions = raw_cve.get("descriptions", [])
    description = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

    metrics = raw_cve.get("metrics", {})
    cvss_score, cvss_severity = None, None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            data = entries[0].get("cvssData", {})
            cvss_score = data.get("baseScore")
            cvss_severity = data.get("baseSeverity") or entries[0].get("baseSeverity")
            break

    cwes = [d["value"] for w in raw_cve.get("weaknesses", [])
            for d in w.get("description", []) if d.get("lang") == "en" and d.get("value", "").startswith("CWE-")]

    cpe_entries = []
    for config in raw_cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable"):
                    continue
                vendor, product = _extract_cpe_vendor_product(match.get("criteria", ""))
                if not vendor or not product:
                    continue
                cpe_entries.append({
                    "vendor": vendor,
                    "product": product,
                    "version_start_including": match.get("versionStartIncluding"),
                    "version_start_excluding": match.get("versionStartExcluding"),
                    "version_end_including": match.get("versionEndIncluding"),
                    "version_end_excluding": match.get("versionEndExcluding"),
                })

    if not cpe_entries:
        return []  # no structured vendor/product data — nothing this schema can match on

    entries = []
    for cpe in cpe_entries:
        entries.append({
            "cve": cve_id,
            "vendor": cpe["vendor"].replace("_", " "),
            "product": cpe["product"].replace("_", " "),
            "name": description[:80],
            "date_added": raw_cve.get("published", ""),
            "due_date": "",
            "description": description,
            "required_action": "",
            "ransomware_use": "Unknown",
            "cwes": cwes,
            "cvss_score": cvss_score,
            "cvss_severity": cvss_severity,
            "source": "nvd",
            "cpe_version_range": {
                "start_including": cpe["version_start_including"],
                "start_excluding": cpe["version_start_excluding"],
                "end_including": cpe["version_end_including"],
                "end_excluding": cpe["version_end_excluding"],
            },
        })
    return entries


def _fetch_json(url: str, api_key: str = None, timeout: int = 30):
    headers = {"User-Agent": "VulnRadar/1.0"}
    if api_key:
        headers["apiKey"] = api_key
    req = urllib.request.Request(url, headers=headers)
    body = http_utils.request_with_retry(req, timeout=timeout)
    return json.loads(body.decode("utf-8"))


def fetch_normalized(minutes_back: int = 20, api_key: str = None, timeout: int = 30, _loader=None):
    """Polls for CVEs modified in the last `minutes_back` minutes
    (default wider than the 15-minute schedule interval, so a slow/
    delayed workflow run doesn't create a gap — NVD's window query is
    authoritative and complete, unlike cve_org's rolling snapshot, so a
    wider window is safe: it just re-confirms already-seen CVEs, which
    state_diff.py correctly no-ops on)."""
    api_key = api_key or os.environ.get("NVD_API_KEY")

    if _loader:
        loader = _loader
    else:
        end = datetime.now(timezone.utc)
        start = end - timedelta(minutes=minutes_back)
        params = {
            "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000") + "+00:00",
            "lastModEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000") + "+00:00",
            "resultsPerPage": 100,
        }
        url = f"{NVD_BASE_URL}?{urllib.parse.urlencode(params)}"
        loader = lambda: _fetch_json(url, api_key, timeout)

    try:
        raw = loader()
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
        return [], f"NVD fetch failed: {e}"
    except json.JSONDecodeError as e:
        return [], f"NVD response was not valid JSON: {e}"

    vulns = raw.get("vulnerabilities")
    if vulns is None:
        return [], "NVD response had no 'vulnerabilities' key — API format may have changed"

    entries = []
    for v in vulns:
        entries.extend(_normalize_cve(v.get("cve", {})))
    return entries, None


if __name__ == "__main__":
    entries, error = fetch_normalized()
    if error:
        print(f"⚠️ {error}")
    else:
        print(f"✅ fetched {len(entries)} normalized entries from NVD")

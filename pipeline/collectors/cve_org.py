#!/usr/bin/env python3
"""
pipeline/collectors/cve_org.py

Collects from the OFFICIAL CVE.org record repository
(https://github.com/CVEProject/cvelistV5), NOT the NVD or CISA KEV.
This is the speed source: cvelistV5's cves/delta.json is updated by
MITRE's own automation roughly every 7 minutes, listing CVE IDs that
were just published or updated — often well before NVD analyzes them
and LONG before CISA KEV would ever list them (KEV only adds a CVE
after confirmed real-world exploitation, which can take days/weeks).

IMPORTANT — this is fundamentally different from cisa_kev.py, read
before changing the polling interval:

  delta.json is a SNAPSHOT of the most recent batch of changes, not a
  complete log. If this collector polls less often than delta.json's
  own ~7-minute update cadence, a CVE that appeared in one delta and
  was then superseded by a later delta before the next poll could be
  MISSED entirely. This is mitigated two ways:
    1. the workflow polls this collector every 15 minutes (see
       .github/workflows/), close to the feed's own cadence
    2. every fetch records its own fetchTime; if the gap since the
       last successful fetch is suspiciously large (missed scheduled
       runs, an outage, etc.), a warning is printed so this is visible
       rather than silently trusting an incomplete window — see
       check_for_gap() below
  This is a known, accepted V1 limitation, not a hidden one: for
  guaranteed completeness, the roadmap's git-clone-and-diff approach
  would be needed instead of polling delta.json. See docs/ROADMAP.md.
"""
import json
import urllib.request
import urllib.error
from datetime import datetime, timezone

from pipeline.collectors import http_utils

DELTA_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/delta.json"
GAP_WARNING_THRESHOLD_MINUTES = 20  # delta.json updates ~every 7 min; a 20+ min
                                     # gap since our last successful fetch means
                                     # we likely missed at least one delta window


def _fetch_json(url: str, timeout: int = 20) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "VulnRadar/1.0"})
    body = http_utils.request_with_retry(req, timeout=timeout)
    return json.loads(body.decode("utf-8"))


def _normalize_record(cve_id: str, record: dict) -> list:
    """One CVE record can list multiple affected vendor/product pairs
    (rare but real — e.g. a library vulnerable across several
    downstream packages). Emit one normalized entry PER pair so the
    existing technology_matcher.py (built for KEV's one-vendor-per-entry
    shape) works unchanged — this is why the schema below deliberately
    matches cisa_kev.py's normalize_entry() output shape exactly."""
    meta = record.get("cveMetadata", {})
    if meta.get("state") != "PUBLISHED":
        return []  # REJECTED/RESERVED records carry no useful vendor/product data

    cna = record.get("containers", {}).get("cna", {})
    descriptions = cna.get("descriptions", [])
    description = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
    title = cna.get("title", "")

    cvss_score = None
    cvss_severity = None
    for metric in cna.get("metrics", []):
        for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
            if key in metric:
                cvss_score = metric[key].get("baseScore")
                cvss_severity = metric[key].get("baseSeverity")
                break
        if cvss_score is not None:
            break

    affected = cna.get("affected", []) or [{"vendor": "unknown", "product": "unknown"}]
    entries = []
    for a in affected:
        entries.append({
            "cve": cve_id,
            "vendor": (a.get("vendor") or "unknown").strip(),
            "product": (a.get("product") or "unknown").strip(),
            "name": title or description[:80],
            "date_added": meta.get("datePublished", ""),
            "due_date": "",
            "description": description,
            "required_action": "",
            "ransomware_use": "Unknown",  # cve.org records don't carry this — KEV-only field
            "cwes": [d["cweId"] for pt in cna.get("problemTypes", [])
                     for d in pt.get("descriptions", []) if d.get("cweId")],
            "cvss_score": cvss_score,
            "cvss_severity": cvss_severity,
            "source": "cve_org",
        })
    return entries


def fetch_normalized(delta_url: str = DELTA_URL, timeout: int = 20,
                      _delta_loader=None, _record_loader=None):
    """Returns (entries, error, gap_warning). entries is a flat list —
    same normalized schema as cisa_kev.py's, plus cvss_score/
    cvss_severity, so it can be diffed/matched/rendered with the exact
    same downstream modules.

    _delta_loader/_record_loader are injectable fetch functions used by
    tests to avoid live network calls — production code never needs to
    pass these, they default to the real HTTP fetchers."""
    delta_loader = _delta_loader or (lambda: _fetch_json(delta_url, timeout))
    record_loader = _record_loader or (lambda url: _fetch_json(url, timeout))

    try:
        delta = delta_loader()
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
        return [], f"delta.json fetch failed: {e}", None
    except json.JSONDecodeError as e:
        return [], f"delta.json was not valid JSON: {e}", None

    if delta.get("error"):
        return [], f"delta.json reported its own error(s): {delta['error']}", None

    changed = (delta.get("new") or []) + (delta.get("updated") or [])
    entries = []
    fetch_errors = 0
    for item in changed:
        cve_id = item.get("cveId")
        link = item.get("githubLink")
        if not cve_id or not link:
            continue
        try:
            record = record_loader(link)
        except Exception:
            fetch_errors += 1
            continue  # one bad record fetch must not stop the rest
        entries.extend(_normalize_record(cve_id, record))

    if fetch_errors:
        print(f"⚠️ {fetch_errors} of {len(changed)} individual CVE record fetch(es) failed "
              f"(skipped, not fatal to the run)")

    return entries, None, delta.get("fetchTime")


def check_for_gap(current_fetch_time: str, last_fetch_time: str) -> str:
    """Returns a warning string if the gap between this fetch and the
    last one exceeds the threshold, else None. Both timestamps are
    ISO8601 (delta.json's own fetchTime format)."""
    if not last_fetch_time:
        return None
    try:
        cur = datetime.fromisoformat(current_fetch_time.replace("Z", "+00:00"))
        prev = datetime.fromisoformat(last_fetch_time.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    gap_minutes = (cur - prev).total_seconds() / 60
    if gap_minutes > GAP_WARNING_THRESHOLD_MINUTES:
        return (f"⚠️ {gap_minutes:.0f} minutes since the last successful cve_org fetch "
                f"(threshold: {GAP_WARNING_THRESHOLD_MINUTES}min) — some CVEs published in "
                f"between may have been missed since delta.json is a snapshot, not a full log. "
                f"See cve_org.py's module docstring.")
    return None


if __name__ == "__main__":
    entries, error, fetch_time = fetch_normalized()
    if error:
        print(f"⚠️ {error}")
    else:
        print(f"✅ fetched {len(entries)} entries from cve.org delta (fetchTime={fetch_time})")

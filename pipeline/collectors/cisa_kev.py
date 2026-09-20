#!/usr/bin/env python3
"""
pipeline/collectors/cisa_kev.py

Collects from CISA's Known Exploited Vulnerabilities (KEV) catalog —
a real, free, no-auth-required, government-maintained feed of CVEs
with CONFIRMED real-world exploitation, not just theoretical severity.
This is deliberately the first (and for V1, only) source: it is the
single highest-signal-to-noise CVE feed that exists — every entry on
it is already known to be actively exploited, which is a much stronger
prioritization signal than CVSS score alone.

Feed URL (public, versioned, no API key):
  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

Normalizes CISA's schema into this project's internal schema so future
collectors (NVD, GitHub Security Advisories, vendor feeds) can plug in
without changing anything downstream.
"""
import json
import urllib.request
import urllib.error

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def normalize_entry(raw: dict) -> dict:
    """CISA's own field names -> this project's internal schema."""
    return {
        "cve": raw.get("cveID", "").strip(),
        "vendor": raw.get("vendorProject", "").strip(),
        "product": raw.get("product", "").strip(),
        "name": raw.get("vulnerabilityName", "").strip(),
        "date_added": raw.get("dateAdded", "").strip(),
        "due_date": raw.get("dueDate", "").strip(),
        "description": raw.get("shortDescription", "").strip(),
        "required_action": raw.get("requiredAction", "").strip(),
        "ransomware_use": raw.get("knownRansomwareCampaignUse", "Unknown").strip(),
        "cwes": raw.get("cwes", []) or [],
        "source": "cisa_kev",
    }


def fetch_raw(url: str = KEV_URL, timeout: int = 20) -> dict:
    """Fetches and parses the raw CISA KEV JSON. Raises on failure —
    callers decide how to handle that (see fetch_normalized's try/except
    for the CLI-friendly version)."""
    req = urllib.request.Request(url, headers={"User-Agent": "VulnRadar/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_normalized(url: str = KEV_URL, timeout: int = 20):
    """Returns (entries, error). entries is a list of normalized dicts
    (empty list on failure, never None, so callers don't need a null
    check). error is None on success, a short string otherwise —
    callers must check it before trusting an empty entries list means
    'zero vulnerabilities', not 'the fetch failed'."""
    try:
        raw = fetch_raw(url, timeout)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
        return [], f"fetch failed: {e}"
    except json.JSONDecodeError as e:
        return [], f"response was not valid JSON: {e}"

    vulns = raw.get("vulnerabilities")
    if vulns is None:
        return [], "response JSON had no 'vulnerabilities' key — feed format may have changed"

    return [normalize_entry(v) for v in vulns if v.get("cveID")], None


def load_from_file(path: str):
    """Same normalization, but from a local JSON file — used for tests
    and for re-processing an already-downloaded snapshot without
    hitting the network again."""
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    vulns = raw.get("vulnerabilities", [])
    return [normalize_entry(v) for v in vulns if v.get("cveID")]


if __name__ == "__main__":
    entries, error = fetch_normalized()
    if error:
        print(f"⚠️ {error}")
    else:
        print(f"✅ fetched {len(entries)} KEV entries")

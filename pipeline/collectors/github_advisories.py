#!/usr/bin/env python3
"""
pipeline/collectors/github_advisories.py

Collects from GitHub's Security Advisory database
(https://github.com/advisories) via the public REST API
(GET /advisories). This fills a real gap the other two sources don't
cover well: dependency/library-level CVEs (npm, PyPI, Maven, NuGet,
RubyGems, Go, etc.) — the kind of vulnerability that shows up in a
target's package.json/requirements.txt rather than being tied to a
"vendor product" the way KEV/cve.org's schema assumes.

Reviewed advisories with a CVE ID are in scope (ghost/malware/
unreviewed advisories, and ones without a CVE ID, are excluded — this
project's schema is CVE-centric by design).

API docs: https://docs.github.com/en/rest/security-advisories
No token required for basic access (60 req/hr), but an optional token
(set GITHUB_TOKEN or pass one in) raises the limit to 5000/hr — the
GitHub Actions workflow already has GITHUB_TOKEN available for free,
so production runs should never hit the unauthenticated limit.

IMPORTANT — schema honesty: unlike cisa_kev.py and cve_org.py, this
collector's exact live response shape was NOT verified against a live
fetch during development (the development sandbox's shared IP was
already rate-limited against api.github.com at the time). The
normalization logic below follows GitHub's officially documented REST
API schema, which is stable and versioned, but should be spot-checked
against real output the first time this actually runs in CI — see
pipeline/tests/fixtures/github_advisory_sample.json for the schema this
was built against, and README.md's note about this.
"""
import json
import os
import urllib.request
import urllib.error

ADVISORIES_URL = "https://api.github.com/advisories?per_page=100&sort=published&direction=desc"


def _normalize_advisory(raw: dict) -> list:
    """One advisory can affect multiple packages/ecosystems — emit one
    normalized entry per (ecosystem, package) pair, same reasoning as
    cve_org.py's multi-product handling."""
    cve_id = raw.get("cve_id")
    if not cve_id:
        return []  # GHSA-only advisories (no assigned CVE) are out of scope for V1

    cvss = raw.get("cvss") or {}
    cwes = [c.get("cwe_id") for c in (raw.get("cwes") or []) if c.get("cwe_id")]
    vulns = raw.get("vulnerabilities") or []
    if not vulns:
        return []

    entries = []
    for v in vulns:
        pkg = v.get("package") or {}
        ecosystem = (pkg.get("ecosystem") or "unknown").strip()
        name = (pkg.get("name") or "unknown").strip()
        entries.append({
            "cve": cve_id,
            "vendor": ecosystem,   # e.g. "npm", "pip", "maven" — the ecosystem IS the "vendor" here
            "product": name,
            "name": raw.get("summary", ""),
            "date_added": raw.get("published_at", ""),
            "due_date": "",
            "description": raw.get("description", "") or raw.get("summary", ""),
            "required_action": (f"Upgrade to {v['first_patched_version']['identifier']} or later"
                                 if v.get("first_patched_version") else "See advisory for remediation"),
            "ransomware_use": "Unknown",
            "cwes": cwes,
            "cvss_score": cvss.get("score"),
            "cvss_severity": (raw.get("severity") or "").upper() or None,
            "source": "github_advisories",
            "vulnerable_version_range": v.get("vulnerable_version_range", ""),
        })
    return entries


def _fetch_json(url: str, token: str = None, timeout: int = 20):
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "VulnRadar/1.0"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_normalized(url: str = ADVISORIES_URL, token: str = None, timeout: int = 20,
                      _loader=None):
    """token defaults to the GITHUB_TOKEN environment variable if set
    (GitHub Actions provides this automatically at no extra setup cost).
    _loader is injectable for tests, same pattern as cve_org.py."""
    token = token or os.environ.get("GITHUB_TOKEN")
    loader = _loader or (lambda: _fetch_json(url, token, timeout))

    try:
        raw_list = loader()
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
        return [], f"GitHub Advisories fetch failed: {e}"
    except json.JSONDecodeError as e:
        return [], f"response was not valid JSON: {e}"

    if isinstance(raw_list, dict) and raw_list.get("message"):
        # GitHub's API returns a dict with 'message' on errors (rate limit, auth, etc.)
        # instead of the expected list — surfaced explicitly rather than crashing on
        # the list-comprehension below.
        return [], f"GitHub API error: {raw_list['message']}"

    entries = []
    for advisory in raw_list:
        entries.extend(_normalize_advisory(advisory))
    return entries, None


if __name__ == "__main__":
    entries, error = fetch_normalized()
    if error:
        print(f"⚠️ {error}")
    else:
        print(f"✅ fetched {len(entries)} normalized entries from GitHub Advisories")

#!/usr/bin/env python3
"""
pipeline/recon/exposure_scan.py

Passive information-disclosure recon: plain GET requests to well-known
paths (no injection, no auth bypass attempts, nothing that mutates
anything). This is the same risk category as pipeline/recon/fingerprint.py
(also a plain GET) - it does NOT require a target's scan_allowed flag,
unlike pipeline/verify/nuclei_runner.py which actively probes for a
specific CVE.

Ported and simplified from a much larger, more invasive CI pipeline
(the "BugBountyCI" repo) - deliberately dropped from that version:
Tor/proxychains IP rotation, header spoofing, and any active injection
testing (XSS/SQLi/SSTI/SSRF/command injection payloads). Those are a
different risk category and do not belong in an unattended 15-minute
cron job; they were left out entirely, not merged.

What this checks, per target:
  - git_exposure: /.git/HEAD, /.git/config (must actually look like a
    real git ref/config, not just return 200 - avoids soft-404 false
    positives)
  - sensitive_files: /.env, /wp-config.php, /.aws/credentials, etc,
    with baseline-diffing against a random not_a_real_path to reject
    single-page apps that return 200+HTML for everything
  - source_maps: for each <script src> on the homepage, checks
    "<script>.map"; if found, extracts embedded source file paths and
    scans for AWS/Google/OpenAI-style API key patterns in the map
    content (these are unintentionally-shipped debug artifacts, not
    something being attacked)

Never raises: any single check failing (timeout, connection error,
malformed response) is skipped, never crashes the run.
"""
import re
import urllib.error
import urllib.request

from pipeline.recon.user_agents import random_ua

TIMEOUT = 6

GIT_PATHS = ["/.git/HEAD", "/.git/config"]
SENSITIVE_PATHS = [
    "/.env", "/wp-config.php", "/config.json", "/credentials.json",
    "/.aws/credentials", "/Dockerfile", "/backup.sql",
]
SECRET_PATTERNS = {
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "Google API Key": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    "OpenAI-style Key": re.compile(r"sk-[A-Za-z0-9]{40,}"),
    "JWT": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
}


def _get(url: str, timeout: int = TIMEOUT):
    """Returns (status_code, body_text) or (None, None) on any failure."""
    req = urllib.request.Request(url, headers={"User-Agent": random_ua()})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(200_000).decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return None, None


def check_git_exposure(base_url: str) -> list:
    hits = []
    for path in GIT_PATHS:
        status, body = _get(base_url + path)
        if status == 200 and body and re.search(r"ref:\s*refs/heads/|gitdir:", body):
            hits.append(base_url + path)
    return hits


def check_sensitive_files(base_url: str) -> list:
    base_status, base_body = _get(base_url + "/__vulnradar_not_a_real_path_xyz")
    base_len = len(base_body or "")
    base_is_html = bool(base_body and re.search(r"<html|<!doctype", base_body, re.I))

    hits = []
    for path in SENSITIVE_PATHS:
        status, body = _get(base_url + path)
        if status != 200 or not body:
            continue
        if re.search(r"<html|<!doctype", body, re.I) and base_is_html:
            # SPA/soft-404 that serves HTML for every path - only trust this
            # hit if it's meaningfully different in size from the baseline.
            if abs(len(body) - base_len) < 200:
                continue
        hits.append(base_url + path)
    return hits


def _extract_js_urls(html: str, base_url: str) -> list:
    urls = []
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html, re.I):
        src = m.group(1)
        if src.startswith("http"):
            urls.append(src)
        elif src.startswith("/"):
            urls.append(base_url + src)
    return urls[:20]  # a target with hundreds of JS files gets capped, not fully crawled


def check_source_maps(base_url: str) -> dict:
    status, html = _get(base_url)
    found, endpoints, secrets = [], set(), set()
    if not html:
        return {"maps": found, "endpoints": [], "secrets": []}

    for js_url in _extract_js_urls(html, base_url):
        map_url = js_url + ".map"
        m_status, m_body = _get(map_url)
        if m_status != 200 or not m_body:
            continue
        found.append(map_url)
        try:
            import json
            data = json.loads(m_body)
            for src in (data.get("sources") or []):
                if src and src != "null":
                    endpoints.add(src)
        except Exception:
            pass  # not valid JSON - still worth flagging that the map exists
        for label, pattern in SECRET_PATTERNS.items():
            if pattern.search(m_body):
                secrets.add(label)
    return {"maps": found, "endpoints": sorted(endpoints)[:30], "secrets": sorted(secrets)}


def scan_target(domain: str, timeout: int = TIMEOUT) -> dict:
    """Returns a report dict; never raises. Each sub-check is independently
    wrapped so one failing check (e.g. git works, sensitive-files times out)
    doesn't blank out the others."""
    base_url = domain if domain.startswith("http") else f"https://{domain}"
    report = {"target": domain, "git_exposure": [], "sensitive_files": [],
              "source_maps": {"maps": [], "endpoints": [], "secrets": []}, "error": None}
    try:
        report["git_exposure"] = check_git_exposure(base_url)
    except Exception as e:
        report["error"] = f"git check failed: {e}"
    try:
        report["sensitive_files"] = check_sensitive_files(base_url)
    except Exception as e:
        report["error"] = (report["error"] or "") + f" sensitive-files check failed: {e}"
    try:
        report["source_maps"] = check_source_maps(base_url)
    except Exception as e:
        report["error"] = (report["error"] or "") + f" source-map check failed: {e}"
    return report


def has_findings(report: dict) -> bool:
    return bool(report["git_exposure"] or report["sensitive_files"]
                or report["source_maps"]["maps"] or report["source_maps"]["secrets"])


def scan_targets(domains: list, timeout: int = TIMEOUT) -> list:
    return [scan_target(d, timeout=timeout) for d in domains]

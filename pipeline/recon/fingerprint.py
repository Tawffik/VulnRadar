#!/usr/bin/env python3
"""
pipeline/recon/fingerprint.py

Runs ProjectDiscovery's `httpx` (-tech-detect -json) against a target
domain to auto-detect its tech stack, instead of relying on someone
hand-typing targets/*.yaml. httpx's tech detection is Wappalyzer-derived
and returns entries like "Nginx:1.18.0", "OpenSSH:8.2p1" — vendor,
product AND version in one string where the fingerprint allows it.

Requires the `httpx` binary (github.com/projectdiscovery/httpx) on
PATH — NOT the Python httpx HTTP client library, a name collision this
project has to live with since that's what the security tooling is
actually called. install_httpx.sh documents installing it in CI.

Design:
  - subprocess, not a Python port: httpx's fingerprint database is
    maintained upstream and improves without any code change here.
  - never raises: a missing binary, a timeout, or a target that's
    simply down must never break the hunt. Returns (detections, error).
  - one target at a time, explicit timeout, no follow-redirects to
    other hosts (stays scoped to what was asked).
"""
import json
import shutil
import subprocess

from pipeline.recon.user_agents import random_ua

HTTPX_TIMEOUT_SECONDS = 25
HTTPX_BINARY = "httpx"

# Wappalyzer-style detections that are NOT software with CVEs: security
# headers, protocols, CDNs/analytics/fonts/UI libs. Keeping them would
# only create meaningless (or false) CVE matches, e.g. "HSTS" on okx.com.
NOISE = {
    "hsts", "http/2", "http/3", "hsts preload", "cloudflare", "cloudfront",
    "akamai", "akamaighost", "fastly", "incapsula", "imperva", "sucuri",
    "google font api", "google fonts", "google analytics",
    "google tag manager", "google hosted libraries", "cdnjs", "jsdelivr", "unpkg",
    "font awesome", "open graph", "webpack", "core-js", "lodash", "gzip",
    "amazon s3", "amazon web services", "microsoft 365", "cloudflare bot management",
    "content security policy", "x-frame-options", "x-xss-protection",
}

# Substring fallback: WAF/CDN vendors ship many header/banner variants
# (AkamaiGHost, Akamai Edge, cloudflare-nginx...) that an exact-match
# NOISE lookup will always miss one of. If the exact key isn't in NOISE,
# also reject it when any noise word appears as a substring.
_NOISE_SUBSTRINGS = ("akamai", "cloudflare", "incapsula", "imperva", "sucuri",
                     "fastly", "cloudfront")

# httpx/Wappalyzer name -> (vendor, product) as CISA/NVD name them, so the
# substring matcher hits. Anything not listed keeps its detected name.
ALIASES = {
    "nginx": ("nginx", "nginx"),
    "apache http server": ("Apache", "HTTP Server"),
    "apache": ("Apache", "HTTP Server"),
    "openssh": ("OpenBSD", "OpenSSH"),
    "iis": ("Microsoft", "Internet Information Services"),
    "microsoft-iis": ("Microsoft", "Internet Information Services"),
    "php": ("PHP", "PHP"),
    "wordpress": ("WordPress", "WordPress"),
    "drupal": ("Drupal", "Drupal"),
    "joomla": ("Joomla", "Joomla"),
    "jquery": ("jQuery", "jQuery"),
    "node.js": ("Node.js", "Node.js"),
    "express": ("Expressjs", "Express"),
    "tomcat": ("Apache", "Tomcat"),
    "apache tomcat": ("Apache", "Tomcat"),
    "openresty": ("OpenResty", "OpenResty"),
    "litespeed": ("LiteSpeed Technologies", "LiteSpeed Web Server"),
    "grafana": ("Grafana", "Grafana"),
    "jenkins": ("Jenkins", "Jenkins"),
    "gitlab": ("GitLab", "GitLab"),
    "spring": ("VMware", "Spring Framework"),
    "next.js": ("Vercel", "Next.js"),
}


def _normalize(name: str, version):
    """Returns (vendor, product, version) or None if it's noise."""
    key = name.strip().lower()
    if not key or key in NOISE or any(n in key for n in _NOISE_SUBSTRINGS):
        return None
    if key in ALIASES:
        vendor, product = ALIASES[key]
        return vendor, product, version
    return name.strip(), name.strip(), version


def _parse_server_header(value: str):
    """'nginx/1.18.0 (Ubuntu)' -> ('nginx', '1.18.0'); 'cloudflare' -> ('cloudflare', None)."""
    if not value:
        return None
    first = value.split()[0]
    if "/" in first:
        n, v = first.split("/", 1)
        return n.strip(), (v.strip() or None)
    return first.strip(), None


def is_available(_which=None) -> bool:
    which = _which or shutil.which
    return which(HTTPX_BINARY) is not None


def _parse_tech_string(tech: str):
    """'Nginx:1.18.0' -> ('Nginx', '1.18.0'); 'WordPress' -> ('WordPress', None)."""
    if ":" in tech:
        vendor, version = tech.split(":", 1)
        return vendor.strip(), (version.strip() or None)
    return tech.strip(), None


def parse_httpx_output(raw_stdout: str) -> list:
    """httpx -json emits one JSON object per line. Combines the
    Wappalyzer 'tech' list AND the Server header ('webserver'), drops
    non-software noise (HSTS, CDNs, fonts...), normalizes names to what
    CISA/NVD use, and de-duplicates (preferring the entry that has a
    version). Returns [{"vendor","product","version"}]."""
    found = {}   # (vendor.lower, product.lower) -> dict

    def add(name, version):
        norm = _normalize(name, version)
        if not norm:
            return
        vendor, product, ver = norm
        key = (vendor.lower(), product.lower())
        if key not in found or (ver and not found[key]["version"]):
            found[key] = {"vendor": vendor, "product": product, "version": ver}

    for line in raw_stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue  # a stray non-JSON line (banner, warning) must not crash parsing
        for tech in row.get("tech", []) or []:
            name, version = _parse_tech_string(tech)
            if name:
                add(name, version)
        srv = _parse_server_header(row.get("webserver", ""))
        if srv:
            add(srv[0], srv[1])
    return list(found.values())


def run_httpx(target: str, timeout: int = HTTPX_TIMEOUT_SECONDS, _runner=None) -> tuple:
    """Returns (technologies, error). _runner is injectable for tests —
    it must behave like subprocess.run and accept the same args."""
    if not is_available():
        return [], "httpx binary not found on PATH (see scripts/install_httpx.sh)"

    runner = _runner or subprocess.run
    cmd = [HTTPX_BINARY, "-u", target, "-tech-detect", "-json", "-silent",
           "-web-server", "-timeout", str(timeout), "-no-color", "-follow-host-redirects",
           "-H", f"User-Agent: {random_ua()}"]
    try:
        proc = runner(cmd, capture_output=True, text=True, timeout=timeout + 10)
    except subprocess.TimeoutExpired:
        return [], f"httpx timed out after {timeout + 10}s on {target}"
    except FileNotFoundError:
        return [], "httpx binary not found on PATH"
    except Exception as e:  # a recon tool must never take the whole hunt down with it
        return [], f"httpx failed unexpectedly: {type(e).__name__}: {e}"

    if proc.returncode not in (0, 1):  # httpx returns 1 on "no results", not an error
        return [], f"httpx exited {proc.returncode}: {(proc.stderr or '').strip()[:300]}"

    return parse_httpx_output(proc.stdout), None


def fingerprint_targets(target_domains: list, timeout: int = HTTPX_TIMEOUT_SECONDS,
                         _runner=None) -> dict:
    """Fingerprints each domain independently — one failing/offline target
    must not stop the others. Returns {domain: {"technologies": [...],
    "error": str|None}}."""
    results = {}
    for domain in target_domains:
        techs, error = run_httpx(domain, timeout=timeout, _runner=_runner)
        results[domain] = {"technologies": techs, "error": error}
    return results

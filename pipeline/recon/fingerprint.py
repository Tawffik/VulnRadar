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

HTTPX_TIMEOUT_SECONDS = 25
HTTPX_BINARY = "httpx"


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
    """httpx -json emits one JSON object per line. Returns a de-duplicated
    list of {"vendor": ..., "product": ..., "version": ...}. vendor and
    product are set equal (httpx doesn't separate them) — the matcher
    already treats vendor-OR-product as a hit, and having both lets a
    version-aware target file (see build_target_technologies) be built
    directly from this without re-shaping."""
    seen = set()
    techs = []
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
            if not name:
                continue
            key = (name.lower(), version)
            if key in seen:
                continue
            seen.add(key)
            techs.append({"vendor": name, "product": name, "version": version})
    return techs


def run_httpx(target: str, timeout: int = HTTPX_TIMEOUT_SECONDS, _runner=None) -> tuple:
    """Returns (technologies, error). _runner is injectable for tests —
    it must behave like subprocess.run and accept the same args."""
    if not is_available():
        return [], "httpx binary not found on PATH (see scripts/install_httpx.sh)"

    runner = _runner or subprocess.run
    cmd = [HTTPX_BINARY, "-u", target, "-tech-detect", "-json", "-silent",
           "-timeout", str(timeout), "-no-color", "-follow-host-redirects"]
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

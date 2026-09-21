#!/usr/bin/env python3
"""
pipeline/recon/subdomains.py

Optional passive subdomain discovery with ProjectDiscovery's `subfinder`
(-passive: queries public sources like certificate transparency; it does
NOT touch the target). Protected apex domains often hide their stack
(e.g. okx.com only shows "HSTS"), while subdomains frequently expose it.

Opt-in per target via `discover_subdomains: true` in targets/*.yaml, and
capped by `max_subdomains` (default 15) so one big target can't blow up
the run. Discovered hosts are only FINGERPRINTED (a normal HTTP request);
nuclei is never run on subdomains — scan_allowed applies to the exact
domain in `target:` only.

Never raises: any failure returns ([], error).
"""
import shutil
import subprocess

SUBFINDER_BINARY = "subfinder"
DEFAULT_MAX = 15


def is_available() -> bool:
    return shutil.which(SUBFINDER_BINARY) is not None


def discover(domain: str, max_results: int = DEFAULT_MAX, timeout: int = 60, _runner=None) -> tuple:
    if not is_available() and _runner is None:
        return [], "subfinder binary not found on PATH"
    runner = _runner or subprocess.run
    try:
        proc = runner([SUBFINDER_BINARY, "-d", domain, "-passive", "-silent", "-timeout", "30"],
                      capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return [], f"subfinder timed out on {domain}"
    except Exception as e:
        return [], f"subfinder failed: {type(e).__name__}: {e}"
    hosts = []
    for line in (proc.stdout or "").splitlines():
        h = line.strip().lower()
        # stay strictly inside the target: only the domain itself or its subdomains
        if h and (h == domain or h.endswith("." + domain)) and "*" not in h and h not in hosts:
            hosts.append(h)
    hosts.sort(key=lambda h: (h != domain, len(h), h))   # apex first, then shortest
    return hosts[:max_results], None

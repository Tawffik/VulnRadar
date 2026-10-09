"""
pipeline/monitor/probe.py

Resolve hostnames and check HTTP(S) liveness. No nuclei, no fuzzing.

Prefer ProjectDiscovery httpx when available (batch, -silent -sc).
Fallback: stdlib socket + urllib for offline-friendly unit tests via hooks.
"""
from __future__ import annotations

import shutil
import socket
import subprocess
import urllib.error
import urllib.request
from typing import Callable, Iterable, List, Optional, Tuple

from pipeline.recon.user_agents import random_ua

HTTPX_BINARY = "httpx"
DEFAULT_TIMEOUT = 8


def is_httpx_available() -> bool:
    return shutil.which(HTTPX_BINARY) is not None


def resolve_host(host: str, timeout: float = 3.0) -> bool:
    """True if DNS resolves to at least one address."""
    host = (host or "").strip().lower()
    if not host:
        return False
    try:
        socket.setdefaulttimeout(timeout)
        socket.getaddrinfo(host, None)
        return True
    except OSError:
        return False


def http_live(url: str, timeout: int = DEFAULT_TIMEOUT) -> bool:
    """True if any HTTP response is received (including 4xx/5xx)."""
    req = urllib.request.Request(
        url,
        method="GET",
        headers={"User-Agent": random_ua()},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp.read(64)
            return True
    except urllib.error.HTTPError:
        # server answered — live
        return True
    except Exception:
        return False


def probe_hosts_stdlib(
    hosts: Iterable[str],
    timeout: int = DEFAULT_TIMEOUT,
    _resolve: Optional[Callable[[str], bool]] = None,
    _http: Optional[Callable[[str], bool]] = None,
) -> Tuple[List[str], List[str]]:
    """
    Returns (live_hosts, unresolved_or_dead).
    Tries https then http. Only marks live if TCP/HTTP responds.
    """
    resolve = _resolve or resolve_host
    http = _http or http_live
    live: List[str] = []
    dead: List[str] = []
    for h in hosts:
        h = (h or "").strip().lower()
        if not h:
            continue
        if not resolve(h):
            dead.append(h)
            continue
        ok = http(f"https://{h}/") or http(f"http://{h}/")
        if ok:
            live.append(h)
        else:
            dead.append(h)
    return live, dead


def probe_hosts_httpx(
    hosts: Iterable[str],
    timeout: int = DEFAULT_TIMEOUT,
    _runner=None,
) -> Tuple[List[str], Optional[str]]:
    """
    Batch probe with httpx. Returns (live_hostnames, error_or_None).
    """
    hosts = [h.strip().lower() for h in hosts if h and h.strip()]
    if not hosts:
        return [], None
    if not is_httpx_available() and _runner is None:
        return [], "httpx binary not found on PATH"

    runner = _runner or subprocess.run
    urls = "\n".join(f"https://{h}" for h in hosts)
    try:
        proc = runner(
            [
                HTTPX_BINARY,
                "-silent",
                "-sc",
                "-timeout", str(timeout),
                "-retries", "0",
                "-no-color",
            ],
            input=urls,
            capture_output=True,
            text=True,
            timeout=max(60, timeout * max(1, len(hosts) // 5)),
        )
    except subprocess.TimeoutExpired:
        return [], "httpx timed out"
    except Exception as e:
        return [], f"httpx failed: {type(e).__name__}: {e}"

    live = []
    seen = set()
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        # httpx may print URL or URL [status]
        url = line.split()[0]
        host = url
        for prefix in ("https://", "http://"):
            if host.startswith(prefix):
                host = host[len(prefix):]
        host = host.split("/")[0].split(":")[0].lower()
        if host and host not in seen:
            seen.add(host)
            live.append(host)
    return live, None


def probe_hosts(hosts: Iterable[str], timeout: int = DEFAULT_TIMEOUT) -> Tuple[List[str], dict]:
    """
    Prefer httpx; fall back to stdlib. meta explains path taken.
    """
    hosts = [h.strip().lower() for h in hosts if h and h.strip()]
    meta = {"method": None, "error": None, "input_count": len(hosts)}
    if not hosts:
        meta["method"] = "empty"
        return [], meta

    if is_httpx_available():
        live, err = probe_hosts_httpx(hosts, timeout=timeout)
        meta["method"] = "httpx"
        meta["error"] = err
        if err is None:
            return sorted(set(live)), meta
        # fall through on error

    live, _dead = probe_hosts_stdlib(hosts, timeout=timeout)
    meta["method"] = "stdlib" if meta["method"] is None else f"{meta['method']}+stdlib_fallback"
    return sorted(set(live)), meta

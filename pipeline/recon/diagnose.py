#!/usr/bin/env python3
"""
pipeline/recon/diagnose.py

A single plain GET request, logged with enough detail to answer one
question honestly: is a target returning "no fingerprint signal"
because it's genuinely blocking the request (WAF/IP-based reject), or
because it responds completely normally and there's just nothing
recognizable in the response? Those look identical from httpx's
"0 technologies detected" output alone - this module exists to stop
guessing between them.

Never raises. Never retried, never rate-limit-sensitive - this is one
diagnostic request per target per run, logged to stdout so it shows up
directly in the Actions run log next to the fingerprint result.
"""
import urllib.error
import urllib.request

from pipeline.recon.user_agents import random_ua

TIMEOUT = 10

# Status codes/signatures commonly associated with active blocking,
# as opposed to a normal (if uninformative) 200/301/404.
BLOCK_LIKE_STATUS = {403, 406, 429, 503, 999}
BLOCK_LIKE_BODY_MARKERS = (
    "access denied", "request blocked", "captcha", "cloudflare ray id",
    "sorry, you have been blocked", "attention required",
)


def diagnose_target(domain: str, timeout: int = TIMEOUT) -> dict:
    """Returns {"status": int|None, "server_header": str, "body_len": int,
    "likely_blocked": bool, "summary": str}. Never raises."""
    url = domain if domain.startswith("http") else f"https://{domain}"
    req = urllib.request.Request(url, headers={"User-Agent": random_ua()})

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            server = resp.headers.get("Server", "") or ""
            body = resp.read(20_000).decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        status = e.code
        server = e.headers.get("Server", "") if e.headers else ""
        body = ""
        try:
            body = e.read(20_000).decode("utf-8", "ignore")
        except Exception:
            pass
    except urllib.error.URLError as e:
        return {"status": None, "server_header": "", "body_len": 0,
                "likely_blocked": True,
                "summary": f"connection failed ({e.reason}) — could be network-level blocking, DNS failure, or the runner's own egress rules"}
    except Exception as e:
        return {"status": None, "server_header": "", "body_len": 0,
                "likely_blocked": False,
                "summary": f"diagnostic request errored unexpectedly: {type(e).__name__}: {e}"}

    body_lower = body.lower()
    marker_hit = next((m for m in BLOCK_LIKE_BODY_MARKERS if m in body_lower), None)
    likely_blocked = status in BLOCK_LIKE_STATUS or marker_hit is not None

    if likely_blocked:
        reason = f"status {status}" + (f", body mentions '{marker_hit}'" if marker_hit else "")
        summary = f"HTTP {status}, looks like active blocking ({reason}) — Server: '{server or 'not sent'}'"
    else:
        summary = (f"HTTP {status}, no block signature — responded normally, "
                    f"{len(body)} bytes, Server: '{server or 'not sent'}' "
                    f"(if httpx still finds 0 technologies, the site just isn't leaking a fingerprint, not blocking)")

    return {"status": status, "server_header": server, "body_len": len(body),
            "likely_blocked": likely_blocked, "summary": summary}

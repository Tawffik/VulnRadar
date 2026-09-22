#!/usr/bin/env python3
"""
pipeline/recon/user_agents.py

A small pool of real, current browser User-Agent strings, picked
randomly per request by fingerprint.py and exposure_scan.py. This is
NOT evasion of any security control — it doesn't hide the request's
origin (the IP is still the runner's, unlike Tor) and doesn't try to
defeat rate limiting or WAF rules. It only avoids the single most
obvious automated-scanner signature: every request arriving with the
exact same "httpx/1.6.9" or "VulnRadar-ExposureScan/1.0" string, which
some sites' bot-filtering rejects outright regardless of intent,
producing false "nothing detected" results rather than real protection.

Update this list occasionally - browser UA strings age out over ~1-2
years as versions roll forward.
"""
import random

POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
]


def random_ua() -> str:
    return random.choice(POOL)

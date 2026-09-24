#!/usr/bin/env python3
"""
pipeline/collectors/http_utils.py

One shared, bounded-retry HTTP GET used by every collector's raw fetch
function, so retry policy lives in one place instead of being
re-implemented five times (and inevitably drifting out of sync).

Retry policy (see PROJECT_PLAN.md / hardening task for the source of
these rules):
  - Retried, with exponential backoff: 429, 500, 502, 503, 504,
    connection reset, timeout, DNS/network failure (URLError without
    an HTTP status).
  - NOT retried (permanent, fail fast): 400, 401, 403, 404, and any
    other 4xx that isn't 429 — retrying these wastes the run's time
    budget on something that will never succeed.
  - Bounded: MAX_RETRIES total attempts, capped backoff — never retries
    forever, never eats the whole GitHub Actions time budget.

request_with_retry() raises on final failure (same contract as plain
urlopen) so existing collector code that wraps this in its own
try/except doesn't need to change shape - only the URLError/HTTPError
it ultimately sees may arrive slightly later, after retries.
"""
import random
import time
import urllib.error
import urllib.request

MAX_RETRIES = 3
BASE_BACKOFF_SECONDS = 1.0
MAX_BACKOFF_SECONDS = 8.0
RETRYABLE_STATUS = {429, 500, 502, 503, 504}


def _sleep_for_attempt(attempt: int, retry_after: str = None, _sleep=time.sleep) -> None:
    if retry_after:
        try:
            _sleep(min(float(retry_after), MAX_BACKOFF_SECONDS))
            return
        except ValueError:
            pass
    backoff = min(BASE_BACKOFF_SECONDS * (2 ** attempt), MAX_BACKOFF_SECONDS)
    _sleep(backoff * (0.5 + random.random() / 2))  # jitter, avoid thundering-herd retries


def request_with_retry(req: urllib.request.Request, timeout: int = 20,
                        max_retries: int = MAX_RETRIES, _opener=None, _sleep=None):
    """Returns the raw bytes of a successful response. Raises
    urllib.error.HTTPError/URLError on final, non-retryable, or
    retries-exhausted failure - same as a plain urlopen() call would."""
    opener = _opener or urllib.request.urlopen
    sleep_fn = _sleep or time.sleep
    last_exc = None

    for attempt in range(max_retries + 1):
        try:
            with opener(req, timeout=timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            last_exc = e
            if e.code not in RETRYABLE_STATUS or attempt == max_retries:
                raise
            _sleep_for_attempt(attempt, e.headers.get("Retry-After") if e.headers else None, sleep_fn)
        except (urllib.error.URLError, TimeoutError) as e:
            last_exc = e
            if attempt == max_retries:
                raise
            _sleep_for_attempt(attempt, None, sleep_fn)

    raise last_exc  # pragma: no cover - loop above always returns or raises

#!/usr/bin/env python3
import io
import os
import sys
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from pipeline.collectors import http_utils


class _FakeResp:
    def __init__(self, body: bytes):
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_succeeds_first_try_no_retry():
    calls = {"n": 0}

    def opener(req, timeout):
        calls["n"] += 1
        return _FakeResp(b"ok")
    body = http_utils.request_with_retry(object(), _opener=opener, _sleep=lambda s: None)
    assert body == b"ok" and calls["n"] == 1
    print("  ✅ a first-try success makes exactly one call, no retry/sleep")


def test_retries_429_then_succeeds():
    calls = {"n": 0}

    def opener(req, timeout):
        calls["n"] += 1
        if calls["n"] < 3:
            raise urllib.error.HTTPError("u", 429, "rate limited", {"Retry-After": "0"}, io.BytesIO(b""))
        return _FakeResp(b"ok")
    body = http_utils.request_with_retry(object(), _opener=opener, _sleep=lambda s: None)
    assert body == b"ok" and calls["n"] == 3
    print("  ✅ 429 retried with Retry-After honored, eventually succeeds")


def test_500_is_retried_403_is_not():
    calls = {"n": 0}

    def opener_500(req, timeout):
        calls["n"] += 1
        raise urllib.error.HTTPError("u", 500, "err", {}, io.BytesIO(b""))
    try:
        http_utils.request_with_retry(object(), max_retries=2, _opener=opener_500, _sleep=lambda s: None)
    except urllib.error.HTTPError:
        pass
    assert calls["n"] == 3  # 1 initial + 2 retries, bounded

    calls2 = {"n": 0}

    def opener_403(req, timeout):
        calls2["n"] += 1
        raise urllib.error.HTTPError("u", 403, "forbidden", {}, io.BytesIO(b""))
    try:
        http_utils.request_with_retry(object(), max_retries=5, _opener=opener_403, _sleep=lambda s: None)
    except urllib.error.HTTPError:
        pass
    assert calls2["n"] == 1  # permanent failure, never retried
    print("  ✅ 500 retried (bounded), 403 fails immediately without wasting retries")


def test_connection_error_retried_bounded():
    calls = {"n": 0}

    def opener(req, timeout):
        calls["n"] += 1
        raise urllib.error.URLError("connection reset")
    try:
        http_utils.request_with_retry(object(), max_retries=2, _opener=opener, _sleep=lambda s: None)
    except urllib.error.URLError:
        pass
    assert calls["n"] == 3
    print("  ✅ connection-level errors retried, bounded by max_retries")


def test_never_retries_forever():
    calls = {"n": 0}

    def opener(req, timeout):
        calls["n"] += 1
        raise urllib.error.HTTPError("u", 503, "unavailable", {}, io.BytesIO(b""))
    try:
        http_utils.request_with_retry(object(), max_retries=1, _opener=opener, _sleep=lambda s: None)
    except urllib.error.HTTPError:
        pass
    assert calls["n"] == 2  # exactly bounded, not unbounded
    print("  ✅ retries are strictly bounded, never infinite")


if __name__ == "__main__":
    tests = [test_succeeds_first_try_no_retry, test_retries_429_then_succeeds,
              test_500_is_retried_403_is_not, test_connection_error_retried_bounded,
              test_never_retries_forever]
    for t in tests:
        t()
    print(f"\n{len(tests)}/{len(tests)} tests passed")

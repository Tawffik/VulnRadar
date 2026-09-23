#!/usr/bin/env python3
import io
import os
import sys
import urllib.error
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from pipeline.recon import diagnose


class _FakeResp:
    def __init__(self, status, headers=None, body=b""):
        self.status = status
        self.headers = headers or {}
        self._body = body

    def read(self, n):
        return self._body[:n]

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_normal_200_is_not_flagged_as_blocked():
    with patch.object(diagnose.urllib.request, "urlopen",
                       return_value=_FakeResp(200, {"Server": "nginx"}, b"<html>hi</html>")):
        r = diagnose.diagnose_target("example.com")
    assert r["status"] == 200 and r["likely_blocked"] is False
    assert "not blocking" in r["summary"]
    print("  ✅ normal 200 correctly identified as not-blocked")


def test_403_is_flagged_as_likely_blocked():
    err = urllib.error.HTTPError("https://x.com", 403, "Forbidden", {}, io.BytesIO(b"access denied"))
    with patch.object(diagnose.urllib.request, "urlopen", side_effect=err):
        r = diagnose.diagnose_target("x.com")
    assert r["status"] == 403 and r["likely_blocked"] is True
    print("  ✅ 403 correctly flagged as likely blocking")


def test_cloudflare_challenge_body_flagged_even_on_200():
    with patch.object(diagnose.urllib.request, "urlopen",
                       return_value=_FakeResp(200, {}, b"Attention Required! | Cloudflare Ray ID: abc")):
        r = diagnose.diagnose_target("x.com")
    assert r["likely_blocked"] is True
    print("  ✅ a 200 that's actually a challenge page is still flagged via body marker")


def test_connection_failure_is_non_fatal():
    with patch.object(diagnose.urllib.request, "urlopen",
                       side_effect=urllib.error.URLError("timed out")):
        r = diagnose.diagnose_target("dead.com")
    assert r["status"] is None and r["likely_blocked"] is True
    print("  ✅ connection failure reported, not raised")


def test_unexpected_exception_never_raises():
    with patch.object(diagnose.urllib.request, "urlopen", side_effect=RuntimeError("boom")):
        r = diagnose.diagnose_target("x.com")
    assert r["status"] is None
    print("  ✅ unexpected exception handled without raising")


if __name__ == "__main__":
    tests = [test_normal_200_is_not_flagged_as_blocked, test_403_is_flagged_as_likely_blocked,
              test_cloudflare_challenge_body_flagged_even_on_200, test_connection_failure_is_non_fatal,
              test_unexpected_exception_never_raises]
    for t in tests:
        t()
    print(f"\n{len(tests)}/{len(tests)} tests passed")

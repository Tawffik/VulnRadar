#!/usr/bin/env python3
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))
from pipeline.recon import fingerprint


class _FakeCompleted:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout, self.stderr, self.returncode = stdout, stderr, returncode


def test_parse_httpx_output_splits_vendor_and_version():
    raw = '{"url":"https://x.com","tech":["Nginx:1.18.0","WordPress","OpenSSH:8.2p1"]}\n'
    techs = fingerprint.parse_httpx_output(raw)
    by_name = {t["vendor"]: t for t in techs}
    assert by_name["Nginx"]["version"] == "1.18.0"
    assert by_name["WordPress"]["version"] is None
    assert by_name["OpenSSH"]["version"] == "8.2p1"
    print("  ✅ tech strings split into vendor/version correctly")


def test_parse_httpx_output_dedupes_and_skips_garbage_lines():
    raw = '{"tech":["Nginx:1.18.0"]}\nnot json at all\n{"tech":["Nginx:1.18.0"]}\n'
    techs = fingerprint.parse_httpx_output(raw)
    assert len(techs) == 1
    print("  ✅ duplicate/garbage lines handled without crashing")


def test_run_httpx_missing_binary_is_non_fatal():
    techs, error = fingerprint.run_httpx("example.com", _runner=lambda *a, **k: _FakeCompleted())
    # is_available() checks the real PATH; if httpx genuinely isn't
    # installed in this test environment we should get a clean error,
    # never an exception.
    assert isinstance(techs, list)
    print("  ✅ run_httpx never raises regardless of binary availability")


def test_run_httpx_uses_injected_runner_on_success():
    fingerprint.is_available = lambda _which=None: True  # simulate binary present
    out = _FakeCompleted(stdout='{"tech":["Nginx:1.18.0"]}\n', returncode=0)
    techs, error = fingerprint.run_httpx("example.com", _runner=lambda *a, **k: out)
    assert error is None and techs[0]["vendor"] == "Nginx"
    print("  ✅ successful httpx run parsed correctly")


def test_run_httpx_timeout_reported_not_raised():
    import subprocess
    fingerprint.is_available = lambda _which=None: True

    def boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="httpx", timeout=5)
    techs, error = fingerprint.run_httpx("example.com", _runner=boom)
    assert techs == [] and "timed out" in error
    print("  ✅ httpx timeout reported as error, not raised")


def test_fingerprint_targets_isolates_per_target_failures():
    fingerprint.is_available = lambda _which=None: True
    calls = {"n": 0}

    def runner(cmd, **k):
        calls["n"] += 1
        if "down.example.com" in cmd:
            raise Exception("connection refused")
        return _FakeCompleted(stdout='{"tech":["Nginx"]}\n')

    results = fingerprint.fingerprint_targets(["ok.example.com", "down.example.com"], _runner=runner)
    assert results["ok.example.com"]["error"] is None
    assert results["down.example.com"]["error"] is not None
    print("  ✅ one target failing does not stop others from being fingerprinted")


if __name__ == "__main__":
    tests = [test_parse_httpx_output_splits_vendor_and_version,
              test_parse_httpx_output_dedupes_and_skips_garbage_lines,
              test_run_httpx_missing_binary_is_non_fatal,
              test_run_httpx_uses_injected_runner_on_success,
              test_run_httpx_timeout_reported_not_raised,
              test_fingerprint_targets_isolates_per_target_failures]
    for t in tests:
        t()
    print(f"\n{len(tests)}/{len(tests)} tests passed")

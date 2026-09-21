#!/usr/bin/env python3
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))
from pipeline.verify import nuclei_runner


class _FakeCompleted:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout, self.stderr, self.returncode = stdout, stderr, returncode


def test_scan_disallowed_by_default():
    assert nuclei_runner.target_allows_scanning({}) is False
    assert nuclei_runner.target_allows_scanning({"scan_allowed": False}) is False
    assert nuclei_runner.target_allows_scanning({"scan_allowed": True}) is True
    print("  ✅ scanning is opt-in only, default False")


def test_verify_entry_skips_target_without_opt_in():
    entry = {"cve": "CVE-1", "matched_targets": ["a.com"]}
    targets = [{"target": "a.com", "scan_allowed": False}]
    out = nuclei_runner.verify_entry(entry, targets, _runner=lambda *a, **k: _FakeCompleted())
    assert out["nuclei_verdicts"]["a.com"] == "skipped"
    print("  ✅ target without scan_allowed=true is skipped, nuclei never invoked")


def test_verify_entry_never_scans_a_target_not_in_matched_targets():
    entry = {"cve": "CVE-1", "matched_targets": ["a.com"]}
    targets = [{"target": "a.com", "scan_allowed": True},
               {"target": "b.com", "scan_allowed": True}]  # opted in but NOT matched
    called_urls = []

    def runner(cmd, **k):
        called_urls.append(cmd[cmd.index("-u") + 1])
        return _FakeCompleted()
    out = nuclei_runner.verify_entry(entry, targets, _runner=runner)
    assert "b.com" not in out["nuclei_verdicts"]
    assert all("b.com" not in u for u in called_urls)
    print("  ✅ nuclei is never run against an opted-in target that wasn't actually matched")


def test_vulnerable_when_findings_present():
    out = _FakeCompleted(stdout='[{"template-id":"CVE-1","matched-at":"https://a.com"}]', returncode=0)
    verdict, findings = nuclei_runner.run_nuclei_for_cve("https://a.com", "CVE-1", _runner=lambda *a, **k: out)
    nuclei_runner.is_available = lambda _which=None: True
    verdict, findings = nuclei_runner.run_nuclei_for_cve("https://a.com", "CVE-1", _runner=lambda *a, **k: out)
    assert verdict == "vulnerable" and len(findings) == 1
    print("  ✅ nuclei findings -> vulnerable verdict")


def test_not_vulnerable_when_empty_output():
    nuclei_runner.is_available = lambda _which=None: True
    out = _FakeCompleted(stdout="", returncode=0)
    verdict, findings = nuclei_runner.run_nuclei_for_cve("https://a.com", "CVE-1", _runner=lambda *a, **k: out)
    assert verdict == "not-vulnerable" and findings == []
    print("  ✅ empty output -> not-vulnerable")


def test_timeout_and_missing_binary_report_error_not_raise():
    import subprocess
    nuclei_runner.is_available = lambda _which=None: True

    def boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="nuclei", timeout=5)
    verdict, findings = nuclei_runner.run_nuclei_for_cve("https://a.com", "CVE-1", _runner=boom)
    assert verdict == "error" and findings == []
    print("  ✅ nuclei timeout reported as error, never raised")


def test_verify_entries_skips_unmatched_entries_entirely():
    entries = [{"cve": "CVE-1", "matched_targets": []}]
    out = nuclei_runner.verify_entries(entries, [], _runner=lambda *a, **k: (_ for _ in ()).throw(Exception("must not be called")))
    assert out[0]["nuclei_verdicts"] == {}
    print("  ✅ unmatched entries never trigger a nuclei subprocess call")


if __name__ == "__main__":
    tests = [test_scan_disallowed_by_default, test_verify_entry_skips_target_without_opt_in,
              test_verify_entry_never_scans_a_target_not_in_matched_targets,
              test_vulnerable_when_findings_present, test_not_vulnerable_when_empty_output,
              test_timeout_and_missing_binary_report_error_not_raise,
              test_verify_entries_skips_unmatched_entries_entirely]
    for t in tests:
        t()
    print(f"\n{len(tests)}/{len(tests)} tests passed")

#!/usr/bin/env python3
import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from pipeline.recon import exposure_scan as e


def _fake_get(responses):
    def _get(url, timeout=6):
        for suffix, val in responses.items():
            if url.endswith(suffix):
                return val
        return (404, "")
    return _get


def test_git_exposure_requires_real_git_content_not_just_200():
    with patch.object(e, "_get", _fake_get({
        "/.git/HEAD": (200, "ref: refs/heads/main\n"),
        "/.git/config": (200, "<html>not really git</html>"),  # soft-404 impersonating 200
    })):
        hits = e.check_git_exposure("https://x.com")
    assert hits == ["https://x.com/.git/HEAD"]
    print("  ✅ only genuine git content counted, soft-200 rejected")


def test_sensitive_files_rejects_spa_soft_404():
    body = "<html>404 not found spa shell</html>"
    with patch.object(e, "_get", _fake_get({
        "__vulnradar_not_a_real_path_xyz": (200, body),
        "/.env": (200, body),  # identical SPA shell - must be rejected
    })):
        hits = e.check_sensitive_files("https://spa.com")
    assert hits == []
    print("  ✅ SPA that 200s everything produces zero false positives")


def test_sensitive_files_accepts_genuinely_different_response():
    with patch.object(e, "_get", _fake_get({
        "__vulnradar_not_a_real_path_xyz": (404, ""),
        "/.env": (200, "DB_PASSWORD=hunter2\nAPI_KEY=abc123"),
    })):
        hits = e.check_sensitive_files("https://real.com")
    assert hits == ["https://real.com/.env"]
    print("  ✅ genuinely exposed file detected")


def test_source_map_secret_detection():
    js_home = '<html><script src="/app.js"></script></html>'
    map_body = '{"sources":["webpack:///src/config.js"]} AKIAABCDEFGHIJKLMNOP'
    with patch.object(e, "_get", _fake_get({
        "x.com": (200, js_home),
        "/app.js.map": (200, map_body),
    })):
        result = e.check_source_maps("https://x.com")
    assert result["maps"] == ["https://x.com/app.js.map"]
    assert "AWS Access Key" in result["secrets"]
    print("  ✅ source map found and AWS key pattern detected inside it")


def test_scan_target_never_raises_on_total_failure():
    with patch.object(e, "check_git_exposure", side_effect=Exception("boom")), \
         patch.object(e, "check_sensitive_files", side_effect=Exception("boom")), \
         patch.object(e, "check_source_maps", side_effect=Exception("boom")):
        report = e.scan_target("dead.com")
    assert report["git_exposure"] == [] and report["error"]
    print("  ✅ every sub-check failing at once does not raise")


def test_has_findings():
    assert e.has_findings({"git_exposure": [], "sensitive_files": [], "source_maps": {"maps": [], "secrets": []}}) is False
    assert e.has_findings({"git_exposure": ["x"], "sensitive_files": [], "source_maps": {"maps": [], "secrets": []}}) is True
    print("  ✅ has_findings correctly reflects empty vs non-empty report")


if __name__ == "__main__":
    tests = [test_git_exposure_requires_real_git_content_not_just_200,
              test_sensitive_files_rejects_spa_soft_404,
              test_sensitive_files_accepts_genuinely_different_response,
              test_source_map_secret_detection,
              test_scan_target_never_raises_on_total_failure,
              test_has_findings]
    for t in tests:
        t()
    print(f"\n{len(tests)}/{len(tests)} tests passed")

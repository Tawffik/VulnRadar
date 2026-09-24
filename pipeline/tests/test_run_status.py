#!/usr/bin/env python3
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from pipeline.intelligence.run_status import (
    classify_error, CollectorResult, TargetResult, RunSummary,
    SUCCESS, EMPTY, FAILED, TIMEOUT, RATE_LIMITED, INVALID_RESPONSE,
    RUN_SUCCESS, RUN_DEGRADED, RUN_FAILED, EXIT_SUCCESS, EXIT_DEGRADED, EXIT_FATAL,
)


def test_classify_success_and_empty():
    assert classify_error(None, 5) == SUCCESS
    assert classify_error(None, 0) == EMPTY
    print("  ✅ no error + count>0 -> SUCCESS, count==0 -> EMPTY (never confused)")


def test_classify_error_buckets():
    assert classify_error("fetch failed: HTTP Error 429: Too Many Requests", 0) == RATE_LIMITED
    assert classify_error("fetch failed: timed out", 0) == TIMEOUT
    assert classify_error("response was not valid JSON: ...", 0) == INVALID_RESPONSE
    assert classify_error("response JSON had no 'vulnerabilities' key — feed format may have changed", 0) == INVALID_RESPONSE
    assert classify_error("fetch failed: HTTP Error 403: Forbidden", 0) == FAILED
    print("  ✅ error strings classified into the right bucket")


def test_collector_result_is_ok():
    assert CollectorResult("x", [{"cve": "A"}], None).is_ok() is True
    assert CollectorResult("x", [], None).is_ok() is True         # EMPTY is still ok
    assert CollectorResult("x", [], "boom").is_ok() is False
    print("  ✅ EMPTY counts as ok, FAILED does not")


def test_run_summary_all_ok_is_success():
    s = RunSummary()
    for name in ["a", "b"]:
        s.add_collector(CollectorResult(name, [{"cve": "X"}], None))
    assert s.overall_status() == RUN_SUCCESS
    assert s.exit_code() == EXIT_SUCCESS
    print("  ✅ all collectors ok, no targets -> SUCCESS / exit 0")


def test_run_summary_one_failure_is_degraded():
    s = RunSummary()
    s.add_collector(CollectorResult("cisa_kev", [], "HTTP 403", previous_state_used=True))
    s.add_collector(CollectorResult("cve_org", [{"cve": "X"}], None))
    assert s.overall_status() == RUN_DEGRADED
    assert s.exit_code() == EXIT_DEGRADED
    print("  ✅ one source failed, others ok -> DEGRADED / exit 10")


def test_run_summary_all_failed_no_fallback_is_failed():
    s = RunSummary()
    s.add_collector(CollectorResult("cisa_kev", [], "HTTP 403", previous_state_used=False))
    s.add_collector(CollectorResult("cve_org", [], "timeout", previous_state_used=False))
    assert s.overall_status() == RUN_FAILED
    assert s.exit_code() == EXIT_FATAL
    print("  ✅ every source failed AND no previous state anywhere -> FAILED / exit 20")


def test_run_summary_all_failed_but_fallback_available_is_degraded_not_failed():
    """This is the important distinction from acceptance-criteria Scenario G:
    'no usable intelligence' (FAILED) is different from 'nothing new this
    run but we still have history' (DEGRADED)."""
    s = RunSummary()
    s.add_collector(CollectorResult("cisa_kev", [], "HTTP 403", previous_state_used=True))
    assert s.overall_status() == RUN_DEGRADED
    print("  ✅ all failed but a previous-state fallback exists -> DEGRADED, not FAILED")


def test_target_result_status():
    assert TargetResult("a.com", fingerprint_ok=True, exposure_ok=True).status == SUCCESS
    assert TargetResult("a.com", fingerprint_ok=False, exposure_ok=True).status == "DEGRADED"
    assert TargetResult("a.com", fingerprint_ok=False, exposure_ok=False).status == FAILED
    print("  ✅ target status reflects partial vs total failure correctly")


def test_render_markdown_and_json_do_not_raise():
    s = RunSummary()
    s.add_collector(CollectorResult("cisa_kev", [], "HTTP 403", previous_state_used=True))
    s.add_target(TargetResult("a.com", fingerprint_ok=True))
    s.set_stage("matching", "SUCCESS")
    s.warn("something to note")
    md = s.render_markdown()
    d = s.to_dict()
    assert "DEGRADED" in md and "cisa_kev" in md and d["overall"] == "DEGRADED"
    print("  ✅ markdown + json rendering both work without raising")


if __name__ == "__main__":
    tests = [test_classify_success_and_empty, test_classify_error_buckets, test_collector_result_is_ok,
              test_run_summary_all_ok_is_success, test_run_summary_one_failure_is_degraded,
              test_run_summary_all_failed_no_fallback_is_failed,
              test_run_summary_all_failed_but_fallback_available_is_degraded_not_failed,
              test_target_result_status, test_render_markdown_and_json_do_not_raise]
    for t in tests:
        t()
    print(f"\n{len(tests)}/{len(tests)} tests passed")

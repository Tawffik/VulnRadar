#!/usr/bin/env python3
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))
from pipeline.intelligence import version_check


def test_version_inside_range_is_confirmed():
    r = {"start_including": "1.18.0", "start_excluding": None, "end_including": None, "end_excluding": "1.20.0"}
    assert version_check.version_in_range("1.19.0", r) == "confirmed"
    print("  ✅ version inside [start_including, end_excluding) -> confirmed")


def test_version_outside_range_is_safe():
    r = {"start_including": "1.18.0", "start_excluding": None, "end_including": None, "end_excluding": "1.20.0"}
    assert version_check.version_in_range("1.21.0", r) == "safe"
    assert version_check.version_in_range("1.17.0", r) == "safe"
    print("  ✅ version outside range -> safe on both sides")


def test_boundary_including_vs_excluding():
    r_inc = {"start_including": "1.18.0", "start_excluding": None, "end_including": "1.20.0", "end_excluding": None}
    assert version_check.version_in_range("1.20.0", r_inc) == "confirmed"
    r_exc = {"start_including": None, "start_excluding": "1.18.0", "end_including": None, "end_excluding": "1.20.0"}
    assert version_check.version_in_range("1.18.0", r_exc) == "safe"
    print("  ✅ including vs excluding boundaries respected")


def test_no_installed_version_is_unknown():
    r = {"start_including": "1.0", "start_excluding": None, "end_including": None, "end_excluding": "2.0"}
    assert version_check.version_in_range(None, r) == "unknown"
    print("  ✅ no fingerprinted version -> unknown, never a guess")


def test_no_version_range_data_is_unknown():
    assert version_check.version_in_range("1.19.0", {}) == "unknown"
    assert version_check.version_in_range("1.19.0", None) == "unknown"
    print("  ✅ no NVD version-range data -> unknown")


def test_malformed_bound_falls_back_to_unknown_not_crash():
    r = {"start_including": "not-a-version", "start_excluding": None, "end_including": None, "end_excluding": None}
    assert version_check.version_in_range("1.19.0", r) == "unknown"
    print("  ✅ malformed CVE bound handled without crashing or false-confirming")


def test_annotate_entry_matches_by_vendor_or_product_and_picks_best():
    entry = {"cve": "CVE-1", "vendor": "nginx", "product": "nginx", "matched_targets": ["a.com"],
              "cpe_version_range": {"start_including": None, "start_excluding": None,
                                     "end_including": None, "end_excluding": "1.20.0"}}
    targets = [{"target": "a.com", "technologies": [{"vendor": "nginx", "product": "nginx", "version": "1.19.0"}]}]
    out = version_check.annotate_entry(entry, targets)
    assert out["version_verdict"] == "confirmed"
    print("  ✅ annotate_entry finds the matching technology and verdicts correctly")


def test_annotate_entry_unmatched_target_is_unknown():
    entry = {"cve": "CVE-1", "vendor": "nginx", "product": "nginx", "matched_targets": []}
    out = version_check.annotate_entry(entry, [])
    assert out["version_verdict"] == "unknown"
    print("  ✅ no matched targets -> unknown, no crash")


if __name__ == "__main__":
    tests = [test_version_inside_range_is_confirmed, test_version_outside_range_is_safe,
              test_boundary_including_vs_excluding, test_no_installed_version_is_unknown,
              test_no_version_range_data_is_unknown, test_malformed_bound_falls_back_to_unknown_not_crash,
              test_annotate_entry_matches_by_vendor_or_product_and_picks_best,
              test_annotate_entry_unmatched_target_is_unknown]
    for t in tests:
        t()
    print(f"\n{len(tests)}/{len(tests)} tests passed")

#!/usr/bin/env python3
"""
pipeline/tests/test_merge_sources.py
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, REPO_ROOT)

from pipeline.run_hunt import merge_sources


def _entry(cve, source, **extra):
    base = {"cve": cve, "vendor": "V", "product": "P", "name": "n", "date_added": "2026-01-01",
            "due_date": "", "description": "d", "required_action": "", "ransomware_use": "Unknown",
            "cwes": [], "source": source}
    base.update(extra)
    return base


def test_last_argument_wins_on_conflict():
    org = [_entry("CVE-2026-1", "cve_org")]
    kev = [_entry("CVE-2026-1", "cisa_kev", ransomware_use="Known")]
    merged = merge_sources(org, kev)  # kev is LAST -> wins, matching ascending-priority order
    assert len(merged) == 1
    assert merged[0]["ransomware_use"] == "Known"
    assert set(merged[0]["sources"]) == {"cve_org", "cisa_kev"}
    print("  ✅ later argument wins on conflict, both sources still recorded")


def test_four_source_priority_order():
    """Matches run_hunt.py's real call: merge_sources(nuclei, org, gh, nvd, kev) —
    kev (last) must win even when all five report the same CVE."""
    nuclei = [_entry("CVE-2026-9", "nuclei_templates", cvss_score=None)]
    org = [_entry("CVE-2026-9", "cve_org", cvss_score=None)]
    gh = [_entry("CVE-2026-9", "github_advisories", cvss_score=5.0)]
    nvd_e = [_entry("CVE-2026-9", "nvd", cvss_score=7.0)]
    kev = [_entry("CVE-2026-9", "cisa_kev", cvss_score=None, ransomware_use="Known")]
    merged = merge_sources(nuclei, org, gh, nvd_e, kev)
    assert len(merged) == 1
    assert merged[0]["ransomware_use"] == "Known"  # kev's data (last) wins
    assert set(merged[0]["sources"]) == {"nuclei_templates", "cve_org", "github_advisories", "nvd", "cisa_kev"}
    print("  ✅ 5-way merge: kev wins as the last/highest-priority source, all 5 sources recorded")


def test_entry_seen_by_only_one_source_is_kept():
    org = [_entry("CVE-2026-2", "cve_org")]
    merged = merge_sources(org, [], [], [])
    assert len(merged) == 1
    assert merged[0]["sources"] == ["cve_org"]
    print("  ✅ a CVE seen by only one source is kept, tagged with just that source")


def test_no_duplicate_cves_in_output():
    org = [_entry("CVE-2026-4", "cve_org")]
    kev = [_entry("CVE-2026-4", "cisa_kev"), _entry("CVE-2026-5", "cisa_kev")]
    merged = merge_sources(org, [], [], kev)
    cves = [e["cve"] for e in merged]
    assert len(cves) == len(set(cves)) == 2
    print("  ✅ no duplicate CVE entries in merged output even with overlap across sources")


def test_empty_inputs_produce_empty_output():
    assert merge_sources([], [], [], []) == []
    print("  ✅ all-empty inputs produce an empty list, not a crash")


if __name__ == "__main__":
    tests = [
        test_last_argument_wins_on_conflict,
        test_four_source_priority_order,
        test_entry_seen_by_only_one_source_is_kept,
        test_no_duplicate_cves_in_output,
        test_empty_inputs_produce_empty_output,
    ]
    failed = 0
    for t in tests:
        try:
            t()
        except AssertionError as e:
            failed += 1
            print(f"  ❌ {t.__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} tests passed")
    sys.exit(1 if failed else 0)

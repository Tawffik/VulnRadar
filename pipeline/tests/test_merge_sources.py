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


def test_kev_wins_on_conflict_but_both_sources_recorded():
    org = [_entry("CVE-2026-1", "cve_org")]
    kev = [_entry("CVE-2026-1", "cisa_kev", ransomware_use="Known")]
    merged = merge_sources(kev, org)
    assert len(merged) == 1
    assert merged[0]["ransomware_use"] == "Known"  # KEV's data wins
    assert set(merged[0]["sources"]) == {"cve_org", "cisa_kev"}  # but both are recorded
    print("  ✅ conflicting entry: KEV's data wins, both sources recorded in 'sources'")


def test_cve_org_only_entry_is_kept():
    org = [_entry("CVE-2026-2", "cve_org")]
    kev = []
    merged = merge_sources(kev, org)
    assert len(merged) == 1
    assert merged[0]["sources"] == ["cve_org"]
    print("  ✅ a CVE seen only by cve_org (not yet in KEV) is kept, tagged cve_org-only")


def test_kev_only_entry_is_kept():
    org = []
    kev = [_entry("CVE-2026-3", "cisa_kev")]
    merged = merge_sources(kev, org)
    assert len(merged) == 1
    assert merged[0]["sources"] == ["cisa_kev"]
    print("  ✅ a CVE seen only by KEV is kept, tagged cisa_kev-only")


def test_no_duplicate_cves_in_output():
    org = [_entry("CVE-2026-4", "cve_org")]
    kev = [_entry("CVE-2026-4", "cisa_kev"), _entry("CVE-2026-5", "cisa_kev")]
    merged = merge_sources(kev, org)
    cves = [e["cve"] for e in merged]
    assert len(cves) == len(set(cves)) == 2
    print("  ✅ no duplicate CVE entries in merged output even with overlap")


if __name__ == "__main__":
    tests = [
        test_kev_wins_on_conflict_but_both_sources_recorded,
        test_cve_org_only_entry_is_kept,
        test_kev_only_entry_is_kept,
        test_no_duplicate_cves_in_output,
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

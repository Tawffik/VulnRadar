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


def test_malformed_entry_missing_cve_id_does_not_crash():
    """Real robustness gap found during a pre-push audit (not from a
    live failure): a collector entry missing 'cve' entirely used to
    crash the whole run via a raw dict-index KeyError, right at the
    first place incoming data is processed. Especially plausible for
    nvd.py/github_advisories.py/nuclei_templates.py, which weren't
    live-verified during development. Now skipped with a warning
    instead."""
    good = [_entry("CVE-2026-6", "cve_org")]
    malformed = [{"vendor": "V", "product": "P", "source": "nvd"}]  # no 'cve' key at all
    merged = merge_sources(good, malformed)
    assert len(merged) == 1
    assert merged[0]["cve"] == "CVE-2026-6"
    print("  ✅ a malformed entry with no CVE ID is skipped, not a crash, valid entries still processed")


def test_full_pipeline_survives_malformed_entry_end_to_end():
    """The real end-to-end proof: merge -> diff -> match -> render, with
    one malformed entry mixed in among real ones, all the way through.
    Not just merge_sources() in isolation."""
    import tempfile
    from pipeline.intelligence import state_diff, technology_matcher
    from pipeline.reporting import hunter_queue as hq

    good = [_entry("CVE-2026-7", "cve_org", vendor="nginx", product="nginx")]
    malformed = [{"vendor": "V", "product": "P", "source": "nuclei_templates"}]  # missing 'cve'
    merged = merge_sources(good, malformed)

    with tempfile.TemporaryDirectory() as tmp:
        state_path = f"{tmp}/state.json"
        previous_state = state_diff.load_state(state_path)
        new_entries, updated_entries, _ = state_diff.diff(merged, previous_state)
        targets = [{"target": "example.com", "technologies": [{"vendor": "nginx"}]}]
        new_entries = technology_matcher.match_targets(new_entries, targets)
        md = hq.render(new_entries, [], len(targets))
        state_diff.save_state(state_path, merged)

    assert "CVE-2026-7" in md
    print("  ✅ full pipeline (merge -> diff -> match -> render -> save_state) survives a "
          "malformed entry end-to-end, real entry still reaches the final output")


if __name__ == "__main__":
    tests = [
        test_last_argument_wins_on_conflict,
        test_four_source_priority_order,
        test_entry_seen_by_only_one_source_is_kept,
        test_no_duplicate_cves_in_output,
        test_empty_inputs_produce_empty_output,
        test_malformed_entry_missing_cve_id_does_not_crash,
        test_full_pipeline_survives_malformed_entry_end_to_end,
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

#!/usr/bin/env python3
"""
pipeline/tests/test_vulnradar.py

Full test suite for VulnRadar V1, run against the realistic KEV fixture
(pipeline/tests/fixtures/kev_sample.json) — matching the exact real
CISA KEV schema, not an invented shape.

Run with: python3 pipeline/tests/test_vulnradar.py
"""
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, REPO_ROOT)

from pipeline.collectors import cisa_kev
from pipeline.intelligence import state_diff, technology_matcher
from pipeline.reporting import hunter_queue

FIXTURE = os.path.join(HERE, "fixtures", "kev_sample.json")


def test_load_and_normalize_real_schema():
    entries = cisa_kev.load_from_file(FIXTURE)
    assert len(entries) == 3
    apache = next(e for e in entries if e["cve"] == "CVE-2024-99001")
    assert apache["vendor"] == "Apache"
    assert apache["product"] == "HTTP Server"
    assert apache["ransomware_use"] == "Unknown"
    assert apache["source"] == "cisa_kev"
    print("  ✅ real CISA KEV schema normalized correctly")


def test_missing_cve_id_is_skipped_not_crashed():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump({"vulnerabilities": [{"vendorProject": "X"}, {"cveID": "CVE-2024-1"}]}, f)
        path = f.name
    try:
        entries = cisa_kev.load_from_file(path)
        assert len(entries) == 1  # the entry with no cveID is skipped
        print("  ✅ entry with missing cveID skipped, not crashed")
    finally:
        os.unlink(path)


def test_first_run_everything_is_new():
    entries = cisa_kev.load_from_file(FIXTURE)
    previous_state = state_diff.load_state("/nonexistent/path/state.json")
    assert previous_state == {}
    new, updated, unchanged = state_diff.diff(entries, previous_state)
    assert len(new) == 3
    assert len(updated) == 0
    assert unchanged == 0
    print("  ✅ first-ever run: all 3 entries correctly show as NEW")


def test_second_run_shows_nothing_new():
    entries = cisa_kev.load_from_file(FIXTURE)
    with tempfile.TemporaryDirectory() as tmp:
        state_path = os.path.join(tmp, "state.json")
        state_diff.save_state(state_path, entries)

        previous_state = state_diff.load_state(state_path)
        new, updated, unchanged = state_diff.diff(entries, previous_state)
        assert len(new) == 0
        assert len(updated) == 0
        assert unchanged == 3
        print("  ✅ second run with identical data: 0 new, 0 updated, 3 unchanged")


def test_ransomware_flag_change_is_detected_as_update():
    entries = cisa_kev.load_from_file(FIXTURE)
    with tempfile.TemporaryDirectory() as tmp:
        state_path = os.path.join(tmp, "state.json")
        state_diff.save_state(state_path, entries)

        # Simulate CISA updating CVE-2024-99001's ransomware flag from Unknown to Known
        updated_entries = [dict(e) for e in entries]
        for e in updated_entries:
            if e["cve"] == "CVE-2024-99001":
                e["ransomware_use"] = "Known"

        previous_state = state_diff.load_state(state_path)
        new, updated, unchanged = state_diff.diff(updated_entries, previous_state)
        assert len(new) == 0
        assert len(updated) == 1
        assert updated[0]["cve"] == "CVE-2024-99001"
        assert updated[0]["previous_ransomware_use"] == "Unknown"
        assert unchanged == 2
        print("  ✅ ransomware flag change on an already-known CVE correctly detected as UPDATED")


def test_technology_matcher_both_fields_required_when_both_specified():
    entries = cisa_kev.load_from_file(FIXTURE)
    targets = [{"target": "example.com", "technologies": [{"vendor": "nginx", "product": "nginx"}]}]
    results = technology_matcher.match_targets(entries, targets)
    matched = [r for r in results if r["matched_targets"]]
    assert len(matched) == 1
    assert matched[0]["cve"] == "CVE-2024-99002"
    print("  ✅ vendor+product match: only the nginx entry matched, not Apache or the unrelated one")


def test_technology_matcher_vendor_only_is_broader():
    entries = cisa_kev.load_from_file(FIXTURE)
    targets = [{"target": "example.com", "technologies": [{"vendor": "Apache"}]}]
    results = technology_matcher.match_targets(entries, targets)
    matched = [r for r in results if r["matched_targets"]]
    assert len(matched) == 1
    assert matched[0]["cve"] == "CVE-2024-99001"
    print("  ✅ vendor-only target field matches on vendor alone")


def test_no_targets_means_no_matches_but_no_crash():
    entries = cisa_kev.load_from_file(FIXTURE)
    results = technology_matcher.match_targets(entries, [])
    assert all(r["matched_targets"] == [] for r in results)
    print("  ✅ zero targets configured -> zero matches, no crash")


def test_malformed_target_file_is_skipped():
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "bad.yaml"), "w") as f:
            f.write("not: valid: yaml: [[[")
        with open(os.path.join(tmp, "good.yaml"), "w") as f:
            f.write("target: example.com\ntechnologies:\n  - vendor: nginx\n")
        targets = technology_matcher.load_all_targets(tmp)
        assert len(targets) == 1
        assert targets[0]["target"] == "example.com"
        print("  ✅ malformed target YAML skipped, well-formed one still loaded")


def test_target_with_empty_technologies_is_still_loaded():
    """Regression: a target not yet fingerprinted (technologies: []) was
    silently excluded from load_all_targets entirely, meaning it could
    never start matching even after a successful later fingerprint scan
    wrote real technologies into the same run's in-memory list."""
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "empty.yaml"), "w") as f:
            f.write("target: okx.com\ntechnologies: []\n")
        targets = technology_matcher.load_all_targets(tmp)
        assert len(targets) == 1 and targets[0]["target"] == "okx.com"
    print("  ✅ a target with an empty technology list is still loaded, not dropped")


def test_hunter_queue_only_shows_matched_or_ransomware_entries():
    entries = cisa_kev.load_from_file(FIXTURE)
    targets = [{"target": "example.com", "technologies": [{"vendor": "Apache", "product": "HTTP Server"}]}]
    matched = technology_matcher.match_targets(entries, targets)
    md = hunter_queue.render(matched, [], len(targets))

    assert "CVE-2024-99001" in md  # matched target
    assert "CVE-2024-99002" in md  # known ransomware use, even though unmatched here
    assert "CVE-2024-99003" not in md  # neither matched nor ransomware -> excluded
    print("  ✅ hunter_queue.md includes matched + ransomware entries, excludes the irrelevant one")


def test_hunter_queue_priority_ordering():
    entries = cisa_kev.load_from_file(FIXTURE)
    targets = [{"target": "example.com", "technologies": [
        {"vendor": "Apache", "product": "HTTP Server"},
        {"vendor": "nginx", "product": "nginx"},
    ]}]
    matched = technology_matcher.match_targets(entries, targets)
    md = hunter_queue.render(matched, [], len(targets))
    # nginx entry is matched AND known-ransomware -> must appear before Apache (matched, Unknown ransomware)
    pos_nginx = md.index("CVE-2024-99002")
    pos_apache = md.index("CVE-2024-99001")
    assert pos_nginx < pos_apache
    print("  ✅ priority ordering: matched+ransomware entry ranked above matched-only entry")


def test_empty_kev_produces_clean_message():
    md = hunter_queue.render([], [], 0)
    assert "No target-relevant" in md
    print("  ✅ zero candidates produces a clean message, not a broken/empty file")


def test_fetch_error_never_silently_advances_state():
    """A live-network failure (e.g. CISA's feed is down or changes shape)
    must never look like 'zero new CVEs today' — this is checked at the
    run_hunt.py orchestration level, verified here by confirming
    fetch_normalized's contract: error is non-None on failure, distinct
    from an empty-but-successful list."""
    entries, error = cisa_kev.fetch_normalized(url="https://this-domain-does-not-exist-vulnradar-test.invalid")
    assert error is not None
    assert entries == []
    print("  ✅ fetch failure returns a non-None error, never silently returns an empty success")


if __name__ == "__main__":
    tests = [
        test_load_and_normalize_real_schema,
        test_missing_cve_id_is_skipped_not_crashed,
        test_first_run_everything_is_new,
        test_second_run_shows_nothing_new,
        test_ransomware_flag_change_is_detected_as_update,
        test_technology_matcher_both_fields_required_when_both_specified,
        test_technology_matcher_vendor_only_is_broader,
        test_no_targets_means_no_matches_but_no_crash,
        test_malformed_target_file_is_skipped,
        test_hunter_queue_only_shows_matched_or_ransomware_entries,
        test_hunter_queue_priority_ordering,
        test_empty_kev_produces_clean_message,
        test_fetch_error_never_silently_advances_state,
    ]
    failed = 0
    for t in tests:
        try:
            t()
        except AssertionError as e:
            failed += 1
            print(f"  ❌ {t.__name__}: {e}")
        except Exception as e:
            failed += 1
            print(f"  ❌ {t.__name__}: unexpected {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} tests passed")
    sys.exit(1 if failed else 0)

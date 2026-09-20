#!/usr/bin/env python3
"""
pipeline/tests/test_cve_org.py

Tests against a real fixture captured from a LIVE fetch of the actual
CVEProject/cvelistV5 delta.json and CVE-2026-94030.json during this
session — not invented test data.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, REPO_ROOT)

from pipeline.collectors import cve_org

FIXTURES = os.path.join(HERE, "fixtures")
DELTA_SAMPLE = os.path.join(FIXTURES, "cve_org_delta_sample.json")
RECORD_SAMPLE = os.path.join(FIXTURES, "cve_org_record_sample.json")


def _load(path):
    with open(path) as f:
        return json.load(f)


def test_real_fixture_normalizes_correctly():
    """The exact live data fetched during this session: CVE-2026-94030,
    SerenityOS, CVSS 2.3 LOW, published state."""
    delta = _load(DELTA_SAMPLE)
    record = _load(RECORD_SAMPLE)

    entries, error, fetch_time = cve_org.fetch_normalized(
        _delta_loader=lambda: delta,
        _record_loader=lambda url: record,
    )
    assert error is None
    assert fetch_time == "2026-09-20T13:34:08.559Z"
    assert len(entries) == 1
    e = entries[0]
    assert e["cve"] == "CVE-2026-94030"
    assert e["product"] == "SerenityOS"
    assert e["cvss_score"] == 2.3
    assert e["cvss_severity"] == "LOW"
    assert e["source"] == "cve_org"
    print("  ✅ real live-captured fixture (CVE-2026-94030) normalized correctly, "
          "including CVSS extraction")


def test_rejected_state_is_excluded():
    delta = {"fetchTime": "2026-01-01T00:00:00Z", "new": [
        {"cveId": "CVE-2026-1", "githubLink": "http://x"}], "updated": [], "error": []}
    rejected_record = {
        "cveMetadata": {"cveId": "CVE-2026-1", "state": "REJECTED"},
        "containers": {"cna": {}},
    }
    entries, error, _ = cve_org.fetch_normalized(
        _delta_loader=lambda: delta, _record_loader=lambda url: rejected_record)
    assert error is None
    assert entries == []
    print("  ✅ REJECTED-state CVE records correctly excluded (no vendor/product data of value)")


def test_multiple_affected_products_each_get_own_entry():
    delta = {"fetchTime": "2026-01-01T00:00:00Z", "new": [
        {"cveId": "CVE-2026-2", "githubLink": "http://x"}], "updated": [], "error": []}
    multi_record = {
        "cveMetadata": {"cveId": "CVE-2026-2", "state": "PUBLISHED", "datePublished": "2026-01-01"},
        "containers": {"cna": {
            "title": "Multi-product issue",
            "descriptions": [{"lang": "en", "value": "affects two products"}],
            "affected": [
                {"vendor": "VendorA", "product": "ProductA"},
                {"vendor": "VendorB", "product": "ProductB"},
            ],
            "metrics": [],
            "problemTypes": [],
        }},
    }
    entries, error, _ = cve_org.fetch_normalized(
        _delta_loader=lambda: delta, _record_loader=lambda url: multi_record)
    assert len(entries) == 2
    assert {e["product"] for e in entries} == {"ProductA", "ProductB"}
    assert all(e["cve"] == "CVE-2026-2" for e in entries)
    print("  ✅ a CVE affecting 2 products correctly produces 2 normalized entries")


def test_delta_error_field_is_surfaced():
    delta = {"fetchTime": "x", "new": [], "updated": [], "error": ["something broke upstream"]}
    entries, error, _ = cve_org.fetch_normalized(_delta_loader=lambda: delta)
    assert entries == []
    assert error is not None and "something broke upstream" in error
    print("  ✅ delta.json's own error field is surfaced, not silently ignored")


def test_one_bad_record_fetch_does_not_stop_the_others():
    delta = {"fetchTime": "x", "new": [
        {"cveId": "CVE-2026-3", "githubLink": "http://bad"},
        {"cveId": "CVE-2026-4", "githubLink": "http://good"},
    ], "updated": [], "error": []}
    good_record = {
        "cveMetadata": {"cveId": "CVE-2026-4", "state": "PUBLISHED", "datePublished": "2026-01-01"},
        "containers": {"cna": {"title": "ok", "descriptions": [], "affected": [
            {"vendor": "V", "product": "P"}], "metrics": [], "problemTypes": []}},
    }
    def record_loader(url):
        if "bad" in url:
            raise ConnectionError("simulated failure")
        return good_record

    entries, error, _ = cve_org.fetch_normalized(_delta_loader=lambda: delta, _record_loader=record_loader)
    assert error is None
    assert len(entries) == 1
    assert entries[0]["cve"] == "CVE-2026-4"
    print("  ✅ one failed individual-record fetch doesn't stop the rest of the batch")


def test_gap_warning_triggers_past_threshold():
    warning = cve_org.check_for_gap("2026-01-01T00:30:00Z", "2026-01-01T00:00:00Z")
    assert warning is not None
    assert "30" in warning
    print("  ✅ a 30-minute gap correctly triggers the missed-delta warning")


def test_no_gap_warning_within_threshold():
    warning = cve_org.check_for_gap("2026-01-01T00:10:00Z", "2026-01-01T00:00:00Z")
    assert warning is None
    print("  ✅ a 10-minute gap (within the ~7min cadence) does not trigger a warning")


def test_no_gap_warning_on_first_ever_run():
    warning = cve_org.check_for_gap("2026-01-01T00:10:00Z", None)
    assert warning is None
    print("  ✅ first-ever run (no previous fetch time) doesn't warn")


def test_same_normalized_schema_as_cisa_kev():
    """Critical for reuse: this collector's output must have the exact
    same keys cisa_kev.py's normalize_entry() produces, so
    technology_matcher.py and hunter_queue.py work on either source
    unchanged."""
    from pipeline.collectors import cisa_kev
    kev_entries = cisa_kev.load_from_file(os.path.join(FIXTURES, "kev_sample.json"))
    delta = _load(DELTA_SAMPLE)
    record = _load(RECORD_SAMPLE)
    org_entries, _, _ = cve_org.fetch_normalized(_delta_loader=lambda: delta, _record_loader=lambda u: record)

    kev_keys = set(kev_entries[0].keys())
    org_keys = set(org_entries[0].keys())
    missing_from_org = kev_keys - org_keys
    assert not missing_from_org, f"cve_org entries are missing keys cisa_kev entries have: {missing_from_org}"
    print(f"  ✅ cve_org's normalized schema is a superset of cisa_kev's "
          f"({len(org_keys)} keys vs {len(kev_keys)}) — safe to reuse the same matcher/renderer")


if __name__ == "__main__":
    tests = [
        test_real_fixture_normalizes_correctly,
        test_rejected_state_is_excluded,
        test_multiple_affected_products_each_get_own_entry,
        test_delta_error_field_is_surfaced,
        test_one_bad_record_fetch_does_not_stop_the_others,
        test_gap_warning_triggers_past_threshold,
        test_no_gap_warning_within_threshold,
        test_no_gap_warning_on_first_ever_run,
        test_same_normalized_schema_as_cisa_kev,
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

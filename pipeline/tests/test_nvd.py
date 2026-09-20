#!/usr/bin/env python3
"""
pipeline/tests/test_nvd.py
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, REPO_ROOT)

from pipeline.collectors import nvd

FIXTURE = os.path.join(HERE, "fixtures", "nvd_sample.json")


def _load_fixture():
    with open(FIXTURE) as f:
        return json.load(f)


def test_cve_normalizes_with_version_range():
    entries, error = nvd.fetch_normalized(_loader=_load_fixture)
    assert error is None
    assert len(entries) == 1  # only the vulnerable:true cpeMatch, not the patched one
    e = entries[0]
    assert e["cve"] == "CVE-2024-77001"
    assert e["vendor"] == "examplevendor"
    assert e["product"] == "examplesoftware"
    assert e["cvss_score"] == 9.8
    assert e["cvss_severity"] == "CRITICAL"
    assert "CWE-94" in e["cwes"]
    assert e["cpe_version_range"]["start_including"] == "3.0.0"
    assert e["cpe_version_range"]["end_excluding"] == "3.5.2"
    assert e["source"] == "nvd"
    print("  ✅ NVD CVE normalized correctly, including CPE version range for future Version Intelligence")


def test_non_vulnerable_cpe_match_excluded():
    """The fixture has 2 cpeMatch entries: one vulnerable:true (3.0.0-3.5.2)
    and one vulnerable:false (the patched 3.5.2 itself) — only the first
    should produce an entry."""
    entries, error = nvd.fetch_normalized(_loader=_load_fixture)
    assert len(entries) == 1
    print("  ✅ vulnerable:false CPE match entry correctly excluded")


def test_cpe_vendor_product_extraction():
    vendor, product = nvd._extract_cpe_vendor_product(
        "cpe:2.3:a:examplevendor:examplesoftware:*:*:*:*:*:*:*:*")
    assert vendor == "examplevendor"
    assert product == "examplesoftware"
    print("  ✅ CPE 2.3 URI parsed correctly into vendor/product")


def test_malformed_cpe_string_does_not_crash():
    vendor, product = nvd._extract_cpe_vendor_product("not-a-cpe-string")
    assert vendor is None and product is None
    print("  ✅ malformed CPE string returns (None, None), doesn't crash")


def test_cve_with_no_cpe_data_produces_no_entries():
    raw = {"vulnerabilities": [{"cve": {
        "id": "CVE-2024-1", "published": "2024-01-01", "descriptions": [],
        "metrics": {}, "weaknesses": [], "configurations": [],
    }}]}
    entries, error = nvd.fetch_normalized(_loader=lambda: raw)
    assert entries == []
    print("  ✅ a CVE with zero structured CPE data produces zero entries (nothing to match on)")


def test_missing_vulnerabilities_key_is_an_error_not_a_silent_empty():
    entries, error = nvd.fetch_normalized(_loader=lambda: {"unexpected": "shape"})
    assert entries == []
    assert error is not None
    print("  ✅ a response missing the expected 'vulnerabilities' key is a surfaced error, not silent 0 results")


def test_same_normalized_schema_as_cisa_kev():
    from pipeline.collectors import cisa_kev
    kev_entries = cisa_kev.load_from_file(os.path.join(HERE, "fixtures", "kev_sample.json"))
    nvd_entries, _ = nvd.fetch_normalized(_loader=_load_fixture)
    missing = set(kev_entries[0].keys()) - set(nvd_entries[0].keys())
    assert not missing, f"nvd entries missing keys cisa_kev has: {missing}"
    print("  ✅ nvd schema is a superset of cisa_kev's — safe to reuse matcher/renderer")


if __name__ == "__main__":
    tests = [
        test_cve_normalizes_with_version_range,
        test_non_vulnerable_cpe_match_excluded,
        test_cpe_vendor_product_extraction,
        test_malformed_cpe_string_does_not_crash,
        test_cve_with_no_cpe_data_produces_no_entries,
        test_missing_vulnerabilities_key_is_an_error_not_a_silent_empty,
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

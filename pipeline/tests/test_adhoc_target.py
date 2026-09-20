#!/usr/bin/env python3
"""
pipeline/tests/test_adhoc_target.py
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, REPO_ROOT)

from pipeline.run_hunt import parse_adhoc_technologies


def test_vendor_and_product_pair():
    result = parse_adhoc_technologies("nginx:nginx")
    assert result == [{"vendor": "nginx", "product": "nginx"}]
    print("  ✅ vendor:product pair parsed correctly")


def test_multiple_pairs():
    result = parse_adhoc_technologies("nginx:nginx,Apache:HTTP Server")
    assert len(result) == 2
    assert result[1] == {"vendor": "Apache", "product": "HTTP Server"}
    print("  ✅ multiple comma-separated pairs parsed correctly")


def test_vendor_only_trailing_colon():
    result = parse_adhoc_technologies("nodejs:")
    assert result == [{"vendor": "nodejs", "product": ""}]
    print("  ✅ vendor-only (trailing colon, blank product) parsed correctly")


def test_vendor_only_no_colon():
    result = parse_adhoc_technologies("nodejs")
    assert result == [{"vendor": "nodejs", "product": ""}]
    print("  ✅ vendor-only (no colon at all) also works")


def test_empty_string_produces_empty_list():
    assert parse_adhoc_technologies("") == []
    assert parse_adhoc_technologies(None) == []
    print("  ✅ empty/None input produces an empty list, not a crash")


def test_whitespace_is_trimmed():
    result = parse_adhoc_technologies("  nginx : nginx  ,  Apache : HTTP Server  ")
    assert result == [{"vendor": "nginx", "product": "nginx"}, {"vendor": "Apache", "product": "HTTP Server"}]
    print("  ✅ leading/trailing whitespace around vendor/product trimmed correctly")


def test_stray_commas_are_ignored():
    result = parse_adhoc_technologies("nginx:nginx,,Apache:HTTP Server,")
    assert len(result) == 2
    print("  ✅ empty entries from stray/trailing commas ignored, not turned into blank technologies")


def test_parsed_technologies_actually_match_via_technology_matcher():
    """End-to-end proof: parse_adhoc_technologies' output is a real,
    usable input to technology_matcher.py, not just a data shape that
    happens to look right."""
    from pipeline.intelligence import technology_matcher
    from pipeline.collectors import cisa_kev
    entries = cisa_kev.load_from_file(os.path.join(HERE, "fixtures", "kev_sample.json"))
    adhoc_target = {"target": "mytarget.com", "technologies": parse_adhoc_technologies("nginx:nginx")}
    results = technology_matcher.match_targets(entries, [adhoc_target])
    matched = [r for r in results if r["matched_targets"]]
    assert len(matched) == 1
    assert matched[0]["cve"] == "CVE-2024-99002"
    print("  ✅ ad-hoc-parsed technologies correctly match real KEV fixture data end-to-end")


if __name__ == "__main__":
    tests = [
        test_vendor_and_product_pair,
        test_multiple_pairs,
        test_vendor_only_trailing_colon,
        test_vendor_only_no_colon,
        test_empty_string_produces_empty_list,
        test_whitespace_is_trimmed,
        test_stray_commas_are_ignored,
        test_parsed_technologies_actually_match_via_technology_matcher,
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

#!/usr/bin/env python3
"""
pipeline/tests/test_github_advisories.py
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, REPO_ROOT)

from pipeline.collectors import github_advisories

FIXTURE = os.path.join(HERE, "fixtures", "github_advisory_sample.json")


def _load_fixture():
    with open(FIXTURE) as f:
        return json.load(f)


def test_advisory_with_cve_normalizes_correctly():
    entries, error = github_advisories.fetch_normalized(_loader=_load_fixture)
    assert error is None
    assert len(entries) == 1  # the malware advisory (no cve_id) is excluded
    e = entries[0]
    assert e["cve"] == "CVE-2024-88001"
    assert e["vendor"] == "npm"
    assert e["product"] == "example-npm-package"
    assert e["cvss_score"] == 7.3
    assert e["cvss_severity"] == "HIGH"
    assert "2.1.0" in e["required_action"]
    assert e["source"] == "github_advisories"
    print("  ✅ advisory with a CVE ID normalized correctly, including upgrade guidance")


def test_advisory_without_cve_id_is_excluded():
    """The malware-type advisory in the fixture has no cve_id at all —
    confirms it's excluded, not crashed on."""
    entries, error = github_advisories.fetch_normalized(_loader=_load_fixture)
    cves = [e["cve"] for e in entries]
    assert "GHSA-dddd-eeee-ffff" not in cves  # never even attempted as a "cve"
    assert len(entries) == 1
    print("  ✅ advisory with no assigned CVE ID correctly excluded (CVE-centric schema)")


def test_api_error_dict_response_surfaced():
    """GitHub's API returns {'message': '...'} on rate-limit/auth errors
    instead of a list — must be caught explicitly, not crash on iteration."""
    error_response = {"message": "API rate limit exceeded for 1.2.3.4."}
    entries, error = github_advisories.fetch_normalized(_loader=lambda: error_response)
    assert entries == []
    assert error is not None and "rate limit" in error
    print("  ✅ GitHub's error-dict response format (not a list) surfaced as an error, not crashed on")


def test_same_normalized_schema_as_cisa_kev():
    from pipeline.collectors import cisa_kev
    kev_entries = cisa_kev.load_from_file(os.path.join(HERE, "fixtures", "kev_sample.json"))
    gh_entries, _ = github_advisories.fetch_normalized(_loader=_load_fixture)
    missing = set(kev_entries[0].keys()) - set(gh_entries[0].keys())
    assert not missing, f"github_advisories entries missing keys cisa_kev has: {missing}"
    print("  ✅ github_advisories schema is a superset of cisa_kev's — safe to reuse matcher/renderer")


if __name__ == "__main__":
    tests = [
        test_advisory_with_cve_normalizes_correctly,
        test_advisory_without_cve_id_is_excluded,
        test_api_error_dict_response_surfaced,
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

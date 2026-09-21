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

def test_first_patched_version_accepts_string_and_object_shapes():
    """Regression: the live API returns first_patched_version as a plain
    string; the original code assumed an object and crashed every run."""
    def make(fpv):
        return [{"cve_id": "CVE-2024-1", "summary": "s", "severity": "high",
                 "vulnerabilities": [{"package": {"ecosystem": "npm", "name": "x"},
                                      "first_patched_version": fpv}]}]
    for fpv in ("2.1.0", {"identifier": "2.1.0"}):
        entries, err = github_advisories.fetch_normalized(_loader=lambda f=fpv: make(f))
        assert err is None and "2.1.0" in entries[0]["required_action"]
    entries, err = github_advisories.fetch_normalized(_loader=lambda: make(None))
    assert "See advisory" in entries[0]["required_action"]
    print("  ✅ first_patched_version: string / object / null all handled")


def test_one_malformed_advisory_does_not_crash():
    good = {"cve_id": "CVE-2024-2", "vulnerabilities": [{"package": {"ecosystem": "npm", "name": "y"}}]}
    bad = {"cve_id": "CVE-2024-3", "vulnerabilities": ["not-a-dict"]}
    entries, err = github_advisories.fetch_normalized(_loader=lambda: [bad, good])
    assert err is None and len(entries) == 1 and entries[0]["cve"] == "CVE-2024-2"
    print("  ✅ malformed advisory skipped, rest kept")


if __name__ == "__main__":
    tests = [
        test_advisory_with_cve_normalizes_correctly,
        test_advisory_without_cve_id_is_excluded,
        test_api_error_dict_response_surfaced,
        test_same_normalized_schema_as_cisa_kev,
        test_first_patched_version_accepts_string_and_object_shapes,
        test_one_malformed_advisory_does_not_crash,
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

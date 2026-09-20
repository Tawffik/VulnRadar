#!/usr/bin/env python3
"""
pipeline/tests/test_nuclei_templates.py
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, REPO_ROOT)

from pipeline.collectors import nuclei_templates as nt

SAMPLE_TEMPLATE = """id: CVE-2024-55001

info:
  name: Example Software Unauthenticated RCE
  author: someone
  severity: critical
  tags: cve,cve2024,examplesoftware,rce,unauth

requests:
  - method: GET
    path:
      - "{{BaseURL}}/vulnerable-endpoint"
"""


def _commit_list():
    return [{"sha": "abc123"}]


def _commit_detail_with_new_template(sha):
    return {
        "sha": sha,
        "commit": {"author": {"date": "2026-01-01T00:00:00Z"}},
        "files": [
            {"filename": "http/cves/2024/CVE-2024-55001.yaml", "status": "added",
             "raw_url": "https://raw.githubusercontent.com/x/y/main/http/cves/2024/CVE-2024-55001.yaml"},
            {"filename": "README.md", "status": "modified"},  # unrelated file, must be ignored
        ],
    }


def test_two_step_api_correctly_fetches_commit_detail_for_files():
    """Regression test for a real bug caught before commit: the GitHub
    commits LIST endpoint does NOT include per-commit files - only the
    single-commit detail endpoint does. This confirms the two-step call
    actually happens rather than silently reading a nonexistent 'files'
    key off the list response."""
    entries, error = nt.fetch_normalized(
        _commits_loader=_commit_list,
        _commit_detail_loader=_commit_detail_with_new_template,
        _template_loader=lambda url: SAMPLE_TEMPLATE,
    )
    assert error is None
    assert len(entries) == 1
    print("  ✅ two-step commit-list -> commit-detail API flow correctly extracts new template files")


def test_added_cve_template_normalizes_correctly():
    entries, error = nt.fetch_normalized(
        _commits_loader=_commit_list,
        _commit_detail_loader=_commit_detail_with_new_template,
        _template_loader=lambda url: SAMPLE_TEMPLATE,
    )
    e = entries[0]
    assert e["cve"] == "CVE-2024-55001"
    assert e["vendor"] == "examplesoftware"  # first non-generic tag
    assert e["product"] == "nuclei-template"
    assert e["name"] == "Example Software Unauthenticated RCE"
    assert e["source"] == "nuclei_templates"
    print("  ✅ new CVE template normalized correctly, vendor guessed from tags")


def test_non_cve_or_modified_files_ignored():
    """The fixture's README.md modification must never produce an entry."""
    entries, error = nt.fetch_normalized(
        _commits_loader=_commit_list,
        _commit_detail_loader=_commit_detail_with_new_template,
        _template_loader=lambda url: SAMPLE_TEMPLATE,
    )
    assert len(entries) == 1  # only the CVE template, not README.md
    print("  ✅ non-CVE-template file changes (README.md) correctly ignored")


def test_generic_tags_are_skipped_for_vendor_guess():
    vendor = nt._guess_vendor_from_tags("cve,rce,unauth,wordpress")
    assert vendor == "wordpress"
    print("  ✅ generic tags (cve, rce, unauth) skipped, first specific tag used as vendor guess")


def test_no_specific_tags_falls_back_to_unknown():
    vendor = nt._guess_vendor_from_tags("cve,rce,intrusive")
    assert vendor == "unknown"
    print("  ✅ all-generic tags correctly fall back to vendor='unknown' rather than a wrong guess")


def test_modified_template_not_added_is_ignored():
    """Only NEWLY ADDED templates matter — a modified (already-known)
    template must not be re-reported as if it were a new CVE."""
    def detail(sha):
        return {"commit": {"author": {"date": "x"}}, "files": [
            {"filename": "http/cves/2024/CVE-2024-1.yaml", "status": "modified"}]}
    entries, error = nt.fetch_normalized(_commits_loader=_commit_list, _commit_detail_loader=detail)
    assert entries == []
    print("  ✅ a MODIFIED (not added) template file produces zero entries")


def test_api_error_dict_response_surfaced():
    error_response = {"message": "API rate limit exceeded"}
    entries, error = nt.fetch_normalized(_commits_loader=lambda: error_response)
    assert entries == []
    assert error is not None and "rate limit" in error
    print("  ✅ GitHub's error-dict response surfaced as an error, not crashed on")


def test_bad_commit_detail_does_not_stop_others():
    def flaky_commits():
        return [{"sha": "bad"}, {"sha": "good"}]
    def flaky_detail(sha):
        if sha == "bad":
            raise ConnectionError("simulated failure")
        return _commit_detail_with_new_template(sha)
    entries, error = nt.fetch_normalized(
        _commits_loader=flaky_commits, _commit_detail_loader=flaky_detail,
        _template_loader=lambda url: SAMPLE_TEMPLATE)
    assert error is None
    assert len(entries) == 1
    print("  ✅ one failed commit-detail fetch doesn't stop the rest of the batch")


def test_same_normalized_schema_as_cisa_kev():
    from pipeline.collectors import cisa_kev
    kev_entries = cisa_kev.load_from_file(os.path.join(HERE, "fixtures", "kev_sample.json"))
    nt_entries, _ = nt.fetch_normalized(
        _commits_loader=_commit_list, _commit_detail_loader=_commit_detail_with_new_template,
        _template_loader=lambda url: SAMPLE_TEMPLATE)
    missing = set(kev_entries[0].keys()) - set(nt_entries[0].keys())
    assert not missing, f"nuclei_templates entries missing keys cisa_kev has: {missing}"
    print("  ✅ nuclei_templates schema is a superset of cisa_kev's — safe to reuse matcher/renderer")


if __name__ == "__main__":
    tests = [
        test_two_step_api_correctly_fetches_commit_detail_for_files,
        test_added_cve_template_normalizes_correctly,
        test_non_cve_or_modified_files_ignored,
        test_generic_tags_are_skipped_for_vendor_guess,
        test_no_specific_tags_falls_back_to_unknown,
        test_modified_template_not_added_is_ignored,
        test_api_error_dict_response_surfaced,
        test_bad_commit_detail_does_not_stop_others,
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

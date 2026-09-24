#!/usr/bin/env python3
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from pipeline.intelligence import state_store
from pipeline.intelligence.run_status import CollectorResult


def test_save_and_load_one_source():
    with tempfile.TemporaryDirectory() as d:
        entries = [{"cve": "CVE-1", "date_added": "2024-01-01", "ransomware_use": "Known"}]
        n = state_store.save_source_state(d, "cisa_kev", entries)
        assert n == 1
        state = state_store.load_source_state(d, "cisa_kev")
        assert state["CVE-1"]["ransomware_use"] == "Known"
    print("  ✅ save/load round-trips correctly for one source")


def test_failed_source_state_untouched():
    """The core bug fix: a source that fails this run must NOT have its
    state file overwritten/emptied - update_states() must skip it
    entirely, not write an empty state."""
    with tempfile.TemporaryDirectory() as d:
        state_store.save_source_state(d, "cisa_kev", [{"cve": "CVE-OLD", "date_added": "x", "ransomware_use": "Unknown"}])
        results = [
            CollectorResult("cisa_kev", [], "HTTP 403 Forbidden"),   # failed this run
            CollectorResult("cve_org", [{"cve": "CVE-NEW"}], None),   # succeeded
        ]
        written = state_store.update_states(d, results)
        assert "cisa_kev" not in written and "cve_org" in written
        # cisa_kev.json must still have CVE-OLD, untouched
        assert state_store.load_source_state(d, "cisa_kev") == {"CVE-OLD": {"date_added": "x", "ransomware_use": "Unknown"}}
    print("  ✅ a failed source's state file is left completely untouched")


def test_merged_state_survives_one_source_failing():
    """Regression test for the actual bug found in this project: a CVE
    known ONLY via CISA KEV must still show as 'already seen' (not
    reported as new again) on a run where CISA's fetch fails, as long
    as a previous successful CISA run had recorded it."""
    with tempfile.TemporaryDirectory() as d:
        # Simulate a prior successful KEV run that saw a KEV-only CVE.
        state_store.save_source_state(d, "cisa_kev", [{"cve": "CVE-KEV-ONLY", "date_added": "2024-01-01", "ransomware_use": "Unknown"}])
        state_store.save_source_state(d, "cve_org", [{"cve": "CVE-FROM-ORG", "date_added": "2024-01-01", "ransomware_use": "Unknown"}])

        # Now simulate today's run where CISA fails (its file is never
        # touched, so it's not in `written`), but we still need the
        # MERGED view for diffing to include CVE-KEV-ONLY.
        merged = state_store.load_merged_state(d)
        assert "CVE-KEV-ONLY" in merged and "CVE-FROM-ORG" in merged

        from pipeline.intelligence import state_diff
        # This run's fresh entries (from sources that succeeded) do NOT
        # include CVE-KEV-ONLY at all, since KEV itself failed today.
        this_run_entries = [{"cve": "CVE-FROM-ORG", "ransomware_use": "Unknown"}]
        new_entries, updated, unchanged = state_diff.diff(this_run_entries, merged)
        assert new_entries == []  # CVE-FROM-ORG already known -> not "new"
        assert unchanged == 1
        # Critically: CVE-KEV-ONLY is simply absent from this run's
        # results (KEV didn't run), NOT wrongly reported as new - the
        # old single-state-file design would have made it reappear as
        # "new" the next time KEV succeeded, because save_state()
        # would have wiped it out of the state entirely on the failed run.
    print("  ✅ a KEV-only CVE survives a failed CISA run in the merged state (the actual bug, fixed)")


def test_load_merged_state_combines_all_sources():
    with tempfile.TemporaryDirectory() as d:
        state_store.save_source_state(d, "cisa_kev", [{"cve": "A", "date_added": "", "ransomware_use": "Unknown"}])
        state_store.save_source_state(d, "nvd", [{"cve": "B", "date_added": "", "ransomware_use": "Unknown"}])
        merged = state_store.load_merged_state(d)
        assert set(merged.keys()) == {"A", "B"}
    print("  ✅ merged state combines every per-source file")


def test_migrate_legacy_state_preserves_history():
    with tempfile.TemporaryDirectory() as d:
        legacy_path = os.path.join(d, "kev_state.json")
        state_dir = os.path.join(d, "state")
        import json
        with open(legacy_path, "w") as f:
            json.dump({"CVE-LEGACY": {"date_added": "2023-01-01", "ransomware_use": "Unknown"}}, f)
        state_store.migrate_legacy_state(legacy_path, state_dir)
        assert state_store.load_source_state(state_dir, "cisa_kev") == {"CVE-LEGACY": {"date_added": "2023-01-01", "ransomware_use": "Unknown"}}
    print("  ✅ legacy single-file state migrates into cisa_kev.json, not discarded")


def test_migrate_is_noop_once_new_files_exist():
    with tempfile.TemporaryDirectory() as d:
        legacy_path = os.path.join(d, "kev_state.json")
        state_dir = os.path.join(d, "state")
        import json
        with open(legacy_path, "w") as f:
            json.dump({"CVE-LEGACY": {}}, f)
        state_store.save_source_state(state_dir, "cisa_kev", [{"cve": "CVE-NEW", "date_added": "", "ransomware_use": "Unknown"}])
        state_store.migrate_legacy_state(legacy_path, state_dir)
        # must NOT have been overwritten by the legacy migration
        assert "CVE-NEW" in state_store.load_source_state(state_dir, "cisa_kev")
        assert "CVE-LEGACY" not in state_store.load_source_state(state_dir, "cisa_kev")
    print("  ✅ migration is a no-op once real per-source state already exists")


def test_corrupt_state_file_treated_as_empty_not_crash():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "cisa_kev.json")
        with open(path, "w") as f:
            f.write("{not valid json")
        state = state_store.load_source_state(d, "cisa_kev")
        assert state == {}
    print("  ✅ a corrupt state file loads as empty rather than crashing")


if __name__ == "__main__":
    tests = [test_save_and_load_one_source, test_failed_source_state_untouched,
              test_merged_state_survives_one_source_failing, test_load_merged_state_combines_all_sources,
              test_migrate_legacy_state_preserves_history, test_migrate_is_noop_once_new_files_exist,
              test_corrupt_state_file_treated_as_empty_not_crash]
    for t in tests:
        t()
    print(f"\n{len(tests)}/{len(tests)} tests passed")

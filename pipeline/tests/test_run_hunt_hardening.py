#!/usr/bin/env python3
"""
pipeline/tests/test_run_hunt_hardening.py

Integration tests that invoke pipeline/run_hunt.py as a real subprocess
(same as the workflow does), covering the acceptance-criteria scenarios
from the fault-tolerance hardening task. Subprocess (not direct import)
deliberately, so this exercises the actual exit code the workflow reads
via `$?`, not just an in-process return value.
"""
import json
import os
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RUN_HUNT = os.path.join(REPO_ROOT, "pipeline", "run_hunt.py")

VALID_KEV = {"vulnerabilities": [{"cveID": "CVE-2024-0001", "vendorProject": "nginx", "product": "nginx",
                                    "vulnerabilityName": "t", "dateAdded": "2024-01-01", "dueDate": "2024-02-01",
                                    "shortDescription": "d", "requiredAction": "patch",
                                    "knownRansomwareCampaignUse": "Unknown"}]}


def _run(kev_file, state_dir, targets_dir, extra_args=None):
    args = [sys.executable, RUN_HUNT, "--kev-file", kev_file,
             "--skip-cve-org", "--skip-github-advisories", "--skip-nvd", "--skip-nuclei-templates",
             "--state-file", os.path.join(state_dir, "kev_state.json"),
             "--output", os.path.join(state_dir, "hunter_queue.md"),
             "--targets-dir", targets_dir]
    if extra_args:
        args += extra_args
    return subprocess.run(args, capture_output=True, text=True, cwd=REPO_ROOT)


def _empty_targets_dir():
    d = tempfile.mkdtemp()
    return d  # no target files - keeps these tests focused on collector/state behavior


def test_cisa_failure_does_not_crash_and_is_degraded():
    """Acceptance Scenario A: CISA fails, others 'succeed' (here: skipped
    -> EMPTY, which is a legitimate success-shaped state) -> DEGRADED,
    exit 10, hunt continues and produces a report."""
    with tempfile.TemporaryDirectory() as d:
        result = _run(os.path.join(d, "does_not_exist.json"), d, _empty_targets_dir())
        assert result.returncode == 10, result.stdout + result.stderr
        assert "DEGRADED" in result.stdout
        assert os.path.isfile(os.path.join(d, "hunter_queue.md"))
    print("  ✅ Scenario A: CISA failure -> DEGRADED (exit 10), run continues, report produced")


def test_valid_kev_all_else_skipped_is_success():
    with tempfile.TemporaryDirectory() as d:
        kev_path = os.path.join(d, "kev.json")
        with open(kev_path, "w") as f:
            json.dump(VALID_KEV, f)
        result = _run(kev_path, d, _empty_targets_dir())
        assert result.returncode == 0, result.stdout + result.stderr
        assert "SUCCESS" in result.stdout
    print("  ✅ everything ok -> SUCCESS (exit 0)")


def test_kev_only_cve_survives_a_later_cisa_failure():
    """The actual state-loss bug this task's audit found, exercised
    end-to-end exactly as the workflow would run it twice in a row."""
    with tempfile.TemporaryDirectory() as d:
        kev_path = os.path.join(d, "kev.json")
        with open(kev_path, "w") as f:
            json.dump(VALID_KEV, f)
        targets_dir = _empty_targets_dir()

        r1 = _run(kev_path, d, targets_dir)
        assert r1.returncode == 0
        assert "1 new" in r1.stdout or "diff: 1 new" in r1.stdout

        # Second run: CISA now fails (bad path). The CVE from run 1 must
        # NOT be reported as new again, and cisa_kev.json must survive.
        r2 = _run(os.path.join(d, "missing.json"), d, targets_dir)
        assert r2.returncode == 10
        assert "0 new" in r2.stdout or "diff: 0 new" in r2.stdout
        with open(os.path.join(d, "cisa_kev.json")) as f:
            state = json.load(f)
        assert "CVE-2024-0001" in state
    print("  ✅ regression: a KEV-only CVE is not re-reported as new after CISA fails on a later run")


def test_run_summary_json_written_and_shaped_correctly():
    with tempfile.TemporaryDirectory() as d:
        result = _run(os.path.join(d, "missing.json"), d, _empty_targets_dir())
        summary_path = os.path.join(REPO_ROOT, "output", "run_summary.json")
        assert os.path.isfile(summary_path)
        with open(summary_path) as f:
            data = json.load(f)
        assert data["overall"] == "DEGRADED"
        assert any(c["name"] == "cisa_kev" and c["status"] == "FAILED" for c in data["collectors"])
    print("  ✅ output/run_summary.json is written with the correct shape")


def test_hunter_queue_notes_partial_coverage():
    with tempfile.TemporaryDirectory() as d:
        result = _run(os.path.join(d, "missing.json"), d, _empty_targets_dir())
        with open(os.path.join(d, "hunter_queue.md")) as f:
            content = f.read()
        assert "partial source coverage" in content.lower()
    print("  ✅ a degraded run's hunter_queue.md explicitly flags partial coverage, not silent")


if __name__ == "__main__":
    tests = [test_cisa_failure_does_not_crash_and_is_degraded, test_valid_kev_all_else_skipped_is_success,
              test_kev_only_cve_survives_a_later_cisa_failure, test_run_summary_json_written_and_shaped_correctly,
              test_hunter_queue_notes_partial_coverage]
    for t in tests:
        t()
    print(f"\n{len(tests)}/{len(tests)} tests passed")

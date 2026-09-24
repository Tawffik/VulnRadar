#!/usr/bin/env python3
"""
pipeline/intelligence/state_store.py

Replaces the single kev_state.json blob with one state file per
collector (data/state/<source>.json), specifically to fix a real bug:
the old single-file save_state(path, entries) overwrote the ENTIRE
state with only whatever this run's merge produced. If a source failed
and returned [], any CVE known ONLY through that source silently
vanished from state - the next time that source succeeded again, the
same CVE would be reported as "new" a second time. See
docs/PROJECT_PLAN.md for the full writeup.

With per-source files: a source that fails this run keeps its
existing file untouched (last-known-good), while sources that
succeeded advance normally. The merged view used for diffing is built
by loading all 5 files and combining them - so a failed source's
older CVEs are still present for diff purposes even on a run where
that source itself contributed nothing new.
"""
import json
import os

SOURCES = ("cisa_kev", "cve_org", "github_advisories", "nvd", "nuclei_templates")


def _path_for(state_dir: str, source: str) -> str:
    return os.path.join(state_dir, f"{source}.json")


def load_source_state(state_dir: str, source: str) -> dict:
    path = _path_for(state_dir, source)
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}  # corrupt file — treat as empty rather than crash the run


def save_source_state(state_dir: str, source: str, entries: list) -> int:
    """Writes this source's state from its own entries. Returns the
    number of entries written. Only ever called for a source that
    succeeded this run (see update_states below) - a failed source's
    file is simply never touched, which is the fix."""
    os.makedirs(state_dir, exist_ok=True)
    state = {}
    for e in entries:
        cve = e.get("cve")
        if not cve:
            continue
        state[cve] = {"date_added": e.get("date_added", ""),
                       "ransomware_use": e.get("ransomware_use", "Unknown")}
    with open(_path_for(state_dir, source), "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
    return len(state)


def update_states(state_dir: str, collector_results: list) -> dict:
    """collector_results: list of run_status.CollectorResult. Advances
    state only for sources that succeeded (is_ok()); leaves failed
    sources' files untouched. Returns {source: written_count} for
    sources that were actually written this run."""
    written = {}
    for r in collector_results:
        if r.name not in SOURCES:
            continue
        if r.is_ok():
            written[r.name] = save_source_state(state_dir, r.name, r.entries)
    return written


def load_merged_state(state_dir: str) -> dict:
    """Combines all 5 per-source state files into one {cve: {...}} view
    for diffing against, so a CVE known only via a source that failed
    THIS run (but succeeded before) is still correctly treated as
    'already seen', not reported as new again."""
    merged = {}
    for source in SOURCES:
        merged.update(load_source_state(state_dir, source))
    return merged


def migrate_legacy_state(legacy_path: str, state_dir: str) -> None:
    """One-time migration: if the old single-file kev_state.json still
    exists and none of the new per-source files exist yet, treat its
    contents as cisa_kev's state (that file's history is entirely from
    when KEV was the only source merged in early runs) so history isn't
    silently discarded on upgrade. Safe to call every run - it's a
    no-op once any per-source file exists."""
    if not os.path.isfile(legacy_path):
        return
    if any(os.path.isfile(_path_for(state_dir, s)) for s in SOURCES):
        return
    try:
        with open(legacy_path, "r", encoding="utf-8") as f:
            legacy = json.load(f)
    except (OSError, json.JSONDecodeError):
        return
    if legacy:
        os.makedirs(state_dir, exist_ok=True)
        with open(_path_for(state_dir, "cisa_kev"), "w", encoding="utf-8") as f:
            json.dump(legacy, f, indent=2)

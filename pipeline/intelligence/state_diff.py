#!/usr/bin/env python3
"""
pipeline/intelligence/state_diff.py

The single most important piece of intelligence in this project (per
the design brief): a CVE feed is nearly useless re-read in full every
day. What matters is the DIFF — what's NEW since last time. Without
this, every run would re-report the same ~1,300+ KEV entries forever.

State is a simple flat file (data/state/kev_state.json): the set of CVE
IDs seen as of the last successful run, plus each entry's date_added
(to detect a metadata update on an already-known CVE, not just brand
new entries).
"""
import json
import os


def load_state(state_path: str):
    if not os.path.isfile(state_path):
        return {}  # first run ever — everything will show as NEW, which is correct
    try:
        with open(state_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}  # corrupt state file — treat as first run rather than crash


def save_state(state_path: str, entries: list):
    os.makedirs(os.path.dirname(state_path), exist_ok=True)
    state = {}
    skipped = 0
    for e in entries:
        cve = e.get("cve")
        if not cve:
            skipped += 1
            continue  # can't track state for an entry with no CVE ID at all
        state[cve] = {"date_added": e.get("date_added", ""),
                      "ransomware_use": e.get("ransomware_use", "Unknown")}
    if skipped:
        print(f"⚠️ {skipped} entry/entries had no CVE ID and were skipped when saving state "
              f"(a collector may have a schema issue — check its source)")
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def diff(entries: list, previous_state: dict):
    """Returns (new_entries, updated_entries, unchanged_count).

    NEW: CVE not present in previous_state at all.
    UPDATED: CVE present, but its ransomware_use flag changed (the one
    field genuinely worth re-flagging — CISA marking a known CVE as now
    tied to ransomware activity is a real priority change, unlike most
    other field edits which are typically just wording/typo fixes).

    Uses .get() throughout rather than direct indexing — a single
    malformed entry from any of the 5 collectors (missing a field due
    to an unforeseen upstream schema change, especially plausible for
    nvd.py/github_advisories.py/nuclei_templates.py, which weren't
    live-verified during development — see their docstrings) must
    never crash the whole run and silently look like a KEV/cve.org
    fetch failure instead of what it actually is."""
    new_entries = []
    updated_entries = []
    unchanged_count = 0
    skipped = 0

    for e in entries:
        cve = e.get("cve")
        if not cve:
            skipped += 1
            continue
        ransomware_use = e.get("ransomware_use", "Unknown")
        prev = previous_state.get(cve)
        if prev is None:
            new_entries.append(e)
        elif prev.get("ransomware_use") != ransomware_use:
            updated_entries.append({**e, "previous_ransomware_use": prev.get("ransomware_use")})
        else:
            unchanged_count += 1

    if skipped:
        print(f"⚠️ {skipped} entry/entries had no CVE ID and were skipped during diff "
              f"(a collector may have a schema issue — check its source)")

    return new_entries, updated_entries, unchanged_count

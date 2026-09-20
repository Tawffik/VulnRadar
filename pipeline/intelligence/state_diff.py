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
    state = {e["cve"]: {"date_added": e["date_added"], "ransomware_use": e["ransomware_use"]}
             for e in entries}
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def diff(entries: list, previous_state: dict):
    """Returns (new_entries, updated_entries, unchanged_count).

    NEW: CVE not present in previous_state at all.
    UPDATED: CVE present, but its ransomware_use flag changed (the one
    field genuinely worth re-flagging — CISA marking a known CVE as now
    tied to ransomware activity is a real priority change, unlike most
    other field edits which are typically just wording/typo fixes).
    """
    new_entries = []
    updated_entries = []
    unchanged_count = 0

    for e in entries:
        cve = e["cve"]
        prev = previous_state.get(cve)
        if prev is None:
            new_entries.append(e)
        elif prev.get("ransomware_use") != e["ransomware_use"]:
            updated_entries.append({**e, "previous_ransomware_use": prev.get("ransomware_use")})
        else:
            unchanged_count += 1

    return new_entries, updated_entries, unchanged_count

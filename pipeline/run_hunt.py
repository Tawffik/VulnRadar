#!/usr/bin/env python3
"""
pipeline/run_hunt.py

Orchestrates one full VulnRadar run using TWO sources together:
  - cisa_kev: confirmed real-world exploitation (authoritative, but slow —
    CISA only adds a CVE after confirming active exploitation)
  - cve_org: the official CVE.org record feed, updated ~every 7 minutes —
    the speed source, often surfacing a CVE hours/days before KEV would

  fetch both -> merge (KEV wins on conflict, cve_org tags "seen first")
  -> diff against last state -> match against targets/*.yaml
  -> render output/hunter_queue.md -> save new state

Usage:
  python3 pipeline/run_hunt.py [--kev-file PATH] [--skip-cve-org]
                                [--targets-dir DIR] [--state-file PATH]
                                [--output PATH]

--kev-file lets CI (or a test) pass a pre-downloaded snapshot instead of
hitting the network, e.g. after a separate `curl` step — this keeps the
network dependency isolated to one place instead of buried in Python,
matching this project's own established pattern from BugBountyCI.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pipeline.collectors import cisa_kev, cve_org
from pipeline.intelligence import state_diff, technology_matcher
from pipeline.reporting import hunter_queue


def merge_sources(kev_entries: list, org_entries: list) -> list:
    """Combines both collectors into one list, deduped by CVE ID. If a
    CVE appears in both, the KEV version wins (it carries the
    authoritative ransomware_use flag cve_org never has), but the entry
    is tagged with BOTH source names so the speed advantage of cve_org
    (which likely saw this CVE first) isn't lost from the record."""
    by_cve = {}
    for e in org_entries:
        by_cve[e["cve"]] = {**e, "sources": [e["source"]]}
    for e in kev_entries:
        if e["cve"] in by_cve:
            by_cve[e["cve"]] = {**e, "sources": [by_cve[e["cve"]]["source"], e["source"]]}
        else:
            by_cve[e["cve"]] = {**e, "sources": [e["source"]]}
    return list(by_cve.values())


def main():
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ap = argparse.ArgumentParser()
    ap.add_argument("--kev-file", default=None,
                     help="path to a local KEV JSON file instead of fetching live")
    ap.add_argument("--skip-cve-org", action="store_true",
                     help="skip the cve.org speed source (e.g. for offline/CLI testing)")
    ap.add_argument("--targets-dir", default=os.path.join(repo_root, "targets"))
    ap.add_argument("--state-file", default=os.path.join(repo_root, "data", "state", "kev_state.json"))
    ap.add_argument("--cve-org-fetch-log", default=os.path.join(repo_root, "data", "state", "cve_org_last_fetch.txt"))
    ap.add_argument("--output", default=os.path.join(repo_root, "output", "hunter_queue.md"))
    args = ap.parse_args()

    if args.kev_file:
        kev_entries = cisa_kev.load_from_file(args.kev_file)
        kev_error = None
    else:
        kev_entries, kev_error = cisa_kev.fetch_normalized()

    if kev_error:
        print(f"⚠️ KEV fetch failed: {kev_error}")
        print("ℹ️ Not overwriting existing state/output on a failed fetch — "
              "a fetch failure must never look like 'zero new CVEs today'.")
        sys.exit(1)
    print(f"ℹ️ {len(kev_entries)} total KEV entries loaded (confirmed-exploitation source)")

    org_entries = []
    if not args.skip_cve_org:
        org_entries, org_error, org_fetch_time = cve_org.fetch_normalized()
        if org_error:
            # cve_org failing is NOT fatal the way KEV failing is — KEV is the
            # authoritative confirmation source; cve_org is the speed bonus on
            # top of it. Losing the speed source for one run still leaves KEV
            # working, so this run continues rather than aborting entirely.
            print(f"⚠️ cve.org fetch failed (continuing with KEV only): {org_error}")
        else:
            print(f"ℹ️ {len(org_entries)} entries from cve.org delta (near-real-time source)")
            last_fetch_time = None
            if os.path.isfile(args.cve_org_fetch_log):
                with open(args.cve_org_fetch_log) as f:
                    last_fetch_time = f.read().strip() or None
            gap_warning = cve_org.check_for_gap(org_fetch_time, last_fetch_time)
            if gap_warning:
                print(gap_warning)
            os.makedirs(os.path.dirname(args.cve_org_fetch_log), exist_ok=True)
            with open(args.cve_org_fetch_log, "w") as f:
                f.write(org_fetch_time or "")

    entries = merge_sources(kev_entries, org_entries)
    print(f"ℹ️ {len(entries)} unique CVEs after merging both sources")

    previous_state = state_diff.load_state(args.state_file)
    new_entries, updated_entries, unchanged_count = state_diff.diff(entries, previous_state)
    print(f"ℹ️ diff: {len(new_entries)} new, {len(updated_entries)} updated, {unchanged_count} unchanged")

    targets = technology_matcher.load_all_targets(args.targets_dir)
    print(f"ℹ️ {len(targets)} target(s) loaded from {args.targets_dir}")

    new_entries = technology_matcher.match_targets(new_entries, targets)
    updated_entries = technology_matcher.match_targets(updated_entries, targets)

    md = hunter_queue.render(new_entries, updated_entries, len(targets))
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(md)
    print(f"✅ hunter_queue.md written -> {args.output}")

    # Only advance state on a fully successful run — see the early exit
    # above for the KEV fetch-failure case.
    state_diff.save_state(args.state_file, entries)
    print(f"✅ state saved -> {args.state_file}")


if __name__ == "__main__":
    main()

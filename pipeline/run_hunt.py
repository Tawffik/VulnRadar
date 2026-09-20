#!/usr/bin/env python3
"""
pipeline/run_hunt.py

Orchestrates one full VulnRadar run:
  fetch CISA KEV -> diff against last state -> match against targets/*.yaml
  -> render output/hunter_queue.md -> save new state

Usage:
  python3 pipeline/run_hunt.py [--kev-file PATH] [--targets-dir DIR]
                                [--state-file PATH] [--output PATH]

--kev-file lets CI (or a test) pass a pre-downloaded snapshot instead of
hitting the network, e.g. after a separate `curl` step — this keeps the
network dependency isolated to one place instead of buried in Python,
matching this project's own established pattern from BugBountyCI.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pipeline.collectors import cisa_kev
from pipeline.intelligence import state_diff, technology_matcher
from pipeline.reporting import hunter_queue


def main():
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ap = argparse.ArgumentParser()
    ap.add_argument("--kev-file", default=None,
                     help="path to a local KEV JSON file instead of fetching live")
    ap.add_argument("--targets-dir", default=os.path.join(repo_root, "targets"))
    ap.add_argument("--state-file", default=os.path.join(repo_root, "data", "state", "kev_state.json"))
    ap.add_argument("--output", default=os.path.join(repo_root, "output", "hunter_queue.md"))
    args = ap.parse_args()

    if args.kev_file:
        entries = cisa_kev.load_from_file(args.kev_file)
        error = None
    else:
        entries, error = cisa_kev.fetch_normalized()

    if error:
        print(f"⚠️ KEV fetch failed: {error}")
        print("ℹ️ Not overwriting existing state/output on a failed fetch — "
              "a fetch failure must never look like 'zero new CVEs today'.")
        sys.exit(1)

    print(f"ℹ️ {len(entries)} total KEV entries loaded")

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
    # above for the fetch-failure case.
    state_diff.save_state(args.state_file, entries)
    print(f"✅ state saved -> {args.state_file}")


if __name__ == "__main__":
    main()

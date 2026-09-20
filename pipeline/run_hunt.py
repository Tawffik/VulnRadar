#!/usr/bin/env python3
"""
pipeline/run_hunt.py

Orchestrates one full VulnRadar run using FIVE sources together:
  - cisa_kev: confirmed real-world exploitation (authoritative, but slow —
    CISA only adds a CVE after confirming active exploitation)
  - cve_org: the official CVE.org record feed, updated ~every 7 minutes —
    the speed source, often surfacing a CVE hours/days before KEV would
  - github_advisories: dependency/library-level CVEs (npm, PyPI, Maven,
    etc.) neither of the above cover well
  - nvd: structured CPE version-range data, feeding the future Version
    Intelligence roadmap item (captured now, not yet used for matching)
  - nuclei_templates: a NEW public Nuclei detection template for a CVE
    is a strong "a working PoC/detection already exists" signal, often
    appearing within hours of disclosure

  fetch all five -> merge (ascending priority: nuclei_templates < cve_org
  < github_advisories < nvd < cisa_kev, every source tagged even when
  another wins) -> diff against last state -> match against
  targets/*.yaml -> render output/hunter_queue.md -> save new state

Usage:
  python3 pipeline/run_hunt.py [--kev-file PATH]
                                [--skip-cve-org] [--skip-github-advisories]
                                [--skip-nvd] [--skip-nuclei-templates]
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

from pipeline.collectors import cisa_kev, cve_org, github_advisories, nvd, nuclei_templates
from pipeline.intelligence import state_diff, technology_matcher
from pipeline.reporting import hunter_queue


def merge_sources(*entry_lists: list) -> list:
    """Combines any number of collectors into one list, deduped by CVE
    ID. entry_lists must be given in ASCENDING priority order — later
    lists win on conflict. Current priority (lowest to highest):
        nuclei_templates < cve_org < github_advisories < nvd < cisa_kev
    nuclei_templates is lowest priority because its vendor/product is a
    tag-based heuristic guess, not structured data like the other four
    (see nuclei_templates.py's own docstring) — it should never
    override a more reliable source's vendor/product when both report
    the same CVE. cisa_kev wins overall because it carries the
    authoritative ransomware_use flag none of the others have; nvd is
    next-highest because it has structured CPE version data the others
    lack. Every source that contributed to a given CVE is recorded in
    'sources' regardless of which one's data ultimately wins, so a fast
    sighting from a lower-priority source is never silently lost even
    after a higher-priority source later confirms the same CVE."""
    by_cve = {}
    skipped = 0
    for entries in entry_lists:
        for e in entries:
            cve = e.get("cve")
            if not cve:
                skipped += 1
                continue  # a malformed entry from any collector must not crash the whole run
            source = e.get("source", "unknown")
            if cve in by_cve:
                prior_sources = by_cve[cve]["sources"]
                by_cve[cve] = {**e, "sources": prior_sources + [source]}
            else:
                by_cve[cve] = {**e, "sources": [source]}
    if skipped:
        print(f"⚠️ {skipped} entry/entries had no CVE ID and were skipped during merge "
              f"(a collector may have a schema issue — check its source)")
    return list(by_cve.values())


def parse_adhoc_technologies(tech_string: str) -> list:
    """Parses 'vendor:product,vendor:product' (product optional, e.g.
    'nginx:,Apache:HTTP Server') into technology_matcher.py's expected
    shape. Used both by --adhoc-tech here and by scripts/save_target.py
    when persisting a workflow_dispatch input as a real target file, so
    the two never drift out of sync on parsing rules."""
    technologies = []
    for pair in (tech_string or "").split(","):
        pair = pair.strip()
        if not pair:
            continue
        if ":" in pair:
            vendor, product = pair.split(":", 1)
        else:
            vendor, product = pair, ""
        vendor = vendor.strip()
        product = product.strip()
        if vendor or product:
            technologies.append({"vendor": vendor, "product": product})
    return technologies


def main():
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ap = argparse.ArgumentParser()
    ap.add_argument("--kev-file", default=None,
                     help="path to a local KEV JSON file instead of fetching live")
    ap.add_argument("--skip-cve-org", action="store_true")
    ap.add_argument("--skip-github-advisories", action="store_true")
    ap.add_argument("--skip-nvd", action="store_true")
    ap.add_argument("--skip-nuclei-templates", action="store_true")
    ap.add_argument("--targets-dir", default=os.path.join(repo_root, "targets"))
    ap.add_argument("--state-file", default=os.path.join(repo_root, "data", "state", "kev_state.json"))
    ap.add_argument("--cve-org-fetch-log", default=os.path.join(repo_root, "data", "state", "cve_org_last_fetch.txt"))
    ap.add_argument("--output", default=os.path.join(repo_root, "output", "hunter_queue.md"))
    ap.add_argument("--adhoc-target", default=None,
                     help="a target domain not saved to targets/*.yaml — for a one-off check "
                          "(e.g. from a workflow_dispatch input) without a permanent file")
    ap.add_argument("--adhoc-tech", default="",
                     help="comma-separated vendor:product pairs for --adhoc-target, "
                          "e.g. 'nginx:nginx,Apache:HTTP Server'")
    args = ap.parse_args()

    if args.kev_file:
        kev_entries = cisa_kev.load_from_file(args.kev_file)
        kev_error = None
    else:
        kev_entries, kev_error = cisa_kev.fetch_normalized()

    if kev_error:
        # KEV is the only source whose failure is fatal to the run — it's
        # the authoritative confirmed-exploitation signal every other
        # source's priority is defined relative to (see merge_sources()).
        print(f"⚠️ KEV fetch failed: {kev_error}")
        print("ℹ️ Not overwriting existing state/output on a failed fetch — "
              "a fetch failure must never look like 'zero new CVEs today'.")
        sys.exit(1)
    print(f"ℹ️ {len(kev_entries)} total KEV entries loaded (confirmed-exploitation source)")

    org_entries = []
    if not args.skip_cve_org:
        org_entries, org_error, org_fetch_time = cve_org.fetch_normalized()
        if org_error:
            print(f"⚠️ cve.org fetch failed (continuing without it): {org_error}")
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

    gh_entries = []
    if not args.skip_github_advisories:
        gh_entries, gh_error = github_advisories.fetch_normalized()
        if gh_error:
            print(f"⚠️ GitHub Advisories fetch failed (continuing without it): {gh_error}")
        else:
            print(f"ℹ️ {len(gh_entries)} entries from GitHub Security Advisories "
                  f"(dependency/library CVEs)")

    nvd_entries = []
    if not args.skip_nvd:
        nvd_entries, nvd_error = nvd.fetch_normalized()
        if nvd_error:
            print(f"⚠️ NVD fetch failed (continuing without it): {nvd_error}")
        else:
            print(f"ℹ️ {len(nvd_entries)} entries from NVD (structured CPE/version data)")

    nuclei_entries = []
    if not args.skip_nuclei_templates:
        nuclei_entries, nuclei_error = nuclei_templates.fetch_normalized()
        if nuclei_error:
            print(f"⚠️ Nuclei Templates fetch failed (continuing without it): {nuclei_error}")
        else:
            print(f"ℹ️ {len(nuclei_entries)} entries from new Nuclei CVE templates "
                  f"(PoC/detection-availability signal)")

    # Ascending priority order — see merge_sources()'s own docstring for why.
    entries = merge_sources(nuclei_entries, org_entries, gh_entries, nvd_entries, kev_entries)
    print(f"ℹ️ {len(entries)} unique CVEs after merging all sources")

    previous_state = state_diff.load_state(args.state_file)
    new_entries, updated_entries, unchanged_count = state_diff.diff(entries, previous_state)
    print(f"ℹ️ diff: {len(new_entries)} new, {len(updated_entries)} updated, {unchanged_count} unchanged")

    targets = technology_matcher.load_all_targets(args.targets_dir)
    print(f"ℹ️ {len(targets)} target(s) loaded from {args.targets_dir}")

    if args.adhoc_target:
        adhoc = {"target": args.adhoc_target, "technologies": parse_adhoc_technologies(args.adhoc_tech)}
        targets.append(adhoc)
        print(f"ℹ️ + 1 ad-hoc target ({args.adhoc_target}, "
              f"{len(adhoc['technologies'])} technology/ies) — not saved to targets/")

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

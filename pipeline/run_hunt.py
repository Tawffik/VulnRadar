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
from pipeline.intelligence import state_diff, state_store, technology_matcher, version_check
from pipeline.intelligence.run_status import RunSummary, CollectorResult, TargetResult, RUN_FAILED
from pipeline.verify import nuclei_runner
from pipeline.recon import exposure_scan
from pipeline.reporting import hunter_queue
from pipeline.notifiers import discord


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

    summary = RunSummary()
    state_dir = os.path.dirname(args.state_file) or "."
    state_store.migrate_legacy_state(args.state_file, state_dir)

    # ---- 5 collectors, each isolated: one failing never stops the rest,
    # and CISA is no longer special-cased as fatal — every source is
    # handled through the same uniform path (see docs/PROJECT_PLAN.md,
    # "Bugs Fixed" #8 for why this changed and what it fixes). ----
    if args.kev_file:
        try:
            kev_entries, kev_error = cisa_kev.load_from_file(args.kev_file), None
        except (OSError, ValueError) as e:
            # a local snapshot path (used by CI/tests) can be missing or
            # malformed too - this must classify as a normal collector
            # failure, not crash the whole run before any other source
            # even gets a chance to run.
            kev_entries, kev_error = [], f"could not load KEV snapshot file: {e}"
    else:
        kev_entries, kev_error = cisa_kev.fetch_normalized()
    kev_result = CollectorResult("cisa_kev", kev_entries, kev_error)
    if kev_error:
        print(f"⚠️ CISA KEV fetch failed (continuing without it, previous KEV state preserved): {kev_error}")
    else:
        print(f"ℹ️ {len(kev_entries)} total KEV entries loaded (confirmed-exploitation source)")

    org_entries, org_error = [], None
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
                summary.warn(gap_warning)
            os.makedirs(os.path.dirname(args.cve_org_fetch_log), exist_ok=True)
            with open(args.cve_org_fetch_log, "w") as f:
                f.write(org_fetch_time or "")
    org_result = CollectorResult("cve_org", org_entries, org_error)

    gh_entries, gh_error = [], None
    if not args.skip_github_advisories:
        gh_entries, gh_error = github_advisories.fetch_normalized()
        if gh_error:
            print(f"⚠️ GitHub Advisories fetch failed (continuing without it): {gh_error}")
        else:
            print(f"ℹ️ {len(gh_entries)} entries from GitHub Security Advisories (dependency/library CVEs)")
    gh_result = CollectorResult("github_advisories", gh_entries, gh_error)

    nvd_entries, nvd_error = [], None
    if not args.skip_nvd:
        nvd_entries, nvd_error = nvd.fetch_normalized()
        if nvd_error:
            print(f"⚠️ NVD fetch failed (continuing without it): {nvd_error}")
        else:
            print(f"ℹ️ {len(nvd_entries)} entries from NVD (structured CPE/version data)")
    nvd_result = CollectorResult("nvd", nvd_entries, nvd_error)

    nuclei_entries, nuclei_error = [], None
    if not args.skip_nuclei_templates:
        nuclei_entries, nuclei_error = nuclei_templates.fetch_normalized()
        if nuclei_error:
            print(f"⚠️ Nuclei Templates fetch failed (continuing without it): {nuclei_error}")
        else:
            print(f"ℹ️ {len(nuclei_entries)} entries from new Nuclei CVE templates (PoC/detection-availability signal)")
    nuclei_result = CollectorResult("nuclei_templates", nuclei_entries, nuclei_error)

    collector_results = [kev_result, org_result, gh_result, nvd_result, nuclei_result]
    for r in collector_results:
        summary.add_collector(r)

    # A source that failed this run falls back to its OWN last-known-good
    # per-source state file for diffing purposes (see state_store.py) -
    # this is the actual fix for the state-loss bug: a CVE known only via
    # a source that's down today is still correctly "already seen"
    # against the merged view below, not silently forgotten.
    for r in collector_results:
        if not r.is_ok():
            r.previous_state_used = bool(state_store.load_source_state(state_dir, r.name))

    if all(not r.is_ok() for r in collector_results) and not any(r.previous_state_used for r in collector_results):
        # Scenario G: nothing usable at all, and no prior history to fall
        # back on either. Do NOT claim "no vulnerabilities found" and do
        # NOT touch state/output - preserve whatever was there before.
        print("❌ all 5 sources failed and no previous state exists — no usable intelligence this run")
        summary.set_stage("matching", "SKIPPED")
        summary.set_stage("reporting", "SKIPPED")
        print(summary.render_markdown())
        _write_step_summary(summary)
        summary.write_json(os.path.join(repo_root, "output", "run_summary.json"))
        sys.exit(summary.exit_code())

    # Ascending priority order — see merge_sources()'s own docstring for why.
    entries = merge_sources(nuclei_entries, org_entries, gh_entries, nvd_entries, kev_entries)
    print(f"ℹ️ {len(entries)} unique CVEs after merging all sources that succeeded this run")

    previous_state = state_store.load_merged_state(state_dir)
    new_entries, updated_entries, unchanged_count = state_diff.diff(entries, previous_state)
    print(f"ℹ️ diff: {len(new_entries)} new, {len(updated_entries)} updated, {unchanged_count} unchanged")
    summary.counts.update({"new_cves": len(new_entries), "updated_cves": len(updated_entries)})

    targets = technology_matcher.load_all_targets(args.targets_dir)
    print(f"ℹ️ {len(targets)} target(s) loaded from {args.targets_dir}")

    if args.adhoc_target:
        adhoc = {"target": args.adhoc_target, "technologies": parse_adhoc_technologies(args.adhoc_tech)}
        targets.append(adhoc)
        print(f"ℹ️ + 1 ad-hoc target ({args.adhoc_target}, "
              f"{len(adhoc['technologies'])} technology/ies) — not saved to targets/")

    try:
        new_entries = technology_matcher.match_targets(new_entries, targets)
        updated_entries = technology_matcher.match_targets(updated_entries, targets)
        summary.set_stage("matching", "SUCCESS")
    except Exception as e:
        summary.set_stage("matching", "FAILED")
        summary.warn(f"target matching failed unexpectedly, entries left unmatched: {type(e).__name__}: {e}")

    try:
        new_entries = version_check.annotate_entries(new_entries, targets)
        updated_entries = version_check.annotate_entries(updated_entries, targets)
        summary.set_stage("version_check", "SUCCESS")
    except Exception as e:
        summary.set_stage("version_check", "UNAVAILABLE")
        summary.warn(f"version check failed unexpectedly, verdicts left as unknown: {type(e).__name__}: {e}")

    if nuclei_runner.is_available():
        try:
            new_entries = nuclei_runner.verify_entries(new_entries, targets)
            updated_entries = nuclei_runner.verify_entries(updated_entries, targets)
            summary.set_stage("nuclei_verification", "SUCCESS")
        except Exception as e:
            summary.set_stage("nuclei_verification", "UNAVAILABLE")
            summary.warn(f"nuclei verification failed unexpectedly: {type(e).__name__}: {e}")
    else:
        print("ℹ️ nuclei binary not found — skipping live verification (name-match only)")
        summary.set_stage("nuclei_verification", "UNAVAILABLE")

    exposure_reports = []
    real_domains = [t["target"] for t in targets if t.get("target")]
    if real_domains:
        try:
            exposure_reports = exposure_scan.scan_targets(real_domains)
            n_findings = sum(1 for r in exposure_reports if exposure_scan.has_findings(r))
            print(f"ℹ️ exposure scan: {n_findings}/{len(exposure_reports)} target(s) with findings")
            summary.set_stage("exposure_scan", "SUCCESS")
        except Exception as e:
            summary.set_stage("exposure_scan", "FAILED")
            summary.warn(f"exposure scan failed unexpectedly: {type(e).__name__}: {e}")

    for t in targets:
        name = t.get("target")
        if not name:
            continue
        exp = next((r for r in exposure_reports if r.get("target") == name), None)
        summary.add_target(TargetResult(name, fingerprint_ok=True,   # fingerprinting runs as a
                                                                        # separate prior workflow step
                                                                        # (scripts/refresh_target_fingerprints.py),
                                                                        # which already isolates per-target
                                                                        # failures itself - not re-tracked here
                                          exposure_ok=not (exp and exp.get("error")),
                                          exposure_error=exp.get("error") if exp else None))

    try:
        md = hunter_queue.render(new_entries, updated_entries, len(targets))
        md += hunter_queue.render_exposure(exposure_reports)
        if not all(r.is_ok() for r in collector_results):
            failed_names = ", ".join(r.name for r in collector_results if not r.is_ok())
            md = (f"> ⚠️ **This report is based on partial source coverage** "
                  f"({failed_names} unavailable this run). Absence of a finding here "
                  f"does not mean no vulnerability exists — see Pipeline Health below.\n\n") + md
        md += "\n\n" + summary.render_markdown()
        os.makedirs(os.path.dirname(args.output), exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(md)
        print(f"✅ hunter_queue.md written -> {args.output}")
        summary.set_stage("reporting", "SUCCESS")
    except Exception as e:
        summary.set_stage("reporting", "FAILED")
        summary.warn(f"report generation failed unexpectedly: {type(e).__name__}: {e}")

    # Notifications are independent of everything above succeeding -
    # discord.notify already never raises (see its own docstring); this
    # try/except is defense-in-depth against a bug in that guarantee, not
    # a substitute for it.
    try:
        n_sent = discord.notify(new_entries, updated_entries, exposure_reports=exposure_reports)
        if n_sent:
            print(f"✅ {n_sent} entr(y/ies) sent to Discord")
        elif os.environ.get("DISCORD_WEBHOOK_URL"):
            print("ℹ️ nothing sent to Discord this run (nothing relevant, or see warning above)")
        else:
            print("ℹ️ DISCORD_WEBHOOK_URL not set — Discord notifications disabled")
        summary.set_stage("notifications", "SUCCESS")
    except Exception as e:
        summary.set_stage("notifications", "FAILED")
        summary.warn(f"Discord notification failed unexpectedly (hunt result unaffected): {type(e).__name__}: {e}")

    # Only sources that succeeded THIS run advance their state file; a
    # failed source's file is left untouched (see state_store.py) - this
    # is the fix for the state-loss bug described at the top of main().
    written = state_store.update_states(state_dir, collector_results)
    print(f"✅ state saved for: {', '.join(written) or '(no source succeeded this run)'}")

    print("\n" + summary.render_markdown())
    _write_step_summary(summary)
    summary.write_json(os.path.join(repo_root, "output", "run_summary.json"))
    sys.exit(summary.exit_code())


def _write_step_summary(summary: RunSummary) -> None:
    """Appends to $GITHUB_STEP_SUMMARY when running inside GitHub Actions
    (see workflow section 31 of the hardening spec) - a no-op locally."""
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(summary.render_markdown() + "\n")
    except OSError as e:
        print(f"⚠️ could not write $GITHUB_STEP_SUMMARY: {e}")


if __name__ == "__main__":
    main()

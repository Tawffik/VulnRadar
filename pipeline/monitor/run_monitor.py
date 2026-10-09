#!/usr/bin/env python3
"""
pipeline/monitor/run_monitor.py

One Subdomain Monitor cycle for all targets (or a single --domain):
  passive discover → probe live → baseline diff (new/removed)

Never runs nuclei. Never scans outside each target's domain suffix.
Writes data/monitor/<domain>/ and output/monitor_summary.md
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from pipeline.intelligence import technology_matcher
from pipeline.monitor.baseline import apply_run
from pipeline.monitor.probe import probe_hosts
from pipeline.recon import subdomains

DEFAULT_MAX_SUBS = 200


def _domain_dir(monitor_dir: Path, domain: str) -> Path:
    safe = domain.strip().lower().replace("/", "_")
    return monitor_dir / safe


def monitor_one(
    domain: str,
    monitor_dir: Path,
    *,
    max_subdomains: int = DEFAULT_MAX_SUBS,
    probe_timeout: int = 8,
) -> dict:
    domain = domain.strip().lower()
    report = {
        "target": domain,
        "status": "INCOMPLETE",
        "discovered": 0,
        "live": 0,
        "new_count": 0,
        "removed_count": 0,
        "discover_error": None,
        "probe": {},
        "ts": datetime.now(timezone.utc).isoformat(),
    }

    hosts, err = subdomains.discover(domain, max_results=max_subdomains, timeout=90)
    report["discover_error"] = err
    # Always include apex
    if domain not in hosts:
        hosts = [domain] + list(hosts)
    # scope filter again
    hosts = [h for h in hosts if h == domain or h.endswith("." + domain)]
    report["discovered"] = len(hosts)

    ddir = _domain_dir(monitor_dir, domain)
    ddir.mkdir(parents=True, exist_ok=True)
    (ddir / "subdomains.txt").write_text(
        "\n".join(hosts) + ("\n" if hosts else ""), encoding="utf-8"
    )

    live, probe_meta = probe_hosts(hosts, timeout=probe_timeout)
    report["probe"] = probe_meta
    report["live"] = len(live)

    # Incomplete if discovery failed hard AND no live hosts
    force_empty = False
    if not live and err:
        report["status"] = "INCOMPLETE"
    elif not live:
        report["status"] = "INCOMPLETE_EMPTY_LIVE"
    else:
        report["status"] = "COMPLETE"

    diff = apply_run(ddir, live, force_update_empty=force_empty)
    report["new_count"] = diff["new_count"]
    report["removed_count"] = diff["removed_count"]
    report["new"] = diff["new"][:50]
    report["removed"] = diff["removed"][:50]
    report["baseline_updated"] = diff["baseline_updated"]
    if report["status"] == "COMPLETE" and diff.get("status") == "INCOMPLETE_EMPTY_LIVE":
        report["status"] = "INCOMPLETE_EMPTY_LIVE"

    (ddir / "state.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def write_summary(reports: list, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# VulnRadar Subdomain Monitor",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        f"Targets: {len(reports)}",
        "",
        "| Target | Status | Discovered | Live | New | Removed |",
        "|--------|--------|----------:|-----:|----:|--------:|",
    ]
    for r in reports:
        lines.append(
            f"| {r['target']} | {r['status']} | {r['discovered']} | {r['live']} | "
            f"{r['new_count']} | {r['removed_count']} |"
        )
    lines.append("")
    for r in reports:
        if r.get("new"):
            lines.append(f"### New on {r['target']}")
            for h in r["new"]:
                lines.append(f"- `{h}`")
            lines.append("")
        if r.get("removed"):
            lines.append(f"### Removed on {r['target']}")
            for h in r["removed"]:
                lines.append(f"- `{h}`")
            lines.append("")
        if r.get("discover_error"):
            lines.append(f"- _{r['target']} discovery: {r['discover_error']}_")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="VulnRadar subdomain baseline monitor")
    ap.add_argument("--targets-dir", default="targets")
    ap.add_argument("--monitor-dir", default="data/monitor")
    ap.add_argument("--output", default="output/monitor_summary.md")
    ap.add_argument("--domain", default="", help="Optional single domain override")
    ap.add_argument("--max-subdomains", type=int, default=DEFAULT_MAX_SUBS)
    ap.add_argument("--probe-timeout", type=int, default=8)
    args = ap.parse_args(argv)

    monitor_dir = Path(args.monitor_dir)
    monitor_dir.mkdir(parents=True, exist_ok=True)

    if args.domain.strip():
        domains = [args.domain.strip().lower()]
    else:
        targets = technology_matcher.load_all_targets(args.targets_dir)
        domains = [t["target"].strip().lower() for t in targets if t.get("target")]
        # skip pure example placeholder if others exist
        if len(domains) > 1:
            domains = [d for d in domains if d != "example.com"]

    if not domains:
        print("No targets to monitor")
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text("# VulnRadar Subdomain Monitor\n\nNo targets.\n")
        return 10

    reports = []
    for d in domains:
        print(f"📡 Monitoring {d} ...")
        r = monitor_one(
            d,
            monitor_dir,
            max_subdomains=args.max_subdomains,
            probe_timeout=args.probe_timeout,
        )
        reports.append(r)
        print(
            f"   status={r['status']} discovered={r['discovered']} live={r['live']} "
            f"new={r['new_count']} removed={r['removed_count']}"
        )

    write_summary(reports, Path(args.output))
    summary_json = Path(args.output).with_suffix(".json")
    summary_json.write_text(json.dumps({"reports": reports}, indent=2) + "\n")

    complete = sum(1 for r in reports if r["status"] == "COMPLETE")
    if complete == 0:
        return 10  # degraded
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

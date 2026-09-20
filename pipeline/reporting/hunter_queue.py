#!/usr/bin/env python3
"""
pipeline/reporting/hunter_queue.py

Renders the final output/hunter_queue.md. Deliberately does NOT dump
every new KEV entry — CISA adds dozens of entries a week, and the vast
majority won't matter to any given set of targets. Per this project's
own design principle (from the CVE Intelligence brief): "CVE Intelligence
+ Target Correlation + Detection Orchestration", not "CVE Scanner" —
value comes from relevance, not volume.

Priority tiers (investigation priority, NOT CVSS/severity):
  1. NEW + matched to a target + known ransomware use   (highest)
  2. NEW + matched to a target
  3. UPDATED (ransomware flag changed) + matched to a target
  4. NEW + known ransomware use, but no target match     (reference only —
     still worth a glance in case the target list is incomplete)

Entries with no target match and no ransomware flag are counted in the
summary but never rendered individually — that's the whole point of
having a matcher at all.
"""
from datetime import datetime, timezone


def _priority(entry: dict) -> int:
    matched = bool(entry.get("matched_targets"))
    ransomware = entry.get("ransomware_use") == "Known"
    if matched and ransomware:
        return 0
    if matched:
        return 1
    if entry.get("_is_update") and matched:
        return 2
    if ransomware:
        return 3
    return 99  # never actually rendered — see render()


def render(new_entries: list, updated_entries: list, targets_loaded: int) -> str:
    for e in updated_entries:
        e["_is_update"] = True

    candidates = [e for e in (new_entries + updated_entries)
                  if e.get("matched_targets") or e.get("ransomware_use") == "Known"]
    candidates.sort(key=_priority)

    lines = [
        "# VulnRadar Hunter Queue",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        f"Targets loaded: {targets_loaded}",
        f"New KEV entries this run: {len(new_entries)}",
        f"Updated KEV entries this run (ransomware flag changed): {len(updated_entries)}",
        f"Entries below (target-matched or known-ransomware): {len(candidates)}",
        "",
        "> A CVE affecting a matched technology is a candidate needing manual "
        "version verification, not a confirmed vulnerability. This project "
        "does not run exploitation — see 'Next Safe Action' on each entry.",
        "",
    ]

    if not candidates:
        lines.append("No target-relevant or high-priority KEV entries this run.")
        return "\n".join(lines) + "\n"

    for i, e in enumerate(candidates, 1):
        status = "UPDATED — now flagged for known ransomware use" if e.get("_is_update") else "NEW"
        targets_str = ", ".join(e["matched_targets"]) if e.get("matched_targets") else "(no configured target matched — reference only)"

        lines += [
            f"## {i}. {e['cve']} — {status}",
            "",
            f"**Vendor / Product:** {e['vendor']} / {e['product']}",
            f"**Name:** {e['name']}",
            f"**Matched target(s):** {targets_str}",
            f"**Known ransomware use:** {e['ransomware_use']}",
            f"**Date added to KEV:** {e['date_added']}",
            f"**CISA required action:** {e.get('required_action', '(none listed)')}",
            "",
            f"**Description:** {e.get('description', '(none)')}",
            "",
            "**Next Safe Action:** Verify the exact deployed version on the "
            "matched target(s) falls within the affected range before treating "
            "this as a real finding. Reproduce only within authorized scope.",
            "",
            "---",
            "",
        ]
    return "\n".join(lines)

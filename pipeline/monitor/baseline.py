"""
pipeline/monitor/baseline.py

Pure baseline diff for subdomain monitoring.
No network I/O — discovery/probe stay in callers so tests stay offline.

Semantics match the BugBountyCI Subdomain Monitor artifacts:
  prev (previous live set) vs live (current live set)
  → new / removed / still
Incomplete runs must not overwrite a good baseline with an empty live set
unless force_update_empty is True.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable


def _norm_set(hosts: Iterable[str]) -> set[str]:
    out = set()
    for h in hosts:
        h = (h or "").strip().lower()
        if not h or h.startswith("#"):
            continue
        out.add(h)
    return out


def diff_baselines(prev: Iterable[str], live: Iterable[str]) -> dict:
    p, l = _norm_set(prev), _norm_set(live)
    return {
        "prev_count": len(p),
        "live_count": len(l),
        "new": sorted(l - p),
        "removed": sorted(p - l),
        "still": sorted(p & l),
        "new_count": len(l - p),
        "removed_count": len(p - l),
        "still_count": len(p & l),
    }


def should_update_baseline(live: Iterable[str], *, force_update_empty: bool = False) -> bool:
    """Refuse to replace a baseline with empty live unless forced (avoids false 'all removed')."""
    live_n = len(_norm_set(live))
    if live_n > 0:
        return True
    return force_update_empty


def apply_run(
    state_dir: Path,
    live_hosts: Iterable[str],
    *,
    force_update_empty: bool = False,
) -> dict:
    """
    Read prev.txt if present, write live/new/removed/prev for next run.
    Returns the diff dict plus status.
    """
    state_dir = Path(state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    prev_path = state_dir / "prev.txt"
    live_path = state_dir / "live.txt"
    new_path = state_dir / "new.txt"
    removed_path = state_dir / "removed.txt"

    prev = []
    if prev_path.exists():
        prev = prev_path.read_text(encoding="utf-8", errors="replace").splitlines()

    live_list = sorted(_norm_set(live_hosts))
    result = diff_baselines(prev, live_list)
    result["status"] = "COMPLETE" if live_list or force_update_empty else "INCOMPLETE_EMPTY_LIVE"
    result["baseline_updated"] = False

    live_path.write_text("\n".join(live_list) + ("\n" if live_list else ""), encoding="utf-8")
    new_path.write_text("\n".join(result["new"]) + ("\n" if result["new"] else ""), encoding="utf-8")
    removed_path.write_text("\n".join(result["removed"]) + ("\n" if result["removed"] else ""), encoding="utf-8")

    if should_update_baseline(live_list, force_update_empty=force_update_empty):
        prev_path.write_text("\n".join(live_list) + ("\n" if live_list else ""), encoding="utf-8")
        result["baseline_updated"] = True

    return result

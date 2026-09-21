#!/usr/bin/env python3
"""
pipeline/intelligence/version_check.py

Compares a target's known installed version (from a fingerprint scan,
now stored in targets/*.yaml as `version:` alongside each technology —
see pipeline/recon/fingerprint.py) against a CVE's NVD cpe_version_range
(nvd.py already collects this; nothing used it until now).

Returns one of three verdicts per (entry, target-technology) pair:
  "confirmed"  - target's version falls inside the CVE's affected range
  "safe"       - target's version falls OUTSIDE the range (patched/newer)
  "unknown"    - can't tell: target has no known version, or the CVE
                 entry has no version-range data (KEV/cve.org/github_
                 advisories/nuclei_templates don't carry this; nvd.py
                 does) — this is the common case and is treated the
                 same as today's "needs manual verification", never as
                 a false "confirmed"

Version comparison uses packaging.version when available (handles real
semver plus common oddities like "1.18.0p1"); falls back to a simple
tuple-of-ints comparison otherwise so this never hard-fails on a
missing dependency, just gets less precise on unusual version strings.
"""
import re

try:
    from packaging.version import Version, InvalidVersion
    _HAVE_PACKAGING = True
except ImportError:
    _HAVE_PACKAGING = False


def _parse(v: str):
    if v is None:
        return None
    if _HAVE_PACKAGING:
        try:
            return Version(v)
        except InvalidVersion:
            pass
    # Fallback: pull out the leading dotted-number run, e.g. "1.18.0p1" -> (1,18,0)
    m = re.match(r"^(\d+(?:\.\d+)*)", str(v))
    if not m:
        return None
    return tuple(int(x) for x in m.group(1).split("."))


def _cmp(a, b) -> int:
    """-1/0/1, comparing two values from _parse() (both Version, or both tuple)."""
    if isinstance(a, tuple) or isinstance(b, tuple):
        a = a if isinstance(a, tuple) else (a,)
        b = b if isinstance(b, tuple) else (b,)
        return (a > b) - (a < b)
    return (a > b) - (a < b)


def version_in_range(installed: str, version_range: dict) -> str:
    """version_range keys: start_including, start_excluding,
    end_including, end_excluding (any may be None). Returns
    "confirmed" | "safe" | "unknown"."""
    if not installed or not version_range:
        return "unknown"
    if not any(version_range.get(k) for k in
               ("start_including", "start_excluding", "end_including", "end_excluding")):
        return "unknown"  # NVD listed this CPE but with no bounded version range

    v = _parse(installed)
    if v is None:
        return "unknown"

    lo_inc, lo_exc = version_range.get("start_including"), version_range.get("start_excluding")
    hi_inc, hi_exc = version_range.get("end_including"), version_range.get("end_excluding")

    for bound, op in ((lo_inc, "lo_inc"), (lo_exc, "lo_exc"), (hi_inc, "hi_inc"), (hi_exc, "hi_exc")):
        if bound is None:
            continue
        pb = _parse(bound)
        if pb is None:
            return "unknown"  # a malformed bound must fall back to manual verification, not a guess
        c = _cmp(v, pb)
        if op == "lo_inc" and c < 0:
            return "safe"
        if op == "lo_exc" and c <= 0:
            return "safe"
        if op == "hi_inc" and c > 0:
            return "safe"
        if op == "hi_exc" and c >= 0:
            return "safe"
    return "confirmed"


def annotate_entry(entry: dict, targets: list) -> dict:
    """Given a matched entry (already has 'matched_targets' from
    technology_matcher.match_targets) and the full targets list, adds
    'version_verdict': the BEST verdict across every matched target's
    technology that shares this entry's vendor/product ("confirmed" >
    "unknown" > "safe" — one confirmed hit anywhere is worth surfacing
    even if other targets on the list are patched)."""
    if not entry.get("matched_targets"):
        return {**entry, "version_verdict": "unknown"}

    vr = entry.get("cpe_version_range")
    ev, ep = (entry.get("vendor") or "").lower(), (entry.get("product") or "").lower()
    rank = {"confirmed": 2, "unknown": 1, "safe": 0}
    best = "unknown"
    for target in targets:
        if target.get("target") not in entry["matched_targets"]:
            continue
        for tech in target.get("technologies") or []:
            tv, tp = (tech.get("vendor") or "").lower(), (tech.get("product") or "").lower()
            if ev not in (tv, tp) and ep not in (tv, tp) and tv not in (ev, ep) and tp not in (ev, ep):
                continue
            verdict = version_in_range(tech.get("version"), vr)
            if rank[verdict] > rank[best]:
                best = verdict
    return {**entry, "version_verdict": best}


def annotate_entries(entries: list, targets: list) -> list:
    return [annotate_entry(e, targets) for e in entries]

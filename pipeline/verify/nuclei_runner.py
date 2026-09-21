#!/usr/bin/env python3
"""
pipeline/verify/nuclei_runner.py

For a CVE that (a) matched a target's tech stack, and (b) has a known
nuclei template (nuclei_templates.py already detects "a new template
for CVE-X was just published" as a signal — this module goes one step
further and actually RUNS it), executes that template against the
target and reports the real result instead of "possibly affected".

SCOPE SAFETY — read before changing:
  - Only ever runs against a target already listed in targets/*.yaml.
    Never runs against an ad-hoc/unsaved target, and never runs against
    anything not explicitly present in the targets list passed in.
  - A target file can opt out entirely with `scan_allowed: false` (see
    targets/example.yaml) — checked BEFORE any subprocess call, not
    just documented. Default is false (opt-in), so a target added
    without that field is never auto-scanned.
  - Nuclei runs in its least invasive template mode: this only checks
    templates tagged for CVE detection (nuclei's own `-id CVE-XXXX-XXXXX`
    selector), never a full unrestricted scan.
  - Never raises: a nuclei failure/timeout/missing-binary is reported
    as a verdict of "error", the hunt continues regardless.

Verdicts: "vulnerable" | "not-vulnerable" | "no-template" | "skipped"
(scan not allowed) | "error" (nuclei problem, not a security finding).
"""
import json
import shutil
import subprocess

NUCLEI_TIMEOUT_SECONDS = 30
NUCLEI_BINARY = "nuclei"


def is_available(_which=None) -> bool:
    which = _which or shutil.which
    return which(NUCLEI_BINARY) is not None


def target_allows_scanning(target: dict) -> bool:
    """Opt-in only: missing or falsy scan_allowed means no scanning."""
    return bool(target.get("scan_allowed"))


def run_nuclei_for_cve(url: str, cve: str, timeout: int = NUCLEI_TIMEOUT_SECONDS,
                        _runner=None) -> tuple:
    """Returns (verdict, raw_findings). _runner injectable for tests."""
    if not is_available():
        return "error", []

    runner = _runner or subprocess.run
    cmd = [NUCLEI_BINARY, "-u", url, "-id", cve, "-json-export", "-",
           "-silent", "-timeout", str(timeout), "-no-color"]
    try:
        proc = runner(cmd, capture_output=True, text=True, timeout=timeout + 15)
    except subprocess.TimeoutExpired:
        return "error", []
    except FileNotFoundError:
        return "error", []
    except Exception:
        return "error", []

    out = (proc.stdout or "").strip()
    if not out:
        # nuclei prints nothing when no template exists for this CVE ID,
        # and nothing when the template ran but found nothing — both
        # look identical on stdout, so return code / stderr disambiguates.
        if "no templates" in (proc.stderr or "").lower() or "no results" in (proc.stderr or "").lower():
            return "no-template", []
        return "not-vulnerable", []

    try:
        findings = json.loads(out) if out.startswith("[") else [json.loads(line) for line in out.splitlines() if line.strip()]
    except json.JSONDecodeError:
        return "error", []

    return ("vulnerable", findings) if findings else ("not-vulnerable", [])


def verify_entry(entry: dict, targets: list, timeout: int = NUCLEI_TIMEOUT_SECONDS,
                  _runner=None) -> dict:
    """Only runs when entry['matched_targets'] is non-empty. Adds
    'nuclei_verdicts': {target_domain: verdict}. Never mutates entry
    in place; returns a new dict."""
    matched = entry.get("matched_targets") or []
    if not matched:
        return {**entry, "nuclei_verdicts": {}}

    by_domain = {t.get("target"): t for t in targets}
    verdicts = {}
    for domain in matched:
        target = by_domain.get(domain)
        if not target or not target_allows_scanning(target):
            verdicts[domain] = "skipped"
            continue
        url = target.get("url") or f"https://{domain}"
        verdict, _findings = run_nuclei_for_cve(url, entry.get("cve", ""), timeout=timeout, _runner=_runner)
        verdicts[domain] = verdict
    return {**entry, "nuclei_verdicts": verdicts}


def verify_entries(entries: list, targets: list, timeout: int = NUCLEI_TIMEOUT_SECONDS,
                    _runner=None) -> list:
    """Only worth calling on the already-filtered candidate list (matched
    or ransomware-known), not every raw entry — see run_hunt.py wiring."""
    return [verify_entry(e, targets, timeout=timeout, _runner=_runner) for e in entries]

#!/usr/bin/env python3
"""
pipeline/intelligence/run_status.py

The data model this hardening task is built around: every collector,
every target, and the run overall get an explicit status, so "zero
results" and "couldn't fetch" are never confused (see classify_error's
docstring), and a partial failure is reported as DEGRADED rather than
silently hidden or wrongly treated as a hard FAILED.
"""
import json
import os

# Collector-level statuses
SUCCESS = "SUCCESS"
EMPTY = "EMPTY"
FAILED = "FAILED"
TIMEOUT = "TIMEOUT"
RATE_LIMITED = "RATE_LIMITED"
INVALID_RESPONSE = "INVALID_RESPONSE"

# Overall run statuses
RUN_SUCCESS = "SUCCESS"
RUN_DEGRADED = "DEGRADED"
RUN_FAILED = "FAILED"

# Exit-code semantics (see docs/PROJECT_PLAN.md and the workflow's
# "Run VulnRadar" step, which reads this back out of stdout/state).
EXIT_SUCCESS = 0
EXIT_DEGRADED = 10
EXIT_FATAL = 20


def classify_error(error: str, entry_count: int) -> str:
    """Turns a collector's (entries, error) result into one status.
    error is None on a successful fetch (even if entry_count == 0 -
    that's a legitimate EMPTY, e.g. cve.org's delta genuinely had no
    NEW records in this window). error is a string on any failure -
    classified by keyword, since every collector's error strings are
    already written descriptively (see each collector's fetch_normalized
    docstring) rather than as a separate structured exception type,
    which would have meant changing all 5 collectors' return contracts.
    A wrong classification only affects the human-readable status
    label, never whether the failure is treated as fatal - that's
    always "continue without this source" regardless of which specific
    bucket it lands in."""
    if error is None:
        return SUCCESS if entry_count > 0 else EMPTY

    e = error.lower()
    if "429" in e or "rate limit" in e or "rate-limit" in e:
        return RATE_LIMITED
    if "timed out" in e or "timeout" in e:
        return TIMEOUT
    if "not valid json" in e or "invalid" in e or "unexpected" in e or "format may have changed" in e:
        return INVALID_RESPONSE
    return FAILED


class CollectorResult:
    """One source's outcome for this run."""

    def __init__(self, name: str, entries: list, error: str, previous_state_used: bool = False):
        self.name = name
        self.entries = entries or []
        self.error = error
        self.status = classify_error(error, len(self.entries))
        # True when this source failed and we fell back to its last
        # known-good per-source state file instead of losing that
        # source's previously-known CVEs entirely (see state_store.py).
        self.previous_state_used = previous_state_used

    def is_ok(self) -> bool:
        return self.status in (SUCCESS, EMPTY)

    def to_dict(self) -> dict:
        return {"name": self.name, "status": self.status, "count": len(self.entries),
                "error": self.error, "previous_state_used": self.previous_state_used}


class TargetResult:
    """One target's outcome for this run's fingerprint/exposure stages."""

    def __init__(self, name: str, fingerprint_ok: bool, fingerprint_error: str = None,
                 exposure_ok: bool = True, exposure_error: str = None):
        self.name = name
        self.fingerprint_ok = fingerprint_ok
        self.fingerprint_error = fingerprint_error
        self.exposure_ok = exposure_ok
        self.exposure_error = exposure_error

    @property
    def status(self) -> str:
        if self.fingerprint_ok and self.exposure_ok:
            return SUCCESS
        if not self.fingerprint_ok and not self.exposure_ok:
            return FAILED
        return "DEGRADED"

    def to_dict(self) -> dict:
        return {"name": self.name, "status": self.status,
                "fingerprint_error": self.fingerprint_error, "exposure_error": self.exposure_error}


class RunSummary:
    """Aggregates every stage's outcome and computes the overall run
    status + exit code. Built incrementally during run_hunt.py's
    main(), then rendered as both a human-readable block (for stdout
    and $GITHUB_STEP_SUMMARY) and JSON (for the workflow / next run to
    read back programmatically if ever needed)."""

    def __init__(self):
        self.collectors: list = []
        self.targets: list = []
        self.stage_status: dict = {}   # e.g. {"matching": "SUCCESS", "nuclei": "UNAVAILABLE"}
        self.counts: dict = {}         # arbitrary named counters for the summary table
        self.warnings: list = []
        self.persistence_status: str = None   # set by the workflow layer, not this run

    def add_collector(self, result: CollectorResult) -> None:
        self.collectors.append(result)

    def add_target(self, result: TargetResult) -> None:
        self.targets.append(result)

    def set_stage(self, name: str, status: str) -> None:
        self.stage_status[name] = status

    def warn(self, message: str) -> None:
        self.warnings.append(message)

    def overall_status(self) -> str:
        """FAILED only when there is no usable intelligence at all: every
        collector failed AND nothing was previously known either. A
        single collector succeeding, or a previous-state fallback
        keeping old data available, is enough for DEGRADED rather than
        FAILED - because the run still produced or preserved something
        usable, matching acceptance-criteria Scenario G's distinction
        ("no usable intelligence collected" vs. merely incomplete)."""
        if not self.collectors:
            return RUN_SUCCESS  # nothing tracked yet - caller hasn't started, not a failure state
        all_failed = all(not c.is_ok() for c in self.collectors)
        any_state_available = any(c.is_ok() or c.previous_state_used for c in self.collectors)
        if all_failed and not any_state_available:
            return RUN_FAILED
        if all(c.is_ok() for c in self.collectors) and all(t.status == SUCCESS for t in self.targets):
            return RUN_SUCCESS
        return RUN_DEGRADED

    def exit_code(self) -> int:
        status = self.overall_status()
        return {RUN_SUCCESS: EXIT_SUCCESS, RUN_DEGRADED: EXIT_DEGRADED, RUN_FAILED: EXIT_FATAL}[status]

    def to_dict(self) -> dict:
        return {
            "overall": self.overall_status(),
            "exit_code": self.exit_code(),
            "collectors": [c.to_dict() for c in self.collectors],
            "targets": [t.to_dict() for t in self.targets],
            "stages": self.stage_status,
            "counts": self.counts,
            "warnings": self.warnings,
        }

    def render_markdown(self) -> str:
        d = self.to_dict()
        lines = ["## Pipeline Health\n", f"**Overall: {d['overall']}**\n",
                  "| Component | Status |", "|---|---|"]
        for c in d["collectors"]:
            extra = " (using previous state)" if c["previous_state_used"] else ""
            lines.append(f"| {c['name']} | {c['status']}{extra} |")
        for name, status in d["stages"].items():
            lines.append(f"| {name} | {status} |")
        lines.append("")
        if d["targets"]:
            lines.append("| Target | Status |")
            lines.append("|---|---|")
            for t in d["targets"]:
                lines.append(f"| {t['name']} | {t['status']} |")
            lines.append("")
        if d["counts"]:
            lines.append("**Counts:**")
            for k, v in d["counts"].items():
                lines.append(f"- {k}: {v}")
            lines.append("")
        if d["warnings"]:
            lines.append("**Warnings:**")
            for w in d["warnings"]:
                lines.append(f"- {w}")
            lines.append("")
        return "\n".join(lines)

    def write_json(self, path: str) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

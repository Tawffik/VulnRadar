#!/usr/bin/env python3
"""
scripts/refresh_target_fingerprints.py

Runs httpx tech-detect against every targets/*.yaml's `target:` domain
and rewrites its `technologies:` list from the result. A target's
technologies are now machine-maintained, not hand-typed — this is what
closes the "okx-com.yaml has technologies: []" gap.

Behavior on failure (unreachable host, httpx missing, etc.): the
existing technologies in the file are LEFT UNTOUCHED and a warning is
printed. A failed fingerprint scan must never silently wipe a target's
known stack down to empty.

Run manually, or on a schedule separate from the main hunt (fingerprints
change slowly; CVEs need checking every 15 min, tech stacks don't).
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import yaml  # noqa: E402

from pipeline.recon import fingerprint  # noqa: E402
from pipeline.intelligence import technology_matcher  # noqa: E402


def refresh_one(path: str, timeout: int) -> str:
    data = technology_matcher.load_target(path)
    target = data.get("target")
    if not target:
        return f"⚠️ {path}: no 'target:' field, skipped"

    techs, error = fingerprint.run_httpx(target, timeout=timeout)
    if error:
        return f"⚠️ {path} ({target}): fingerprint failed, keeping existing list — {error}"

    new_techs = [{"vendor": t["vendor"], "product": t["product"],
                  **({"version": t["version"]} if t.get("version") else {})}
                 for t in techs]
    data["technologies"] = new_techs
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=False, allow_unicode=True)
    return f"✅ {path} ({target}): {len(new_techs)} technolog{'y' if len(new_techs)==1 else 'ies'} detected"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--targets-dir", default=os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "targets"))
    ap.add_argument("--timeout", type=int, default=fingerprint.HTTPX_TIMEOUT_SECONDS)
    args = ap.parse_args()

    if not fingerprint.is_available():
        print("❌ httpx binary not found on PATH. Install it first "
              "(see scripts/install_httpx.sh) — nothing was changed.")
        sys.exit(1)

    paths = sorted(
        os.path.join(args.targets_dir, f)
        for f in os.listdir(args.targets_dir)
        if f.endswith((".yaml", ".yml"))
    )
    if not paths:
        print(f"ℹ️ no target files found in {args.targets_dir}")
        return

    for path in paths:
        print(refresh_one(path, args.timeout))


if __name__ == "__main__":
    main()

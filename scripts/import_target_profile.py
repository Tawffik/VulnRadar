#!/usr/bin/env python3
"""Import a BugBountyCI/Agentic target_profile.json into targets/<slug>.yaml.

Usage:
  python3 scripts/import_target_profile.py --profile agent-handoff/example.com/target_profile.json
  python3 scripts/import_target_profile.py --profile profile.json --targets-dir targets --slug example-com

The output is a normal VulnRadar target file; existing files are only replaced
with --force.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import yaml


def slugify(target: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", target.lower()).strip("-")
    return slug or "target"


def convert(profile: dict) -> dict:
    target = str(profile.get("target", "")).strip().lower()
    if not target:
        raise ValueError("target_profile.target is required")
    techs = profile.get("technologies") or []
    if not isinstance(techs, list):
        raise ValueError("technologies must be a list")
    out = {
        "target": target,
        "technologies": [
            {"vendor": str(t.get("vendor", "")), "product": str(t.get("product", ""))}
            for t in techs if isinstance(t, dict) and (t.get("vendor") or t.get("product"))
        ],
    }
    if profile.get("discover_subdomains") is not None:
        out["discover_subdomains"] = bool(profile["discover_subdomains"])
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, help="target_profile.json")
    parser.add_argument("--targets-dir", default="targets")
    parser.add_argument("--slug", default="")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    profile = json.loads(Path(args.profile).read_text(encoding="utf-8"))
    try:
        target = convert(profile)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    slug = args.slug or slugify(target["target"])
    dest = Path(args.targets_dir) / f"{slug}.yaml"
    if dest.exists() and not args.force:
        print(f"error: {dest} exists (use --force)", file=sys.stderr)
        return 1
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(yaml.safe_dump(target, sort_keys=False, allow_unicode=True), encoding="utf-8")
    print(f"[+] wrote {dest} ({len(target['technologies'])} technologies)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

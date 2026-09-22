#!/usr/bin/env python3
"""
scripts/save_target.py

Turns a workflow_dispatch "target_domain" + "technologies" input into a
permanent targets/*.yaml file, using the same parsing logic run_hunt.py
uses for --adhoc-tech (see pipeline/run_hunt.py's parse_adhoc_technologies).
"""
import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pipeline.run_hunt import parse_adhoc_technologies


def slugify(target: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", target.lower()).strip("-") or "target"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--technologies", default="")
    args = ap.parse_args()

    if not args.target.strip():
        print("ℹ️ No target domain provided, nothing to save.")
        return

    technologies = parse_adhoc_technologies(args.technologies)
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    targets_dir = os.path.join(repo_root, "targets")
    os.makedirs(targets_dir, exist_ok=True)
    path = os.path.join(targets_dir, f"{slugify(args.target)}.yaml")

    lines = [f"target: {args.target.strip()}",
             "scan_allowed: false  # nuclei OFF until you confirm this target's program allows active scanning",
             "technologies:"]
    if technologies:
        for t in technologies:
            lines.append(f"  - vendor: {t['vendor']}")
            if t.get("product"):
                lines.append(f"    product: {t['product']}")
    else:
        lines.append("  []  # no technologies specified yet — edit this file to add some")

    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")

    # Commit this new file so future scheduled runs pick it up too —
    # separate from run_hunt.py's own state/output commit, so a target
    # file addition is its own clean, reviewable commit.
    import subprocess
    import time

    def run(cmd):
        return subprocess.run(cmd, shell=True).returncode

    run('git config user.name "vulnradar-bot"')
    run('git config user.email "vulnradar-bot@users.noreply.github.com"')
    run(f'git add "{path}"')
    if run(f'git commit -m "chore: add target {args.target.strip()} [automated]" -q') != 0:
        print(f"ℹ️ nothing new to commit for {path}")
        return

    for attempt in range(1, 6):
        if run("git push -q") == 0:
            print(f"✅ saved and pushed {path}")
            return
        print(f"⚠️ push rejected (attempt {attempt}), rebasing onto latest main...")
        if run("git pull --rebase --autostash -X ours -q origin main") != 0:
            run("git rebase --abort")
            time.sleep(attempt * 5)

    print(f"❌ saved {path} locally but could not push after 5 attempts — "
          f"this run's target-save was lost, please re-run the workflow")
    sys.exit(1)


if __name__ == "__main__":
    main()

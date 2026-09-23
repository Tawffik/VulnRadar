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
import datetime
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import yaml  # noqa: E402

from pipeline.recon import fingerprint, subdomains  # noqa: E402
from pipeline.recon.diagnose import diagnose_target  # noqa: E402
from pipeline.intelligence import technology_matcher  # noqa: E402


def refresh_one(path: str, timeout: int, diagnostics: list) -> str:
    data = technology_matcher.load_target(path)
    target = data.get("target")
    if not target:
        return f"⚠️ {path}: no 'target:' field, skipped"

    diag = diagnose_target(target, timeout=timeout)
    print(f"🔎 {target}: {diag['summary']}")
    diagnostics.append((target, diag))

    hosts = [target]
    if data.get("discover_subdomains"):
        subs, sub_err = subdomains.discover(target, max_results=int(data.get("max_subdomains", subdomains.DEFAULT_MAX)))
        if sub_err:
            print(f"⚠️ {target}: subdomain discovery skipped — {sub_err}")
        else:
            hosts = list(dict.fromkeys([target] + subs))
            print(f"ℹ️ {target}: {len(hosts)} host(s) to fingerprint (incl. {len(hosts)-1} subdomain(s))")

    techs, error = [], None
    errors = 0
    seen = {}
    for host in hosts:
        t, e = fingerprint.run_httpx(host, timeout=timeout)
        if e:
            errors += 1
            error = e
            continue
        for x in t:   # merge across hosts, keep the entry that has a version
            k = (x["vendor"].lower(), x["product"].lower())
            if k not in seen or (x.get("version") and not seen[k].get("version")):
                seen[k] = x
    techs = list(seen.values())
    if errors == len(hosts):   # every host failed -> genuine failure, not "found nothing"
        return f"⚠️ {path} ({target}): fingerprint failed, keeping existing list — {error}"

    if not techs:
        return (f"⚠️ {path} ({target}): httpx detected nothing (site may block scanners), "
                f"keeping existing list")

    new_techs = [{"vendor": t["vendor"], "product": t["product"],
                  **({"version": t["version"]} if t.get("version") else {})}
                 for t in techs]
    data["technologies"] = new_techs
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=False, allow_unicode=True)
    return f"✅ {path} ({target}): {len(new_techs)} technolog{'y' if len(new_techs)==1 else 'ies'} detected"


def write_diagnostics_report(diagnostics: list) -> None:
    """Writes output/diagnostics.md so the real HTTP status/response for
    each target is visible in the repo itself, not only in the (harder
    to reach) Actions run log — this is what settles "is it a real
    block or just no fingerprint signal" with evidence, not a guess."""
    out_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "output")
    os.makedirs(out_dir, exist_ok=True)
    lines = ["# Target Reachability Diagnostics\n",
              f"Generated: {datetime.datetime.now(datetime.timezone.utc).isoformat()}\n",
              "One plain GET request per target, to tell a real block apart from \"no fingerprint signal\".\n"]
    for target, diag in diagnostics:
        flag = "🚫 likely blocked" if diag["likely_blocked"] else "✅ reachable, no block signature"
        lines.append(f"### {target} — {flag}")
        lines.append(f"- HTTP status: {diag['status']}")
        lines.append(f"- Server header: `{diag['server_header'] or '(not sent)'}`")
        lines.append(f"- Response size: {diag['body_len']} bytes")
        lines.append(f"- {diag['summary']}\n")
    with open(os.path.join(out_dir, "diagnostics.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


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

    diagnostics = []
    for path in paths:
        print(refresh_one(path, args.timeout, diagnostics))

    write_diagnostics_report(diagnostics)


if __name__ == "__main__":
    main()

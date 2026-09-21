#!/usr/bin/env python3
"""
pipeline/intelligence/technology_matcher.py

Matches KEV entries against a target's declared technology stack
(targets/*.yaml). This is deliberately simple for V1: substring,
case-insensitive matching on vendor/product name. No version-range
logic yet (see the "possibly affected vs confirmed" note in
targets/example.yaml and the project's own design principle: never
claim CONFIRMED from a name match alone).

A target file looks like:
  target: example.com
  technologies:
    - vendor: Apache
      product: HTTP Server
    - vendor: nginx
      product: nginx

Matching is intentionally loose (either vendor OR product substring
match is enough) because real-world naming is inconsistent between
CISA's catalog and how people describe their own stack (e.g. "nginx"
vs "NGINX", "Apache" vs "Apache Software Foundation"). This means V1
will have false positives on generic vendor names — that's an accepted,
documented tradeoff for a first version; see targets/example.yaml for
guidance on being specific.
"""
import os

try:
    import yaml
except ImportError:
    yaml = None


def load_target(path: str) -> dict:
    if yaml is None:
        raise RuntimeError("PyYAML is required to load target files (pip install pyyaml)")
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def load_all_targets(targets_dir: str) -> list:
    """Loads every *.yaml file in targets_dir, skipping any that fail to
    parse (logged, not crashed on) so one bad target file doesn't stop
    the whole run."""
    targets = []
    if not os.path.isdir(targets_dir):
        return targets
    for fname in sorted(os.listdir(targets_dir)):
        if not fname.endswith((".yaml", ".yml")):
            continue
        path = os.path.join(targets_dir, fname)
        try:
            t = load_target(path)
            if t.get("target"):
                t.setdefault("technologies", [])
                targets.append(t)  # loaded even with an empty tech list (e.g. not yet
                                    # fingerprinted) - it just won't match anything until
                                    # it has technologies; excluding it entirely meant a
                                    # target could never pick up matches once fingerprinted
        except Exception:
            continue  # a malformed target file is skipped, not fatal
    return targets


def _matches(entry: dict, tech: dict) -> bool:
    vendor = (tech.get("vendor") or "").strip().lower()
    product = (tech.get("product") or "").strip().lower()
    entry_vendor = (entry.get("vendor") or "").lower()
    entry_product = (entry.get("product") or "").lower()

    vendor_match = bool(vendor) and (vendor in entry_vendor or entry_vendor in vendor)
    product_match = bool(product) and (product in entry_product or entry_product in product)

    # Require BOTH if both are specified — vendor-only OR product-only
    # matching alone produces too many false positives on common single
    # words (e.g. a target with just product: "Server" would match
    # nearly everything). If a target specifies only one field, that
    # field alone is enough (the target author's own choice to be broad).
    if vendor and product:
        return vendor_match and product_match
    return vendor_match or product_match


def match_targets(entries: list, targets: list) -> list:
    """Returns entries augmented with a 'matched_targets' list (empty if
    no target matched — those entries are still returned so callers can
    decide whether to keep unmatched entries visible at a lower priority
    or drop them, rather than this function silently deciding for them)."""
    results = []
    for entry in entries:
        matched = []
        for target in targets:
            for tech in target.get("technologies", []):
                if _matches(entry, tech):
                    matched.append(target["target"])
                    break
        results.append({**entry, "matched_targets": matched})
    return results

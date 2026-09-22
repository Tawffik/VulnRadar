#!/usr/bin/env python3
"""
pipeline/notifiers/discord.py

Sends new/updated CVEs to a Discord channel via an incoming webhook.

Which entries are sent (same relevance rule as hunter_queue.md, so the
channel is signal, not a firehose of every CVE published):
  - NEW or UPDATED and matched to one of your targets, OR
  - known ransomware use.
Set NOTIFY_ALL=1 to send every new entry instead (very noisy — hundreds
per run on a fresh state).

Configuration: the DISCORD_WEBHOOK_URL environment variable (a GitHub
repo secret in CI). If unset, notifying is silently skipped. A Discord
failure NEVER fails the hunt — it only prints a warning.
"""
import json
import os
import time
import urllib.error
import urllib.request

MAX_EMBEDS_PER_MESSAGE = 10   # Discord hard limit
MAX_ENTRIES_PER_RUN = 30      # safety cap; the rest are summarized in one line

RED, ORANGE, BLUE = 0xE74C3C, 0xE67E22, 0x3498DB


def select_entries(new_entries: list, updated_entries: list, notify_all: bool = False) -> list:
    picked = []
    for e in new_entries + updated_entries:
        if notify_all or e.get("matched_targets") or e.get("ransomware_use") == "Known":
            picked.append(e)

    def rank(e):
        matched = bool(e.get("matched_targets"))
        ransom = e.get("ransomware_use") == "Known"
        nuclei_hit = any(v == "vulnerable" for v in (e.get("nuclei_verdicts") or {}).values())
        confirmed = e.get("version_verdict") == "confirmed"
        if nuclei_hit:
            return 0
        if matched and (ransom or confirmed):
            return 1
        return 2 if matched else 3
    picked.sort(key=rank)
    return picked


def _trunc(text, n):
    text = str(text or "")
    return text if len(text) <= n else text[: n - 1] + "…"


def build_embed(e: dict, is_update: bool = False) -> dict:
    matched = e.get("matched_targets") or []
    ransom = e.get("ransomware_use") == "Known"
    nuclei_hit = any(v == "vulnerable" for v in (e.get("nuclei_verdicts") or {}).values())
    confirmed = e.get("version_verdict") == "confirmed"
    color = RED if (nuclei_hit or ransom) else ORANGE if (matched and confirmed) else ORANGE if matched else BLUE
    status = "🔥 LIVE HIT" if nuclei_hit else ("UPDATED" if is_update else "NEW")
    fields = [
        {"name": "Vendor / Product", "value": _trunc(f"{e.get('vendor','?')} / {e.get('product','?')}", 200), "inline": True},
        {"name": "Matched target(s)", "value": _trunc(", ".join(matched) or "— (no target matched)", 200), "inline": True},
        {"name": "Ransomware use", "value": _trunc(e.get("ransomware_use", "Unknown"), 50), "inline": True},
    ]
    if e.get("cvss_score") is not None:
        fields.append({"name": "CVSS", "value": _trunc(f"{e['cvss_score']} {e.get('cvss_severity') or ''}".strip(), 50), "inline": True})
    if e.get("sources"):
        fields.append({"name": "Sources", "value": _trunc(", ".join(dict.fromkeys(e["sources"])), 200), "inline": True})
    if e.get("version_verdict") and e["version_verdict"] != "unknown":
        fields.append({"name": "Version check", "value": _trunc(e["version_verdict"], 50), "inline": True})
    nv = e.get("nuclei_verdicts") or {}
    if nv:
        fields.append({"name": "Nuclei", "value": _trunc(", ".join(f"{d}: {v}" for d, v in nv.items()), 200), "inline": True})
    fields.append({"name": "Next safe action",
                   "value": "Verify the deployed version is in the affected range before treating this as a finding. Stay within authorized scope.",
                   "inline": False})
    cve = e.get("cve", "unknown")
    return {
        "title": _trunc(f"{status} — {cve}", 250),
        "url": f"https://www.cve.org/CVERecord?id={cve}",
        "description": _trunc(e.get("name") or e.get("description") or "", 1000),
        "color": color,
        "fields": fields,
    }


def _post(webhook_url: str, payload: dict, timeout: int = 15) -> None:
    req = urllib.request.Request(
        webhook_url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "VulnRadar/1.0"}, method="POST")
    for attempt in range(3):
        try:
            urllib.request.urlopen(req, timeout=timeout).read()
            return
        except urllib.error.HTTPError as err:
            if err.code == 429 and attempt < 2:      # rate limited: honor Retry-After
                try:
                    wait = float(err.headers.get("Retry-After", "2"))
                except ValueError:
                    wait = 2.0
                time.sleep(min(wait, 10))
                continue
            raise


def build_exposure_embed(report: dict) -> dict:
    fields = []
    if report["git_exposure"]:
        fields.append({"name": "Git exposure", "value": _trunc("\n".join(report["git_exposure"]), 500), "inline": False})
    if report["sensitive_files"]:
        fields.append({"name": "Sensitive files", "value": _trunc("\n".join(report["sensitive_files"]), 500), "inline": False})
    sm = report["source_maps"]
    if sm["maps"]:
        fields.append({"name": "Source maps", "value": _trunc(f"{len(sm['maps'])} found", 100), "inline": True})
    if sm["secrets"]:
        fields.append({"name": "⚠️ Possible secrets in maps", "value": _trunc(", ".join(sm["secrets"]), 200), "inline": True})
    return {
        "title": _trunc(f"🔍 Exposure findings — {report['target']}", 250),
        "color": RED if (sm.get("secrets") or report["git_exposure"]) else ORANGE,
        "fields": fields,
        "description": "Passive GET-only recon. Verify manually before reporting.",
    }


def notify(new_entries: list, updated_entries: list, webhook_url: str = None,
           notify_all: bool = None, exposure_reports: list = None, _sender=None) -> int:
    """Returns the number of entries sent. Never raises."""
    webhook_url = webhook_url or os.environ.get("DISCORD_WEBHOOK_URL")
    if not webhook_url:
        return 0
    if notify_all is None:
        notify_all = os.environ.get("NOTIFY_ALL") == "1"
    sender = _sender or (lambda p: _post(webhook_url, p))

    from pipeline.recon.exposure_scan import has_findings
    exposure_hits = [r for r in (exposure_reports or []) if has_findings(r)][:MAX_ENTRIES_PER_RUN]

    update_ids = {id(e) for e in updated_entries}
    picked = select_entries(new_entries, updated_entries, notify_all)
    if not picked and not exposure_hits:
        return 0

    overflow = max(0, len(picked) - MAX_ENTRIES_PER_RUN)
    picked = picked[:MAX_ENTRIES_PER_RUN]
    embeds = [build_embed(e, id(e) in update_ids) for e in picked]
    embeds += [build_exposure_embed(r) for r in exposure_hits]

    sent = 0
    try:
        for i in range(0, len(embeds), MAX_EMBEDS_PER_MESSAGE):
            chunk = embeds[i:i + MAX_EMBEDS_PER_MESSAGE]
            payload = {"username": "VulnRadar", "embeds": chunk}
            if i == 0:
                cve_part = f"{len(picked) + overflow} relevant CVE(s)" if picked else ""
                exp_part = f"{len(exposure_hits)} exposure finding(s)" if exposure_hits else ""
                payload["content"] = "🚨 **VulnRadar**: " + " + ".join(p for p in [cve_part, exp_part] if p) + " this run"
                if overflow:
                    payload["content"] += f" (showing top {len(picked)}, {overflow} more in hunter_queue.md)"
            sender(payload)
            sent += len(chunk)
            time.sleep(1)  # stay well under Discord's webhook rate limit
    except Exception as err:  # notification problems must never break the hunt
        print(f"⚠️ Discord notification failed (hunt unaffected): {type(err).__name__}: {err}")
    return sent

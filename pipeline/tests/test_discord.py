#!/usr/bin/env python3
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from pipeline.notifiers import discord

def E(cve, matched=(), ransom="Unknown"):
    return {"cve": cve, "vendor": "nginx", "product": "nginx", "name": "n", "description": "d",
            "ransomware_use": ransom, "matched_targets": list(matched), "sources": ["cve_org"]}

def test_only_relevant_entries_sent_and_ranked():
    sent = []
    new = [E("CVE-1"), E("CVE-2", ["a.com"]), E("CVE-3", ["a.com"], "Known"), E("CVE-4", [], "Known")]
    n = discord.notify(new, [], webhook_url="http://x", _sender=sent.append)
    titles = [em["title"] for p in sent for em in p["embeds"]]
    assert n == 3 and "CVE-1" not in " ".join(titles)
    assert titles[0].endswith("CVE-3")   # matched + ransomware first
    print("  ✅ only relevant CVEs sent, highest priority first")

def test_no_webhook_means_silent_skip():
    os.environ.pop("DISCORD_WEBHOOK_URL", None)
    assert discord.notify([E("CVE-2", ["a.com"])], []) == 0
    print("  ✅ no webhook configured -> skipped")

def test_failure_never_raises():
    def boom(p): raise RuntimeError("discord down")
    n = discord.notify([E("CVE-2", ["a.com"])], [], webhook_url="http://x", _sender=boom)
    assert n == 0
    print("  ✅ Discord failure does not raise")

def test_batching_and_cap():
    sent = []
    new = [E(f"CVE-{i}", ["a.com"]) for i in range(45)]
    discord.notify(new, [], webhook_url="http://x", _sender=sent.append)
    assert sum(len(p["embeds"]) for p in sent) == 30 and all(len(p["embeds"]) <= 10 for p in sent)
    assert "15 more" in sent[0]["content"]
    print("  ✅ batches of <=10, capped at 30 with overflow note")

def test_embed_limits_respected():
    e = E("CVE-9", ["a.com"]); e["name"] = "x" * 5000
    em = discord.build_embed(e)
    assert len(em["description"]) <= 1000 and len(em["title"]) <= 256
    print("  ✅ embed field limits respected")

if __name__ == "__main__":
    tests = [test_only_relevant_entries_sent_and_ranked, test_no_webhook_means_silent_skip,
             test_failure_never_raises, test_batching_and_cap, test_embed_limits_respected]
    for t in tests: t()
    print(f"\n{len(tests)}/{len(tests)} tests passed")

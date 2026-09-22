#!/usr/bin/env python3
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from pipeline.recon.user_agents import random_ua, POOL

def test_returns_a_real_pool_entry():
    for _ in range(20):
        assert random_ua() in POOL
    print("  ✅ random_ua always returns a pool entry")

def test_pool_looks_like_real_browsers_not_bot_strings():
    for ua in POOL:
        assert "Mozilla/5.0" in ua
        assert "httpx" not in ua.lower() and "vulnradar" not in ua.lower() and "bot" not in ua.lower()
    print("  ✅ pool entries are real browser UAs, no bot fingerprint")

if __name__ == "__main__":
    test_returns_a_real_pool_entry()
    test_pool_looks_like_real_browsers_not_bot_strings()
    print("\n2/2 tests passed")

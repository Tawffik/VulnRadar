#!/usr/bin/env python3
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from pipeline.recon import subdomains

class _FakeCompleted:
    def __init__(self, stdout="", returncode=0): self.stdout, self.returncode = stdout, returncode

def test_filters_to_domain_and_subdomains_only():
    out = _FakeCompleted(stdout="api.okx.com\nokx.com\nevil.com\nwww.okx.com\n*.okx.com\n")
    hosts, err = subdomains.discover("okx.com", _runner=lambda *a, **k: out)
    assert err is None and set(hosts) == {"okx.com", "api.okx.com", "www.okx.com"}
    assert "evil.com" not in hosts
    print("  ✅ only the domain itself and true subdomains kept, wildcard/off-scope dropped")

def test_capped_at_max_results():
    out = _FakeCompleted(stdout="\n".join(f"s{i}.okx.com" for i in range(50)))
    hosts, err = subdomains.discover("okx.com", max_results=5, _runner=lambda *a, **k: out)
    assert len(hosts) == 5
    print("  ✅ result capped at max_subdomains")

def test_timeout_and_failure_are_non_fatal():
    import subprocess
    def boom(*a, **k): raise subprocess.TimeoutExpired(cmd="subfinder", timeout=5)
    hosts, err = subdomains.discover("okx.com", _runner=boom)
    assert hosts == [] and "timed out" in err
    print("  ✅ subfinder timeout reported as error, never raised")

def test_command_does_not_use_removed_passive_flag():
    """Regression: subfinder v2 removed `-passive`; an explicit flag makes
    subfinder exit immediately with 'flag provided but not defined', so
    discovery silently returned 0 subdomains on every run."""
    captured = {}
    def fake(cmd, **k):
        captured["cmd"] = cmd
        return _FakeCompleted(stdout="api.okx.com\n")
    subdomains.discover("okx.com", _runner=fake)
    assert "-passive" not in captured["cmd"], "subfinder v2 rejects -passive"
    print("  ✅ command omits the removed -passive flag")

if __name__ == "__main__":
    for t in [test_filters_to_domain_and_subdomains_only, test_capped_at_max_results, test_timeout_and_failure_are_non_fatal, test_command_does_not_use_removed_passive_flag]:
        t()
    print("\n4/4 tests passed")

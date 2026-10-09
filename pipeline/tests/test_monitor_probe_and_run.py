from pathlib import Path
from pipeline.monitor.probe import probe_hosts_stdlib
from pipeline.monitor.run_monitor import monitor_one, write_summary


def test_probe_stdlib_hooks():
    def resolve(h):
        return h.startswith("live")

    def http(url):
        return "live1" in url

    live, dead = probe_hosts_stdlib(
        ["live1.example.com", "dead.example.com"],
        _resolve=resolve,
        _http=http,
    )
    assert live == ["live1.example.com"]
    assert "dead.example.com" in dead


def test_monitor_one_with_mocks(tmp_path, monkeypatch):
    from pipeline.recon import subdomains
    from pipeline.monitor import run_monitor

    def fake_discover(domain, max_results=200, timeout=90, _runner=None):
        return [domain, f"a.{domain}", f"b.{domain}"], None

    def fake_probe(hosts, timeout=8):
        # only apex + a live
        domain = hosts[0].split(".", 1)[-1] if hosts else "example.com"
        # hosts may be full list
        live = [h for h in hosts if h == hosts[0] or h.startswith("a.")]
        return live, {"method": "mock"}

    monkeypatch.setattr(subdomains, "discover", fake_discover)
    monkeypatch.setattr(run_monitor, "probe_hosts", fake_probe)

    r = monitor_one("example.com", tmp_path / "mon")
    assert r["status"] == "COMPLETE"
    assert r["live"] >= 1
    assert (tmp_path / "mon" / "example.com" / "live.txt").exists()
    # second run: no new if same live
    r2 = monitor_one("example.com", tmp_path / "mon")
    assert r2["new_count"] == 0


def test_write_summary(tmp_path):
    p = tmp_path / "summary.md"
    write_summary(
        [{"target": "x.com", "status": "COMPLETE", "discovered": 3, "live": 2, "new_count": 1, "removed_count": 0, "new": ["a.x.com"]}],
        p,
    )
    text = p.read_text()
    assert "x.com" in text
    assert "a.x.com" in text

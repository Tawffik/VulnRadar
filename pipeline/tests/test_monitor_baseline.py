from pathlib import Path

from pipeline.monitor.baseline import apply_run, diff_baselines, should_update_baseline


def test_diff_new_and_removed():
    d = diff_baselines(["a.example.com", "b.example.com"], ["b.example.com", "c.example.com"])
    assert d["new"] == ["c.example.com"]
    assert d["removed"] == ["a.example.com"]
    assert d["still"] == ["b.example.com"]
    assert d["new_count"] == 1


def test_empty_live_does_not_clobber_baseline(tmp_path: Path):
    first = apply_run(tmp_path, ["x.example.com", "y.example.com"])
    assert first["baseline_updated"] is True
    assert (tmp_path / "prev.txt").read_text().strip().splitlines() == ["x.example.com", "y.example.com"]

    second = apply_run(tmp_path, [])  # failed discovery
    assert second["status"] == "INCOMPLETE_EMPTY_LIVE"
    assert second["baseline_updated"] is False
    # prev preserved
    assert "x.example.com" in (tmp_path / "prev.txt").read_text()
    assert second["removed_count"] == 2  # diff still reports what would be removed


def test_force_empty_updates(tmp_path: Path):
    apply_run(tmp_path, ["a.example.com"])
    r = apply_run(tmp_path, [], force_update_empty=True)
    assert r["baseline_updated"] is True
    assert (tmp_path / "prev.txt").read_text().strip() == ""


def test_should_update():
    assert should_update_baseline(["h"]) is True
    assert should_update_baseline([]) is False
    assert should_update_baseline([], force_update_empty=True) is True

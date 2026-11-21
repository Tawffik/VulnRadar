"""EPSS enrichment is bounded, target-matched only, and fail-open."""
from pipeline.intelligence import epss


def test_enrich_only_matched_entries():
    entries = [
        {"cve": "CVE-1", "matched_targets": ["a.com"]},
        {"cve": "CVE-2", "matched_targets": []},
        {"cve": "CVE-3", "matched_targets": ["b.com"], "epss": 0.1},
    ]

    def fake(cve):
        return {"epss": 0.42, "epss_percentile": 0.9, "epss_date": "2026-11-20"}

    entries, n = epss.enrich_entries(entries, fetch=fake)
    assert n == 1
    assert entries[0]["epss"] == 0.42
    assert "epss" not in entries[1]
    assert entries[2]["epss"] == 0.1


def test_enrich_is_bounded_and_never_raises():
    entries = [{"cve": f"CVE-{i}", "matched_targets": ["a.com"]} for i in range(5)]

    def fake(cve):
        raise RuntimeError("upstream down")

    entries, n = epss.enrich_entries(entries, fetch=fake, max_entries=2)
    assert n == 0
    assert len(entries) == 5

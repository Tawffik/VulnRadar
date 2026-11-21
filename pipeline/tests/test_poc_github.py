from pipeline.intelligence import poc_github


def test_enrich_only_matched_and_bounded():
    entries = [
        {"cve": "CVE-2024-3400", "matched_targets": ["a.com"]},
        {"cve": "CVE-2024-9999", "matched_targets": []},
    ]

    def fake(cve):
        return {"poc_count": 2, "poc_repos": ["https://github.com/x/y"]}

    entries, n = poc_github.enrich_entries(entries, fetch=fake, max_entries=1)
    assert n == 1
    assert entries[0]["poc_count"] == 2
    assert "poc_count" not in entries[1]


def test_enrich_never_raises():
    entries = [{"cve": "CVE-2024-3400", "matched_targets": ["a.com"]}]

    def fake(cve):
        raise RuntimeError("down")

    entries, n = poc_github.enrich_entries(entries, fetch=fake)
    assert n == 0

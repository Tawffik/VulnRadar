"""Automation guardrails: no unavailable runner labels, explicit timeouts."""
from pathlib import Path

WORKFLOWS = Path(__file__).resolve().parents[2] / ".github" / "workflows"


def test_workflows_use_github_hosted_runners():
    for path in WORKFLOWS.glob("*.yml"):
        text = path.read_text(encoding="utf-8")
        assert "sengi-" not in text, f"{path.name}: custom/unavailable runner label"
        assert "runs-on: ubuntu-" in text or "runs-on: ${{" in text, f"{path.name}: no runner"


def test_workflows_have_timeouts():
    for path in WORKFLOWS.glob("*.yml"):
        text = path.read_text(encoding="utf-8")
        assert "timeout-minutes:" in text, f"{path.name}: no job timeout"

import json
from pathlib import Path
import subprocess
import sys

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "import_target_profile.py"
sys.path.insert(0, str(REPO / "scripts"))
import import_target_profile as imp


def test_convert_profile():
    out = imp.convert({"target": "Example.COM", "technologies": [
        {"vendor": "nginx", "product": "nginx"}, {"vendor": "Apache", "product": ""}]})
    assert out["target"] == "example.com"
    assert len(out["technologies"]) == 2


def test_cli_writes_target(tmp_path):
    profile = tmp_path / "profile.json"
    profile.write_text(json.dumps({"target": "example.com", "technologies": [
        {"vendor": "nginx", "product": "nginx"}]}))
    targets = tmp_path / "targets"
    proc = subprocess.run([sys.executable, str(SCRIPT), "--profile", str(profile),
                           "--targets-dir", str(targets)], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert (targets / "example-com.yaml").exists()

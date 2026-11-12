"""CLI tests: end-to-end runs through main() and the module entry point."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from ai_code_reviewer.cli import main

FIXTURES = Path(__file__).parent / "fixtures"
ROOT = Path(__file__).parent.parent


def test_cli_markdown_to_stdout(capsys):
    assert main([str(FIXTURES / "vulnerable"), "--fail-on", "none"]) == 0
    out = capsys.readouterr().out
    assert "# AI Code Reviewer" in out
    assert "SEC001" in out


def test_cli_clean_directory_exits_zero(capsys):
    assert main([str(FIXTURES / "safe")]) == 0
    assert "No security findings" in capsys.readouterr().out


def test_cli_fail_on_high_exits_one():
    assert main([str(FIXTURES / "vulnerable")]) == 1  # default fail-on high


def test_cli_fail_on_none_exits_zero():
    assert main([str(FIXTURES / "vulnerable"), "--fail-on", "none"]) == 0


def test_cli_fail_on_critical_exits_zero_when_no_critical(tmp_path):
    (tmp_path / "a.py").write_text("import hashlib\nx = hashlib.md5(b'data')\n")
    assert main([str(tmp_path), "--fail-on", "critical"]) == 0
    assert main([str(tmp_path), "--fail-on", "medium"]) == 1


def test_cli_min_severity_filters_output(capsys):
    assert main([str(FIXTURES / "vulnerable"), "--fail-on", "none",
                 "--min-severity", "critical",
                 "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["findings"]
    assert {f["severity"] for f in payload["findings"]} == {"critical"}


def test_cli_json_output_file(tmp_path):
    out = tmp_path / "out.json"
    assert main([str(FIXTURES / "vulnerable"), "--format", "json",
                 "--output", str(out), "--fail-on", "none"]) == 0
    payload = json.loads(out.read_text())
    assert payload["summary"]["total"] > 0


def test_cli_format_all_writes_three_reports(tmp_path):
    out_dir = tmp_path / "reports"
    assert main([str(FIXTURES / "vulnerable"), "--format", "all",
                 "--output-dir", str(out_dir), "--fail-on", "none"]) == 0
    assert (out_dir / "report.json").exists()
    assert (out_dir / "report.sarif").exists()
    assert (out_dir / "report.md").exists()
    assert json.loads((out_dir / "report.sarif").read_text())["version"] == "2.1.0"


def test_cli_diff_mode(tmp_path):
    diff = tmp_path / "change.diff"
    diff.write_text(
        "diff --git a/app.py b/app.py\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,1 +1,2 @@\n"
        " import os\n"
        "+api_key = \"sk-live-9f8e7d6c5b4a39281706\"\n"
    )
    assert main(["--diff", str(diff), "--fail-on", "none"]) == 0
    assert main(["--diff", str(diff)]) == 1  # high severity present


def test_cli_missing_path_exits_two(capsys):
    assert main(["/does/not/exist"]) == 2
    assert "error" in capsys.readouterr().err


def test_cli_missing_diff_file_exits_two():
    assert main(["--diff", "/does/not/exist.diff"]) == 2


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "0.1.0" in capsys.readouterr().out


def test_module_entry_point_runs():
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run(
        [sys.executable, "-m", "ai_code_reviewer",
         str(FIXTURES / "safe")],
        capture_output=True, text=True, env=env, cwd=str(ROOT),
    )
    assert proc.returncode == 0
    assert "No security findings" in proc.stdout

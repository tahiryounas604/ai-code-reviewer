"""Reporter tests: JSON, SARIF, and Markdown output."""

import json
from pathlib import Path

from ai_code_reviewer.engine import scan_directory
from ai_code_reviewer.reporters import (
    findings_to_json,
    findings_to_markdown,
    findings_to_sarif,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _findings():
    return scan_directory(FIXTURES / "vulnerable")


def test_json_report_is_valid_and_complete():
    payload = json.loads(findings_to_json(_findings()))
    assert payload["tool"] == "ai-code-reviewer"
    assert payload["engine"].startswith("rule-based")
    assert payload["summary"]["total"] == len(payload["findings"])
    assert payload["summary"]["by_severity"]["critical"] >= 1
    finding = payload["findings"][0]
    assert set(finding) == {"rule_id", "category", "severity", "file",
                            "line", "message", "suggestion", "code"}
    assert all(f["file"] and f["line"] >= 1 for f in payload["findings"])


def test_json_report_empty():
    payload = json.loads(findings_to_json([]))
    assert payload["summary"]["total"] == 0
    assert payload["findings"] == []


def test_sarif_report_structure():
    sarif = json.loads(findings_to_sarif(_findings()))
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].endswith("sarif-2.1.0.json")
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "ai-code-reviewer"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert rule_ids == {f.rule_id for f in _findings()}
    assert len(run["results"]) == len(_findings())
    result = run["results"][0]
    assert result["ruleId"]
    assert result["level"] in {"error", "warning", "note"}
    loc = result["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"]
    assert loc["region"]["startLine"] >= 1
    assert result["message"]["text"].strip()


def test_sarif_level_mapping():
    findings = _findings()
    sarif = json.loads(findings_to_sarif(findings))
    by_rule = {r["ruleId"]: r["level"]
               for r in sarif["runs"][0]["results"]}
    assert by_rule["DES002"] == "error"   # critical
    assert by_rule["CRY001"] == "warning"  # medium


def test_sarif_report_empty():
    sarif = json.loads(findings_to_sarif([]))
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["tool"]["driver"]["rules"] == []


def test_markdown_report_contents():
    md = findings_to_markdown(_findings())
    assert md.startswith("# AI Code Reviewer")
    assert "Total findings:" in md
    assert "SEC001" in md
    assert "Suggested fix:" in md
    assert "secrets.py" in md
    assert "```" in md


def test_markdown_report_empty():
    md = findings_to_markdown([])
    assert "No security findings" in md
    assert "Total findings:** 0" in md

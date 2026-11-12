"""Engine tests: file/directory scanning, severity filtering, summaries."""

from pathlib import Path

from ai_code_reviewer.engine import (
    Finding,
    filter_by_severity,
    scan_directory,
    scan_file,
    summarize,
)

FIXTURES = Path(__file__).parent / "fixtures"


def test_scan_file_returns_structured_findings():
    findings = scan_file(FIXTURES / "vulnerable" / "secrets.py")
    assert findings
    for f in findings:
        assert isinstance(f, Finding)
        assert f.rule_id and f.category and f.severity
        assert f.file.endswith("secrets.py")
        assert f.line >= 1
        assert f.message.strip()
        assert f.suggestion.strip()
        assert f.code.strip()
    d = findings[0].to_dict()
    assert set(d) == {"rule_id", "category", "severity", "file", "line",
                      "message", "suggestion", "code"}


def test_scan_file_skips_binary_and_missing_files(tmp_path):
    binary = tmp_path / "blob.bin"
    binary.write_bytes(b"\x00\x01\x02\xff\xfe")
    assert scan_file(binary) == []
    assert scan_file(tmp_path / "does-not-exist.py") == []


def test_scan_directory_vulnerable_fixtures():
    findings = scan_directory(FIXTURES / "vulnerable")
    assert len(findings) >= 13  # at least one per rule
    assert {f.rule_id for f in findings} == {
        "SEC001", "SEC002", "SEC003", "SQL001", "SQL002", "DES001",
        "DES002", "CRY001", "CRY002", "CRY003", "TRA001", "SSRF001",
        "DBG001",
    }


def test_scan_directory_safe_fixtures_is_clean():
    assert scan_directory(FIXTURES / "safe") == []


def test_scan_directory_skips_excluded_dirs_and_non_code_files(tmp_path):
    (tmp_path / "app.py").write_text('api_key = "sk-live-9f8e7d6c5b4a39281706"\n')
    (tmp_path / "notes.txt").write_text('api_key = "sk-live-9f8e7d6c5b4a39281706"\n')
    venv = tmp_path / ".venv"
    venv.mkdir()
    (venv / "bad.py").write_text('api_key = "sk-live-9f8e7d6c5b4a39281706"\n')
    git = tmp_path / ".git"
    git.mkdir()
    (git / "bad.py").write_text('api_key = "sk-live-9f8e7d6c5b4a39281706"\n')
    findings = scan_directory(tmp_path)
    assert len(findings) == 1
    assert findings[0].file.endswith("app.py")


def test_scan_directory_exclude_pattern(tmp_path):
    (tmp_path / "a.py").write_text('api_key = "sk-live-9f8e7d6c5b4a39281706"\n')
    (tmp_path / "b.py").write_text('api_key = "sk-live-9f8e7d6c5b4a39281706"\n')
    findings = scan_directory(tmp_path, exclude_patterns=["b.py"])
    assert len(findings) == 1
    assert findings[0].file.endswith("a.py")


def test_scan_directory_accepts_single_file():
    findings = scan_directory(FIXTURES / "vulnerable" / "ssrf.py")
    assert {f.rule_id for f in findings} == {"SSRF001"}


def test_min_severity_filter():
    findings = scan_directory(FIXTURES / "vulnerable")
    critical_only = filter_by_severity(findings, "critical")
    assert critical_only
    assert {f.severity for f in critical_only} == {"critical"}
    assert len(critical_only) < len(findings)
    high_and_up = filter_by_severity(findings, "high")
    assert {f.severity for f in high_and_up} <= {"critical", "high"}


def test_summarize_counts():
    findings = scan_directory(FIXTURES / "vulnerable")
    summary = summarize(findings)
    assert summary["total"] == len(findings)
    assert sum(summary["by_severity"].values()) == len(findings)
    assert summary["by_severity"]["critical"] >= 1
    assert summary["by_severity"]["high"] >= 1
    assert summary["by_severity"]["medium"] >= 1
    assert set(summary["by_rule"]) == {f.rule_id for f in findings}
    assert summary["rule_names"]["SEC001"] == "Hardcoded secret"


def test_summarize_empty():
    summary = summarize([])
    assert summary["total"] == 0
    assert summary["by_rule"] == {}

"""Scanning engine: scan files, directories, and unified diffs."""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass
from pathlib import Path

from .rules import RULES, RULES_BY_ID, SEVERITY_RANK

# Source file extensions scanned by default.
SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php",
    ".c", ".h", ".cpp", ".cc", ".cs", ".sh", ".pl", ".swift", ".kt",
}

# Directories never scanned (dependencies, VCS metadata, build output).
DEFAULT_EXCLUDE_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", ".venv", "venv", "node_modules",
    ".tox", ".pytest_cache", "dist", "build", ".eggs", "vendor",
}


@dataclass
class Finding:
    rule_id: str
    category: str
    severity: str
    file: str
    line: int
    message: str
    suggestion: str
    code: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity,
            "file": self.file,
            "line": self.line,
            "message": self.message,
            "suggestion": self.suggestion,
            "code": self.code,
        }


def scan_lines(file_display: str, lines: list[str]) -> list[Finding]:
    """Scan already-read lines; returns one finding per rule per line."""
    findings: list[Finding] = []
    for lineno, raw in enumerate(lines, start=1):
        line = raw.rstrip("\n")
        for rule in RULES:
            if rule.matches(line):
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        category=rule.category,
                        severity=rule.severity,
                        file=file_display,
                        line=lineno,
                        message=rule.description,
                        suggestion=rule.fix,
                        code=line.strip()[:200],
                    )
                )
    return findings


def scan_file(path: str | Path) -> list[Finding]:
    """Scan one file. Unreadable / binary files yield no findings."""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeDecodeError):
        return []
    return scan_lines(str(path), text.splitlines())


def _is_excluded(rel: Path, exclude_patterns: list[str]) -> bool:
    text = rel.as_posix()
    return any(fnmatch.fnmatch(text, pat) or fnmatch.fnmatch(text, f"**/{pat}")
               for pat in exclude_patterns)


def scan_directory(
    root: str | Path,
    exclude_patterns: list[str] | None = None,
    min_severity: str = "low",
) -> list[Finding]:
    """Recursively scan a directory, skipping excluded dirs/patterns."""
    root = Path(root)
    exclude_patterns = list(exclude_patterns or [])
    min_rank = SEVERITY_RANK.get(min_severity, 1)
    findings: list[Finding] = []
    if root.is_file():
        found = scan_file(root)
    else:
        found = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [
                d for d in dirnames
                if d not in DEFAULT_EXCLUDE_DIRS
                and not _is_excluded(Path(dirpath, d).relative_to(root), exclude_patterns)
            ]
            for name in sorted(filenames):
                fpath = Path(dirpath, name)
                if fpath.suffix.lower() not in SCAN_EXTENSIONS:
                    continue
                rel = fpath.relative_to(root)
                if _is_excluded(rel, exclude_patterns):
                    continue
                found.extend(scan_file(fpath))
    return [f for f in found if SEVERITY_RANK[f.severity] >= min_rank]


def filter_by_severity(findings: list[Finding], min_severity: str) -> list[Finding]:
    min_rank = SEVERITY_RANK.get(min_severity, 1)
    return [f for f in findings if SEVERITY_RANK[f.severity] >= min_rank]


def summarize(findings: list[Finding]) -> dict:
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    by_rule: dict[str, int] = {}
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1
    return {
        "total": len(findings),
        "by_severity": by_severity,
        "by_rule": dict(sorted(by_rule.items())),
        "rule_names": {rid: RULES_BY_ID[rid].name for rid in by_rule},
    }

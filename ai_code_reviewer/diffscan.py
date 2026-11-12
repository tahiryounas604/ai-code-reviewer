"""Parse a unified git diff and scan only its added lines."""

from __future__ import annotations

import re

from .engine import scan_lines

_DIFF_GIT_RE = re.compile(r"^diff --git a/(.+?) b/(.+)$")
_NEW_FILE_RE = re.compile(r"^\+\+\+ b/(.+)$")
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def parse_diff(diff_text: str) -> dict[str, list[tuple[int, str]]]:
    """Return {file_path: [(new_line_number, line_content), ...]} for added lines.

    Only lines added by the diff are returned; removed and context lines
    are ignored, so review comments point at code the PR actually adds.
    """
    result: dict[str, list[tuple[int, str]]] = {}
    current_file: str | None = None
    new_lineno = 0
    for raw in diff_text.splitlines():
        if raw.startswith("diff --git "):
            m = _DIFF_GIT_RE.match(raw)
            current_file = m.group(2) if m else None
            new_lineno = 0
            continue
        if raw.startswith("+++ "):
            m = _NEW_FILE_RE.match(raw)
            if m:
                current_file = m.group(1)
                result.setdefault(current_file, [])
            continue
        if raw.startswith("--- "):
            continue
        if raw.startswith("@@ "):
            m = _HUNK_RE.match(raw)
            if m:
                new_lineno = int(m.group(1))
            continue
        if current_file is None:
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            result.setdefault(current_file, []).append((new_lineno, raw[1:]))
            new_lineno += 1
        elif raw.startswith("-"):
            continue  # removed line: new-file line number does not advance
        else:
            new_lineno += 1  # context line
    return {k: v for k, v in result.items() if v}


def scan_diff(diff_text: str, min_severity: str = "low"):
    """Scan only the added lines of a unified diff."""
    from .engine import filter_by_severity

    findings = []
    for file_path, added in parse_diff(diff_text).items():
        # scan_lines numbers lines from 1; remap to real new-file numbers.
        for lineno, content in added:
            for finding in scan_lines(file_path, [content]):
                finding.line = lineno
                findings.append(finding)
    return filter_by_severity(findings, min_severity)

"""Command-line interface for ai-code-reviewer."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .diffscan import scan_diff
from .engine import scan_directory, scan_file, summarize
from .reporters import findings_to_json, findings_to_markdown, findings_to_sarif
from .rules import SEVERITY_RANK

FORMATS = ("json", "sarif", "markdown", "all")
SEVERITIES = ("critical", "high", "medium", "low", "none")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ai-code-reviewer",
        description=(
            "Rule-based security review of source code (no LLM, no paid AI). "
            "Scans a file/directory or a unified git diff and reports "
            "security findings as JSON, SARIF, and/or Markdown."
        ),
    )
    parser.add_argument("path", nargs="?", default=".",
                        help="file or directory to scan (default: .)")
    parser.add_argument("--diff", metavar="FILE",
                        help="scan only added lines of a unified diff file "
                             "('-' reads stdin); overrides path")
    parser.add_argument("--format", choices=FORMATS, default="markdown",
                        help="output format (default: markdown)")
    parser.add_argument("--output", metavar="FILE",
                        help="write the report to FILE instead of stdout "
                             "(single format only)")
    parser.add_argument("--output-dir", metavar="DIR", default=".",
                        help="directory for --format all "
                             "(writes report.json, report.sarif, report.md)")
    parser.add_argument("--fail-on", choices=SEVERITIES, default="high",
                        help="exit 1 if any finding is at or above this "
                             "severity (default: high; 'none' never fails)")
    parser.add_argument("--min-severity", choices=("critical", "high", "medium", "low"),
                        default="low", help="ignore findings below this severity")
    parser.add_argument("--exclude", action="append", default=[],
                        metavar="PATTERN",
                        help="glob pattern to exclude, relative to the scan "
                             "root (repeatable)")
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    return parser


def render(findings, fmt: str) -> str:
    if fmt == "json":
        return findings_to_json(findings)
    if fmt == "sarif":
        return findings_to_sarif(findings)
    return findings_to_markdown(findings)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.diff:
        if args.diff == "-":
            diff_text = sys.stdin.read()
        else:
            try:
                diff_text = Path(args.diff).read_text(encoding="utf-8")
            except OSError as exc:
                print(f"error: cannot read diff file: {exc}", file=sys.stderr)
                return 2
        findings = scan_diff(diff_text, min_severity=args.min_severity)
    else:
        target = Path(args.path)
        if not target.exists():
            print(f"error: no such file or directory: {args.path}", file=sys.stderr)
            return 2
        if target.is_file():
            from .engine import filter_by_severity
            findings = filter_by_severity(scan_file(target), args.min_severity)
        else:
            findings = scan_directory(target, exclude_patterns=args.exclude,
                                      min_severity=args.min_severity)

    summary = summarize(findings)

    if args.format == "all":
        out_dir = Path(args.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "report.json").write_text(findings_to_json(findings), encoding="utf-8")
        (out_dir / "report.sarif").write_text(findings_to_sarif(findings), encoding="utf-8")
        (out_dir / "report.md").write_text(findings_to_markdown(findings), encoding="utf-8")
        print(f"Wrote report.json, report.sarif, report.md to {out_dir} "
              f"({summary['total']} findings)")
    elif args.output:
        Path(args.output).write_text(render(findings, args.format), encoding="utf-8")
        print(f"Wrote {args.output} ({summary['total']} findings)")
    else:
        print(render(findings, args.format), end="")

    if args.fail_on == "none":
        return 0
    threshold = SEVERITY_RANK[args.fail_on]
    worst = max((SEVERITY_RANK[f.severity] for f in findings), default=0)
    return 1 if worst >= threshold else 0


if __name__ == "__main__":
    raise SystemExit(main())

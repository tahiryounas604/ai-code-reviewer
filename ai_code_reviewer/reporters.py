"""Reporters: JSON, SARIF 2.1.0, and Markdown summary."""

from __future__ import annotations

import json

from . import __version__
from .engine import Finding, summarize
from .rules import RULES_BY_ID

_SEVERITY_ICON = {"critical": ":rotating_light:", "high": ":warning:",
                  "medium": ":eyes:", "low": ":information_source:"}
_SARIF_LEVEL = {"critical": "error", "high": "error",
                "medium": "warning", "low": "note"}


def findings_to_json(findings: list[Finding]) -> str:
    payload = {
        "tool": "ai-code-reviewer",
        "version": __version__,
        "engine": "rule-based (no LLM, no AI model)",
        "summary": summarize(findings),
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2) + "\n"


def findings_to_sarif(findings: list[Finding]) -> str:
    """SARIF 2.1.0 document consumable by GitHub code scanning."""
    rules = []
    seen: set[str] = set()
    for f in findings:
        if f.rule_id in seen:
            continue
        seen.add(f.rule_id)
        rule = RULES_BY_ID[f.rule_id]
        rules.append({
            "id": rule.rule_id,
            "name": rule.name,
            "shortDescription": {"text": rule.description},
            "fullDescription": {"text": rule.description},
            "help": {"text": rule.fix},
            "defaultConfiguration": {"level": _SARIF_LEVEL[rule.severity]},
            "properties": {"severity": rule.severity, "category": rule.category},
        })
    results = [{
        "ruleId": f.rule_id,
        "level": _SARIF_LEVEL[f.severity],
        "message": {"text": f"{f.message} Suggested fix: {f.suggestion}"},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": f.file},
                "region": {
                    "startLine": f.line,
                    "snippet": {"text": f.code},
                },
            }
        }],
    } for f in findings]
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ai-code-reviewer",
                    "version": __version__,
                    "rules": rules,
                }
            },
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2) + "\n"


def findings_to_markdown(findings: list[Finding]) -> str:
    summary = summarize(findings)
    sev = summary["by_severity"]
    lines = [
        "# AI Code Reviewer — Security Report",
        "",
        "Rule-based review (no LLM, no paid AI). "
        "Findings below are pattern matches — verify each one before acting.",
        "",
        "## Summary",
        "",
        f"- **Total findings:** {summary['total']}",
        f"- Critical: {sev['critical']} | High: {sev['high']} | "
        f"Medium: {sev['medium']} | Low: {sev['low']}",
        "",
    ]
    if not findings:
        lines += ["No security findings. :white_check_mark:", ""]
        return "\n".join(lines)
    lines += ["## Findings", ""]
    ordered = sorted(
        findings,
        key=lambda f: ({"critical": 0, "high": 1, "medium": 2, "low": 3}[f.severity],
                       f.file, f.line),
    )
    for f in ordered:
        icon = _SEVERITY_ICON.get(f.severity, "")
        rule = RULES_BY_ID[f.rule_id]
        lines += [
            f"### {icon} {f.severity.upper()} — {rule.name} "
            f"(`{f.rule_id}`) — `{f.file}:{f.line}`",
            "",
            f.message,
            "",
            f"**Suggested fix:** {f.suggestion}",
            "",
        ]
        if f.code:
            lines += ["```", f.code, "```", ""]
    return "\n".join(lines)

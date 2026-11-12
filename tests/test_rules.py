"""Per-rule tests: every rule fires on its vulnerable fixture and stays
silent on its safe fixture."""

from pathlib import Path

import pytest

from ai_code_reviewer.engine import scan_file
from ai_code_reviewer.rules import RULES_BY_ID

FIXTURES = Path(__file__).parent / "fixtures"

# (fixture filename, rules that must fire on the vulnerable file)
VULNERABLE_CASES = [
    ("secrets.py", {"SEC001", "SEC002", "SEC003"}),
    ("sql_injection.py", {"SQL001", "SQL002"}),
    ("deserialization.py", {"DES001", "DES002"}),
    ("weak_crypto.py", {"CRY001", "CRY002", "CRY003"}),
    ("path_traversal.py", {"TRA001"}),
    ("ssrf.py", {"SSRF001"}),
    ("debug_flag.py", {"DBG001"}),
]

# (fixture filename, rules that must NOT fire on the safe file)
SAFE_CASES = [
    ("secrets.py", {"SEC001", "SEC002", "SEC003"}),
    ("sql_injection.py", {"SQL001", "SQL002"}),
    ("deserialization.py", {"DES001", "DES002"}),
    ("weak_crypto.py", {"CRY001", "CRY002", "CRY003"}),
    ("path_traversal.py", {"TRA001"}),
    ("ssrf.py", {"SSRF001"}),
    ("debug_flag.py", {"DBG001"}),
]


def rule_ids(findings):
    return {f.rule_id for f in findings}


@pytest.mark.parametrize("filename,expected", VULNERABLE_CASES)
def test_vulnerable_fixture_triggers_rule(filename, expected):
    findings = scan_file(FIXTURES / "vulnerable" / filename)
    assert expected <= rule_ids(findings), (
        f"{filename}: expected {expected}, got {rule_ids(findings)}"
    )


@pytest.mark.parametrize("filename,absent", SAFE_CASES)
def test_safe_fixture_does_not_trigger_rule(filename, absent):
    findings = scan_file(FIXTURES / "safe" / filename)
    assert rule_ids(findings) & absent == set(), (
        f"{filename}: safe file wrongly triggered {rule_ids(findings) & absent}"
    )


def test_safe_fixtures_produce_zero_findings():
    for path in sorted((FIXTURES / "safe").glob("*.py")):
        assert scan_file(path) == [], f"safe fixture {path.name} produced findings"


def test_secret_placeholder_values_are_ignored():
    rule = RULES_BY_ID["SEC001"]
    assert not rule.matches('api_key = "your-api-key-here"')
    assert not rule.matches('password = "changeme"')
    assert not rule.matches('api_key = "xxxxxxxx"')
    assert not rule.matches('api_key = "short"')
    assert rule.matches('api_key = "sk-live-9f8e7d6c5b4a39281706"')
    assert rule.matches('password = "SuperSecretPassword123!"')


def test_yaml_safe_loader_is_not_flagged():
    rule = RULES_BY_ID["DES001"]
    assert not rule.matches("config = yaml.load(text, Loader=yaml.SafeLoader)")
    assert rule.matches("config = yaml.load(text)")


def test_each_rule_has_description_and_fix():
    for rule in RULES_BY_ID.values():
        assert rule.description.strip()
        assert rule.fix.strip()
        assert rule.severity in {"critical", "high", "medium", "low"}


def test_all_rule_ids_are_unique_and_prefixed():
    assert len(RULES_BY_ID) == 13
    for rule_id in RULES_BY_ID:
        assert rule_id[:3] in {"SEC", "SQL", "DES", "CRY", "TRA", "SSR", "DBG"}

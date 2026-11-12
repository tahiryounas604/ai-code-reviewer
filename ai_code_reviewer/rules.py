"""Rule definitions for the ai-code-reviewer engine.

Every rule is a set of regular expressions matched against one source line
at a time, plus (where noted) a small value check to cut false positives.
Clean-room implementation: patterns were written from first principles
for this project, not copied from any other scanner.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional

# Values that look like secrets but are obviously placeholders / examples.
_PLACEHOLDER_PREFIXES = (
    "your-", "your_", "example", "changeme", "change-me", "placeholder",
    "xxx", "test", "dummy", "sample", "todo", "insert-", "replace-",
)
_PLACEHOLDER_VALUES = {
    "password", "secret", "changeme", "example", "test", "dummy",
    "placeholder", "xxx", "your-password", "your-secret",
}


def _secret_value_ok(line: str, match: "re.Match[str]") -> bool:
    """Return True only if the captured literal looks like a real secret."""
    value = match.group("value")
    if len(value) < 8:
        return False
    lowered = value.lower()
    if lowered in _PLACEHOLDER_VALUES:
        return False
    if lowered.startswith(_PLACEHOLDER_PREFIXES):
        return False
    if len(set(value)) == 1:  # e.g. "aaaaaaaa"
        return False
    return True


@dataclass(frozen=True)
class Rule:
    rule_id: str
    name: str
    category: str
    severity: str  # critical | high | medium | low
    description: str
    fix: str
    patterns: tuple[str, ...]
    excludes: tuple[str, ...] = ()
    value_check: Optional[Callable[[str, "re.Match[str]"], bool]] = field(
        default=None, repr=False, compare=False
    )

    def matches(self, line: str) -> bool:
        for pattern in self.patterns:
            match = re.search(pattern, line)
            if match is None:
                continue
            if any(re.search(exc, line) for exc in self.excludes):
                continue
            if self.value_check is not None and not self.value_check(line, match):
                continue
            return True
        return False


RULES: tuple[Rule, ...] = (
    Rule(
        rule_id="SEC001",
        name="Hardcoded secret",
        category="secrets",
        severity="high",
        description=(
            "A credential (API key, secret, token, or password) is assigned "
            "as a literal string in source code. Anyone who can read the "
            "code — including after it is committed — owns the credential."
        ),
        fix=(
            "Read the credential from an environment variable or a secrets "
            "manager (e.g. os.environ / os.getenv), never commit a real "
            "value, and rotate any credential that was ever committed."
        ),
        patterns=(
            r"""(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|pwd|client[_-]?secret)\s*[:=]\s*["'](?P<value>[^"']+)["']""",
        ),
        value_check=_secret_value_ok,
    ),
    Rule(
        rule_id="SEC002",
        name="AWS access key ID in source",
        category="secrets",
        severity="critical",
        description=(
            "An AWS access key ID (AKIA...) appears in source code. "
            "Paired with its secret key it grants AWS API access."
        ),
        fix=(
            "Remove the key, revoke it in the AWS console, and use IAM "
            "roles / environment variables instead of embedded keys."
        ),
        patterns=(r"AKIA[0-9A-Z]{16}",),
    ),
    Rule(
        rule_id="SEC003",
        name="Private key in source",
        category="secrets",
        severity="critical",
        description=(
            "A PEM private key block appears in source code. Anyone with "
            "it can impersonate the key owner."
        ),
        fix=(
            "Remove the key, revoke/replace it, and load keys from a "
            "secrets manager or a file outside version control."
        ),
        patterns=(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",),
    ),
    Rule(
        rule_id="SQL001",
        name="SQL injection via string-built query in execute()",
        category="sql-injection",
        severity="high",
        description=(
            "A database execute() call builds its SQL with string "
            "formatting, concatenation, or %-formatting of untrusted data. "
            "An attacker can break out of the query and run arbitrary SQL."
        ),
        fix=(
            "Use parameterised queries: pass values as parameters "
            "(execute(sql, (value,))) instead of interpolating them into "
            "the SQL string."
        ),
        patterns=(
            r"""\.execute\s*\([^)]*f["']""",
            r"""\.execute\s*\([^)]*\.format\s*\(""",
            r"""\.execute\s*\([^)]*\+""",
            r"""\.execute\s*\([^)]*["']\s*%""",
        ),
    ),
    Rule(
        rule_id="SQL002",
        name="SQL query built by string formatting",
        category="sql-injection",
        severity="high",
        description=(
            "A variable named query/sql is built with an f-string, "
            "concatenation, or .format() — the classic setup for SQL "
            "injection when that variable later reaches execute()."
        ),
        fix=(
            "Build the query with placeholders only and pass values as "
            "parameters to execute(); never interpolate user input into SQL."
        ),
        patterns=(
            r"""(?i)\b(query|sql|statement)\s*=\s*[^#\n]*f["']""",
            r"""(?i)\b(query|sql|statement)\s*=\s*[^#\n]*\.format\s*\(""",
            r"""(?i)\b(query|sql|statement)\s*=\s*["'][^"']*["']\s*\+""",
        ),
    ),
    Rule(
        rule_id="DES001",
        name="Unsafe deserialization",
        category="deserialization",
        severity="critical",
        description=(
            "pickle/marshal loads() or yaml.load() without a SafeLoader "
            "deserializes untrusted data. Crafted input can execute "
            "arbitrary code during deserialization."
        ),
        fix=(
            "Never unpickle untrusted data. Use json.loads() for data "
            "exchange, or yaml.safe_load() for YAML."
        ),
        patterns=(
            r"pickle\.(?:loads?|load)\s*\(",
            r"marshal\.(?:loads?|load)\s*\(",
            r"yaml\.load\s*\(",
        ),
        excludes=(r"SafeLoader",),
    ),
    Rule(
        rule_id="DES002",
        name="Dynamic code execution (eval/exec)",
        category="deserialization",
        severity="critical",
        description=(
            "eval() / exec() runs a string as code. If any part of that "
            "string comes from user input, it is remote code execution."
        ),
        fix=(
            "Remove the call. For parsing literals use ast.literal_eval(); "
            "for dynamic behaviour use a dispatch dict of named functions."
        ),
        patterns=(r"\beval\s*\(", r"\bexec\s*\("),
    ),
    Rule(
        rule_id="CRY001",
        name="Weak hash (MD5/SHA1)",
        category="weak-crypto",
        severity="medium",
        description=(
            "MD5 or SHA1 is used. Both are broken for collision resistance "
            "and unsuitable for passwords or integrity checks that must "
            "resist forgery."
        ),
        fix=(
            "Use SHA-256 or better (hashlib.sha256), and for passwords a "
            "purpose-built KDF such as bcrypt, scrypt, or argon2."
        ),
        patterns=(
            r"hashlib\.(?:md5|sha1)\s*\(",
            r"""hashlib\.new\s*\(\s*["'](?:md5|sha1)["']""",
        ),
    ),
    Rule(
        rule_id="CRY002",
        name="Weak cipher (DES)",
        category="weak-crypto",
        severity="high",
        description=(
            "DES is used. Its 56-bit key is brute-forceable with modest "
            "resources and it must not protect anything today."
        ),
        fix="Use AES (AES-256-GCM) from a maintained library instead of DES.",
        patterns=(
            r"DES\.new\s*\(",
            r"Cipher\.DES\b",
            r"""from\s+Crypto\.Cipher\s+import\s+[^#\n]*\bDES\b""",
        ),
    ),
    Rule(
        rule_id="CRY003",
        name="Hardcoded initialization vector (IV)",
        category="weak-crypto",
        severity="medium",
        description=(
            "An encryption IV is a hardcoded literal. A reused IV with the "
            "same key leaks plaintext patterns and breaks CBC/GCM security."
        ),
        fix=(
            "Generate a fresh random IV per encryption (os.urandom(16)), "
            "store it with the ciphertext, and never reuse an IV."
        ),
        patterns=(r"""(?i)\biv\s*=\s*(?:b)?["'][^"']{4,}["']""",),
    ),
    Rule(
        rule_id="TRA001",
        name="Path traversal via constructed file path",
        category="path-traversal",
        severity="high",
        description=(
            "open() / send_file() is called with a path built by string "
            "formatting or concatenation. A value like ../../etc/passwd "
            "can escape the intended directory."
        ),
        fix=(
            "Validate the input against an allow-list, resolve the path "
            "and check it stays under the intended base directory "
            "(e.g. Path.resolve() + is_relative_to(base))."
        ),
        patterns=(
            r"""open\s*\([^)]*f["']""",
            r"""open\s*\([^)]*\.format\s*\(""",
            r"""open\s*\([^)]*\+""",
            r"""send_file\s*\([^)]*(?:f["']|\+|\.format\s*\()""",
        ),
    ),
    Rule(
        rule_id="SSRF001",
        name="SSRF-prone URL construction",
        category="ssrf",
        severity="medium",
        description=(
            "An outbound HTTP request builds its URL by string formatting "
            "or concatenation of untrusted data. An attacker may make the "
            "server request internal addresses (metadata endpoints, "
            "internal services)."
        ),
        fix=(
            "Validate the URL against an allow-list of hosts/schemes, "
            "resolve and block private/loopback/link-local IPs, and never "
            "let user input choose the host."
        ),
        patterns=(
            r"""(?:requests\.(?:get|post|put|delete|head|patch)|urllib\.request\.urlopen|urlopen)\s*\([^)]*f["']""",
            r"""(?:requests\.(?:get|post|put|delete|head|patch)|urllib\.request\.urlopen|urlopen)\s*\([^)]*\.format\s*\(""",
            r"""(?:requests\.(?:get|post|put|delete|head|patch)|urllib\.request\.urlopen|urlopen)\s*\([^)]*\+""",
        ),
    ),
    Rule(
        rule_id="DBG001",
        name="Debug mode left enabled",
        category="debug-flag",
        severity="medium",
        description=(
            "Debug mode is enabled in code. Debug mode can expose stack "
            "traces, an interactive debugger, and detailed errors to "
            "anyone who triggers an error."
        ),
        fix=(
            "Set debug off in production and gate it behind an environment "
            "variable that defaults to off (debug=os.getenv('DEBUG') == '1')."
        ),
        patterns=(
            r"""(?i)\bdebug\s*=\s*True\b""",
            r"""(?i)["']DEBUG["']\]\s*=\s*True\b""",
        ),
    ),
)

RULES_BY_ID = {rule.rule_id: rule for rule in RULES}

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

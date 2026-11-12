# ai-code-reviewer

A rule-based security reviewer for source code — **no LLM, no paid AI,
no network calls**. It scans a directory (or a git diff) for common
security anti-patterns and reports each finding with severity, file/line,
explanation, and a suggested fix.

Part of the [Tytechlabs](https://www.linkedin.com/in/tahiryounas604)
open-source line. License: GPL-3.0.

## What it checks

| Rule | Category | Severity | What it catches |
|------|----------|----------|-----------------|
| SEC001 | Hardcoded secret | High | API key / token / password assigned as a literal |
| SEC002 | Hardcoded secret | Critical | AWS access key ID (`AKIA…`) in source |
| SEC003 | Hardcoded secret | Critical | PEM private key block in source |
| SQL001 | SQL injection | High | `execute()` with f-string / `+` / `%` / `.format()` SQL |
| SQL002 | SQL injection | High | `query`/`sql` variable built by string formatting |
| DES001 | Deserialization | Critical | `pickle`/`marshal` loads, `yaml.load()` without SafeLoader |
| DES002 | Deserialization | Critical | `eval()` / `exec()` on strings |
| CRY001 | Weak crypto | Medium | MD5 / SHA1 |
| CRY002 | Weak crypto | High | DES |
| CRY003 | Weak crypto | Medium | Hardcoded encryption IV |
| TRA001 | Path traversal | High | `open()`/`send_file()` with a constructed path |
| SSRF001 | SSRF | Medium | HTTP request with a constructed URL |
| DBG001 | Debug flag | Medium | `debug=True` / `DEBUG = True` left on |

Every finding carries: rule id, category, severity, file, line,
explanation, suggested fix, and the offending line of code.

## Install

Requires Python 3.9+ and nothing else — the tool uses only the standard
library.

```bash
python3 -m ai_code_reviewer --version   # run from the project directory; no install step needed
```

Optional install as a command:

```bash
pip install .
ai-code-reviewer --help
```

> The GitHub repository for this product is planned
> (`tahiryounas604/ai-code-reviewer`) but has **not been published
> yet** — this build is local only.

## Usage

```bash
# Review a directory (Markdown summary to stdout)
python3 -m ai_code_reviewer path/to/code

# JSON report to a file
python3 -m ai_code_reviewer path/to/code --format json --output report.json

# SARIF report (consumable by GitHub code scanning)
python3 -m ai_code_reviewer path/to/code --format sarif --output report.sarif

# All three formats at once
python3 -m ai_code_reviewer path/to/code --format all --output-dir reviewer-report

# Review only the lines a pull request adds
git diff origin/main...HEAD > change.diff
python3 -m ai_code_reviewer --diff change.diff
cat change.diff | python3 -m ai_code_reviewer --diff -

# Fail CI only on high-or-worse findings (default), or never fail
python3 -m ai_code_reviewer path/to/code --fail-on high
python3 -m ai_code_reviewer path/to/code --fail-on none

# Ignore low/medium findings, exclude paths
python3 -m ai_code_reviewer path/to/code --min-severity high --exclude "tests/*"
```

Exit codes: `0` = clean (or below the `--fail-on` threshold),
`1` = a finding at or above the threshold, `2` = usage error
(missing path / unreadable diff).

## GitHub Action

`action.yml` is a composite action: it runs the reviewer on pull
requests and posts the Markdown report as a PR comment (via the `gh`
CLI, using the built-in `GITHUB_TOKEN`). An example workflow is in
`.github/workflows/review.yml`:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
- uses: ./
  with:
    path: "."
    fail-on: "high"
```

**Not tested live:** the Action code (including the PR-comment step)
was written and YAML-validated locally, but no live GitHub run has
been executed, so the comment-posting step is unverified on GitHub's
runners. The reviewer itself was verified locally (see Tests).

## Tests

```bash
pip install pytest
python3 -m pytest -q
```

54 tests, all passing. Coverage per rule: each of the 13 rules is
tested against a vulnerable fixture (must fire) and a safe fixture
(must stay silent) in `tests/fixtures/`. Reporters (JSON/SARIF/
Markdown), diff parsing, directory scanning, severity filtering, and
the CLI (exit codes, output files, `--diff` mode) are all tested too.

## Honest limits

- **Pattern matching, not understanding.** This is a regex-based
  scanner. It cannot trace data flow: a query built in one function
  and executed in another is missed, and a value that is actually
  validated before use may still be flagged. Every finding needs a
  human to verify it.
- **False positives exist.** Deliberately: a hardcoded-looking test
  value, a URL built from a constant, or a debug flag gated by an
  environment variable in an unusual form can be flagged. The
  placeholder allow-list (`your-api-key`, `changeme`, …) only covers
  the common cases.
- **False negatives exist.** Obfuscation, indirection through
  variables, other languages' idioms, and framework-specific sinks
  (ORM raw queries, template injection, etc.) are not covered.
  A clean report is **not** proof of secure code.
- **Secrets are heuristic.** SEC001 only flags literals of 8+
  characters assigned to credential-like names. Short, split, or
  encoded secrets are missed; high-entropy detection is not
  implemented.
- **Scope.** The rule set covers the seven categories above only.
  It does not check authentication, authorization, dependencies with
  known CVEs, or infrastructure configuration.
- **Self-scan quirk.** Scanning this repo's own rule table
  (`ai_code_reviewer/rules.py`) and test data self-triggers by
  design — the pattern definitions and planted test secrets contain
  the very strings the rules detect. CI excludes those two paths for
  that reason (see `.github/workflows/ci.yml`).
- **GitHub Action untested live.** See the GitHub Action section
  above.

Built by Tahir Younas — Penetration Tester & Application Security Engineer — https://www.linkedin.com/in/tahiryounas604 | Tytechlabs
